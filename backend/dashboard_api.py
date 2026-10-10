"""Read-only dashboard endpoints for the NIGRAANI Next.js SOC interface.

These endpoints strictly query the existing SQLite database (demo.db) and the
Isolation Forest model (models/iforest.joblib). They do not generate fake data
or alter core analyzer/detection/risk engine logic.
"""

from __future__ import annotations

import json
import sqlite3
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request

from backend.database import DB_PATH, ORDERS, USERS, get_connection, get_calls_for_incident
from backend.ml.anomaly_detector import AnomalyDetector, ModelNotFoundError
from backend.ml.features import FEATURE_NAMES, extract_windows, parse_timestamp
from backend.notification_service import (
    get_notification,
    get_unread_count,
    list_notifications,
    set_all_notifications_read,
    set_notification_read,
)
from backend.twilio_service import (
    get_call_details,
    get_voice_config_status,
    handle_twilio_callback,
    list_calls,
    trigger_manual_test_call,
)

router = APIRouter(tags=["dashboard"])

_detector_instance: AnomalyDetector | None = None
_detector_error: str | None = None


def get_detector() -> AnomalyDetector | None:
    global _detector_instance, _detector_error
    if _detector_instance is not None:
        return _detector_instance
    try:
        _detector_instance = AnomalyDetector()
        _detector_error = None
        return _detector_instance
    except Exception as exc:
        _detector_error = str(exc)
        return None


def _parse_json(value: Any, default: Any = None) -> Any:
    if value is None:
        return default
    if isinstance(value, (list, dict)):
        return value
    if isinstance(value, str):
        try:
            return json.loads(value)
        except Exception:
            return default
    return default


def _parse_event_ids(raw: Any) -> list[int]:
    data = _parse_json(raw, [])
    if not isinstance(data, list):
        return []
    result = []
    for item in data:
        try:
            result.append(int(item))
        except (TypeError, ValueError):
            continue
    return result


def _unique_detections(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    unique: dict[tuple[Any, ...], dict[str, Any]] = {}
    for row in rows:
        event_ids = tuple(sorted(set(_parse_event_ids(row.get("event_ids")))))
        if not event_ids:
            key = ("unlinked", row.get("detection_id"))
        else:
            key = (
                row.get("detector"),
                row.get("attack_type"),
                row.get("ip"),
                row.get("user_id"),
                event_ids,
            )
        unique.setdefault(key, row)
    return sorted(unique.values(), key=lambda row: row.get("detection_id", 0))


def _unique_decisions(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    unique: dict[tuple[Any, ...], dict[str, Any]] = {}
    for row in rows:
        event_ids = _parse_json(row.get("event_ids"))
        if isinstance(event_ids, list) and event_ids:
            key = (
                "window",
                row.get("ip"),
                tuple(sorted(set(_parse_event_ids(event_ids)))),
                row.get("source"),
            )
        else:
            key = (
                "legacy",
                row.get("ip"),
                row.get("risk_score"),
                row.get("risk_level"),
                row.get("action"),
                json.dumps(_parse_json(row.get("reasons"), []), sort_keys=True),
                row.get("source"),
            )
        unique[key] = row
    return sorted(unique.values(), key=lambda row: row.get("decision_id", 0))


def _severity_band(score: Any) -> str:
    try:
        val = float(score)
    except (TypeError, ValueError):
        return "LOW"
    if val >= 80:
        return "CRITICAL"
    if val >= 60:
        return "HIGH"
    if val >= 30:
        return "MEDIUM"
    return "LOW"


@router.get("/health")
def get_health() -> dict[str, Any]:
    det = get_detector()
    model_loaded = det is not None

    db_connected = False
    counts = {}
    last_event_ts = None
    try:
        with get_connection() as conn:
            for table in ("security_events", "users", "orders"):
                n = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                counts[table] = n
            detections = [
                dict(row) for row in conn.execute("SELECT * FROM detections").fetchall()
            ]
            decisions = [
                dict(row) for row in conn.execute("SELECT * FROM decisions").fetchall()
            ]
            counts["detections"] = len(_unique_detections(detections))
            counts["decisions"] = len(_unique_decisions(decisions))
            last_ev = conn.execute("SELECT timestamp FROM security_events ORDER BY event_id DESC LIMIT 1").fetchone()
            if last_ev:
                last_event_ts = last_ev["timestamp"]
            db_connected = True
    except Exception as exc:
        counts["error"] = str(exc)

    return {
        "status": "online" if db_connected else "degraded",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "backend": {
            "status": "online",
            "version": "1.0.0",
            "name": "NIGRAANI API Security Engine",
        },
        "database": {
            "status": "connected" if db_connected else "error",
            "path": str(DB_PATH.name),
            "counts": counts,
            "last_event_timestamp": last_event_ts,
        },
        "ml_engine": {
            "status": "healthy" if model_loaded else "unavailable",
            "model": "Isolation Forest",
            "features_contract": list(FEATURE_NAMES),
            "metadata": det.metadata if det else {},
            "error": _detector_error,
        },
        "analyzer": {
            "status": "active" if counts.get("decisions", 0) > 0 else "idle",
            "total_decisions": counts.get("decisions", 0),
            "total_detections": counts.get("detections", 0),
        },
    }


@router.get("/summary")
def get_summary() -> dict[str, Any]:
    with get_connection() as conn:
        events = [dict(r) for r in conn.execute("SELECT * FROM security_events ORDER BY event_id ASC").fetchall()]
        detections = _unique_detections(
            [dict(r) for r in conn.execute("SELECT * FROM detections ORDER BY detection_id ASC").fetchall()]
        )
        decisions = _unique_decisions(
            [dict(r) for r in conn.execute("SELECT * FROM decisions ORDER BY decision_id ASC").fetchall()]
        )

    det = get_detector()
    ml_windows = []
    ml_anomalies_count = 0
    if det and events:
        try:
            windows = extract_windows(events)
            scored = det.score_windows(windows)
            ml_windows = scored
            ml_anomalies_count = sum(1 for w in scored if w.get("is_anomalous"))
        except Exception:
            pass

    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for d in detections:
        band = _severity_band(d.get("severity", 0))
        sev_counts[band] = sev_counts.get(band, 0) + 1

    latest_by_ip: dict[str, dict[str, Any]] = {}
    for d in decisions:
        ip = d.get("ip", "unknown")
        latest_by_ip[ip] = d

    decision_counts = {"ALLOW": 0, "MONITOR": 0, "THROTTLE": 0, "BLOCK": 0}
    for d in latest_by_ip.values():
        act = str(d.get("action", "")).upper()
        if act in decision_counts:
            decision_counts[act] += 1

    worst_decision = None
    if latest_by_ip:
        sorted_decisions = sorted(
            latest_by_ip.values(),
            key=lambda x: (x.get("risk_score", 0), x.get("decision_id", 0)),
            reverse=True,
        )
        top = sorted_decisions[0]
        worst_decision = {
            "decision_id": top.get("decision_id"),
            "ip": top.get("ip"),
            "risk_score": top.get("risk_score"),
            "risk_level": top.get("risk_level"),
            "action": top.get("action"),
            "reasons": _parse_json(top.get("reasons"), []),
            "source": top.get("source"),
        }

    blocked_count = sum(
        1
        for d in latest_by_ip.values()
        if str(d.get("action", "")).upper() == "BLOCK"
    )

    events_by_id = {int(e["event_id"]): e for e in events}
    recent_detections = []
    for d in reversed(detections[-12:]):
        e_ids = _parse_event_ids(d.get("event_ids"))
        linked_ep = "No data"
        linked_ts = None
        for eid in e_ids:
            if eid in events_by_id:
                linked_ep = events_by_id[eid].get("endpoint", "No data")
                linked_ts = events_by_id[eid].get("timestamp")
                break

        ip_dec = latest_by_ip.get(d.get("ip"))

        matched_ml = None
        for w in ml_windows:
            w_ids = set(w.get("event_ids", []))
            if set(e_ids).intersection(w_ids):
                matched_ml = w.get("ml_score")
                break

        recent_detections.append(
            {
                "detection_id": d.get("detection_id"),
                "detector": d.get("detector"),
                "attack_type": d.get("attack_type"),
                "severity": d.get("severity"),
                "severity_band": _severity_band(d.get("severity")),
                "ip": d.get("ip"),
                "user_id": d.get("user_id"),
                "evidence": d.get("evidence"),
                "owasp": d.get("owasp"),
                "event_ids": e_ids,
                "linked_endpoint": linked_ep,
                "linked_timestamp": linked_ts,
                "ml_score": matched_ml,
                "risk_score": ip_dec.get("risk_score") if ip_dec else None,
                "risk_level": ip_dec.get("risk_level") if ip_dec else None,
                "action": ip_dec.get("action") if ip_dec else None,
            }
        )

    return {
        "kpis": {
            "api_requests": len(events),
            "ml_windows": len(ml_windows),
            "ml_anomalies": ml_anomalies_count,
            "security_detections": len(detections),
            "high_threats": sev_counts["HIGH"],
            "critical_threats": sev_counts["CRITICAL"],
            "blocked_requests": blocked_count,
        },
        "threat_posture": worst_decision,
        "severity_distribution": sev_counts,
        "decision_distribution": decision_counts,
        "recent_detections": recent_detections,
    }


@router.get("/traffic")
def get_traffic() -> dict[str, Any]:
    with get_connection() as conn:
        events = [dict(r) for r in conn.execute("SELECT * FROM security_events ORDER BY event_id ASC").fetchall()]

    if not events:
        return {
            "summary": {
                "request_volume": 0,
                "unique_ips": 0,
                "unique_endpoints": 0,
                "http_methods": 0,
                "error_rate_pct": 0.0,
                "avg_latency_ms": 0.0,
            },
            "timeline": [],
            "endpoints": [],
            "methods": [],
            "status_codes": [],
            "latency_distribution": [],
        }

    total = len(events)
    unique_ips = len({e["ip"] for e in events})
    unique_endpoints = len({e["endpoint"] for e in events})
    methods_counter = Counter(e["method"] for e in events)
    status_counter = Counter(str(e["status_code"]) for e in events)
    error_count = sum(1 for e in events if int(e["status_code"]) >= 400)
    latencies = [float(e["response_time_ms"]) for e in events]
    avg_latency = sum(latencies) / total if total else 0.0

    endpoint_stats: dict[str, dict[str, Any]] = {}
    for e in events:
        ep = e["endpoint"]
        if ep not in endpoint_stats:
            endpoint_stats[ep] = {"endpoint": ep, "count": 0, "errors": 0, "latencies": []}
        endpoint_stats[ep]["count"] += 1
        if int(e["status_code"]) >= 400:
            endpoint_stats[ep]["errors"] += 1
        endpoint_stats[ep]["latencies"].append(float(e["response_time_ms"]))

    endpoint_list = []
    for ep, st in endpoint_stats.items():
        count = st["count"]
        endpoint_list.append(
            {
                "endpoint": ep,
                "count": count,
                "error_rate": round(st["errors"] / count * 100, 1),
                "avg_latency": round(sum(st["latencies"]) / count, 1),
            }
        )
    endpoint_list.sort(key=lambda x: x["count"], reverse=True)

    timeline_bins: dict[str, dict[str, Any]] = {}
    for e in events:
        try:
            ts = parse_timestamp(e["timestamp"])
            epoch_bin = int(ts.timestamp() // 30) * 30
            bin_iso = datetime.fromtimestamp(epoch_bin, tz=timezone.utc).isoformat()
            if bin_iso not in timeline_bins:
                timeline_bins[bin_iso] = {
                    "timestamp": bin_iso,
                    "requests": 0,
                    "errors": 0,
                    "avg_latency": 0.0,
                    "_lats": [],
                }
            timeline_bins[bin_iso]["requests"] += 1
            if int(e["status_code"]) >= 400:
                timeline_bins[bin_iso]["errors"] += 1
            timeline_bins[bin_iso]["_lats"].append(float(e["response_time_ms"]))
        except Exception:
            continue

    timeline_list = []
    for bin_iso, data in sorted(timeline_bins.items(), key=lambda x: x[0]):
        reqs = data["requests"]
        data["avg_latency"] = round(sum(data["_lats"]) / reqs, 1) if reqs else 0.0
        del data["_lats"]
        timeline_list.append(data)

    lat_buckets = {"<10ms": 0, "10-25ms": 0, "25-50ms": 0, "50-100ms": 0, ">100ms": 0}
    for lat in latencies:
        if lat < 10:
            lat_buckets["<10ms"] += 1
        elif lat < 25:
            lat_buckets["10-25ms"] += 1
        elif lat < 50:
            lat_buckets["25-50ms"] += 1
        elif lat < 100:
            lat_buckets["50-100ms"] += 1
        else:
            lat_buckets[">100ms"] += 1

    latency_list = [{"range": k, "count": v} for k, v in lat_buckets.items()]

    return {
        "summary": {
            "request_volume": total,
            "unique_ips": unique_ips,
            "unique_endpoints": unique_endpoints,
            "http_methods": len(methods_counter),
            "error_rate_pct": round(error_count / total * 100, 1),
            "avg_latency_ms": round(avg_latency, 1),
        },
        "timeline": timeline_list,
        "endpoints": endpoint_list[:15],
        "methods": [{"method": k, "count": v} for k, v in methods_counter.items()],
        "status_codes": [{"status_code": k, "count": v} for k, v in status_counter.items()],
        "latency_distribution": latency_list,
    }


@router.get("/threats")
def get_threats() -> dict[str, Any]:
    with get_connection() as conn:
        detections = _unique_detections(
            [dict(r) for r in conn.execute("SELECT * FROM detections ORDER BY detection_id ASC").fetchall()]
        )
        events = [dict(r) for r in conn.execute("SELECT * FROM security_events").fetchall()]
        decisions = _unique_decisions(
            [dict(r) for r in conn.execute("SELECT * FROM decisions ORDER BY decision_id ASC").fetchall()]
        )

    if not detections:
        return {
            "summary": {
                "total_detections": 0,
                "unique_attack_types": 0,
                "unique_source_ips": 0,
                "highest_severity": 0,
            },
            "attack_types": [],
            "severities": [],
            "top_source_ips": [],
            "top_endpoints": [],
            "timeline": [],
            "detections": [],
        }

    total = len(detections)
    attack_counter = Counter(d["attack_type"] for d in detections)
    ip_counter = Counter(d["ip"] for d in detections)
    severities = [int(d["severity"]) for d in detections]
    max_sev = max(severities) if severities else 0

    sev_bands: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for s in severities:
        band = _severity_band(s)
        sev_bands[band] += 1

    events_by_id = {int(e["event_id"]): e for e in events}

    latest_by_ip = {}
    for d in decisions:
        latest_by_ip[d["ip"]] = d

    ep_counter: Counter[str] = Counter()
    enriched_detections = []
    timeline_bins: dict[str, int] = {}

    for d in detections:
        e_ids = _parse_event_ids(d.get("event_ids"))
        linked_ep = "No data"
        linked_ts = None
        for eid in e_ids:
            if eid in events_by_id:
                ep = events_by_id[eid].get("endpoint")
                if ep:
                    ep_counter[ep] += 1
                    linked_ep = ep
                ts_str = events_by_id[eid].get("timestamp")
                if ts_str:
                    linked_ts = ts_str
                    try:
                        pts = parse_timestamp(ts_str)
                        bin_30s = int(pts.timestamp() // 30) * 30
                        bin_iso = datetime.fromtimestamp(bin_30s, tz=timezone.utc).isoformat()
                        timeline_bins[bin_iso] = timeline_bins.get(bin_iso, 0) + 1
                    except Exception:
                        pass
                break

        ip_dec = latest_by_ip.get(d.get("ip"))

        enriched_detections.append(
            {
                "detection_id": d.get("detection_id"),
                "detector": d.get("detector"),
                "attack_type": d.get("attack_type"),
                "severity": d.get("severity"),
                "severity_band": _severity_band(d.get("severity")),
                "ip": d.get("ip"),
                "user_id": d.get("user_id"),
                "evidence": d.get("evidence"),
                "owasp": d.get("owasp"),
                "event_ids": e_ids,
                "linked_endpoint": linked_ep,
                "linked_timestamp": linked_ts,
                "risk_score": ip_dec.get("risk_score") if ip_dec else None,
                "risk_level": ip_dec.get("risk_level") if ip_dec else None,
                "action": ip_dec.get("action") if ip_dec else None,
            }
        )

    top_ips = []
    for ip, count in ip_counter.most_common(10):
        ip_decs = [d for d in detections if d.get("ip") == ip]
        ip_max_sev = max((int(d.get("severity", 0)) for d in ip_decs), default=0)
        dec = latest_by_ip.get(ip)
        top_ips.append(
            {
                "ip": ip,
                "count": count,
                "highest_severity": ip_max_sev,
                "action": dec.get("action") if dec else "None",
                "risk_score": dec.get("risk_score") if dec else None,
            }
        )

    timeline_list = [
        {"timestamp": k, "detections": v} for k, v in sorted(timeline_bins.items(), key=lambda x: x[0])
    ]

    return {
        "summary": {
            "total_detections": total,
            "unique_attack_types": len(attack_counter),
            "unique_source_ips": len(ip_counter),
            "highest_severity": max_sev,
        },
        "attack_types": [{"attack_type": k, "count": v} for k, v in attack_counter.items()],
        "severities": [{"band": k, "count": v} for k, v in sev_bands.items()],
        "top_source_ips": top_ips,
        "top_endpoints": [{"endpoint": k, "count": v} for k, v in ep_counter.most_common(10)],
        "timeline": timeline_list,
        "detections": enriched_detections,
    }


@router.get("/ml")
def get_ml() -> dict[str, Any]:
    det = get_detector()
    if not det:
        return {
            "status": "unavailable",
            "error": _detector_error or "Model not loaded",
            "features_contract": list(FEATURE_NAMES),
            "windows": [],
        }

    with get_connection() as conn:
        events = [dict(r) for r in conn.execute("SELECT * FROM security_events ORDER BY event_id ASC").fetchall()]

    if not events:
        return {
            "status": "ready",
            "summary": {
                "total_windows": 0,
                "anomaly_count": 0,
                "anomaly_rate_pct": 0.0,
                "max_score": 0.0,
                "avg_score": 0.0,
            },
            "features_contract": list(FEATURE_NAMES),
            "normal_vs_anomaly": {"normal": 0, "anomaly": 0},
            "timeline": [],
            "score_distribution": [],
            "windows": [],
        }

    windows = extract_windows(events)
    results = det.score_windows(windows)

    if not results:
        return {
            "status": "ready",
            "summary": {
                "total_windows": 0,
                "anomaly_count": 0,
                "anomaly_rate_pct": 0.0,
                "max_score": 0.0,
                "avg_score": 0.0,
            },
            "features_contract": list(FEATURE_NAMES),
            "normal_vs_anomaly": {"normal": 0, "anomaly": 0},
            "timeline": [],
            "score_distribution": [],
            "windows": [],
        }

    total_w = len(results)
    anom_count = sum(1 for r in results if r.get("is_anomalous"))
    scores = [float(r.get("ml_score", 0)) for r in results]
    max_score = max(scores) if scores else 0.0
    avg_score = sum(scores) / total_w if total_w else 0.0

    normal_count = total_w - anom_count

    timeline = []
    for r in sorted(results, key=lambda x: x["window_start"]):
        timeline.append(
            {
                "window_start": r["window_start"],
                "window_end": r["window_end"],
                "ip": r["ip"],
                "ml_score": r["ml_score"],
                "raw_score": r["raw_score"],
                "is_anomalous": r["is_anomalous"],
            }
        )

    score_bins = {
        "0-20": 0,
        "20-40": 0,
        "40-50": 0,
        "50-60": 0,
        "60-80": 0,
        "80-100": 0,
    }
    for s in scores:
        if s < 20:
            score_bins["0-20"] += 1
        elif s < 40:
            score_bins["20-40"] += 1
        elif s < 50:
            score_bins["40-50"] += 1
        elif s < 60:
            score_bins["50-60"] += 1
        elif s < 80:
            score_bins["60-80"] += 1
        else:
            score_bins["80-100"] += 1

    dist_list = [{"range": k, "count": v} for k, v in score_bins.items()]

    enriched_windows = []
    for win, r in zip(windows, results):
        ground_truth = "NORMAL" if win.is_normal else ", ".join(sorted(x for x in win.sim_labels if x != "normal"))
        enriched_windows.append(
            {
                "ip": r["ip"],
                "window_start": r["window_start"],
                "window_end": r["window_end"],
                "ml_score": r["ml_score"],
                "raw_score": r["raw_score"],
                "is_anomalous": r["is_anomalous"],
                "prediction": "ANOMALY" if r["is_anomalous"] else "NORMAL",
                "ground_truth": ground_truth or "ATTACK",
                "features": r["features"],
                "event_ids": r["event_ids"],
            }
        )

    enriched_windows.sort(key=lambda x: x["ml_score"], reverse=True)

    return {
        "status": "healthy",
        "summary": {
            "total_windows": total_w,
            "anomaly_count": anom_count,
            "anomaly_rate_pct": round(anom_count / total_w * 100, 1),
            "max_score": round(max_score, 1),
            "avg_score": round(avg_score, 1),
        },
        "features_contract": list(FEATURE_NAMES),
        "normal_vs_anomaly": {"normal": normal_count, "anomaly": anom_count},
        "timeline": timeline,
        "score_distribution": dist_list,
        "windows": enriched_windows,
        "metadata": det.metadata,
    }


@router.get("/events")
def get_events(
    search: str = Query("", description="Search IP, endpoint, or method"),
    ip: str = Query("", description="Filter by IP"),
    endpoint: str = Query("", description="Filter by endpoint"),
    method: str = Query("", description="Filter by method"),
    status_code: int | None = Query(None, description="Filter by status code"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> dict[str, Any]:
    with get_connection() as conn:
        query = "SELECT * FROM security_events WHERE 1=1"
        params: list[Any] = []

        if ip:
            query += " AND ip = ?"
            params.append(ip)
        if endpoint:
            query += " AND endpoint = ?"
            params.append(endpoint)
        if method:
            query += " AND method = ?"
            params.append(method)
        if status_code is not None:
            query += " AND status_code = ?"
            params.append(status_code)
        if search:
            query += " AND (ip LIKE ? OR endpoint LIKE ? OR method LIKE ? OR CAST(event_id AS TEXT) LIKE ?)"
            pat = f"%{search}%"
            params.extend([pat, pat, pat, pat])

        count_query = f"SELECT COUNT(*) FROM ({query})"
        total = conn.execute(count_query, params).fetchone()[0]

        query += " ORDER BY event_id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        rows = conn.execute(query, params).fetchall()

    events = [dict(r) for r in rows]
    for e in events:
        uid = e.get("user_id")
        if uid and uid in USERS:
            e["user_name"] = USERS[uid]["name"]
        else:
            e["user_name"] = None

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "events": events,
    }


@router.get("/investigate/{event_id}")
def investigate_event(event_id: int) -> dict[str, Any]:
    with get_connection() as conn:
        ev_row = conn.execute("SELECT * FROM security_events WHERE event_id = ?", (event_id,)).fetchone()
        if not ev_row:
            raise HTTPException(status_code=404, detail=f"Event ID {event_id} not found")
        event = dict(ev_row)

        all_detections = _unique_detections(
            [dict(r) for r in conn.execute("SELECT * FROM detections").fetchall()]
        )
        all_decisions = [
            dict(r)
            for r in conn.execute(
                "SELECT * FROM decisions WHERE ip = ? ORDER BY decision_id ASC", (event["ip"],)
            ).fetchall()
        ]
        all_decisions = _unique_decisions(all_decisions)
        all_events = [dict(r) for r in conn.execute("SELECT * FROM security_events").fetchall()]

    uid = event.get("user_id")
    user_info = USERS.get(uid) if uid else None

    linked_detections = []
    for d in all_detections:
        e_ids = _parse_event_ids(d.get("event_ids"))
        if event_id in e_ids:
            linked_detections.append(
                {
                    "detection_id": d.get("detection_id"),
                    "detector": d.get("detector"),
                    "attack_type": d.get("attack_type"),
                    "severity": d.get("severity"),
                    "severity_band": _severity_band(d.get("severity")),
                    "evidence": d.get("evidence"),
                    "owasp": d.get("owasp"),
                    "event_ids": e_ids,
                }
            )

    det = get_detector()
    ml_window = None
    if det and all_events:
        try:
            windows = extract_windows(all_events)
            scored = det.score_windows(windows)
            matching = [w for w in scored if event_id in w.get("event_ids", [])]
            if matching:
                ml_window = max(matching, key=lambda w: w.get("ml_score", 0))
        except Exception:
            pass

    latest_decision = None
    if all_decisions:
        top = all_decisions[-1]
        latest_decision = {
            "decision_id": top.get("decision_id"),
            "risk_score": top.get("risk_score"),
            "risk_level": top.get("risk_level"),
            "action": top.get("action"),
            "reasons": _parse_json(top.get("reasons"), []),
            "source": top.get("source"),
            "total_decisions_for_ip": len(all_decisions),
        }

    calls = []
    if latest_decision:
        calls = get_calls_for_incident(f"decision-{latest_decision.get('decision_id')}")
    if not calls:
        with get_connection() as conn:
            call_rows = conn.execute(
                "SELECT * FROM call_alerts WHERE metadata LIKE ? ORDER BY call_id DESC",
                (f"%{event['ip']}%",),
            ).fetchall()
            calls = [dict(r) for r in call_rows]
            for c in calls:
                if c.get("metadata") and isinstance(c["metadata"], str):
                    try:
                        c["metadata"] = json.loads(c["metadata"])
                    except Exception:
                        c["metadata"] = {}

    lifecycle = [
        {
            "stage": 1,
            "name": "REQUEST",
            "title": "HTTP Ingestion",
            "status": "COMPLETED",
            "data": {
                "timestamp": event.get("timestamp"),
                "ip": event.get("ip"),
                "method": event.get("method"),
                "endpoint": event.get("endpoint"),
                "status_code": event.get("status_code"),
                "response_time_ms": event.get("response_time_ms"),
                "sim_label": event.get("sim_label"),
            },
        },
        {
            "stage": 2,
            "name": "DETECTION",
            "title": "Rule & Pattern Detectors",
            "status": "FLAGGED" if linked_detections else "CLEAN",
            "data": {
                "detections_count": len(linked_detections),
                "detections": linked_detections,
            },
        },
        {
            "stage": 3,
            "name": "ML ANALYSIS",
            "title": "Isolation Forest Scoring",
            "status": "ANOMALOUS" if (ml_window and ml_window.get("is_anomalous")) else "NORMAL",
            "data": ml_window or {"message": "Not within a scoreable 30s window (requires >=3 requests)"},
        },
        {
            "stage": 4,
            "name": "RISK ENGINE",
            "title": "Severity & ML Fusion",
            "status": latest_decision.get("risk_level", "WAITING") if latest_decision else "WAITING",
            "data": {
                "rule_severity": max([d["severity"] for d in linked_detections], default=0),
                "ml_score": ml_window.get("ml_score") if ml_window else 0,
                "risk_score": latest_decision.get("risk_score") if latest_decision else None,
                "reasons": latest_decision.get("reasons") if latest_decision else [],
            },
        },
        {
            "stage": 5,
            "name": "ENFORCEMENT DECISION",
            "title": "SOC Recommended Action",
            "status": latest_decision.get("action", "ALLOW") if latest_decision else "ALLOW",
            "data": {
                "action": latest_decision.get("action", "ALLOW") if latest_decision else "ALLOW",
                "risk_level": latest_decision.get("risk_level", "ALLOW") if latest_decision else "ALLOW",
                "risk_score": latest_decision.get("risk_score", 0) if latest_decision else 0,
            },
        },
        {
            "stage": 6,
            "name": "VOICE ALERTING & NOTIFICATION",
            "title": "Twilio Outbound Calling & In-App Alert",
            "status": (
                "CALLED"
                if any(c.get("status") in {"completed", "in-progress", "ringing", "initiated"} for c in calls)
                else ("ATTEMPTED" if calls else "STANDBY")
            ),
            "data": {
                "calls_count": len(calls),
                "calls": calls,
            },
        },
    ]

    return {
        "event": event,
        "user": user_info,
        "detections": linked_detections,
        "ml_window": ml_window,
        "decision": latest_decision,
        "lifecycle": lifecycle,
        "calls": calls,
    }


# ==============================================================================
# In-App Notification Endpoints
# ==============================================================================


@router.get("/notifications")
def get_notifications_api(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    unread_only: bool = Query(False),
    severity_band: str | None = Query(None),
) -> dict[str, Any]:
    items, total = list_notifications(
        limit=limit,
        offset=offset,
        unread_only=unread_only,
        severity_band=severity_band,
    )
    unread_count = get_unread_count()
    return {
        "notifications": items,
        "total": total,
        "unread_count": unread_count,
        "limit": limit,
        "offset": offset,
    }


@router.get("/notifications/unread-count")
def get_notifications_unread_count_api() -> dict[str, int]:
    return {"unread_count": get_unread_count()}


@router.post("/notifications/{notification_id}/read")
def mark_notification_read_api(notification_id: int) -> dict[str, Any]:
    notif = get_notification(notification_id)
    if not notif:
        raise HTTPException(status_code=404, detail="Notification not found")
    success = set_notification_read(notification_id)
    return {
        "success": success,
        "notification_id": notification_id,
        "unread_count": get_unread_count(),
    }


@router.post("/notifications/read-all")
def mark_all_notifications_read_api() -> dict[str, Any]:
    updated_count = set_all_notifications_read()
    return {
        "success": True,
        "updated_count": updated_count,
        "unread_count": 0,
    }


# ==============================================================================
# Twilio Outbound Voice Calling Endpoints
# ==============================================================================


@router.get("/calls/config")
def get_calls_config_api() -> dict[str, Any]:
    return get_voice_config_status()


@router.get("/calls")
def get_calls_api(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    incident_id: str | None = Query(None),
) -> dict[str, Any]:
    calls, total = list_calls(limit=limit, offset=offset, incident_id=incident_id)
    return {
        "calls": calls,
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/calls/{call_id_or_sid}")
def get_call_by_id_or_sid_api(call_id_or_sid: str) -> dict[str, Any]:
    call = get_call_details(call_id_or_sid)
    if not call and call_id_or_sid.isdigit():
        from backend.database import get_call_alert_by_id
        call = get_call_alert_by_id(int(call_id_or_sid))
        if call:
            from backend.twilio_service import mask_phone_number
            call["to_number"] = mask_phone_number(call.get("to_number"))
            call["from_number"] = mask_phone_number(call.get("from_number"))
    if not call:
        raise HTTPException(status_code=404, detail="Call record not found")
    return call


@router.post("/calls/test")
def trigger_test_call_api() -> dict[str, Any]:
    result = trigger_manual_test_call()
    if not result.get("success"):
        raise HTTPException(
            status_code=400 if result.get("status") == "skipped" else 502,
            detail=result.get("reason") or result.get("error") or "Failed to initiate test call",
        )
    return result


@router.post("/calls/callback")
async def twilio_callback_webhook(request: Request) -> dict[str, Any]:
    form_data = await request.form()
    payload = {k: str(v) for k, v in form_data.items()}
    signature = request.headers.get("X-Twilio-Signature")
    url = str(request.url)
    res = handle_twilio_callback(payload, signature=signature, url=url)
    return res

