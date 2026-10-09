"""NIGRAANI demo SOC — inspection console over the existing backend.

This file is a consumer only. It does not reimplement Isolation Forest scoring,
BOLA/rate/login/enumeration detection, or ``detection.risk_engine.compute_risk``.
Numbers come from ``demo.db`` (via ``backend.database``) and from scoring
existing events with ``backend.ml.anomaly_detector.AnomalyDetector``.
"""

from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path
from typing import Any

import pandas as pd
import streamlit as st

try:
    import plotly.express as px

    PLOTLY_OK = True
except ImportError:
    PLOTLY_OK = False

REPO_ROOT = Path(__file__).resolve().parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from backend.database import get_connection, get_events_since
from backend.ml.anomaly_detector import AnomalyDetector, ModelNotFoundError
from backend.ml.features import FEATURE_NAMES, extract_windows, parse_timestamp

# Display bands for integer scores already stored by the backend.
# Matches risk_engine.py cutovers (0-29 / 30-59 / 60-79 / 80-100).
# Used only to color badges — never to invent a missing score.
SCORE_BANDS = (
    (80, "CRITICAL", "critical"),
    (60, "HIGH", "high"),
    (30, "MEDIUM", "medium"),
    (0, "LOW", "low"),
)

DETECTION_COLUMNS = [
    "detection_id",
    "detector",
    "attack_type",
    "severity",
    "ip",
    "user_id",
    "evidence",
    "event_ids",
    "owasp",
]
DECISION_COLUMNS = [
    "decision_id",
    "ip",
    "risk_score",
    "risk_level",
    "action",
    "reasons",
    "source",
]


# ---------------------------------------------------------------------------
# Page + CSS
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="NIGRAANI • API Security Operations Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
<style>
:root {
    --bg: #070b12;
    --panel: #0d131d;
    --border: #202b3a;
    --text: #eef4fb;
    --muted: #8290a3;
    --cyan: #38bdf8;
    --green: #22c55e;
    --amber: #f59e0b;
    --orange: #f97316;
    --red: #ef4444;
}
.stApp {
    background:
        radial-gradient(circle at 82% 5%, rgba(56,189,248,.08), transparent 28%),
        radial-gradient(circle at 12% 18%, rgba(99,102,241,.06), transparent 26%),
        var(--bg);
    color: var(--text);
}
.block-container {
    max-width: 1500px;
    padding-top: 6.5rem !important;
    padding-bottom: 3rem;
}
section[data-testid="stMain"] > div {
    padding-top: 0 !important;
}
.nig-header {
    position: relative;
    z-index: 2;
    overflow: visible;
    min-height: 72px;
}
.brand, .title, .subtitle {
    overflow: visible;
}
[data-testid="stSidebar"] { background: #080d15; border-right: 1px solid var(--border); }
[data-testid="stMetric"] {
    background: linear-gradient(145deg, #0e1622, #0a1019);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 14px 16px;
}
[data-testid="stMetricLabel"] {
    color: var(--muted) !important;
    font-size: .76rem !important;
    text-transform: uppercase;
    letter-spacing: .08em;
}
[data-testid="stMetricValue"] { color: var(--text) !important; font-weight: 750; }
div[data-testid="stTabs"] button { color: #8fa0b5; font-weight: 600; }
div[data-testid="stTabs"] button[aria-selected="true"] { color: #f1f7ff; }
.nig-header { display: flex; align-items: center; justify-content: space-between; gap: 18px; margin: 24px 0 1.2rem 0; padding: 8px 0 4px 0; min-height: 86px; overflow: visible !important; }
.brand { display: flex; align-items: center; gap: 15px; }
.shield {
    width: 48px; height: 48px; border-radius: 14px; display: grid; place-items: center;
    background: linear-gradient(145deg, rgba(56,189,248,.22), rgba(37,99,235,.13));
    border: 1px solid rgba(56,189,248,.32); font-size: 25px;
}
.title { font-size: 2rem; line-height: 1.05; font-weight: 800; letter-spacing: -.04em; }
.subtitle { margin-top: 6px; color: var(--muted); font-size: .88rem; }
.live-pill {
    display: inline-flex; align-items: center; gap: 8px; padding: 8px 12px; border-radius: 999px;
    background: rgba(34,197,94,.08); border: 1px solid rgba(34,197,94,.25);
    color: #8df2ae; font-size: .78rem; font-weight: 700; letter-spacing: .06em; text-transform: uppercase;
}
.live-pill.wait {
    background: rgba(245,158,11,.08); border-color: rgba(245,158,11,.28); color: #fde68a;
}
.dot { width: 8px; height: 8px; background: #22c55e; border-radius: 50%; box-shadow: 0 0 12px rgba(34,197,94,.9); }
.dot.wait { background: #f59e0b; box-shadow: 0 0 12px rgba(245,158,11,.9); }
.section-title { font-size: 1rem; font-weight: 750; margin: 1.25rem 0 .65rem; color: #e8f0f8; }
.panel {
    background: linear-gradient(145deg, rgba(16,25,37,.96), rgba(10,16,25,.96));
    border: 1px solid var(--border); border-radius: 15px; padding: 16px 18px;
}
.kicker { color: var(--muted); font-size: .7rem; text-transform: uppercase; letter-spacing: .12em; font-weight: 700; }
.big-score { font-size: 2.4rem; font-weight: 850; line-height: 1; margin: 6px 0 12px; }
.status {
    display: inline-block; padding: 4px 9px; border-radius: 999px; font-size: .7rem;
    font-weight: 800; text-transform: uppercase; letter-spacing: .05em;
}
.status-critical { color:#fecaca; background:rgba(239,68,68,.13); border:1px solid rgba(239,68,68,.25); }
.status-high { color:#fed7aa; background:rgba(249,115,22,.12); border:1px solid rgba(249,115,22,.23); }
.status-medium { color:#fde68a; background:rgba(245,158,11,.11); border:1px solid rgba(245,158,11,.23); }
.status-low { color:#bbf7d0; background:rgba(34,197,94,.09); border:1px solid rgba(34,197,94,.2); }
.health-row { display:flex; align-items:center; justify-content:space-between; padding:9px 0; border-bottom:1px solid #182231; }
.health-row:last-child { border-bottom: 0; }
.health-name { color: #c7d3e1; font-size: .84rem; }
.health-ok { color: #6ee7a0; font-weight: 750; }
.health-warn { color: #fbbf24; font-weight: 750; }
.health-off { color: #94a3b8; font-weight: 750; }
.small-muted { color: var(--muted); font-size: .78rem; }
div[data-testid="stDataFrame"] { border: 1px solid var(--border); border-radius: 12px; overflow: hidden; }
.stButton > button { border-radius: 10px; border: 1px solid #263548; background: #111b29; color: #e8f0f8; }
.stButton > button:hover { border-color: #3b82f6; color: #fff; }
hr { border-color: var(--border); }
</style>
""",
    unsafe_allow_html=True,
)


# ---------------------------------------------------------------------------
# Data access — existing database helpers only
# ---------------------------------------------------------------------------
def _empty(columns: list[str]) -> pd.DataFrame:
    return pd.DataFrame(columns=columns)


@st.cache_data(ttl=4)
def load_events() -> tuple[pd.DataFrame, str | None]:
    try:
        rows = get_events_since(None)
    except Exception as exc:
        return _empty(
            [
                "event_id",
                "timestamp",
                "ip",
                "user_id",
                "method",
                "endpoint",
                "endpoint_pattern",
                "resource_id",
                "resource_owner_id",
                "status_code",
                "response_time_ms",
                "sim_label",
            ]
        ), str(exc)
    return pd.DataFrame(rows), None


@st.cache_data(ttl=4)
def load_table(table: str) -> tuple[pd.DataFrame, str | None]:
    allowed = {"detections": DETECTION_COLUMNS, "decisions": DECISION_COLUMNS}
    if table not in allowed:
        raise ValueError("Invalid table")
    try:
        with get_connection() as conn:
            rows = conn.execute(f"SELECT * FROM {table}").fetchall()
        df = pd.DataFrame([dict(r) for r in rows])
        if df.empty:
            return _empty(allowed[table]), None
        for col in allowed[table]:
            if col not in df.columns:
                df[col] = pd.NA
        return df, None
    except sqlite3.Error as exc:
        return _empty(allowed[table]), str(exc)


@st.cache_data(ttl=4)
def load_users() -> pd.DataFrame:
    try:
        with get_connection() as conn:
            rows = conn.execute("SELECT user_id, name, email FROM users").fetchall()
        df = pd.DataFrame([dict(r) for r in rows])
        return df if not df.empty else _empty(["user_id", "name", "email"])
    except sqlite3.Error:
        return _empty(["user_id", "name", "email"])


@st.cache_resource
def load_detector():
    return AnomalyDetector()


def refresh() -> None:
    load_events.clear()
    load_table.clear()
    load_users.clear()
    load_detector.clear()
    st.rerun()


# ---------------------------------------------------------------------------
# Transformation helpers (display only — no scoring logic)
# ---------------------------------------------------------------------------
def parse_json_field(value: Any, fallback: Any = None) -> Any:
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return fallback
    if isinstance(value, (list, dict)):
        return value
    if isinstance(value, str):
        try:
            return json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return fallback if fallback is not None else value
    return fallback if fallback is not None else value


def parse_event_ids(value: Any) -> list[int]:
    raw = parse_json_field(value, [])
    if not isinstance(raw, list):
        return []
    out: list[int] = []
    for item in raw:
        try:
            out.append(int(item))
        except (TypeError, ValueError):
            continue
    return out


def jsonable(value: Any) -> Any:
    return json.loads(json.dumps(value, default=str))


def to_datetime_series(series: pd.Series) -> pd.Series:
    return pd.to_datetime(series, errors="coerce", utc=True)


def band_for_score(value: Any) -> tuple[str, str]:
    try:
        v = float(value)
    except (TypeError, ValueError):
        return ("NO DATA", "low")
    for threshold, label, css in SCORE_BANDS:
        if v >= threshold:
            return (label, css)
    return ("LOW", "low")


def status_badge(label: str, css: str) -> str:
    return f'<span class="status status-{css}">{label}</span>'


def score_badge(value: Any) -> str:
    label, css = band_for_score(value)
    return status_badge(label, css)


def action_badge_html(action: Any) -> str:
    if action is None or (isinstance(action, float) and pd.isna(action)):
        return status_badge("NO DATA", "low")
    text = str(action).upper()
    css = {
        "BLOCK": "critical",
        "THROTTLE": "high",
        "MONITOR": "medium",
        "ALLOW": "low",
    }.get(text, "low")
    return status_badge(text, css)


def user_label(user_id: Any, users: pd.DataFrame) -> str:
    if user_id is None or (isinstance(user_id, float) and pd.isna(user_id)):
        return "No data"
    try:
        uid = int(user_id)
    except (TypeError, ValueError):
        return str(user_id)
    if users.empty or "user_id" not in users.columns:
        return str(uid)
    hit = users[users["user_id"] == uid]
    if hit.empty:
        return str(uid)
    name = hit.iloc[0].get("name")
    return f"{name} ({uid})" if name else str(uid)


def attach_detection_context(detections: pd.DataFrame, events: pd.DataFrame) -> pd.DataFrame:
    """Add endpoint + timestamp from linked security_events when event_ids parse."""
    if detections.empty:
        return detections
    out = detections.copy()
    event_map: dict[int, dict[str, Any]] = {}
    if not events.empty and "event_id" in events.columns:
        for rec in events.to_dict("records"):
            try:
                event_map[int(rec["event_id"])] = rec
            except (TypeError, ValueError):
                continue

    endpoints: list[str] = []
    timestamps: list[Any] = []
    for raw_ids in out["event_ids"]:
        ids = parse_event_ids(raw_ids)
        linked = [event_map[i] for i in ids if i in event_map]
        if not linked:
            endpoints.append("No data")
            timestamps.append(pd.NaT)
            continue
        ep = next((str(r.get("endpoint") or "") for r in linked if r.get("endpoint")), "No data")
        endpoints.append(ep or "No data")
        ts_vals = []
        for row in linked:
            try:
                ts_vals.append(parse_timestamp(row.get("timestamp")))
            except (TypeError, ValueError):
                continue
        timestamps.append(min(ts_vals) if ts_vals else pd.NaT)
    out["linked_endpoint"] = endpoints
    out["linked_timestamp"] = timestamps
    return out


def latest_decision_per_ip(decisions: pd.DataFrame) -> pd.DataFrame:
    if decisions.empty or "ip" not in decisions.columns:
        return _empty(DECISION_COLUMNS)
    ranked = decisions.sort_values("decision_id")
    return ranked.drop_duplicates("ip", keep="last")


def current_posture(decisions: pd.DataFrame) -> dict[str, Any] | None:
    """Worst latest-per-IP persisted decision. None if the table is empty."""
    latest = latest_decision_per_ip(decisions)
    if latest.empty:
        return None
    latest = latest.copy()
    latest["risk_score"] = pd.to_numeric(latest["risk_score"], errors="coerce")
    latest = latest.dropna(subset=["risk_score"])
    if latest.empty:
        return None
    row = latest.sort_values(["risk_score", "decision_id"], ascending=[False, False]).iloc[0]
    return row.to_dict()


def build_ml_frame(events: pd.DataFrame, detector: AnomalyDetector | None) -> tuple[pd.DataFrame, list[str]]:
    warnings: list[str] = []
    if detector is None or events.empty:
        return pd.DataFrame(), warnings

    records = events.to_dict("records")
    usable: list[dict[str, Any]] = []
    skipped = 0
    for rec in records:
        try:
            parse_timestamp(rec.get("timestamp"))
            usable.append(rec)
        except (TypeError, ValueError):
            skipped += 1
    if skipped:
        warnings.append(f"{skipped} event(s) skipped because the timestamp could not be parsed.")
    if not usable:
        return pd.DataFrame(), warnings

    try:
        windows = extract_windows(usable)
        results = detector.score_windows(windows)
    except Exception as exc:
        warnings.append(f"ML scoring failed: {exc}")
        return pd.DataFrame(), warnings

    if not results:
        return pd.DataFrame(), warnings

    rows = []
    for win, result in zip(windows, results):
        row = dict(result)
        row["prediction"] = "ANOMALY" if result.get("is_anomalous") else "NORMAL"
        if win.is_normal:
            row["ground_truth"] = "NORMAL"
        else:
            labels = sorted(x for x in win.sim_labels if x and x != "normal")
            row["ground_truth"] = ", ".join(labels) if labels else "ATTACK"
        row["sim_labels"] = ", ".join(sorted(win.sim_labels)) if win.sim_labels else "No data"
        rows.append(row)
    return pd.DataFrame(rows), warnings


def merge_ml_onto_detections(detections: pd.DataFrame, ml_df: pd.DataFrame) -> pd.DataFrame:
    """Attach the highest ML window score that shares event_ids with a detection."""
    if detections.empty:
        return detections
    out = detections.copy()
    scores: list[Any] = []
    if ml_df.empty:
        out["ml_score"] = pd.NA
        return out

    window_scores: list[tuple[set[int], float]] = []
    for rec in ml_df.to_dict("records"):
        ids = rec.get("event_ids") or []
        try:
            id_set = {int(x) for x in ids}
        except (TypeError, ValueError):
            id_set = set()
        try:
            window_scores.append((id_set, float(rec.get("ml_score"))))
        except (TypeError, ValueError):
            continue

    for raw_ids in out["event_ids"]:
        det_ids = set(parse_event_ids(raw_ids))
        matched = [s for ids, s in window_scores if det_ids.intersection(ids)]
        scores.append(max(matched) if matched else pd.NA)
    out["ml_score"] = scores
    return out


def apply_filters(
    events: pd.DataFrame,
    detections: pd.DataFrame,
    decisions: pd.DataFrame,
    ml_df: pd.DataFrame,
    *,
    time_start,
    time_end,
    ips: list[str],
    endpoints: list[str],
    methods: list[str],
    severities: list[str],
    attack_types: list[str],
    risk_levels: list[str],
    actions: list[str],
    anomaly_status: list[str],
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    ev = events.copy()
    det = detections.copy()
    dec = decisions.copy()
    ml = ml_df.copy()

    if not ev.empty and "timestamp" in ev.columns:
        ev["_ts"] = to_datetime_series(ev["timestamp"])
        if time_start is not None:
            ev = ev[ev["_ts"].isna() | (ev["_ts"] >= time_start)]
        if time_end is not None:
            ev = ev[ev["_ts"].isna() | (ev["_ts"] <= time_end)]
        ev = ev.drop(columns=["_ts"], errors="ignore")

    if ips:
        if not ev.empty:
            ev = ev[ev["ip"].isin(ips)]
        if not det.empty:
            det = det[det["ip"].isin(ips)]
        if not dec.empty:
            dec = dec[dec["ip"].isin(ips)]
        if not ml.empty:
            ml = ml[ml["ip"].isin(ips)]
    if endpoints and not ev.empty:
        ev = ev[ev["endpoint"].isin(endpoints)]
    if methods and not ev.empty:
        ev = ev[ev["method"].isin(methods)]
    if attack_types and not det.empty:
        det = det[det["attack_type"].isin(attack_types)]
    if severities and not det.empty:
        labels = det["severity"].apply(lambda x: band_for_score(x)[0])
        det = det[labels.isin(severities)]
    if risk_levels and not dec.empty:
        dec = dec[dec["risk_level"].astype(str).isin(risk_levels)]
    if actions and not dec.empty:
        dec = dec[dec["action"].astype(str).isin(actions)]
    if anomaly_status and not ml.empty:
        ml = ml[ml["prediction"].isin(anomaly_status)]

    return ev, det, dec, ml


def plot_or_fallback(fig, fallback_df: pd.DataFrame | None = None) -> None:
    if PLOTLY_OK and fig is not None:
        st.plotly_chart(fig, width="stretch")
    elif fallback_df is not None and not fallback_df.empty:
        st.line_chart(fallback_df)
    else:
        st.info("No data available")


def style_plotly(fig, height: int = 310):
    fig.update_layout(
        height=height,
        margin=dict(l=10, r=10, t=16, b=10),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#d7e3ef"),
    )
    return fig


# ---------------------------------------------------------------------------
# Load pipeline outputs
# ---------------------------------------------------------------------------
events_all, events_error = load_events()
detections_all, detections_error = load_table("detections")
decisions_all, decisions_error = load_table("decisions")
users = load_users()

model_error = None
try:
    detector = load_detector()
except (ModelNotFoundError, ValueError, FileNotFoundError) as exc:
    detector = None
    model_error = str(exc)

ml_all, ml_warnings = build_ml_frame(events_all, detector)
detections_all = attach_detection_context(detections_all, events_all)
detections_all = merge_ml_onto_detections(detections_all, ml_all)

# Latest persisted decision per IP — used to annotate detections without inventing scores
latest_dec = latest_decision_per_ip(decisions_all)
if not detections_all.empty and not latest_dec.empty:
    detections_all = detections_all.merge(
        latest_dec[["ip", "risk_score", "risk_level", "action"]],
        on="ip",
        how="left",
        suffixes=("", "_decision"),
    )
elif not detections_all.empty:
    for col in ("risk_score", "risk_level", "action"):
        if col not in detections_all.columns:
            detections_all[col] = pd.NA


# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------
# Extra top clearance prevents Streamlit's fixed toolbar from clipping the
# first row of the dashboard on initial load / restored browser scroll state.
st.markdown('<div style="height: 18px;"></div>', unsafe_allow_html=True)
system_live = not events_all.empty
pill_class = "live-pill" if system_live else "live-pill wait"
dot_class = "dot" if system_live else "dot wait"
pill_text = "SYSTEM LIVE" if system_live else "WAITING FOR TELEMETRY"
st.markdown(
    f"""
<div class="nig-header">
  <div class="brand">
    <div class="shield">🛡️</div>
    <div>
      <div class="title">NIGRAANI</div>
      <div class="subtitle">API SECURITY OPERATIONS CENTER</div>
    </div>
  </div>
  <div class="{pill_class}"><span class="{dot_class}"></span> {pill_text}</div>
</div>
""",
    unsafe_allow_html=True,
)


# ---------------------------------------------------------------------------
# Sidebar filters — options from real data only
# ---------------------------------------------------------------------------
with st.sidebar:
    st.markdown("### NIGRAANI")
    st.caption("Temporary demo intelligence console")
    if st.button("↻  Refresh telemetry", width="stretch"):
        refresh()

    st.divider()
    st.markdown("**Filters**")
    st.caption("Empty selection = no filter. Filters apply to KPIs, charts, and tables.")

    ts = to_datetime_series(events_all["timestamp"]) if not events_all.empty else pd.Series(dtype="datetime64[ns]")
    time_start = time_end = None
    if ts.notna().any():
        ts_naive = ts.dt.tz_convert("UTC").dt.tz_localize(None) if str(ts.dtype).startswith("datetime64[ns,") else ts
        tmin, tmax = ts_naive.min().to_pydatetime(), ts_naive.max().to_pydatetime()
        if tmin == tmax:
            st.caption(f"Time range: {tmin.isoformat()} (single timestamp)")
            time_start = time_end = pd.Timestamp(tmin, tz="UTC")
        else:
            picked = st.slider(
                "Time range",
                min_value=tmin,
                max_value=tmax,
                value=(tmin, tmax),
            )
            time_start = pd.Timestamp(picked[0], tz="UTC")
            time_end = pd.Timestamp(picked[1], tz="UTC")
    else:
        st.caption("Time range: No data available")

    def _opts(df: pd.DataFrame, col: str) -> list:
        if df.empty or col not in df.columns:
            return []
        return sorted(str(x) for x in df[col].dropna().unique().tolist())

    f_ips = st.multiselect("Source IP", _opts(events_all, "ip"))
    f_endpoints = st.multiselect("Endpoint", _opts(events_all, "endpoint"))
    f_methods = st.multiselect("HTTP method", _opts(events_all, "method"))
    f_attack = st.multiselect("Attack type", _opts(detections_all, "attack_type"))
    f_sev = st.multiselect("Severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    f_risk = st.multiselect("Risk level", _opts(decisions_all, "risk_level"))
    f_action = st.multiselect("Action", _opts(decisions_all, "action"))
    f_anom = st.multiselect("Anomaly status", ["ANOMALY", "NORMAL"])

    events, detections, decisions, ml_df = apply_filters(
        events_all,
        detections_all,
        decisions_all,
        ml_all,
        time_start=time_start,
        time_end=time_end,
        ips=f_ips,
        endpoints=f_endpoints,
        methods=f_methods,
        severities=f_sev,
        attack_types=f_attack,
        risk_levels=f_risk,
        actions=f_action,
        anomaly_status=f_anom,
    )

    st.divider()
    st.markdown("**Pipeline health**")
    health = [
        ("API ingestion", not events_all.empty, f"{len(events_all):,} events"),
        ("Feature extraction", not ml_all.empty, f"{len(ml_all):,} windows"),
        ("Isolation Forest", detector is not None, "Model loaded" if detector else "Unavailable"),
        ("Security detections", not detections_all.empty, f"{len(detections_all):,} records"),
        ("Risk engine", not decisions_all.empty, f"{len(decisions_all):,} decisions"),
    ]
    for name, ok, detail in health:
        state = "ONLINE" if ok else "WAITING"
        css = "health-ok" if ok else "health-warn"
        st.markdown(
            f'<div class="health-row"><span class="health-name">{name}</span>'
            f'<span class="{css}">{state}</span></div>',
            unsafe_allow_html=True,
        )
        st.caption(detail)

    st.divider()
    st.markdown("**Model**")
    if detector is not None:
        st.success("Isolation Forest loaded")
        st.caption(f"Feature contract: {', '.join(FEATURE_NAMES)}")
        if detector.metadata:
            st.caption(f"Training windows: {detector.metadata.get('n_training_windows', 'No data')}")
    else:
        st.error("Model unavailable")
        st.caption("Train with `python -m backend.ml.train_model`")

    st.divider()
    st.caption("Source: existing demo.db + models/iforest.joblib")
    st.caption("No synthetic dashboard values are generated.")


# ---------------------------------------------------------------------------
# KPI row — every value from loaded frames
# ---------------------------------------------------------------------------
total_events = int(len(events))
ml_windows = int(len(ml_df))
ml_anomalies = int(ml_df["is_anomalous"].sum()) if not ml_df.empty and "is_anomalous" in ml_df.columns else 0
detection_count = int(len(detections))
if not detections.empty and "severity" in detections.columns:
    sev = pd.to_numeric(detections["severity"], errors="coerce")
    high_threats = int(((sev >= 60) & (sev < 80)).sum())
    critical_threats = int((sev >= 80).sum())
else:
    high_threats = critical_threats = 0
if not decisions.empty and "action" in decisions.columns:
    blocked = int(decisions["action"].astype(str).str.upper().eq("BLOCK").sum())
else:
    blocked = 0

k = st.columns(6)
k[0].metric("API REQUESTS", f"{total_events:,}")
k[1].metric("ML WINDOWS", f"{ml_windows:,}")
k[2].metric("ANOMALIES", f"{ml_anomalies:,}")
k[3].metric("SECURITY DETECTIONS", f"{detection_count:,}")
k[4].metric("HIGH / CRITICAL THREATS", f"{high_threats:,} / {critical_threats:,}")
k[5].metric("BLOCKED REQUESTS", f"{blocked:,}")
st.caption(
    "BLOCKED REQUESTS counts persisted `decisions.action = BLOCK` rows from the risk engine "
    "(one decision per analyzer run / IP), not per-HTTP-request enforcement."
)

if detections_all.empty:
    st.warning("No persisted detections currently available.")
if decisions_all.empty:
    st.warning("No risk decisions have been persisted yet.")
if model_error:
    st.error(model_error)
for msg in ml_warnings:
    st.warning(msg)
if events_error:
    st.error(f"Failed to read `security_events`: {events_error}")
if detections_error:
    st.error(f"Failed to read `detections`: {detections_error}")
if decisions_error:
    st.error(f"Failed to read `decisions`: {decisions_error}")


tabs = st.tabs(
    [
        "◉ COMMAND CENTER",
        "⚠ THREAT INTELLIGENCE",
        "◌ ML BEHAVIOR",
        "⌁ TRAFFIC",
        "⌕ INVESTIGATE",
        "✓ PIPELINE HEALTH",
    ]
)


# ===========================================================================
# COMMAND CENTER
# ===========================================================================
with tabs[0]:
    left, right = st.columns([1.65, 1])
    with left:
        st.markdown('<div class="section-title">Live API traffic</div>', unsafe_allow_html=True)
        if events.empty:
            st.info("No data available")
        else:
            chart_df = events.copy()
            chart_df["timestamp_dt"] = to_datetime_series(chart_df["timestamp"])
            chart_df = chart_df.dropna(subset=["timestamp_dt"])
            if chart_df.empty:
                st.info("No data available")
            else:
                traffic = (
                    chart_df.set_index("timestamp_dt").resample("10s").size().rename("requests").reset_index()
                )
                if PLOTLY_OK:
                    fig = px.area(traffic, x="timestamp_dt", y="requests", template="plotly_dark")
                    fig.update_traces(line=dict(color="#38bdf8", width=2), fillcolor="rgba(56,189,248,.12)")
                    fig.update_layout(xaxis_title=None, yaxis_title=None)
                    plot_or_fallback(style_plotly(fig), traffic.set_index("timestamp_dt"))
                else:
                    st.line_chart(traffic.set_index("timestamp_dt"))

    with right:
        st.markdown('<div class="section-title">Current threat posture</div>', unsafe_allow_html=True)
        posture = current_posture(decisions)
        if posture is None:
            st.info("No risk decisions have been persisted yet.")
        else:
            score = posture.get("risk_score")
            level = str(posture.get("risk_level") or "No data")
            action = str(posture.get("action") or "No data")
            st.markdown(
                f"""
<div class="panel">
  <div class="kicker">Risk score (worst latest-per-IP persisted decision)</div>
  <div class="big-score">{score}<span style="font-size:1rem;color:#8290a3"> / 100</span></div>
  {action_badge_html(level)}
  <div style="margin-top:14px;color:#b9c5d3;font-size:.85rem">{action}</div>
  <div class="small-muted" style="margin-top:8px">IP {posture.get("ip", "No data")} · decision_id {posture.get("decision_id", "No data")}</div>
</div>
""",
                unsafe_allow_html=True,
            )

        if not detections.empty and "attack_type" in detections.columns:
            st.markdown('<div class="section-title">Detection mix</div>', unsafe_allow_html=True)
            mix = detections["attack_type"].value_counts()
            if mix.empty:
                st.info("No data available")
            elif PLOTLY_OK:
                fig = px.pie(values=mix.values, names=mix.index, hole=0.65, template="plotly_dark")
                fig.update_layout(showlegend=True)
                plot_or_fallback(style_plotly(fig, 235))
            else:
                st.bar_chart(mix)
        else:
            st.markdown('<div class="section-title">Detection mix</div>', unsafe_allow_html=True)
            st.info("No persisted detections currently available.")

    st.markdown('<div class="section-title">Recent security activity</div>', unsafe_allow_html=True)
    if detections.empty:
        st.info("No persisted detections currently available.")
    else:
        view = detections.copy()
        if "severity" in view.columns:
            view = view.sort_values("severity", ascending=False)
        cols = [
            c
            for c in [
                "detector",
                "attack_type",
                "ip",
                "linked_endpoint",
                "user_id",
                "ml_score",
                "severity",
                "risk_score",
                "risk_level",
                "action",
                "owasp",
                "linked_timestamp",
            ]
            if c in view.columns
        ]
        st.dataframe(view[cols].head(12), width="stretch", hide_index=True)


# ===========================================================================
# THREAT INTELLIGENCE
# ===========================================================================
with tabs[1]:
    st.markdown("## Threat intelligence")
    st.caption("Only persisted `detections` / `decisions` rows from demo.db.")

    if detections.empty:
        st.info("No persisted detections currently available.")
    else:
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total detections", f"{len(detections):,}")
        c2.metric("Unique attack types", int(detections["attack_type"].nunique()) if "attack_type" in detections else 0)
        c3.metric("Unique source IPs", int(detections["ip"].nunique()) if "ip" in detections else 0)
        max_sev = pd.to_numeric(detections["severity"], errors="coerce").max() if "severity" in detections else pd.NA
        c4.metric("Highest severity", "No data" if pd.isna(max_sev) else int(max_sev))

        left, right = st.columns(2)
        with left:
            st.markdown("### Detection type breakdown")
            counts = detections["attack_type"].value_counts()
            if PLOTLY_OK:
                fig = px.bar(
                    x=counts.values,
                    y=counts.index,
                    orientation="h",
                    template="plotly_dark",
                    labels={"x": "Detections", "y": ""},
                )
                fig.update_traces(marker_color="#60a5fa")
                plot_or_fallback(style_plotly(fig, 320))
            else:
                st.bar_chart(counts)
        with right:
            st.markdown("### Severity breakdown")
            bands = detections["severity"].apply(lambda x: band_for_score(x)[0]).value_counts()
            if PLOTLY_OK:
                fig = px.bar(x=bands.index, y=bands.values, template="plotly_dark", labels={"x": "", "y": "Count"})
                fig.update_traces(marker_color="#f97316")
                plot_or_fallback(style_plotly(fig, 320))
            else:
                st.bar_chart(bands)

        st.markdown("### Threat timeline")
        if "linked_timestamp" in detections.columns and detections["linked_timestamp"].notna().any():
            tl = detections.dropna(subset=["linked_timestamp"]).copy()
            tl["bucket"] = pd.to_datetime(tl["linked_timestamp"], utc=True).dt.floor("30s")
            series = tl.groupby("bucket").size().rename("detections").reset_index()
            if PLOTLY_OK:
                fig = px.line(series, x="bucket", y="detections", markers=True, template="plotly_dark")
                plot_or_fallback(style_plotly(fig, 260), series.set_index("bucket"))
            else:
                st.line_chart(series.set_index("bucket"))
        else:
            st.info("No timestamps available on detection records (detections table has no timestamp column; linked events did not resolve).")

        st.markdown("### Detection records")
        table = detections.copy()
        if "severity" in table.columns:
            table["severity_badge"] = table["severity"].apply(lambda x: band_for_score(x)[0])
        show_cols = [
            c
            for c in [
                "severity_badge",
                "attack_type",
                "ip",
                "linked_endpoint",
                "user_id",
                "ml_score",
                "risk_score",
                "action",
                "owasp",
                "linked_timestamp",
                "detector",
                "severity",
            ]
            if c in table.columns
        ]
        st.dataframe(
            table.sort_values("severity", ascending=False)[show_cols] if "severity" in table.columns else table[show_cols],
            width="stretch",
            hide_index=True,
        )

        st.markdown("### Threat investigation")
        options = detections.index.tolist()
        selected = st.selectbox(
            "Select a detection",
            options,
            format_func=lambda i: (
                f"{detections.loc[i].get('attack_type', 'unknown')} · "
                f"{detections.loc[i].get('ip', '—')} · "
                f"severity {detections.loc[i].get('severity', '—')}"
            ),
        )
        row = detections.loc[selected]
        event_ids = parse_event_ids(row.get("event_ids"))
        evidence = row.get("evidence", "No data")
        st.markdown(
            f"""
<div class="panel">
<div class="kicker">{row.get('detector', 'No data')} · {row.get('owasp', 'No data')}</div>
<h3 style="margin:5px 0 10px">{row.get('attack_type', 'No data')}</h3>
<div style="color:#c3cfdd">{evidence}</div>
<div style="margin-top:14px">{score_badge(row.get('severity'))}
<span style="margin-left:10px;color:#8290a3">Source IP: {row.get('ip', 'No data')}</span></div>
</div>
""",
            unsafe_allow_html=True,
        )
        i1, i2 = st.columns(2)
        with i1:
            st.write(
                {
                    "detector": row.get("detector", "No data"),
                    "attack_type": row.get("attack_type", "No data"),
                    "source_ip": row.get("ip", "No data"),
                    "endpoint": row.get("linked_endpoint", "No data"),
                    "user": user_label(row.get("user_id"), users),
                    "severity": row.get("severity", "No data"),
                    "owasp": row.get("owasp", "No data"),
                    "related_event_ids": event_ids or "No data",
                }
            )
        with i2:
            ml_val = row.get("ml_score")
            st.write(
                {
                    "ml_score": "No data available" if pd.isna(ml_val) else ml_val,
                    "risk_score": row.get("risk_score") if pd.notna(row.get("risk_score")) else "No data available",
                    "risk_level": row.get("risk_level") if pd.notna(row.get("risk_level")) else "No data available",
                    "action": row.get("action") if pd.notna(row.get("action")) else "No data available",
                }
            )
        st.markdown("**Evidence**")
        st.write(evidence if evidence not in (None, "") else "No data available")


# ===========================================================================
# ML BEHAVIOR
# ===========================================================================
with tabs[2]:
    st.markdown("## ML behavior center")
    st.caption("Windows from `backend.ml.features.extract_windows`; scores from `AnomalyDetector.score_windows`.")

    if ml_df.empty:
        st.info("No data available")
    else:
        a, b, c, d, e = st.columns(5)
        a.metric("Total ML windows", f"{len(ml_df):,}")
        anom = int(ml_df["is_anomalous"].sum()) if "is_anomalous" in ml_df.columns else 0
        b.metric("Anomaly count", f"{anom:,}")
        c.metric("Anomaly percentage", f"{(anom / len(ml_df) * 100):.1f}%")
        d.metric("Highest anomaly score", f"{pd.to_numeric(ml_df['ml_score'], errors='coerce').max():.1f}")
        e.metric("Average anomaly score", f"{pd.to_numeric(ml_df['ml_score'], errors='coerce').mean():.1f}")

        c1, c2, c3 = st.columns(3)
        chart = ml_df.copy()
        chart["window_start"] = to_datetime_series(chart["window_start"])
        with c1:
            st.markdown("### ML anomaly score over time")
            if chart["window_start"].notna().any() and PLOTLY_OK:
                fig = px.line(
                    chart.sort_values("window_start"),
                    x="window_start",
                    y="ml_score",
                    color="ip",
                    markers=True,
                    template="plotly_dark",
                )
                fig.add_hline(
                    y=50,
                    line_dash="dash",
                    line_color="#f59e0b",
                    annotation_text="IF threshold (raw_score=0 → ml_score=50)",
                )
                plot_or_fallback(style_plotly(fig, 320))
            else:
                st.info("No data available")
        with c2:
            st.markdown("### Normal vs anomaly")
            pred = ml_df["prediction"].value_counts()
            if PLOTLY_OK:
                fig = px.pie(values=pred.values, names=pred.index, hole=0.62, template="plotly_dark")
                plot_or_fallback(style_plotly(fig, 320))
            else:
                st.bar_chart(pred)
        with c3:
            st.markdown("### Score distribution")
            if PLOTLY_OK:
                fig = px.histogram(ml_df, x="ml_score", nbins=20, template="plotly_dark")
                fig.update_traces(marker_color="#38bdf8")
                plot_or_fallback(style_plotly(fig, 320))
            else:
                st.bar_chart(ml_df["ml_score"])

        st.markdown("### Behavioral windows")
        display_cols = [
            c
            for c in ["ip", "window_start", "window_end", "ml_score", "raw_score", "prediction", "ground_truth"]
            if c in ml_df.columns
        ]
        display = ml_df.sort_values("ml_score", ascending=False)
        st.dataframe(display[display_cols], width="stretch", hide_index=True)

        st.markdown("### Behavioral investigation")
        idx = st.selectbox(
            "Select an ML window",
            display.index.tolist(),
            format_func=lambda i: (
                f"{display.loc[i, 'ip']} · score {display.loc[i, 'ml_score']} · {display.loc[i, 'prediction']}"
            ),
        )
        selected = display.loc[idx]
        f1, f2 = st.columns([1, 1.4])
        with f1:
            st.markdown(
                f"""
<div class="panel">
<div class="kicker">Behavioral verdict</div>
<div class="big-score">{selected.get('ml_score', '—')}</div>
{score_badge(selected.get('ml_score'))}
<div style="margin-top:14px;color:#c3cfdd">
IP: <b>{selected.get('ip', 'No data')}</b><br>
Window: <b>{selected.get('window_start', 'No data')}</b> → <b>{selected.get('window_end', 'No data')}</b><br>
Prediction: <b>{selected.get('prediction', 'No data')}</b><br>
Ground truth: <b>{selected.get('ground_truth', 'No data')}</b><br>
Raw Isolation Forest score: <b>{selected.get('raw_score', 'No data')}</b>
</div>
</div>
""",
                unsafe_allow_html=True,
            )
        with f2:
            feats = selected.get("features") or {}
            if isinstance(feats, str):
                feats = parse_json_field(feats, {})
            if not isinstance(feats, dict):
                feats = {}
            # Exact feature contract order from features.py — never invented names.
            feature_rows = pd.DataFrame(
                {"Feature": list(FEATURE_NAMES), "Value": [feats.get(name, "No data") for name in FEATURE_NAMES]}
            )
            numeric = feature_rows.copy()
            numeric["Value"] = pd.to_numeric(numeric["Value"], errors="coerce")
            if PLOTLY_OK and numeric["Value"].notna().any():
                fig = px.bar(
                    numeric.dropna(),
                    x="Value",
                    y="Feature",
                    orientation="h",
                    template="plotly_dark",
                )
                fig.update_traces(marker_color="#a78bfa")
                plot_or_fallback(style_plotly(fig, 300))
            st.dataframe(feature_rows, width="stretch", hide_index=True)

        fi = getattr(getattr(detector, "model", None), "feature_importances_", None) if detector else None
        if fi is None:
            st.caption("Feature importance is not available from the loaded Isolation Forest bundle.")
        elif len(fi) == len(FEATURE_NAMES):
            st.caption("IsolationForest.feature_importances_ from the loaded model (not a custom explanation).")
            st.dataframe(
                pd.DataFrame({"Feature": list(FEATURE_NAMES), "Importance": [float(x) for x in fi]}),
                width="stretch",
                hide_index=True,
            )


# ===========================================================================
# TRAFFIC
# ===========================================================================
with tabs[3]:
    st.markdown("## API traffic")
    if events.empty:
        st.info("No data available")
    else:
        err_rate = float((pd.to_numeric(events["status_code"], errors="coerce") >= 400).mean() * 100)
        c1, c2, c3, c4, c5, c6 = st.columns(6)
        c1.metric("Request volume", f"{len(events):,}")
        c2.metric("Unique IPs", int(events["ip"].nunique()))
        c3.metric("Unique endpoints", int(events["endpoint"].nunique()))
        c4.metric("HTTP methods", int(events["method"].nunique()))
        c5.metric("Error rate", f"{err_rate:.1f}%")
        c6.metric("Avg latency", f"{pd.to_numeric(events['response_time_ms'], errors='coerce').mean():.1f} ms")

        r1, r2 = st.columns(2)
        with r1:
            st.markdown("### Requests over time")
            tdf = events.copy()
            tdf["timestamp_dt"] = to_datetime_series(tdf["timestamp"])
            tdf = tdf.dropna(subset=["timestamp_dt"])
            if tdf.empty:
                st.info("No data available")
            else:
                series = tdf.set_index("timestamp_dt").resample("10s").size().rename("requests")
                st.line_chart(series)
        with r2:
            st.markdown("### Endpoint distribution")
            ep = events["endpoint"].value_counts().head(15)
            if PLOTLY_OK:
                fig = px.bar(x=ep.values, y=ep.index, orientation="h", template="plotly_dark")
                fig.update_traces(marker_color="#38bdf8")
                plot_or_fallback(style_plotly(fig, 320))
            else:
                st.bar_chart(ep)

        r3, r4, r5 = st.columns(3)
        with r3:
            st.markdown("### HTTP methods")
            st.bar_chart(events["method"].value_counts())
        with r4:
            st.markdown("### Status codes")
            st.bar_chart(events["status_code"].astype(str).value_counts())
        with r5:
            st.markdown("### Latency")
            lat = pd.to_numeric(events["response_time_ms"], errors="coerce").dropna()
            if lat.empty:
                st.info("No data available")
            elif PLOTLY_OK:
                fig = px.histogram(lat, nbins=20, template="plotly_dark")
                fig.update_traces(marker_color="#22c55e")
                plot_or_fallback(style_plotly(fig, 260))
            else:
                st.bar_chart(lat)

        st.markdown("### Requests")
        q = st.text_input("Search IP, endpoint, method, or event ID")
        table = events.sort_values("event_id", ascending=False)
        if q:
            blob = table.astype(str).apply(lambda col: col.str.contains(q, case=False, na=False))
            table = table[blob.any(axis=1)]
        if table.empty:
            st.info("No data available")
        else:
            st.dataframe(table.head(300), width="stretch", hide_index=True)


# ===========================================================================
# REQUEST INVESTIGATION
# ===========================================================================
with tabs[4]:
    st.markdown("## Request investigation")
    st.caption("Trace one `security_events` row into persisted detections, ML windows, and risk decisions.")

    if events.empty:
        st.info("No data available")
    else:
        ids = events["event_id"].astype("int64").sort_values(ascending=False).tolist()
        selected_id = st.selectbox("Event ID", ids)
        event = events[events["event_id"].astype("int64") == int(selected_id)].iloc[0].to_dict()

        st.markdown("### Request")
        meta = st.columns(5)
        meta[0].metric("METHOD", event.get("method") or "No data")
        meta[1].metric("STATUS", event.get("status_code") if event.get("status_code") is not None else "No data")
        meta[2].metric("USER", user_label(event.get("user_id"), users))
        meta[3].metric("RESOURCE", event.get("resource_id") if event.get("resource_id") is not None else "No data")
        try:
            meta[4].metric("LATENCY", f"{float(event.get('response_time_ms')):.1f} ms")
        except (TypeError, ValueError):
            meta[4].metric("LATENCY", "No data")

        st.markdown(
            f"""
<div class="panel">
<div style="font-size:1.05rem;font-weight:750">{event.get('endpoint') or 'No data'}</div>
<div class="small-muted" style="margin-top:6px">
{event.get('timestamp') or 'No data'} · {event.get('ip') or 'No data'} · {event.get('endpoint_pattern') or 'No data'}
</div>
</div>
""",
            unsafe_allow_html=True,
        )
        st.write(
            {
                "timestamp": event.get("timestamp", "No data"),
                "ip": event.get("ip", "No data"),
                "user": user_label(event.get("user_id"), users),
                "method": event.get("method", "No data"),
                "endpoint": event.get("endpoint", "No data"),
                "endpoint_pattern": event.get("endpoint_pattern", "No data"),
                "resource_id": event.get("resource_id") if event.get("resource_id") is not None else "No data",
                "resource_owner_id": event.get("resource_owner_id")
                if event.get("resource_owner_id") is not None
                else "No data",
                "status_code": event.get("status_code", "No data"),
                "response_time_ms": event.get("response_time_ms", "No data"),
                "sim_label": event.get("sim_label", "No data"),
            }
        )

        st.markdown("### Detection trace")
        related = []
        if not detections.empty:
            for rec in detections.to_dict("records"):
                ids_list = parse_event_ids(rec.get("event_ids"))
                if int(selected_id) in ids_list:
                    related.append(rec)
        if related:
            rel_df = pd.DataFrame(related)
            keep = [
                c
                for c in ["detector", "attack_type", "severity", "ip", "evidence", "owasp", "risk_score", "action"]
                if c in rel_df.columns
            ]
            st.dataframe(rel_df[keep], width="stretch", hide_index=True)
            st.caption("Categories shown are detector names actually stored for this event.")
        else:
            st.info("No persisted detections currently available for this event.")

        st.markdown("### ML result")
        ml_hits = []
        if not ml_df.empty:
            for rec in ml_df.to_dict("records"):
                try:
                    wids = {int(x) for x in (rec.get("event_ids") or [])}
                except (TypeError, ValueError):
                    wids = set()
                if int(selected_id) in wids:
                    ml_hits.append(rec)
        if not ml_hits:
            st.info("No data available — this event is not inside a scoreable ML window (need ≥3 requests / 30s / IP).")
        else:
            hit = max(ml_hits, key=lambda r: float(r.get("ml_score") or 0))
            st.write(
                {
                    "prediction": hit.get("prediction", "No data"),
                    "ml_score": hit.get("ml_score", "No data"),
                    "raw_score": hit.get("raw_score", "No data"),
                    "window_start": hit.get("window_start", "No data"),
                    "window_end": hit.get("window_end", "No data"),
                    "ground_truth": hit.get("ground_truth", "No data"),
                }
            )
            feats = hit.get("features") or {}
            feat_table = pd.DataFrame(
                {"Feature": list(FEATURE_NAMES), "Value": [feats.get(n, "No data") for n in FEATURE_NAMES]}
            )
            st.dataframe(feat_table, width="stretch", hide_index=True)

        st.markdown("### Risk result")
        ip = event.get("ip")
        ip_decisions = decisions_all[decisions_all["ip"] == ip] if (not decisions_all.empty and ip) else pd.DataFrame()
        if ip_decisions.empty:
            st.info("No risk decisions have been persisted yet for this source IP.")
        else:
            latest = ip_decisions.sort_values("decision_id").iloc[-1]
            reasons = parse_json_field(latest.get("reasons"), [])
            st.write(
                {
                    "risk_score": latest.get("risk_score", "No data"),
                    "risk_level": latest.get("risk_level", "No data"),
                    "action": latest.get("action", "No data"),
                    "source": latest.get("source", "No data"),
                    "reasons": reasons if reasons else "No data",
                    "persisted_decisions_for_ip": int(len(ip_decisions)),
                }
            )
            st.caption(
                "Values are the latest persisted row in `decisions` for this IP. "
                "The dashboard does not re-run `compute_risk()`."
            )

        with st.expander("RAW EVENT"):
            st.json(jsonable(event))


# ===========================================================================
# PIPELINE HEALTH
# ===========================================================================
with tabs[5]:
    st.markdown("## Pipeline health")
    st.caption("Unfiltered counts from demo.db and the loaded model — missing stages are WAITING, not 'safe'.")

    checks = [
        ("API INGESTION", len(events_all) > 0, f"{len(events_all):,} events"),
        ("FEATURE EXTRACTION", len(ml_all) > 0, f"{len(ml_all):,} windows"),
        ("ISOLATION FOREST", detector is not None, "Model loaded" if detector else "Unavailable"),
        ("SECURITY DETECTIONS", len(detections_all) > 0, f"{len(detections_all):,} records"),
        ("RISK ENGINE", len(decisions_all) > 0, f"{len(decisions_all):,} decisions"),
    ]
    for name, ok, detail in checks:
        icon = "🟢" if ok else "🟡"
        state = "ONLINE" if ok else "WAITING"
        st.markdown(
            f"""
<div class="panel" style="margin-bottom:9px;padding:13px 16px">
<div style="display:flex;justify-content:space-between;align-items:center">
<span style="font-weight:700">{icon} {name}</span>
<span style="color:{'#6ee7a0' if ok else '#fbbf24'};font-weight:800">{state}</span>
</div>
<div class="small-muted" style="margin-top:5px">{detail}</div>
</div>
""",
            unsafe_allow_html=True,
        )

    if len(detections_all) == 0:
        st.warning("No persisted detections currently available.")
    if len(decisions_all) == 0:
        st.warning("No risk decisions have been persisted yet.")
    if detector is None:
        st.warning("Waiting for pipeline output: Isolation Forest model is not loaded.")

st.divider()
st.caption(
    "NIGRAANI · Temporary demo SOC · Telemetry from backend.database / demo.db; "
    "ML from backend.ml; detections and decisions as persisted by backend.analyzer."
)
