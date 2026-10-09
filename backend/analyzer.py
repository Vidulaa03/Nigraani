from __future__ import annotations

import hashlib
import inspect
import os
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, BinaryIO

from prometheus_client import start_http_server

from backend.database import DB_PATH, get_events_since, insert_decision, insert_detection
from backend.detection import (
    bola_detector,
    enumeration_detector,
    login_failure_detector,
    rate_detector,
)
from backend.detection.risk_engine import compute_risk
from backend.ml.anomaly_detector import AnomalyDetector, ModelNotFoundError
from backend.metrics import (
    ANALYSIS_DURATION,
    ANALYSIS_FAILURES,
    ANALYSIS_RUNS,
    DETECTIONS,
    ML_CLASSIFICATIONS,
    ML_SCORE,
    RISK_DECISIONS,
    RISK_SCORE,
)


try:
    _ANOMALY_DETECTOR: AnomalyDetector | None = AnomalyDetector()
except ModelNotFoundError as exc:
    _ANOMALY_DETECTOR = None
    print(f"WARNING: {exc}", file=sys.stderr)

_RECENT_EVENTS_BY_IP: dict[str, list[dict[str, Any]]] = {}


def _event_timestamp(event: dict[str, Any]) -> datetime:
    timestamp = datetime.fromisoformat(str(event["timestamp"]).replace("Z", "+00:00"))
    return timestamp if timestamp.tzinfo is not None else timestamp.replace(tzinfo=timezone.utc)


def _acquire_single_instance_lock() -> BinaryIO:
    lock_name = hashlib.sha256(str(DB_PATH.resolve()).encode("utf-8")).hexdigest()
    lock_path = Path(tempfile.gettempdir()) / f"nigraani-analyzer-{lock_name}.lock"
    lock_file = lock_path.open("a+b")
    try:
        if os.name == "nt":
            import msvcrt

            lock_file.seek(0)
            if not lock_file.read(1):
                lock_file.write(b"\0")
                lock_file.flush()
            lock_file.seek(0)
            msvcrt.locking(lock_file.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as error:
        lock_file.close()
        raise RuntimeError(
            "Another analyzer is already running for this database."
        ) from error
    return lock_file


def _release_single_instance_lock(lock_file: BinaryIO) -> None:
    if os.name == "nt":
        import msvcrt

        lock_file.seek(0)
        msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
    else:
        import fcntl

        fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
    lock_file.close()


def _detect_ip_activity(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    detections: list[dict[str, Any]] = []
    detections.extend(login_failure_detector.detect(events))
    detections.extend(rate_detector.detect(events))
    detections.extend(enumeration_detector.detect(events))
    detections.extend(bola_detector.detect(events))
    return detections


def score_anomalies(events: list[dict[str, Any]]) -> dict[str, Any] | int | float:
    """Return the scored window when available, or zero otherwise."""
    if _ANOMALY_DETECTOR is None:
        return 0
    result = _ANOMALY_DETECTOR.score_ip_events(events)
    return result if result is not None else 0


def _get_new_events(last_event_id: int | None) -> list[dict[str, Any]]:
    parameters = inspect.signature(get_events_since).parameters
    parameter_name = (
        "last_id" if "last_id" in parameters and "last_event_id" not in parameters
        else "last_event_id"
    )
    return get_events_since(**{parameter_name: last_event_id})


def process_new_events(last_event_id: int | None = None) -> int:
    new_events = _get_new_events(last_event_id)
    if not new_events:
        return last_event_id if last_event_id is not None else 0

    events_by_ip: dict[str, list[dict[str, Any]]] = {}
    for event in new_events:
        ip = event.get("ip", "unknown")
        events_by_ip.setdefault(ip, []).append(event)

    for ip, ip_events in events_by_ip.items():
        events_by_id = {
            int(event["event_id"]): event
            for event in [*_RECENT_EVENTS_BY_IP.get(ip, []), *ip_events]
        }
        candidates = list(events_by_id.values())
        newest_timestamp = max(map(_event_timestamp, ip_events))
        window_start = newest_timestamp - timedelta(seconds=60)
        window_events = [
            event
            for event in candidates
            if window_start <= _event_timestamp(event) <= newest_timestamp
        ]
        _RECENT_EVENTS_BY_IP[ip] = window_events

        started = time.perf_counter()
        try:
            detections = _detect_ip_activity(window_events)
            ml_result = score_anomalies(window_events)
            if isinstance(ml_result, dict):
                ml_score = float(ml_result["ml_score"])
                ml_is_anomalous = bool(ml_result["is_anomalous"])
                ML_SCORE.observe(ml_score)
                ML_CLASSIFICATIONS.labels(
                    "anomalous" if ml_is_anomalous else "normal"
                ).inc()
            else:
                ml_score = float(ml_result)
                ml_is_anomalous = ml_score > 0

            if not detections and not ml_is_anomalous:
                ANALYSIS_RUNS.inc()
                continue

            decision = compute_risk(detections, ml_score)
            for detection in detections:
                insert_detection(detection)
                detector = detection.get("detector")
                if detector in {
                    "login_failure_detector",
                    "rate_detector",
                    "enumeration_detector",
                    "bola_detector",
                }:
                    severity = int(detection.get("severity", 0))
                    severity_band = (
                        "critical" if severity >= 80 else
                        "high" if severity >= 60 else
                        "medium" if severity >= 30 else "low"
                    )
                    DETECTIONS.labels(detector, severity_band).inc()

            if decision["action"] in {"ALLOW", "MONITOR", "THROTTLE", "BLOCK"}:
                RISK_DECISIONS.labels(decision["action"]).inc()
            RISK_SCORE.observe(decision["risk_score"])

            insert_decision(
                {
                    "ip": ip,
                    "risk_score": decision["risk_score"],
                    "risk_level": decision["risk_level"],
                    "action": decision["action"],
                    "reasons": decision["reasons"],
                    "source": "analyzer",
                }
            )
            ANALYSIS_RUNS.inc()
        except Exception:
            ANALYSIS_FAILURES.inc()
            raise
        finally:
            ANALYSIS_DURATION.observe(time.perf_counter() - started)

    return max(int(event["event_id"]) for event in new_events)


def run_loop(interval_seconds: int = 5, stop_after: int | None = None) -> None:
    lock_file = _acquire_single_instance_lock()
    try:
        last_event_id = None
        iterations = 0
        while True:
            if stop_after is not None and iterations >= stop_after:
                break
            last_event_id = process_new_events(last_event_id)
            iterations += 1
            if stop_after is not None and iterations >= stop_after:
                break
            if interval_seconds > 0:
                import time

                time.sleep(interval_seconds)
    finally:
        _release_single_instance_lock(lock_file)


if __name__ == "__main__":
    start_http_server(port=8001, addr="127.0.0.1")
    run_loop()
