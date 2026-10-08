from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from backend.database import get_events_since, insert_decision, insert_detection
from backend.detection import (
    bola_detector,
    enumeration_detector,
    login_failure_detector,
    rate_detector,
)
from backend.detection.risk_engine import compute_risk
from ml.anomaly_detector import score as score_anomalies


def _detect_ip_activity(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    detections = []
    detections.extend(login_failure_detector.detect(events))
    detections.extend(rate_detector.detect(events))
    detections.extend(enumeration_detector.detect(events))
    detections.extend(bola_detector.detect(events))
    return detections


def process_new_events(last_event_id: int | None = None) -> int:
    window_start = datetime.now(timezone.utc) - timedelta(seconds=60)
    events = get_events_since(
        since_timestamp=window_start.isoformat(),
    )
    new_events = [
        event
        for event in events
        if last_event_id is None or int(event["event_id"]) > last_event_id
    ]
    if not new_events:
        return last_event_id if last_event_id is not None else 0

    changed_ips = {event.get("ip", "unknown") for event in new_events}
    detections_by_ip: dict[str, list[dict[str, Any]]] = {}
    for detection in _detect_ip_activity(events):
        detections_by_ip.setdefault(detection["ip"], []).append(detection)

    events_by_ip: dict[str, list[dict[str, Any]]] = {}
    for event in events:
        ip = event.get("ip", "unknown")
        if ip in changed_ips:
            events_by_ip.setdefault(ip, []).append(event)

    for ip, ip_events in events_by_ip.items():
        detections = detections_by_ip.get(ip, [])
        if not detections:
            continue

        ml_score = score_anomalies(ip_events)
        decision = compute_risk(detections, ml_score)
        for detection in detections:
            insert_detection(detection)

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

    return max(int(event["event_id"]) for event in new_events)


def run_loop(interval_seconds: int = 5, stop_after: int | None = None) -> None:
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


if __name__ == "__main__":
    run_loop()
