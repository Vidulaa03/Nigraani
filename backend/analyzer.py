from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

from backend.database import get_events_since, insert_decision, insert_detection
from detection.risk_engine import compute_risk


def _summarize_ip_events(events: list[dict[str, Any]]) -> dict[str, Any]:
    event_count = len(events)
    failed_logins = sum(
        1
        for event in events
        if event.get("endpoint") == "/api/auth/login" and event.get("status_code") in {401, 403}
    )
    rate_hits = max(0, event_count - 20)
    distinct_users = {event.get("user_id") for event in events if event.get("user_id") is not None}
    distinct_resources = {event.get("resource_id") for event in events if event.get("resource_id") is not None}
    resource_errors = sum(
        1
        for event in events
        if event.get("status_code") >= 400 and event.get("resource_id") is not None
    )
    return {
        "event_count": event_count,
        "failed_logins": failed_logins,
        "rate_hits": rate_hits,
        "distinct_users": distinct_users,
        "distinct_resources": distinct_resources,
        "resource_errors": resource_errors,
    }


def _detect_ip_activity(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    detections: list[dict[str, Any]] = []
    summary = _summarize_ip_events(events)
    ip = events[0].get("ip", "unknown")
    user_id = events[0].get("user_id")

    if summary["failed_logins"] >= 5:
        severity = 50 if summary["failed_logins"] < 10 else 80
        detections.append(
            {
                "detector": "login_failure_detector",
                "attack_type": "Brute-force login",
                "severity": severity,
                "ip": ip,
                "user_id": user_id,
                "evidence": f"{summary['failed_logins']} failed login attempts in the last 60 seconds",
                "event_ids": [event["event_id"] for event in events],
                "owasp": "API2:2023",
            }
        )

    if summary["event_count"] >= 30:
        severity = 50 if summary["event_count"] < 80 else 80
        detections.append(
            {
                "detector": "rate_detector",
                "attack_type": "Rate spike",
                "severity": severity,
                "ip": ip,
                "user_id": user_id,
                "evidence": f"{summary['event_count']} requests in a short burst",
                "event_ids": [event["event_id"] for event in events],
                "owasp": "API4:2023",
            }
        )

    enum_requests = [
        event for event in events if event.get("endpoint_pattern") == "/api/users/{user_id}"
    ]
    if len({event.get("resource_id") for event in enum_requests if event.get("resource_id") is not None}) >= 15:
        error_ratio = sum(1 for event in enum_requests if event.get("status_code") >= 400) / max(len(enum_requests), 1)
        if error_ratio >= 0.3:
            detections.append(
                {
                    "detector": "enumeration_detector",
                    "attack_type": "ID enumeration",
                    "severity": 65,
                    "ip": ip,
                    "user_id": user_id,
                    "evidence": f"Enumerated {len({e.get('resource_id') for e in enum_requests if e.get('resource_id') is not None})} distinct user IDs with 404-heavy responses",
                    "event_ids": [event["event_id"] for event in enum_requests],
                    "owasp": "API1:2023",
                }
            )

    owned_bola_events = [
        event
        for event in events
        if event.get("status_code") == 200
        and event.get("resource_owner_id") is not None
        and event.get("user_id") is not None
        and event.get("resource_owner_id") != event.get("user_id")
    ]
    if owned_bola_events:
        severity = 70 if len({event.get("resource_id") for event in owned_bola_events}) < 3 else 90
        detections.append(
            {
                "detector": "bola_detector",
                "attack_type": "BOLA/IDOR",
                "severity": severity,
                "ip": ip,
                "user_id": user_id,
                "evidence": f"User {user_id} accessed resources owned by other users: {[event.get('resource_id') for event in owned_bola_events][:5]}",
                "event_ids": [event["event_id"] for event in owned_bola_events],
                "owasp": "API1:2023",
            }
        )

    return detections


def process_new_events(last_event_id: int | None = None) -> int:
    events = get_events_since(last_event_id)
    if not events:
        return 0

    events_by_ip: dict[str, list[dict[str, Any]]] = {}
    for event in events:
        events_by_ip.setdefault(event.get("ip", "unknown"), []).append(event)

    for ip, ip_events in events_by_ip.items():
        detections = _detect_ip_activity(ip_events)
        if not detections:
            continue

        ml_score = 0
        if any(event.get("sim_label") not in {"normal", None} for event in ip_events):
            ml_score = 70 if any(event.get("sim_label") in {"login_bruteforce", "rate_spike", "bola"} for event in ip_events) else 55

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

    return max(int(event["event_id"]) for event in events)


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
