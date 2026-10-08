from __future__ import annotations

from typing import Any

from backend.detection.base import build_detection
from detection._utils import events_in_window


def detect(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    recent_events = events_in_window(events, 60)
    failed_logins = [
        event
        for event in recent_events
        if event.get("method") == "POST"
        and event.get("endpoint") == "/api/auth/login"
        and event.get("status_code") in {401, 403}
    ]
    if len(failed_logins) < 5:
        return []

    severity = 80 if len(failed_logins) >= 10 else 50
    return [
        build_detection(
            detector="login_failure_detector",
            attack_type="Brute-force login",
            severity=severity,
            ip=str(failed_logins[-1].get("ip", "unknown")),
            user_id=failed_logins[-1].get("user_id"),
            event_ids=(int(event["event_id"]) for event in failed_logins),
            evidence=f"{len(failed_logins)} failed login attempts in the last 60 seconds",
            owasp="API2:2023",
        )
    ]
