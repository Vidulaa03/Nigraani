from __future__ import annotations

from typing import Any

from backend.detection.base import build_detection
from detection._utils import event_time, events_in_window


def detect(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    recent_events = events_in_window(events, 10)
    if len(recent_events) < 30:
        return []

    severity = 80 if len(recent_events) >= 80 else 50
    return [
        build_detection(
            detector="rate_detector",
            attack_type="Rate spike",
            severity=severity,
            ip=str(recent_events[-1].get("ip", "unknown")),
            user_id=recent_events[-1].get("user_id"),
            event_ids=(int(event["event_id"]) for event in recent_events),
            evidence=(
                f"{len(recent_events)} requests in 10 seconds "
                f"ending at {event_time(recent_events[-1]).isoformat()}"
            ),
            owasp="API4:2023",
        )
    ]
