from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any


WINDOW_SECONDS = 10
MEDIUM_THRESHOLD = 30
HIGH_THRESHOLD = 80


def _parse_timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def detect(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect high request volume in rolling ten-second windows per IP."""
    events_by_ip: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        ip = event.get("ip")
        if ip:
            events_by_ip[ip].append(event)

    detections: list[dict[str, Any]] = []
    for ip, ip_events in events_by_ip.items():
        ordered_events = sorted(
            ip_events,
            key=lambda event: _parse_timestamp(event["timestamp"]),
        )
        best_window: list[dict[str, Any]] = []

        for end_index, end_event in enumerate(ordered_events):
            end_time = _parse_timestamp(end_event["timestamp"])
            start_time = end_time - timedelta(seconds=WINDOW_SECONDS)
            window = [
                event
                for event in ordered_events[: end_index + 1]
                if start_time <= _parse_timestamp(event["timestamp"]) <= end_time
            ]
            if len(window) > len(best_window):
                best_window = window

        count = len(best_window)
        if count < MEDIUM_THRESHOLD:
            continue

        severity = HIGH_THRESHOLD if count >= HIGH_THRESHOLD else 50
        detections.append({
            "detector": "rate_detector",
            "attack_type": "Rate Spike",
            "severity": severity,
            "ip": ip,
            "evidence": (
                f"{count} requests observed within a "
                f"{WINDOW_SECONDS}-second window"
            ),
            "event_ids": [event["event_id"] for event in best_window],
        })

    return detections
