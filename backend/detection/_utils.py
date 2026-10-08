from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any


def event_time(event: dict[str, Any]) -> datetime:
    value = datetime.fromisoformat(str(event["timestamp"]).replace("Z", "+00:00"))
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def events_in_window(
    events: list[dict[str, Any]],
    window_seconds: int,
) -> list[dict[str, Any]]:
    if not events:
        return []
    window_end = max(event_time(event) for event in events)
    window_start = window_end - timedelta(seconds=window_seconds)
    return [event for event in events if event_time(event) >= window_start]
