from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

import pandas as pd

from detection._utils import event_time

FEATURE_COLUMNS = (
    "request_count",
    "unique_endpoints",
    "unique_resource_ids",
    "error_rate",
    "login_attempts",
    "login_failures",
    "avg_response_time_ms",
    "max_requests_in_5s",
)
_MINIMUM_WINDOW_EVENTS = 3


def extract_features(
    events: list[dict[str, Any]],
    window_seconds: int = 30,
) -> pd.DataFrame:
    if window_seconds <= 0:
        raise ValueError("window_seconds must be greater than zero")

    grouped_events: dict[tuple[str, int], list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        timestamp = event_time(event)
        window_start = int(timestamp.timestamp() // window_seconds) * window_seconds
        grouped_events[(str(event.get("ip", "unknown")), window_start)].append(event)

    rows = []
    for (ip, window_start), window_events in sorted(grouped_events.items()):
        if len(window_events) < _MINIMUM_WINDOW_EVENTS:
            continue

        login_events = [
            event
            for event in window_events
            if event.get("method") == "POST"
            and event.get("endpoint") == "/api/auth/login"
        ]
        request_times = sorted(event_time(event).timestamp() for event in window_events)
        window_start_index = 0
        max_requests_in_5s = 0
        for index, timestamp in enumerate(request_times):
            while timestamp - request_times[window_start_index] > 5:
                window_start_index += 1
            max_requests_in_5s = max(
                max_requests_in_5s,
                index - window_start_index + 1,
            )

        rows.append(
            {
                "ip": ip,
                "window_start": datetime.fromtimestamp(window_start, timezone.utc),
                "request_count": len(window_events),
                "unique_endpoints": len(
                    {
                        event.get("endpoint_pattern", event.get("endpoint"))
                        for event in window_events
                    }
                ),
                "unique_resource_ids": len(
                    {
                        event["resource_id"]
                        for event in window_events
                        if event.get("resource_id") is not None
                    }
                ),
                "error_rate": sum(
                    1
                    for event in window_events
                    if 400 <= int(event.get("status_code", 0)) < 600
                )
                / len(window_events),
                "login_attempts": len(login_events),
                "login_failures": sum(
                    1 for event in login_events if event.get("status_code") in {401, 403}
                ),
                "avg_response_time_ms": sum(
                    float(event.get("response_time_ms", 0)) for event in window_events
                )
                / len(window_events),
                "max_requests_in_5s": max_requests_in_5s,
            }
        )

    return pd.DataFrame(rows, columns=("ip", "window_start", *FEATURE_COLUMNS))
