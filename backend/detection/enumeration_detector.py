from __future__ import annotations

import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any


WINDOW_SECONDS = 60
MIN_DISTINCT_IDS = 15
MIN_404_RATIO = 0.30
MIN_SEQUENTIAL_RUN = 15


def _parse_timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _longest_sequential_run(resource_ids: list[int]) -> int:
    unique_ids = sorted(set(resource_ids))
    longest = current = 0
    previous = None

    for resource_id in unique_ids:
        if previous is not None and resource_id == previous + 1:
            current += 1
        else:
            current = 1
        longest = max(longest, current)
        previous = resource_id

    return longest


def _resource_id_number(value: Any) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, str) and re.fullmatch(r"\d+", value):
        return int(value)
    return None


def detect(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect resource-ID probing per IP and endpoint pattern."""
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        ip = event.get("ip")
        endpoint_pattern = event.get("endpoint_pattern")
        if ip and endpoint_pattern and event.get("resource_id") is not None:
            grouped[(ip, endpoint_pattern)].append(event)

    detections: list[dict[str, Any]] = []
    for (ip, endpoint_pattern), group in grouped.items():
        ordered_events = sorted(
            group,
            key=lambda event: _parse_timestamp(event["timestamp"]),
        )
        best: tuple[tuple[int, int, int], dict[str, Any]] | None = None

        for end_index, end_event in enumerate(ordered_events):
            end_time = _parse_timestamp(end_event["timestamp"])
            start_time = end_time - timedelta(seconds=WINDOW_SECONDS)
            window = [
                event
                for event in ordered_events[: end_index + 1]
                if start_time <= _parse_timestamp(event["timestamp"]) <= end_time
            ]
            numeric_ids = [
                number
                for event in window
                if (number := _resource_id_number(event.get("resource_id")))
                is not None
            ]
            distinct_ids = set(event["resource_id"] for event in window)
            not_found = sum(event.get("status_code") == 404 for event in window)
            enough_distinct_ids = len(distinct_ids) >= MIN_DISTINCT_IDS
            high_404_ratio = (
                enough_distinct_ids
                and not_found / len(window) >= MIN_404_RATIO
            )
            longest_run = _longest_sequential_run(numeric_ids)
            sequential = longest_run >= MIN_SEQUENTIAL_RUN

            if not (high_404_ratio or sequential):
                continue

            evidence = (
                f"{len(distinct_ids)} distinct resource IDs and "
                f"{not_found}/{len(window)} requests returned 404; "
                f"longest sequential run: {longest_run}"
            )
            detection = {
                "detector": "enumeration_detector",
                "attack_type": "Enumeration",
                "severity": 65,
                "ip": ip,
                "endpoint_pattern": endpoint_pattern,
                "evidence": evidence,
                "event_ids": [event["event_id"] for event in window],
            }
            strength = (
                int(high_404_ratio or sequential),
                len(distinct_ids),
                longest_run,
            )
            if best is None or strength > best[0]:
                best = (strength, detection)

        if best is not None:
            detections.append(best[1])

    return detections
