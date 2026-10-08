from __future__ import annotations

from collections import defaultdict
from typing import Any

from backend.detection.base import build_detection
from detection._utils import events_in_window


def _has_sequential_run(resource_ids: set[int], minimum_run: int = 15) -> bool:
    if len(resource_ids) < minimum_run:
        return False
    run_length = 0
    previous: int | None = None
    for resource_id in sorted(resource_ids):
        run_length = run_length + 1 if previous is not None and resource_id == previous + 1 else 1
        if run_length >= minimum_run:
            return True
        previous = resource_id
    return False


def detect(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    recent_events = events_in_window(events, 60)
    requests_by_pattern: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in recent_events:
        resource_id = event.get("resource_id")
        if resource_id is None:
            continue
        requests_by_pattern[str(event.get("endpoint_pattern", event.get("endpoint", "")))].append(event)

    detections = []
    for pattern, requests in requests_by_pattern.items():
        resource_ids = {
            int(event["resource_id"])
            for event in requests
            if event.get("resource_id") is not None
        }
        if len(resource_ids) < 15:
            continue

        error_ratio = sum(
            1 for event in requests if int(event.get("status_code", 0)) == 404
        ) / len(requests)
        if error_ratio < 0.3 and not _has_sequential_run(resource_ids):
            continue

        detections.append(
            build_detection(
                detector="enumeration_detector",
                attack_type="ID enumeration",
                severity=65,
                ip=str(requests[-1].get("ip", "unknown")),
                user_id=requests[-1].get("user_id"),
                event_ids=(int(event["event_id"]) for event in requests),
                evidence=(
                    f"Probed {len(resource_ids)} distinct resource IDs on {pattern}; "
                    f"{error_ratio:.0%} returned 404"
                ),
                owasp="API1:2023",
            )
        )
    return detections
