from __future__ import annotations

from collections import defaultdict
from typing import Any

from backend.detection.base import build_detection
from detection._utils import events_in_window


def detect(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    recent_events = events_in_window(events, 60)
    foreign_accesses: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for event in recent_events:
        user_id = event.get("user_id")
        owner_id = event.get("resource_owner_id")
        if (
            event.get("status_code") == 200
            and user_id is not None
            and owner_id is not None
            and int(user_id) != int(owner_id)
            and event.get("resource_id") is not None
        ):
            foreign_accesses[int(user_id)].append(event)

    detections = []
    for user_id, accesses in foreign_accesses.items():
        resource_ids = {int(event["resource_id"]) for event in accesses}
        detections.append(
            build_detection(
                detector="bola_detector",
                attack_type="BOLA/IDOR",
                severity=90 if len(resource_ids) >= 3 else 70,
                ip=str(accesses[-1].get("ip", "unknown")),
                user_id=user_id,
                event_ids=(int(event["event_id"]) for event in accesses),
                evidence=(
                    f"User {user_id} accessed resources owned by other users: "
                    f"{sorted(resource_ids)}"
                ),
                owasp="API1:2023",
            )
        )
    return detections