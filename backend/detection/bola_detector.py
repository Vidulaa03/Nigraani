from datetime import datetime, timedelta, timezone


WINDOW_SECONDS = 60
MIN_DISTINCT_FOREIGN_RESOURCES_HIGH = 3


def _parse_timestamp(timestamp: str) -> datetime:
    parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


def detect(events: list[dict]) -> list[dict]:
    """Detect successful access to resources owned by another user."""
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(seconds=WINDOW_SECONDS)
    events_by_ip: dict[str, list[dict]] = {}

    for event in events:
        ip = event.get("ip")
        user_id = event.get("user_id")
        resource_owner_id = event.get("resource_owner_id")
        resource_id = event.get("resource_id")
        timestamp = _parse_timestamp(event["timestamp"])

        if (
            not ip
            or user_id is None
            or resource_owner_id is None
            or resource_id is None
            or event.get("status_code") != 200
            or user_id == resource_owner_id
            or timestamp < cutoff
            or timestamp > now
        ):
            continue

        events_by_ip.setdefault(ip, []).append(event)

    detections = []

    for ip, ip_events in events_by_ip.items():
        ip_events.sort(
            key=lambda event: _parse_timestamp(event["timestamp"])
        )
        best_detection = None
        best_strength = None

        for event in ip_events:
            current_time = _parse_timestamp(event["timestamp"])
            window_start = current_time - timedelta(seconds=WINDOW_SECONDS)
            window_events = [
                candidate
                for candidate in ip_events
                if window_start
                <= _parse_timestamp(candidate["timestamp"])
                <= current_time
            ]
            resource_ids = list(dict.fromkeys(
                candidate["resource_id"]
                for candidate in window_events
            ))
            severity = (
                90
                if len(resource_ids) >= MIN_DISTINCT_FOREIGN_RESOURCES_HIGH
                else 70
            )
            candidate_detection = {
                "detector": "bola_detector",
                "attack_type": "BOLA/IDOR",
                "severity": severity,
                "ip": ip,
                "user_id": event.get("user_id"),
                "evidence": (
                    f"Accessed foreign resources {resource_ids} "
                    f"within {WINDOW_SECONDS} seconds"
                ),
                "event_ids": [
                    candidate.get("event_id")
                    for candidate in window_events
                ],
            }
            strength = (severity, len(resource_ids), len(window_events))

            if best_strength is None or strength > best_strength:
                best_detection = candidate_detection
                best_strength = strength

        if best_detection is not None:
            detections.append(best_detection)

    return detections