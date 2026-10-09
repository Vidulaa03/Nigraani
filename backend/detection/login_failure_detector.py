from datetime import datetime, timedelta


LOGIN_ENDPOINT = "/api/auth/login"
WINDOW_SECONDS = 60

FAILURE_THRESHOLD_MEDIUM = 5
FAILURE_THRESHOLD_HIGH = 10


def _parse_timestamp(timestamp: str) -> datetime:
    return datetime.fromisoformat(timestamp.replace("Z", "+00:00"))


def detect(events: list[dict]) -> list[dict]:
    """Detect repeated failed login attempts from the same IP in 60 seconds."""
    login_failures = [
        event
        for event in events
        if event.get("method") == "POST"
        and event.get("endpoint") == LOGIN_ENDPOINT
        and event.get("status_code") in {401, 403}
    ]

    detections = []
    ips = {event.get("ip") for event in login_failures}

    for ip in ips:
        if not ip:
            continue

        ip_events = [
            event
            for event in login_failures
            if event.get("ip") == ip
        ]
        ip_events.sort(
            key=lambda event: _parse_timestamp(event["timestamp"])
        )

        best_detection = None

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
            failure_count = len(window_events)

            if failure_count >= FAILURE_THRESHOLD_HIGH:
                severity = 80
            elif failure_count >= FAILURE_THRESHOLD_MEDIUM:
                severity = 50
            else:
                continue

            candidate_detection = {
                "detector": "login_failure_detector",
                "attack_type": "Brute Force / Credential Guessing",
                "severity": severity,
                "ip": ip,
                "user_id": event.get("user_id"),
                "evidence": (
                    f"{failure_count} failed login attempts "
                    f"from {ip} within {WINDOW_SECONDS} seconds"
                ),
                "event_ids": [
                    candidate.get("event_id")
                    for candidate in window_events
                ],
            }

            if (
                best_detection is None
                or severity > best_detection["severity"]
            ):
                best_detection = candidate_detection

        if best_detection is not None:
            detections.append(best_detection)

    return detections
