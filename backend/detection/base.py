from __future__ import annotations

from typing import Any, Iterable

EVENT_REQUIRED_FIELDS = (
    "event_id",
    "timestamp",
    "ip",
    "method",
    "endpoint",
    "endpoint_pattern",
    "status_code",
    "response_time_ms",
    "sim_label",
)

DETECTION_REQUIRED_FIELDS = (
    "detector",
    "attack_type",
    "severity",
    "ip",
    "evidence",
    "event_ids",
)


def validate_event(event: dict[str, Any]) -> dict[str, Any]:
    """Validate a security event against the project contract."""
    missing = [field for field in EVENT_REQUIRED_FIELDS if field not in event]
    if missing:
        raise ValueError(f"Event missing required fields: {missing}")

    if not isinstance(event["event_id"], int):
        raise ValueError("event_id must be an integer")

    if not isinstance(event["status_code"], int):
        raise ValueError("status_code must be an integer")

    if not isinstance(event["response_time_ms"], (int, float)):
        raise ValueError("response_time_ms must be numeric")

    if event["endpoint_pattern"] is None:
        raise ValueError("endpoint_pattern cannot be null")

    return event


def build_detection(
    *,
    detector: str,
    attack_type: str,
    severity: int,
    ip: str,
    event_ids: Iterable[int],
    evidence: str,
    user_id: int | None = None,
    owasp: str = "API1:2023",
) -> dict[str, Any]:
    """Create a detection payload in the shared project schema."""
    detection = {
        "detector": detector,
        "attack_type": attack_type,
        "severity": int(severity),
        "ip": ip,
        "user_id": user_id,
        "evidence": evidence,
        "event_ids": list(event_ids),
        "owasp": owasp,
    }

    missing = [field for field in DETECTION_REQUIRED_FIELDS if field not in detection]
    if missing:
        raise ValueError(f"Detection missing required fields: {missing}")

    return detection


def sample_event(**overrides: Any) -> dict[str, Any]:
    """Create a minimal valid sample event for tests and demos."""
    event = {
        "event_id": 1,
        "timestamp": "2026-10-08T12:00:00.000Z",
        "ip": "10.0.0.1",
        "user_id": 101,
        "method": "GET",
        "endpoint": "/api/orders/501",
        "endpoint_pattern": "/api/orders/{order_id}",
        "resource_id": 501,
        "resource_owner_id": 101,
        "status_code": 200,
        "response_time_ms": 12.3,
        "sim_label": "normal",
    }
    event.update(overrides)
    return validate_event(event)
