from __future__ import annotations

import ipaddress
import math
import re
from datetime import datetime
from typing import Any, Iterable

# SQLite INTEGER upper bound; larger values make inserts raise OverflowError.
MAX_IDENTIFIER = 2**63 - 1
MAX_ENDPOINT_LENGTH = 512
HTTP_METHODS = frozenset(
    {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT"}
)
# Stored when no valid client address is known (no client, or a non-IP host
# such as Starlette's TestClient "testclient").
UNKNOWN_IP = "unknown"
# Simulation scenarios (simulation/attacks/*), the Gemini incident fixtures,
# and "unknown" for labels that are absent from this list. Only "normal"
# traffic is used for ML training, so unknown labels never reach the model.
SIM_LABELS = frozenset(
    {
        "normal",
        "login_bruteforce",
        "bola",
        "enumeration",
        "rate_spike",
        "low_slow",
        "sql_injection",
        "unknown",
    }
)
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]")

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


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _check_identifier(event: dict[str, Any], field: str, *, nullable: bool) -> None:
    value = event.get(field)
    if value is None and nullable:
        return
    if not _is_int(value) or not 0 <= value <= MAX_IDENTIFIER:
        raise ValueError(f"{field} must be an integer between 0 and {MAX_IDENTIFIER}")


def _check_path(event: dict[str, Any], field: str) -> None:
    value = event[field]
    if (
        not isinstance(value, str)
        or not value.startswith("/")
        or len(value) > MAX_ENDPOINT_LENGTH
        or _CONTROL_CHARACTERS.search(value)
    ):
        raise ValueError(
            f"{field} must be a path starting with '/', at most "
            f"{MAX_ENDPOINT_LENGTH} characters, without control characters"
        )


def is_valid_ip(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def validate_event(event: dict[str, Any]) -> dict[str, Any]:
    """Validate a security event against the project contract."""
    missing = [field for field in EVENT_REQUIRED_FIELDS if field not in event]
    if missing:
        raise ValueError(f"Event missing required fields: {missing}")

    if not _is_int(event["event_id"]) or not 1 <= event["event_id"] <= MAX_IDENTIFIER:
        raise ValueError(f"event_id must be an integer between 1 and {MAX_IDENTIFIER}")
    for field in ("user_id", "resource_id", "resource_owner_id"):
        _check_identifier(event, field, nullable=True)

    timestamp = event["timestamp"]
    try:
        parsed = datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
    except ValueError:
        parsed = None
    if not isinstance(timestamp, str) or parsed is None or parsed.tzinfo is None:
        raise ValueError("timestamp must be an ISO-8601 string with a timezone")

    if event["ip"] != UNKNOWN_IP and not is_valid_ip(event["ip"]):
        raise ValueError(f"ip must be an IPv4/IPv6 address or {UNKNOWN_IP!r}")

    if event["method"] not in HTTP_METHODS:
        raise ValueError(f"method must be one of {sorted(HTTP_METHODS)}")

    _check_path(event, "endpoint")
    if event["endpoint_pattern"] is None:
        raise ValueError("endpoint_pattern cannot be null")
    _check_path(event, "endpoint_pattern")

    if not _is_int(event["status_code"]) or not 100 <= event["status_code"] <= 599:
        raise ValueError("status_code must be an integer between 100 and 599")

    response_time_ms = event["response_time_ms"]
    if (
        not isinstance(response_time_ms, (int, float))
        or isinstance(response_time_ms, bool)
        or not math.isfinite(response_time_ms)
        or response_time_ms < 0
    ):
        raise ValueError("response_time_ms must be a finite, non-negative number")

    if event["sim_label"] not in SIM_LABELS:
        raise ValueError(f"sim_label must be one of {sorted(SIM_LABELS)}")

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
