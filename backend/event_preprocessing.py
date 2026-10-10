"""Turn untrusted request data into security-event fields.

Values that cannot be trusted as-is are replaced (oversized IDs become None,
malformed X-Forwarded-For falls back to the connecting client, unknown
simulation labels become "unknown") or trimmed (endpoint paths), and each
replacement is counted in nigraani_security_event_fields_sanitized_total.
The result still goes through validate_event() before anything is written.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Mapping

from backend.database import ORDERS
from backend.detection.base import MAX_ENDPOINT_LENGTH, MAX_IDENTIFIER, SIM_LABELS, UNKNOWN_IP
from backend.metrics import SECURITY_EVENT_FIELDS_SANITIZED

_ORDER_PATH = re.compile(r"^/api/orders/(\d+)$")
_USER_PATH = re.compile(r"^/api/users/(\d+)$")
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]")
_DECIMAL = re.compile(r"\d{1,19}")


def parse_identifier(value: Any) -> int | None:
    """Return a non-negative integer that fits in SQLite, otherwise None."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        number = value
    elif isinstance(value, str) and _DECIMAL.fullmatch(value.strip()):
        number = int(value.strip())
    else:
        return None
    return number if 0 <= number <= MAX_IDENTIFIER else None


def canonical_ip(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def client_ip(forwarded_for: str | None, client_host: str | None) -> str:
    """First X-Forwarded-For entry if it is an IP address, else the client."""
    if forwarded_for:
        forwarded = canonical_ip(forwarded_for.split(",")[0])
        if forwarded is not None:
            return forwarded
        SECURITY_EVENT_FIELDS_SANITIZED.labels("ip").inc()
    return canonical_ip(client_host) or UNKNOWN_IP


def sanitize_endpoint(path: str) -> str:
    """Percent-encode control characters and cap the length."""
    cleaned = _CONTROL_CHARACTERS.sub(lambda match: f"%{ord(match.group()):02X}", path or "/")
    if not cleaned.startswith("/"):
        cleaned = f"/{cleaned}"
    cleaned = cleaned[:MAX_ENDPOINT_LENGTH]
    if cleaned != path:
        SECURITY_EVENT_FIELDS_SANITIZED.labels("endpoint").inc()
    return cleaned


def normalize_sim_label(value: str | None) -> str:
    if value is None:
        return "normal"
    label = value.strip().lower()
    if label in SIM_LABELS:
        return label
    SECURITY_EVENT_FIELDS_SANITIZED.labels("sim_label").inc()
    return "unknown"


def derive_endpoint_pattern(endpoint: str) -> str:
    if re.match(r"^/api/orders/\d+$", endpoint):
        return "/api/orders/{order_id}"
    if re.match(r"^/api/users/\d+$", endpoint):
        return "/api/users/{user_id}"
    if endpoint.startswith("/api/auth/"):
        return "/api/auth/{action}"
    return endpoint


def resolve_resource(endpoint: str) -> tuple[int | None, int | None]:
    """Return (resource_id, resource_owner_id) for routes that address one.

    Only /api/orders/{id} has an owner, taken from the server-side ORDERS
    table. /api/users/{id} addresses a user, so it gets a resource_id (the
    enumeration detector needs it) but never an owner. Any other path,
    including ones that merely end in digits, gets neither.
    """
    order = _ORDER_PATH.match(endpoint)
    if order:
        order_id = parse_identifier(order.group(1))
        owner = ORDERS.get(order_id, {}).get("owner_id") if order_id is not None else None
        return order_id, owner
    user = _USER_PATH.match(endpoint)
    if user:
        return parse_identifier(user.group(1)), None
    return None, None


def request_event_fields(
    *,
    method: str,
    path: str,
    headers: Mapping[str, str],
    client_host: str | None,
) -> dict[str, Any]:
    """Event fields for log_security_event() taken from an HTTP request."""
    raw_user_id = headers.get("x-user-id")
    user_id = parse_identifier(raw_user_id)
    if raw_user_id is not None and user_id is None:
        SECURITY_EVENT_FIELDS_SANITIZED.labels("user_id").inc()

    return {
        "ip": client_ip(headers.get("x-forwarded-for"), client_host),
        "method": method.upper(),
        "endpoint": sanitize_endpoint(path),
        "user_id": user_id,
        "sim_label": normalize_sim_label(headers.get("x-sim-label")),
    }
