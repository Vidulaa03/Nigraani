import json
import re
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from backend.database import get_order_by_id, insert_event

LOG_DIR = Path("logs")
LOG_FILE = LOG_DIR / "api_events.jsonl"

LOG_DIR.mkdir(parents=True, exist_ok=True)

_event_id_lock = threading.Lock()
_last_event_id = 0


def _next_event_id() -> int:
    global _last_event_id
    with _event_id_lock:
        _last_event_id = max(time.time_ns() // 1_000, _last_event_id + 1)
        return _last_event_id


def _derive_endpoint_pattern(endpoint: str) -> str:
    if re.match(r"^/api/orders/\d+$", endpoint):
        return "/api/orders/{order_id}"
    if re.match(r"^/api/users/\d+$", endpoint):
        return "/api/users/{user_id}"
    if endpoint.startswith("/api/auth/"):
        return "/api/auth/{action}"
    return endpoint


def _extract_resource_id(endpoint: str) -> int | None:
    match = re.search(r"/(\d+)$", endpoint)
    if not match:
        return None
    return int(match.group(1))


def log_security_event(
    ip: str,
    method: str,
    endpoint: str,
    status_code: int,
    response_time_ms: float,
    user_id: int | None = None,
    resource_id: int | None = None,
    resource_owner_id: int | None = None,
    endpoint_pattern: str | None = None,
    sim_label: str = "normal",
    event_id: int | None = None,
) -> dict[str, Any]:
    endpoint_pattern = endpoint_pattern or _derive_endpoint_pattern(endpoint)
    resource_id = resource_id if resource_id is not None else _extract_resource_id(endpoint)

    if resource_id is not None and resource_owner_id is None:
        order = get_order_by_id(resource_id)
        if order:
            resource_owner_id = order.get("owner_id")

    event = {
        "event_id": event_id if event_id is not None else _next_event_id(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "ip": ip,
        "user_id": user_id,
        "method": method,
        "endpoint": endpoint,
        "endpoint_pattern": endpoint_pattern,
        "resource_id": resource_id,
        "resource_owner_id": resource_owner_id,
        "status_code": status_code,
        "response_time_ms": round(float(response_time_ms), 2),
        "sim_label": sim_label,
    }

    with open(LOG_FILE, "a", encoding="utf-8") as file:
        file.write(json.dumps({k: v for k, v in event.items() if v is not None}) + "\n")

    insert_event(event)
    return event