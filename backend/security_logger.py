"""Persist security events: validate -> database -> JSONL.

The database row is the record the analyzer, dashboard, and incident
evidence read. The JSONL line is appended only after the row is stored, so
the file never holds an event the database rejected. If the database write
fails, the validated event goes to the recovery spool (backend.event_recovery)
and is replayed later; it is still reported as failed, never as stored.
Every rejection or failure is logged and counted in
nigraani_security_events_total; callers get SecurityEventRejected or
SecurityEventPersistenceError instead of a silent drop.
"""

import json
import logging
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import backend.database as database
from backend.database import BASE_DIR, DuplicateEventError, get_max_event_id, insert_event
from backend.detection.base import MAX_IDENTIFIER, validate_event
from backend.event_preprocessing import derive_endpoint_pattern, resolve_resource
from backend.event_recovery import locked_append, spool_event
from backend.metrics import SECURITY_EVENTS, SECURITY_LOG_WRITE_FAILURES

logger = logging.getLogger(__name__)

LOG_DIR = Path(os.environ.get("NIGRAANI_LOG_DIR") or BASE_DIR / "logs")
LOG_FILE = LOG_DIR / "api_events.jsonl"
# Shorter than the general SQLite timeout: the write lock is held while
# waiting, and a spooled event is replayed later, so a long wait only delays
# every other request's logging.
EVENT_WRITE_TIMEOUT_SECONDS = float(os.environ.get("NIGRAANI_EVENT_WRITE_TIMEOUT") or 2.0)

# Held from ID assignment through the JSONL append, so within this process
# events are committed in event_id order. The analyzer reads with
# "event_id > last seen", so an event committed after a higher ID would be
# skipped (the analyzer's look-back only covers other processes' stragglers).
_write_lock = threading.Lock()
# How long a request waits for the write lock before its event is spooled
# instead, so a stuck database cannot make request latency grow without bound.
LOCK_WAIT_SECONDS = float(os.environ.get("NIGRAANI_EVENT_LOCK_WAIT") or 3.0)
# Guards _last_event_id only (no I/O), so spooled events still get unique IDs.
_id_lock = threading.Lock()
_last_event_id = 0
_seeded_from: Path | None = None
_ID_ATTEMPTS = 3


class SecurityEventRejected(ValueError):
    """The event was invalid or a duplicate; nothing was written."""


class SecurityEventPersistenceError(RuntimeError):
    """The event could not be stored in the database.

    ``spooled`` tells whether it was queued in the recovery spool for replay.
    """

    def __init__(self, message: str, *, spooled: bool = False):
        super().__init__(message)
        self.spooled = spooled


def _next_event_id(*, reseed: bool = False, use_database: bool = True) -> int:
    # Epoch microseconds, strictly increasing, and never at or below an ID
    # already stored (protects against restarts and clock steps backwards).
    # The stored maximum is read once per database, and again after another
    # writer took an ID, instead of on every event.
    global _last_event_id, _seeded_from
    floor = 0
    if use_database and (reseed or _seeded_from != database.DB_PATH):
        try:
            floor = get_max_event_id(timeout=EVENT_WRITE_TIMEOUT_SECONDS)
            _seeded_from = database.DB_PATH
        except Exception as error:
            # Keep going on the clock; the insert will fail and be spooled
            # if the database really is unavailable.
            logger.warning("Could not read the highest stored event_id: %s", error)
    with _id_lock:
        _last_event_id = max(time.time_ns() // 1_000, _last_event_id + 1, floor + 1)
        if _last_event_id > MAX_IDENTIFIER:
            raise SecurityEventPersistenceError("event_id space exhausted")
        return _last_event_id


def _timestamp(value: datetime | str | None) -> str:
    if value is None:
        return datetime.now(timezone.utc).isoformat()
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()
    return value


def _reject(reason: str) -> SecurityEventRejected:
    SECURITY_EVENTS.labels("rejected").inc()
    logger.warning("Security event rejected: %s", reason)
    return SecurityEventRejected(reason)


def _fail(
    event: dict[str, Any], error: Exception, *, sink: str = "database"
) -> SecurityEventPersistenceError:
    SECURITY_EVENTS.labels("failed").inc()
    SECURITY_LOG_WRITE_FAILURES.labels(sink).inc()
    logger.error(
        "Security event %s was not stored: %s: %s",
        event["event_id"], type(error).__name__, error,
    )
    spooled = event.get("event_id") is not None and spool_event(event, error)
    return SecurityEventPersistenceError(
        f"security event was not stored: {type(error).__name__}"
        + ("; queued for replay" if spooled else ""),
        spooled=spooled,
    )


def _store(event: dict[str, Any], *, assign_id: bool) -> None:
    """Validate and insert; insert_event() runs validate_event() first."""
    reseed = False
    for attempt in range(1, _ID_ATTEMPTS + 1):
        try:
            if assign_id:
                event["event_id"] = _next_event_id(reseed=reseed)
            insert_event(event, timeout=EVENT_WRITE_TIMEOUT_SECONDS)
            return
        except DuplicateEventError as error:
            if not assign_id:
                raise _reject(str(error)) from None
            if attempt == _ID_ATTEMPTS:
                raise _fail(event, error) from error
            # Another writer (e.g. a second process) took this ID; take the next.
            reseed = True
        except ValueError as error:
            raise _reject(str(error)) from None
        except Exception as error:
            raise _fail(event, error) from error


def append_jsonl(event: dict[str, Any]) -> None:
    """Append a stored event to the JSONL log; failures are reported, not raised."""
    try:
        line = json.dumps({k: v for k, v in event.items() if v is not None}) + "\n"
        # Locked against other processes; starts a fresh line if a crash
        # left a partial one. No fsync: the database row is the durable copy.
        locked_append(LOG_FILE, line, fsync=False)
    except OSError as error:
        # The database row is already committed, so the event is stored; only
        # the JSONL copy is missing.
        SECURITY_LOG_WRITE_FAILURES.labels("jsonl").inc()
        logger.error(
            "Security event %s stored but not appended to %s: %s",
            event["event_id"], LOG_FILE, error,
        )


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
    timestamp: datetime | str | None = None,
) -> dict[str, Any]:
    """Store one security event and return it.

    Raises SecurityEventRejected (invalid or duplicate event_id, nothing
    written) or SecurityEventPersistenceError (database write failed).
    """
    if isinstance(endpoint, str):
        derived_resource_id, derived_owner_id = resolve_resource(endpoint)
        endpoint_pattern = endpoint_pattern or derive_endpoint_pattern(endpoint)
    else:
        derived_resource_id = derived_owner_id = None
    if resource_id is None:
        resource_id = derived_resource_id
    if resource_owner_id is None and resource_id == derived_resource_id:
        resource_owner_id = derived_owner_id

    if isinstance(response_time_ms, (int, float)) and not isinstance(response_time_ms, bool):
        response_time_ms = round(float(response_time_ms), 2)

    event = {
        "event_id": event_id,
        "timestamp": _timestamp(timestamp),
        "ip": ip,
        "user_id": user_id,
        "method": method,
        "endpoint": endpoint,
        "endpoint_pattern": endpoint_pattern,
        "resource_id": resource_id,
        "resource_owner_id": resource_owner_id,
        "status_code": status_code,
        "response_time_ms": response_time_ms,
        "sim_label": sim_label,
    }

    if not _write_lock.acquire(timeout=LOCK_WAIT_SECONDS):
        # Writers are backed up (usually a locked database). Spool instead of
        # queueing behind them; the analyzer replays and analyzes it later.
        if event_id is None:
            event["event_id"] = _next_event_id(use_database=False)
        try:
            validate_event(event)
        except ValueError as error:
            raise _reject(str(error)) from None
        raise _fail(event, TimeoutError("security event writer busy"), sink="busy")
    try:
        _store(event, assign_id=event_id is None)
        append_jsonl(event)
    finally:
        _write_lock.release()

    SECURITY_EVENTS.labels("stored").inc()
    return event
