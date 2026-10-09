"""Read-only retrieval of saved detections and their linked event evidence.

Call ``get_incident_evidence(detection_id)`` with a persisted detection ID.
The result contains only event IDs that resolve to saved security events;
unresolved references and truncation are reported separately. Database errors
raise ``IncidentEvidenceDatabaseError`` and a missing detection returns None.
"""

from __future__ import annotations

import json
import re
import sqlite3
from datetime import datetime, timezone
from typing import Any

from backend.database import get_connection

MAX_LINKED_EVENTS = 100
_MAX_SQLITE_INTEGER = 2**63 - 1

_SENSITIVE_ASSIGNMENT = re.compile(
    r"""(?i)(["']?\b(password|passwd|pwd|api[_-]?key|access[_-]?token|"""
    r"""refresh[_-]?token|token|secret|authorization|auth|cookie|"""
    r"""session[_-]?id)\b["']?\s*[:=]\s*["']?)"""
    r"""(?:bearer\s+)?(?:"[^"]*"|'[^']*'|[^\s,;}]+)"""
)


class IncidentEvidenceDatabaseError(RuntimeError):
    """Raised when saved incident evidence cannot be read from the database."""


def _redact(value: Any) -> Any:
    if isinstance(value, str):
        return _SENSITIVE_ASSIGNMENT.sub(
            lambda match: f"{match.group(1)}[REDACTED]",
            value,
        )
    if isinstance(value, list):
        return [_redact(item) for item in value]
    if isinstance(value, dict):
        return {key: _redact(item) for key, item in value.items()}
    return value


def _safe_endpoint(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    path = value.split("?", 1)[0].split("#", 1)[0]
    return _redact(path)


def _parse_event_ids(value: Any) -> tuple[list[int], int]:
    try:
        decoded = json.loads(value) if isinstance(value, str) else value
    except json.JSONDecodeError:
        return [], 1

    if not isinstance(decoded, list):
        return [], 1

    event_ids: list[int] = []
    invalid_count = 0
    for item in decoded:
        if isinstance(item, bool):
            invalid_count += 1
            continue
        if isinstance(item, int):
            event_id = item
        elif isinstance(item, str) and item.isdecimal():
            if len(item) > 19:
                invalid_count += 1
                continue
            event_id = int(item)
        else:
            invalid_count += 1
            continue

        if event_id <= 0 or event_id > _MAX_SQLITE_INTEGER:
            invalid_count += 1
            continue
        if event_id not in event_ids:
            event_ids.append(event_id)

    return event_ids, invalid_count


def _parse_json(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return value


def _utc_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _time_window(events: list[dict[str, Any]]) -> dict[str, str | None]:
    timestamps = [
        parsed
        for event in events
        if (parsed := _utc_timestamp(event.get("timestamp"))) is not None
    ]
    if not timestamps:
        return {"start": None, "end": None}
    return {
        "start": min(timestamps).isoformat(),
        "end": max(timestamps).isoformat(),
    }


def _owasp_mapping(value: Any) -> list[Any]:
    decoded = _parse_json(value)
    if decoded is None or decoded == "":
        return []
    if isinstance(decoded, list):
        return _redact(decoded)
    return [_redact(decoded)]


def _matching_decision(
    conn: sqlite3.Connection,
    ip: str,
    event_ids: set[int],
) -> dict[str, Any] | None:
    if not event_ids:
        return None

    decision_columns = {
        row["name"] for row in conn.execute("PRAGMA table_info(decisions)")
    }
    if "event_ids" not in decision_columns:
        return None

    rows = conn.execute(
        """
        SELECT decision_id, risk_score, action, reasons, event_ids
        FROM decisions
        WHERE ip = ?
        ORDER BY decision_id DESC
        LIMIT 100
        """,
        (ip,),
    ).fetchall()
    for row in rows:
        decision_event_ids, _ = _parse_event_ids(row["event_ids"])
        if event_ids.intersection(decision_event_ids):
            return dict(row)
    return None


def get_incident_evidence(detection_id: int) -> dict[str, Any] | None:
    """Return a bounded incident payload for one saved detection.

    The contract includes stable ``incident_id``, saved ``detection_id``,
    detector/attack/severity fields, matched saved risk values, a UTC
    ``time_window``, client IP, common endpoint pattern, evidence text,
    OWASP mapping, resolved ``event_ids``, and ``linked_events``. Each linked
    event has ``event_id``, ``timestamp``, ``method``, ``endpoint``,
    ``endpoint_pattern``, ``status_code``, and a derived ``summary``.
    Missing scalar values are None; absent collections are empty lists.
    ``event_reference_status`` distinguishes complete, empty, incomplete,
    and invalid references; unresolved, invalid, and omitted references are
    counted or identified separately.

    Event summaries include only timestamps, method, endpoint, endpoint
    pattern, status code, and a concise derived summary. ``sim_label`` and
    request bodies/headers are never returned. Risk data is included only when
    an existing saved decision references at least one of this detection's
    event IDs; its action remains a recommendation, not an enforcement claim.
    """
    if (
        isinstance(detection_id, bool)
        or not isinstance(detection_id, int)
        or detection_id <= 0
    ):
        raise ValueError("detection_id must be a positive integer")

    try:
        with get_connection() as conn:
            conn.execute("PRAGMA query_only = ON")
            detection_row = conn.execute(
                """
                SELECT detection_id, detector, attack_type, severity, ip,
                       evidence, event_ids, owasp
                FROM detections
                WHERE detection_id = ?
                """,
                (detection_id,),
            ).fetchone()
            if detection_row is None:
                return None

            detection = dict(detection_row)
            referenced_ids, invalid_reference_count = _parse_event_ids(
                detection["event_ids"]
            )
            selected_ids = referenced_ids[:MAX_LINKED_EVENTS]
            omitted_reference_count = max(
                len(referenced_ids) - len(selected_ids),
                0,
            )

            event_rows: list[sqlite3.Row] = []
            if selected_ids:
                placeholders = ",".join("?" for _ in selected_ids)
                event_rows = conn.execute(
                    f"""
                    SELECT event_id, timestamp, ip, method, endpoint,
                           endpoint_pattern, status_code
                    FROM security_events
                    WHERE event_id IN ({placeholders})
                    """,
                    selected_ids,
                ).fetchall()

            events_by_id = {int(row["event_id"]): dict(row) for row in event_rows}
            events = [
                events_by_id[event_id]
                for event_id in selected_ids
                if event_id in events_by_id
            ]
            actual_event_ids = [int(event["event_id"]) for event in events]
            unresolved_event_ids = [
                event_id for event_id in selected_ids if event_id not in events_by_id
            ]
            decision = _matching_decision(
                conn,
                str(detection["ip"]),
                set(actual_event_ids),
            )
    except sqlite3.Error:
        raise IncidentEvidenceDatabaseError(
            "Unable to retrieve incident evidence from the database."
        ) from None

    linked_events = []
    for event in events:
        method = event.get("method")
        endpoint = _safe_endpoint(event.get("endpoint"))
        status_code = event.get("status_code")
        request_summary = " ".join(
            str(part)
            for part in (method, endpoint)
            if part is not None
        )
        if status_code is not None:
            request_summary = f"{request_summary} returned HTTP {status_code}"
        linked_events.append(
            {
                "event_id": int(event["event_id"]),
                "timestamp": event.get("timestamp"),
                "method": method,
                "endpoint": endpoint,
                "endpoint_pattern": _safe_endpoint(event.get("endpoint_pattern")),
                "status_code": status_code,
                "summary": _redact(request_summary),
            }
        )

    endpoint_patterns = {
        event["endpoint_pattern"]
        for event in linked_events
        if event["endpoint_pattern"] is not None
    }

    if invalid_reference_count:
        reference_status = "invalid"
    elif not referenced_ids:
        reference_status = "empty"
    elif unresolved_event_ids or omitted_reference_count:
        reference_status = "incomplete"
    else:
        reference_status = "complete"

    return {
        "incident_id": f"detection:{detection_id}",
        "detection_id": detection_id,
        "detector": detection["detector"],
        "attack_type": detection["attack_type"],
        "severity": detection["severity"],
        "risk_score": decision["risk_score"] if decision else None,
        "action": decision["action"] if decision else None,
        "risk_reasons": _redact(_parse_json(decision["reasons"])) if decision else [],
        "time_window": _time_window(events),
        "client": {"ip_address": detection["ip"]},
        "endpoint_pattern": (
            next(iter(endpoint_patterns)) if len(endpoint_patterns) == 1 else None
        ),
        "evidence_text": _redact(detection["evidence"]),
        "event_ids": actual_event_ids,
        "event_reference_status": reference_status,
        "unresolved_event_ids": unresolved_event_ids,
        "invalid_event_reference_count": invalid_reference_count,
        "omitted_event_count": omitted_reference_count,
        "owasp_mapping": _owasp_mapping(detection["owasp"]),
        "linked_events": linked_events,
    }
