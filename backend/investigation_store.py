"""SQLite persistence for Gemini investigation status and validated reports."""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Any

from backend.database import get_connection


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ensure_table(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS investigations (
            investigation_id TEXT PRIMARY KEY,
            detection_id INTEGER NOT NULL UNIQUE,
            status TEXT NOT NULL CHECK (
                status IN ('pending', 'in_progress', 'completed', 'failed')
            ),
            result_json TEXT,
            model_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            completed_at TEXT,
            error_code TEXT
        )
        """
    )


def _row_to_record(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    result = dict(row)
    try:
        result["result"] = (
            json.loads(result.pop("result_json"))
            if result.get("result_json") is not None
            else None
        )
    except json.JSONDecodeError as exc:
        raise sqlite3.DatabaseError(
            "Stored investigation report is invalid."
        ) from exc
    return result


def create_or_get_investigation(
    detection_id: int,
    model_id: str,
) -> tuple[dict[str, Any], bool]:
    """Create a single investigation per detection, returning an existing one."""
    with get_connection() as conn:
        _ensure_table(conn)
        conn.execute("BEGIN IMMEDIATE")
        existing = conn.execute(
            "SELECT * FROM investigations WHERE detection_id = ?",
            (detection_id,),
        ).fetchone()
        if existing is not None:
            record = _row_to_record(existing)
            if record is None:
                raise sqlite3.DatabaseError("Stored investigation record is missing.")
            return record, False

        investigation_id = str(uuid.uuid4())
        conn.execute(
            """
            INSERT INTO investigations (
                investigation_id, detection_id, status, model_id, created_at
            ) VALUES (?, ?, 'pending', ?, ?)
            """,
            (investigation_id, detection_id, model_id, _now()),
        )
        row = conn.execute(
            "SELECT * FROM investigations WHERE investigation_id = ?",
            (investigation_id,),
        ).fetchone()
        record = _row_to_record(row)
        if record is None:
            raise sqlite3.DatabaseError("Created investigation record is missing.")
        return record, True


def retry_investigation(
    detection_id: int,
    model_id: str,
) -> tuple[dict[str, Any], bool]:
    """Reset a failed investigation for retry; keep active/completed rows intact."""
    with get_connection() as conn:
        _ensure_table(conn)
        conn.execute("BEGIN IMMEDIATE")
        existing = conn.execute(
            "SELECT * FROM investigations WHERE detection_id = ?",
            (detection_id,),
        ).fetchone()
        if existing is None:
            investigation_id = str(uuid.uuid4())
            conn.execute(
                """
                INSERT INTO investigations (
                    investigation_id, detection_id, status, model_id, created_at
                ) VALUES (?, ?, 'pending', ?, ?)
                """,
                (investigation_id, detection_id, model_id, _now()),
            )
        else:
            current = _row_to_record(existing)
            if current is None:
                raise sqlite3.DatabaseError("Stored investigation record is missing.")
            if current["status"] != "failed":
                return current, False

            investigation_id = current["investigation_id"]
            conn.execute(
                """
                UPDATE investigations
                SET status = 'pending', result_json = NULL, model_id = ?,
                    created_at = ?, completed_at = NULL, error_code = NULL
                WHERE investigation_id = ?
                """,
                (model_id, _now(), investigation_id),
            )

        row = conn.execute(
            "SELECT * FROM investigations WHERE investigation_id = ?",
            (investigation_id,),
        ).fetchone()
        record = _row_to_record(row)
        if record is None:
            raise sqlite3.DatabaseError("Retried investigation record is missing.")
        return record, True


def get_investigation(investigation_id: str) -> dict[str, Any] | None:
    with get_connection() as conn:
        _ensure_table(conn)
        row = conn.execute(
            "SELECT * FROM investigations WHERE investigation_id = ?",
            (investigation_id,),
        ).fetchone()
    return _row_to_record(row)


def update_investigation(
    investigation_id: str,
    *,
    status: str,
    result: dict[str, Any] | None = None,
    error_code: str | None = None,
) -> None:
    if status not in {"in_progress", "completed", "failed"}:
        raise ValueError("Invalid investigation status.")

    result_json = (
        json.dumps(result, ensure_ascii=True, separators=(",", ":"))
        if result is not None
        else None
    )
    completed_at = _now() if status in {"completed", "failed"} else None
    with get_connection() as conn:
        _ensure_table(conn)
        conn.execute(
            """
            UPDATE investigations
            SET status = ?, result_json = ?, completed_at = ?, error_code = ?
            WHERE investigation_id = ?
            """,
            (status, result_json, completed_at, error_code, investigation_id),
        )
