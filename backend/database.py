import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any

from backend.detection.base import validate_event

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "demo.db"


def _analysis_key(*parts: Any) -> str:
    payload = json.dumps(parts, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _canonical_event_ids(event_ids: Any) -> list[int] | None:
    if isinstance(event_ids, str):
        try:
            event_ids = json.loads(event_ids)
        except json.JSONDecodeError:
            return None
    if not isinstance(event_ids, list) or not event_ids:
        return None
    try:
        return sorted({int(event_id) for event_id in event_ids})
    except (TypeError, ValueError):
        return None

USERS = {
    101: {
        "name": "Kaivalya",
        "email": "kaivalya@example.com",
    },
    102: {
        "name": "Divya",
        "email": "divya@example.com",
    },
    103: {
        "name": "Vidula",
        "email": "vidula@example.com",
    },
    104: {
        "name": "Shravani",
        "email": "shravani@example.com",
    },
    105: {
        "name": "xyz",
        "email": "xyz@example.com",
    },
}

ORDERS = {
    501: {
        "owner_id": 101,
        "product": "Laptop",
        "amount": 75000,
    },
    502: {
        "owner_id": 101,
        "product": "Mouse",
        "amount": 1500,
    },
    601: {
        "owner_id": 102,
        "product": "Phone",
        "amount": 45000,
    },
    602: {
        "owner_id": 102,
        "product": "Keyboard",
        "amount": 3000,
    },
    701: {
        "owner_id": 103,
        "product": "Monitor",
        "amount": 20000,
    },
    702: {
        "owner_id": 103,
        "product": "Tablet",
        "amount": 18000,
    },
    801: {
        "owner_id": 104,
        "product": "Headphones",
        "amount": 6500,
    },
    802: {
        "owner_id": 104,
        "product": "Charger",
        "amount": 1200,
    },
}

_DEMO_ORDER_CATALOG = (
    ("Notebook", 2500),
    ("Desk lamp", 1800),
    ("Backpack", 3200),
    ("Water bottle", 700),
    ("USB hub", 1100),
    ("Webcam", 4500),
    ("Microphone", 5200),
    ("Office chair", 12500),
)

for user_offset, user_id in enumerate(USERS):
    existing_orders = sum(order["owner_id"] == user_id for order in ORDERS.values())
    for order_number, (product, amount) in enumerate(
        _DEMO_ORDER_CATALOG[: 8 - existing_orders],
        start=1,
    ):
        ORDERS[1000 + user_offset * 100 + order_number] = {
            "owner_id": user_id,
            "product": product,
            "amount": amount,
        }


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> Path:
    with get_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS orders (
                order_id INTEGER PRIMARY KEY,
                owner_id INTEGER NOT NULL,
                product TEXT NOT NULL,
                amount REAL NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS security_events (
                event_id INTEGER PRIMARY KEY,
                timestamp TEXT NOT NULL,
                ip TEXT NOT NULL,
                user_id INTEGER,
                method TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                endpoint_pattern TEXT NOT NULL,
                resource_id INTEGER,
                resource_owner_id INTEGER,
                status_code INTEGER NOT NULL,
                response_time_ms REAL NOT NULL,
                sim_label TEXT NOT NULL DEFAULT 'normal'
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS detections (
                detection_id INTEGER PRIMARY KEY AUTOINCREMENT,
                detector TEXT NOT NULL,
                attack_type TEXT NOT NULL,
                severity INTEGER NOT NULL,
                ip TEXT NOT NULL,
                user_id INTEGER,
                evidence TEXT NOT NULL,
                event_ids TEXT NOT NULL,
                owasp TEXT NOT NULL DEFAULT 'API1:2023',
                analysis_key TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS decisions (
                decision_id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                action TEXT NOT NULL,
                reasons TEXT NOT NULL,
                source TEXT NOT NULL DEFAULT 'system',
                event_ids TEXT,
                analysis_key TEXT
            )
            """
        )
        detection_columns = {row["name"] for row in conn.execute("PRAGMA table_info(detections)")}
        if "analysis_key" not in detection_columns:
            conn.execute("ALTER TABLE detections ADD COLUMN analysis_key TEXT")

        decision_columns = {row["name"] for row in conn.execute("PRAGMA table_info(decisions)")}
        if "event_ids" not in decision_columns:
            conn.execute("ALTER TABLE decisions ADD COLUMN event_ids TEXT")
        if "analysis_key" not in decision_columns:
            conn.execute("ALTER TABLE decisions ADD COLUMN analysis_key TEXT")
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_detections_analysis_key "
            "ON detections (analysis_key) WHERE analysis_key IS NOT NULL"
        )
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_decisions_analysis_key "
            "ON decisions (analysis_key) WHERE analysis_key IS NOT NULL"
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS notifications (
                notification_id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id TEXT NOT NULL,
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                severity INTEGER NOT NULL,
                severity_band TEXT NOT NULL,
                created_at TEXT NOT NULL,
                is_read INTEGER NOT NULL DEFAULT 0,
                recipient TEXT NOT NULL DEFAULT 'soc-analyst',
                idempotency_key TEXT UNIQUE NOT NULL,
                metadata TEXT NOT NULL DEFAULT '{}'
            )
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_notifications_created
            ON notifications(created_at DESC)
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_notifications_read
            ON notifications(is_read)
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_notifications_incident
            ON notifications(incident_id)
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS call_alerts (
                call_id INTEGER PRIMARY KEY AUTOINCREMENT,
                call_sid TEXT UNIQUE NOT NULL,
                incident_id TEXT NOT NULL,
                notification_id INTEGER,
                to_number TEXT NOT NULL,
                from_number TEXT NOT NULL,
                trigger_reason TEXT NOT NULL,
                status TEXT NOT NULL,
                severity INTEGER NOT NULL,
                initiated_at TEXT NOT NULL,
                completed_at TEXT,
                duration INTEGER,
                error_message TEXT,
                metadata TEXT NOT NULL DEFAULT '{}'
            )
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_call_alerts_sid
            ON call_alerts(call_sid)
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_call_alerts_incident
            ON call_alerts(incident_id)
            """
        )

        for user_id, payload in USERS.items():
            conn.execute(
                "INSERT OR IGNORE INTO users (user_id, name, email) VALUES (?, ?, ?)",
                (user_id, payload["name"], payload["email"]),
            )

        for order_id, payload in ORDERS.items():
            conn.execute(
                "INSERT OR IGNORE INTO orders (order_id, owner_id, product, amount) VALUES (?, ?, ?, ?)",
                (order_id, payload["owner_id"], payload["product"], payload["amount"]),
            )

        conn.commit()

    return DB_PATH


def get_events_since(
    last_event_id: int | None = None,
    limit: int | None = None,
    since_timestamp: str | None = None,
) -> list[dict[str, Any]]:
    with get_connection() as conn:
        query = "SELECT * FROM security_events"
        params: list[Any] = []
        conditions = []
        if last_event_id is not None:
            conditions.append("event_id > ?")
            params.append(last_event_id)
        if since_timestamp is not None:
            conditions.append("julianday(timestamp) >= julianday(?)")
            params.append(since_timestamp)
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY event_id ASC"
        if limit is not None:
            query += " LIMIT ?"
            params.append(limit)
        rows = conn.execute(query, params).fetchall()
    return [dict(row) for row in rows]


def get_latest_event_id() -> int:
    """Return the current event cursor without loading the event history."""
    with get_connection() as conn:
        row = conn.execute("SELECT COALESCE(MAX(event_id), 0) AS event_id FROM security_events").fetchone()
    return int(row["event_id"])


def insert_event(event: dict[str, Any]) -> int:
    validate_event(event)
    event_id = int(event["event_id"])
    with get_connection() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO security_events (
                event_id, timestamp, ip, user_id, method, endpoint, endpoint_pattern,
                resource_id, resource_owner_id, status_code, response_time_ms, sim_label
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,
                event["timestamp"],
                event["ip"],
                event.get("user_id"),
                event["method"],
                event["endpoint"],
                event["endpoint_pattern"],
                event.get("resource_id"),
                event.get("resource_owner_id"),
                event["status_code"],
                float(event["response_time_ms"]),
                event["sim_label"],
            ),
        )
        conn.commit()
    return event_id


def insert_detection(detection: dict[str, Any]) -> int:
    event_ids = detection.get("event_ids", [])
    canonical_event_ids = _canonical_event_ids(event_ids)
    evidence_payload = event_ids if isinstance(event_ids, str) else json.dumps(event_ids)
    key = (
        _analysis_key(
            detection["detector"], detection["attack_type"], detection["ip"],
            detection.get("user_id"), canonical_event_ids,
        )
        if canonical_event_ids is not None else None
    )
    with get_connection() as conn:
        if key is not None:
            existing = conn.execute(
                "SELECT detection_id FROM detections WHERE analysis_key = ?", (key,)
            ).fetchone()
            if existing:
                return int(existing["detection_id"])
            legacy_rows = conn.execute(
                """SELECT detection_id, event_ids FROM detections
                   WHERE detector = ? AND ip = ? AND attack_type = ?
                     AND user_id IS ? AND analysis_key IS NULL""",
                (detection["detector"], detection["ip"], detection["attack_type"], detection.get("user_id")),
            ).fetchall()
            for row in legacy_rows:
                if _canonical_event_ids(row["event_ids"]) == canonical_event_ids:
                    return int(row["detection_id"])
        cursor = conn.execute(
            """
            INSERT INTO detections (
                detector, attack_type, severity, ip, user_id, evidence, event_ids, owasp, analysis_key
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                detection["detector"],
                detection["attack_type"],
                int(detection["severity"]),
                detection["ip"],
                detection.get("user_id"),
                detection["evidence"],
                evidence_payload,
                detection.get("owasp", "API1:2023"),
                key,
            ),
        )
        conn.commit()
    return int(cursor.lastrowid)


def insert_decision(decision: dict[str, Any]) -> int:
    reasons_payload = json.dumps(decision.get("reasons", []))
    canonical_event_ids = _canonical_event_ids(decision.get("event_ids"))
    event_ids_payload = json.dumps(canonical_event_ids, separators=(",", ":")) if canonical_event_ids else None
    key = (
        _analysis_key(decision["ip"], decision.get("source", "system"), canonical_event_ids)
        if canonical_event_ids is not None else None
    )
    with get_connection() as conn:
        if key is not None:
            existing = conn.execute(
                "SELECT decision_id FROM decisions WHERE analysis_key = ?", (key,)
            ).fetchone()
            if existing:
                return int(existing["decision_id"])
        cursor = conn.execute(
            """
            INSERT INTO decisions (ip, risk_score, risk_level, action, reasons, source, event_ids, analysis_key)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                decision["ip"],
                int(decision["risk_score"]),
                decision["risk_level"],
                decision["action"],
                reasons_payload,
                decision.get("source", "system"),
                event_ids_payload,
                key,
            ),
        )
        conn.commit()
    return int(cursor.lastrowid)


def get_user_by_id(user_id: int) -> dict[str, Any] | None:
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM users WHERE user_id = ?", (user_id,)).fetchone()
    return dict(row) if row else None


def get_order_by_id(order_id: int) -> dict[str, Any] | None:
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM orders WHERE order_id = ?", (order_id,)).fetchone()
    return dict(row) if row else None


def insert_notification(notification: dict[str, Any]) -> int | None:
    """Insert an in-app notification idempotently based on idempotency_key."""
    metadata_payload = json.dumps(notification.get("metadata", {}))
    with get_connection() as conn:
        try:
            cursor = conn.execute(
                """
                INSERT INTO notifications (
                    incident_id, title, message, severity, severity_band,
                    created_at, is_read, recipient, idempotency_key, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(notification["incident_id"]),
                    str(notification["title"]),
                    str(notification["message"]),
                    int(notification["severity"]),
                    str(notification["severity_band"]),
                    str(notification["created_at"]),
                    1 if notification.get("is_read") else 0,
                    str(notification.get("recipient", "soc-analyst")),
                    str(notification["idempotency_key"]),
                    metadata_payload,
                ),
            )
            conn.commit()
            return int(cursor.lastrowid)
        except sqlite3.IntegrityError:
            row = conn.execute(
                "SELECT notification_id FROM notifications WHERE idempotency_key = ?",
                (notification["idempotency_key"],),
            ).fetchone()
            return int(row["notification_id"]) if row else None


def get_notifications(
    limit: int = 50,
    offset: int = 0,
    unread_only: bool = False,
    severity_band: str | None = None,
) -> tuple[list[dict[str, Any]], int]:
    """Return paginated notifications and total count."""
    with get_connection() as conn:
        query = "SELECT * FROM notifications WHERE 1=1"
        params: list[Any] = []
        if unread_only:
            query += " AND is_read = 0"
        if severity_band:
            query += " AND UPPER(severity_band) = UPPER(?)"
            params.append(severity_band)

        count_query = f"SELECT COUNT(*) FROM ({query})"
        total = conn.execute(count_query, params).fetchone()[0]

        query += " ORDER BY notification_id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        rows = conn.execute(query, params).fetchall()

    items = []
    for r in rows:
        item = dict(r)
        item["is_read"] = bool(item["is_read"])
        item["metadata"] = json.loads(item["metadata"]) if item.get("metadata") else {}
        items.append(item)
    return items, total


def get_notification_by_id(notification_id: int) -> dict[str, Any] | None:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM notifications WHERE notification_id = ?",
            (notification_id,),
        ).fetchone()
    if not row:
        return None
    item = dict(row)
    item["is_read"] = bool(item["is_read"])
    item["metadata"] = json.loads(item["metadata"]) if item.get("metadata") else {}
    return item


def get_unread_notifications_count() -> int:
    with get_connection() as conn:
        row = conn.execute("SELECT COUNT(*) FROM notifications WHERE is_read = 0").fetchone()
    return int(row[0]) if row else 0


def mark_notification_read(notification_id: int) -> bool:
    with get_connection() as conn:
        cursor = conn.execute(
            "UPDATE notifications SET is_read = 1 WHERE notification_id = ?",
            (notification_id,),
        )
        conn.commit()
    return cursor.rowcount > 0


def mark_all_notifications_read() -> int:
    with get_connection() as conn:
        cursor = conn.execute("UPDATE notifications SET is_read = 1 WHERE is_read = 0")
        conn.commit()
    return cursor.rowcount


def insert_call_alert(call_alert: dict[str, Any]) -> int:
    """Insert a persisted outbound voice call record."""
    metadata_payload = json.dumps(call_alert.get("metadata", {}))
    with get_connection() as conn:
        cursor = conn.execute(
            """
            INSERT INTO call_alerts (
                call_sid, incident_id, notification_id, to_number, from_number,
                trigger_reason, status, severity, initiated_at, completed_at,
                duration, error_message, metadata
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(call_alert["call_sid"]),
                str(call_alert["incident_id"]),
                call_alert.get("notification_id"),
                str(call_alert["to_number"]),
                str(call_alert["from_number"]),
                str(call_alert["trigger_reason"]),
                str(call_alert.get("status", "queued")),
                int(call_alert.get("severity", 80)),
                str(call_alert["initiated_at"]),
                call_alert.get("completed_at"),
                call_alert.get("duration"),
                call_alert.get("error_message"),
                metadata_payload,
            ),
        )
        conn.commit()
    return int(cursor.lastrowid)


def update_call_alert_status(
    call_sid: str,
    status: str,
    duration: int | None = None,
    completed_at: str | None = None,
    error_message: str | None = None,
) -> bool:
    with get_connection() as conn:
        updates = ["status = ?"]
        params: list[Any] = [status]
        if duration is not None:
            updates.append("duration = ?")
            params.append(duration)
        if completed_at is not None:
            updates.append("completed_at = ?")
            params.append(completed_at)
        if error_message is not None:
            updates.append("error_message = ?")
            params.append(error_message)

        params.append(call_sid)
        query = f"UPDATE call_alerts SET {', '.join(updates)} WHERE call_sid = ?"
        cursor = conn.execute(query, params)
        conn.commit()
    return cursor.rowcount > 0


def get_call_alerts(
    limit: int = 50,
    offset: int = 0,
    incident_id: str | None = None,
) -> tuple[list[dict[str, Any]], int]:
    with get_connection() as conn:
        query = "SELECT * FROM call_alerts WHERE 1=1"
        params: list[Any] = []
        if incident_id:
            query += " AND incident_id = ?"
            params.append(incident_id)

        count_query = f"SELECT COUNT(*) FROM ({query})"
        total = conn.execute(count_query, params).fetchone()[0]

        query += " ORDER BY call_id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        rows = conn.execute(query, params).fetchall()

    items = []
    for r in rows:
        item = dict(r)
        item["metadata"] = json.loads(item["metadata"]) if item.get("metadata") else {}
        items.append(item)
    return items, total


def get_call_alert_by_sid(call_sid: str) -> dict[str, Any] | None:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM call_alerts WHERE call_sid = ?",
            (call_sid,),
        ).fetchone()
    if not row:
        return None
    item = dict(row)
    item["metadata"] = json.loads(item["metadata"]) if item.get("metadata") else {}
    return item


def get_call_alert_by_id(call_id: int) -> dict[str, Any] | None:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM call_alerts WHERE call_id = ?",
            (call_id,),
        ).fetchone()
    if not row:
        return None
    item = dict(row)
    item["metadata"] = json.loads(item["metadata"]) if item.get("metadata") else {}
    return item


def get_last_call_for_incident(incident_id: str) -> dict[str, Any] | None:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM call_alerts WHERE incident_id = ? ORDER BY call_id DESC LIMIT 1",
            (incident_id,),
        ).fetchone()
    if not row:
        return None
    item = dict(row)
    item["metadata"] = json.loads(item["metadata"]) if item.get("metadata") else {}
    return item


def get_calls_for_incident(incident_id: str) -> list[dict[str, Any]]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM call_alerts WHERE incident_id = ? ORDER BY call_id ASC",
            (incident_id,),
        ).fetchall()
    items = []
    for r in rows:
        item = dict(r)
        item["metadata"] = json.loads(item["metadata"]) if item.get("metadata") else {}
        items.append(item)
    return items


init_db()
