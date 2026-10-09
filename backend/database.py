import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any

from backend.detection.base import validate_event

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "demo.db"

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


def _analysis_key(*parts: Any) -> str:
    payload = json.dumps(parts, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _canonical_event_ids(event_ids: Any) -> list[int] | None:
    if not isinstance(event_ids, list) or not event_ids:
        return None
    try:
        return sorted({int(event_id) for event_id in event_ids})
    except (TypeError, ValueError):
        return None


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

        detection_columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(detections)")
        }
        if "analysis_key" not in detection_columns:
            conn.execute("ALTER TABLE detections ADD COLUMN analysis_key TEXT")

        decision_columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(decisions)")
        }
        if "event_ids" not in decision_columns:
            conn.execute("ALTER TABLE decisions ADD COLUMN event_ids TEXT")
        if "analysis_key" not in decision_columns:
            conn.execute("ALTER TABLE decisions ADD COLUMN analysis_key TEXT")

        conn.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_detections_analysis_key
            ON detections (analysis_key)
            WHERE analysis_key IS NOT NULL
            """
        )
        conn.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_decisions_analysis_key
            ON decisions (analysis_key)
            WHERE analysis_key IS NOT NULL
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
    if isinstance(event_ids, str):
        try:
            parsed_event_ids = json.loads(event_ids)
        except json.JSONDecodeError:
            parsed_event_ids = event_ids
    else:
        parsed_event_ids = event_ids
    evidence_payload = (
        event_ids if isinstance(event_ids, str) else json.dumps(event_ids)
    )
    canonical_event_ids = _canonical_event_ids(parsed_event_ids)
    key = (
        _analysis_key(
            detection["detector"],
            detection["attack_type"],
            detection["ip"],
            detection.get("user_id"),
            canonical_event_ids,
        )
        if canonical_event_ids is not None
        else None
    )

    with get_connection() as conn:
        if key is not None:
            existing = conn.execute(
                "SELECT detection_id FROM detections WHERE analysis_key = ?",
                (key,),
            ).fetchone()
            if existing is not None:
                return int(existing["detection_id"])

            legacy_rows = conn.execute(
                """
                SELECT detection_id, event_ids FROM detections
                WHERE detector = ? AND ip = ? AND attack_type = ?
                  AND user_id IS ? AND analysis_key IS NULL
                ORDER BY detection_id ASC
                """,
                (
                    detection["detector"],
                    detection["ip"],
                    detection["attack_type"],
                    detection.get("user_id"),
                ),
            ).fetchall()
            for row in legacy_rows:
                try:
                    existing_event_ids = json.loads(row["event_ids"])
                except json.JSONDecodeError:
                    existing_event_ids = row["event_ids"]
                if _canonical_event_ids(existing_event_ids) == canonical_event_ids:
                    return int(row["detection_id"])

        conn.execute(
            """
            INSERT OR IGNORE INTO detections (
                detector, attack_type, severity, ip, user_id, evidence, event_ids,
                owasp, analysis_key
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
        if key is None:
            return int(conn.execute("SELECT last_insert_rowid()").fetchone()[0])
        row = conn.execute(
            "SELECT detection_id FROM detections WHERE analysis_key = ?",
            (key,),
        ).fetchone()
    if row is None:
        raise RuntimeError("Detection insert did not create or find a record.")
    return int(row["detection_id"])


def insert_decision(decision: dict[str, Any]) -> int:
    reasons_payload = json.dumps(decision.get("reasons", []))
    event_ids = decision.get("event_ids")
    canonical_event_ids = _canonical_event_ids(event_ids)
    event_ids_payload = (
        json.dumps(canonical_event_ids, separators=(",", ":"))
        if canonical_event_ids is not None
        else None
    )
    key = (
        _analysis_key(
            decision["ip"],
            decision.get("source", "system"),
            canonical_event_ids,
        )
        if canonical_event_ids is not None
        else None
    )
    with get_connection() as conn:
        if key is not None:
            existing = conn.execute(
                "SELECT decision_id FROM decisions WHERE analysis_key = ?",
                (key,),
            ).fetchone()
            if existing is not None:
                return int(existing["decision_id"])

        conn.execute(
            """
            INSERT OR IGNORE INTO decisions (
                ip, risk_score, risk_level, action, reasons, source, event_ids, analysis_key
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
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
        if key is None:
            return int(conn.execute("SELECT last_insert_rowid()").fetchone()[0])
        row = conn.execute(
            "SELECT decision_id FROM decisions WHERE analysis_key = ?",
            (key,),
        ).fetchone()
    if row is None:
        raise RuntimeError("Decision insert did not create or find a record.")
    return int(row["decision_id"])


def get_user_by_id(user_id: int) -> dict[str, Any] | None:
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM users WHERE user_id = ?", (user_id,)).fetchone()
    return dict(row) if row else None


def get_order_by_id(order_id: int) -> dict[str, Any] | None:
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM orders WHERE order_id = ?", (order_id,)).fetchone()
    return dict(row) if row else None


init_db()