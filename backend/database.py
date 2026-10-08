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
        "name": "Riya",
        "email": "riya@example.com",
    },
    105: {
        "name": "Aarav",
        "email": "aarav@example.com",
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
                owasp TEXT NOT NULL DEFAULT 'API1:2023'
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
                source TEXT NOT NULL DEFAULT 'system'
            )
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


def get_events_since(last_event_id: int | None = None, limit: int | None = None) -> list[dict[str, Any]]:
    with get_connection() as conn:
        query = "SELECT * FROM security_events"
        params: list[Any] = []
        if last_event_id is not None:
            query += " WHERE event_id > ?"
            params.append(last_event_id)
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
    if "event_ids" in detection and not isinstance(detection["event_ids"], str):
        evidence_payload = json.dumps(detection["event_ids"])
    else:
        evidence_payload = detection.get("event_ids", "[]")

    with get_connection() as conn:
        cursor = conn.execute(
            """
            INSERT INTO detections (
                detector, attack_type, severity, ip, user_id, evidence, event_ids, owasp
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
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
            ),
        )
        conn.commit()
    return int(cursor.lastrowid)


def insert_decision(decision: dict[str, Any]) -> int:
    reasons_payload = json.dumps(decision.get("reasons", []))
    with get_connection() as conn:
        cursor = conn.execute(
            """
            INSERT INTO decisions (ip, risk_score, risk_level, action, reasons, source)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                decision["ip"],
                int(decision["risk_score"]),
                decision["risk_level"],
                decision["action"],
                reasons_payload,
                decision.get("source", "system"),
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


init_db()