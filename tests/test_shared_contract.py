import json
from pathlib import Path

import backend.database as database
from backend.database import (
    get_connection,
    get_events_since,
    init_db,
    insert_decision,
    insert_detection,
    insert_event,
)
from backend.detection.base import build_detection, validate_event


def test_event_contract_is_valid_for_sample_data():
    events = json.loads(Path("tests/sample_events.json").read_text(encoding="utf-8"))

    for event in events:
        validate_event(event)


def test_database_seeds_five_users_and_forty_orders(monkeypatch, tmp_path):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "demo.db")
    init_db()

    with get_connection() as conn:
        assert conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 5
        assert conn.execute("SELECT COUNT(*) FROM orders").fetchone()[0] == 40
        order_counts = conn.execute(
            "SELECT owner_id, COUNT(*) AS order_count FROM orders GROUP BY owner_id"
        ).fetchall()

    assert {row["owner_id"]: row["order_count"] for row in order_counts} == {
        user_id: 8 for user_id in database.USERS
    }


def test_database_helpers_persist_and_read_back_rows(monkeypatch, tmp_path):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "demo.db")
    init_db()
    event = {
        "event_id": 999,
        "timestamp": "2026-10-08T12:00:00.000Z",
        "ip": "10.0.0.99",
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

    event_id = insert_event(event)
    assert event_id == event["event_id"]
    assert get_events_since(event_id - 1) == [event]

    detection = build_detection(
        detector="bola",
        attack_type="BOLA/IDOR",
        severity=90,
        ip="10.0.0.99",
        user_id=101,
        event_ids=[event_id],
        evidence="User 101 accessed order 501 without permission",
    )
    detection_id = insert_detection(detection)
    assert detection_id > 0
    with get_connection() as conn:
        stored_detection = conn.execute(
            "SELECT detector, attack_type, severity, ip, user_id, evidence, event_ids, owasp "
            "FROM detections WHERE detection_id = ?",
            (detection_id,),
        ).fetchone()
    assert dict(stored_detection) == {
        "detector": "bola",
        "attack_type": "BOLA/IDOR",
        "severity": 90,
        "ip": "10.0.0.99",
        "user_id": 101,
        "evidence": "User 101 accessed order 501 without permission",
        "event_ids": json.dumps([event_id]),
        "owasp": "API1:2023",
    }

    decision_id = insert_decision(
        {
            "ip": "10.0.0.99",
            "risk_score": 90,
            "risk_level": "BLOCK",
            "action": "BLOCK",
            "reasons": ["BOLA severity 90"],
            "source": "test",
        }
    )
    assert decision_id > 0
    with get_connection() as conn:
        stored_decision = conn.execute(
            "SELECT ip, risk_score, risk_level, action, reasons, source "
            "FROM decisions WHERE decision_id = ?",
            (decision_id,),
        ).fetchone()
    assert dict(stored_decision) == {
        "ip": "10.0.0.99",
        "risk_score": 90,
        "risk_level": "BLOCK",
        "action": "BLOCK",
        "reasons": json.dumps(["BOLA severity 90"]),
        "source": "test",
    }
