import json
from pathlib import Path

from backend.database import init_db, insert_decision, insert_detection, insert_event
from backend.detection.base import build_detection, validate_event


def test_event_contract_is_valid_for_sample_data():
    events = json.loads(Path("tests/sample_events.json").read_text(encoding="utf-8"))

    for event in events:
        validate_event(event)


def test_database_helpers_persist_rows():
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
    assert event_id > 0

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
