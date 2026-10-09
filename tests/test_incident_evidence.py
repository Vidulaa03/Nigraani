import json
import sqlite3

import pytest

import backend.database as database
import backend.incident_evidence as incident_evidence
from backend.database import init_db, insert_decision, insert_detection, insert_event


def _event(event_id: int, **overrides):
    event = {
        "event_id": event_id,
        "timestamp": f"2026-10-09T12:00:{event_id:02d}+00:00",
        "ip": "192.0.2.10",
        "user_id": None,
        "method": "GET",
        "endpoint": "/api/orders/501",
        "endpoint_pattern": "/api/orders/{order_id}",
        "resource_id": 501,
        "resource_owner_id": 101,
        "status_code": 200,
        "response_time_ms": 12.0,
        "sim_label": "bola",
    }
    event.update(overrides)
    return event


def _detection(**overrides):
    detection = {
        "detector": "bola_detector",
        "attack_type": "BOLA/IDOR",
        "severity": 90,
        "ip": "192.0.2.10",
        "user_id": 101,
        "evidence": "Accessed foreign resource 501",
        "event_ids": [1, 2],
        "owasp": "API1:2023",
    }
    detection.update(overrides)
    return detection


def _init_test_db(monkeypatch, tmp_path):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "incidents.db")
    init_db()


def test_retrieves_saved_detection_and_only_its_real_events(
    monkeypatch,
    tmp_path,
):
    _init_test_db(monkeypatch, tmp_path)
    first_event_id = insert_event(_event(1))
    second_event_id = insert_event(
        _event(
            2,
            timestamp="2026-10-09T12:00:03+00:00",
            endpoint="/api/orders/502?token=private",
        )
    )
    insert_event(_event(3, ip="192.0.2.99", endpoint="/unrelated"))
    detection_id = insert_detection(_detection())
    with database.get_connection() as conn:
        decision_columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(decisions)")
        }
        if "event_ids" not in decision_columns:
            conn.execute("ALTER TABLE decisions ADD COLUMN event_ids TEXT")
        conn.commit()
    decision_id = insert_decision(
        {
            "ip": "192.0.2.10",
            "risk_score": 100,
            "risk_level": "BLOCK",
            "action": "BLOCK",
            "reasons": ["Authorization: Bearer private-value"],
            "source": "analyzer",
            "event_ids": [first_event_id, second_event_id],
        }
    )
    with database.get_connection() as conn:
        conn.execute(
            "UPDATE decisions SET event_ids = ? WHERE decision_id = ?",
            (json.dumps([first_event_id, second_event_id]), decision_id),
        )
        conn.commit()

    payload = incident_evidence.get_incident_evidence(detection_id)

    assert payload is not None
    assert payload["incident_id"] == f"detection:{detection_id}"
    assert payload["detection_id"] == detection_id
    assert payload["detector"] == "bola_detector"
    assert payload["attack_type"] == "BOLA/IDOR"
    assert payload["severity"] == 90
    assert payload["risk_score"] == 100
    assert payload["action"] == "BLOCK"
    assert payload["event_ids"] == [first_event_id, second_event_id]
    assert {event["event_id"] for event in payload["linked_events"]} == {
        first_event_id,
        second_event_id,
    }
    assert payload["event_reference_status"] == "complete"
    assert payload["endpoint_pattern"] == "/api/orders/{order_id}"
    assert payload["owasp_mapping"] == ["API1:2023"]
    assert payload["time_window"] == {
        "start": "2026-10-09T12:00:01+00:00",
        "end": "2026-10-09T12:00:03+00:00",
    }
    assert payload["linked_events"][1]["endpoint"] == "/api/orders/502"
    assert payload["risk_reasons"] == [
        "Authorization: [REDACTED]",
    ]
    assert all("sim_label" not in event for event in payload["linked_events"])
    assert "private" not in json.dumps(payload)


def test_missing_detection_returns_none(monkeypatch, tmp_path):
    _init_test_db(monkeypatch, tmp_path)

    assert incident_evidence.get_incident_evidence(999) is None


def test_detection_without_events_returns_optional_fields_as_empty_or_null(
    monkeypatch,
    tmp_path,
):
    _init_test_db(monkeypatch, tmp_path)
    detection_id = insert_detection(
        _detection(event_ids=[], user_id=None, owasp="")
    )

    payload = incident_evidence.get_incident_evidence(detection_id)

    assert payload is not None
    assert payload["event_ids"] == []
    assert payload["event_reference_status"] == "empty"
    assert payload["linked_events"] == []
    assert payload["client"]["ip_address"] == "192.0.2.10"
    assert payload["endpoint_pattern"] is None
    assert payload["risk_score"] is None
    assert payload["action"] is None
    assert payload["owasp_mapping"] == []
    assert payload["time_window"] == {"start": None, "end": None}


def test_missing_and_invalid_event_references_are_reported_without_substitution(
    monkeypatch,
    tmp_path,
):
    _init_test_db(monkeypatch, tmp_path)
    insert_event(_event(1))
    with database.get_connection() as conn:
        conn.execute(
            """
            INSERT INTO detections (
                detector, attack_type, severity, ip, evidence, event_ids, owasp
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "rate_detector",
                "Rate Spike",
                50,
                "192.0.2.10",
                "30 requests observed",
                json.dumps([1, 999, "not-an-id", "9" * 100, 2**63]),
                "API4:2023",
            ),
        )
        detection_id = int(conn.execute("SELECT last_insert_rowid()").fetchone()[0])
        conn.commit()

    payload = incident_evidence.get_incident_evidence(detection_id)

    assert payload is not None
    assert payload["event_ids"] == [1]
    assert [event["event_id"] for event in payload["linked_events"]] == [1]
    assert payload["unresolved_event_ids"] == [999]
    assert payload["invalid_event_reference_count"] == 3
    assert payload["event_reference_status"] == "invalid"


def test_retrieval_does_not_modify_detection_or_event_records(
    monkeypatch,
    tmp_path,
):
    _init_test_db(monkeypatch, tmp_path)
    insert_event(_event(1))
    detection_id = insert_detection(_detection(event_ids=[1]))
    with database.get_connection() as conn:
        detection_before = tuple(
            conn.execute(
                "SELECT * FROM detections WHERE detection_id = ?",
                (detection_id,),
            ).fetchone()
        )
        event_before = tuple(
            conn.execute(
                "SELECT * FROM security_events WHERE event_id = 1"
            ).fetchone()
        )

    incident_evidence.get_incident_evidence(detection_id)

    with database.get_connection() as conn:
        detection_after = tuple(
            conn.execute(
                "SELECT * FROM detections WHERE detection_id = ?",
                (detection_id,),
            ).fetchone()
        )
        event_after = tuple(
            conn.execute(
                "SELECT * FROM security_events WHERE event_id = 1"
            ).fetchone()
        )
    assert detection_after == detection_before
    assert event_after == event_before


def test_database_errors_are_wrapped_without_sql_details(monkeypatch):
    def fail_to_connect():
        raise sqlite3.OperationalError("private database path")

    monkeypatch.setattr(incident_evidence, "get_connection", fail_to_connect)

    with pytest.raises(
        incident_evidence.IncidentEvidenceDatabaseError,
        match="Unable to retrieve incident evidence from the database",
    ) as error:
        incident_evidence.get_incident_evidence(1)

    assert "private database path" not in str(error.value)
