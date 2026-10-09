import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import backend.database as database
import backend.analyzer as analyzer
import ml.anomaly_detector as anomaly_detector
from backend.analyzer import process_new_events
from backend.database import (
    get_connection,
    init_db,
    insert_decision,
    insert_detection,
    insert_event,
)
from ml.train_model import train_model


def _normal_training_events():
    events = []
    event_id = 1
    start_time = datetime(2026, 10, 1, tzinfo=timezone.utc)
    for window_number in range(30):
        request_count = 3 + window_number % 5
        for request_number in range(request_count):
            user_id = 101 + window_number % 5
            login = (window_number + 1) % 9 == 0 and request_number == request_count - 1
            route_type = "login" if login else ("home", "user", "order")[request_number % 3]
            endpoint = {
                "login": "/api/auth/login",
                "home": "/",
                "user": f"/api/users/{user_id}",
                "order": f"/api/orders/{501 + window_number % 40}",
            }[route_type]
            timestamp = start_time + timedelta(
                seconds=30 * window_number + 10 + request_number * 0.25,
            )
            events.append(
                {
                    "event_id": event_id,
                    "timestamp": timestamp.isoformat(),
                    "ip": "10.1.0.1",
                    "user_id": user_id,
                    "method": "POST" if endpoint == "/api/auth/login" else "GET",
                    "endpoint": endpoint,
                    "endpoint_pattern": (
                        "/api/auth/login"
                        if endpoint == "/api/auth/login"
                        else (
                            "/api/users/{user_id}"
                            if endpoint.startswith("/api/users/")
                            else "/api/orders/{order_id}"
                            if endpoint.startswith("/api/orders/")
                            else "/"
                        )
                    ),
                    "resource_id": (
                        user_id
                        if endpoint.startswith("/api/users/")
                        else 501 + window_number % 40
                        if endpoint.startswith("/api/orders/")
                        else None
                    ),
                    "resource_owner_id": (
                        user_id
                        if endpoint.startswith(("/api/users/", "/api/orders/"))
                        else None
                    ),
                    "status_code": (
                        401
                        if endpoint == "/api/auth/login" and window_number % 18 == 0
                        else 200
                    ),
                    "response_time_ms": 20 + (window_number * 7 + request_number * 3) % 35,
                    "sim_label": "normal",
                }
            )
            event_id += 1
    return events


def test_analyzer_processes_recent_sample_events_and_persists_results(
    monkeypatch,
    tmp_path,
):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "demo.db")
    model_path = tmp_path / "models" / "iforest.joblib"
    monkeypatch.setattr(anomaly_detector, "MODEL_PATH", model_path)
    train_model(_normal_training_events(), model_path)
    init_db()
    sample_events = json.loads(
        Path("tests/sample_events.json").read_text(encoding="utf-8")
    )
    start_time = datetime.now(timezone.utc) - timedelta(seconds=10)

    for index, event in enumerate(sample_events):
        event["timestamp"] = (
            start_time + timedelta(milliseconds=index * 200)
        ).isoformat()
        insert_event(event)

    last_event_id = process_new_events()

    assert last_event_id == max(event["event_id"] for event in sample_events)
    with get_connection() as conn:
        detections = conn.execute(
            "SELECT detector, severity, ip FROM detections"
        ).fetchall()
        decisions = conn.execute(
            "SELECT ip, risk_score, risk_level, action FROM decisions"
        ).fetchall()

    detection_rows = [dict(row) for row in detections]
    decision_rows = {row["ip"]: dict(row) for row in decisions}
    assert any(
        row["detector"] == "login_failure_detector" and row["ip"] == "10.0.0.3"
        for row in detection_rows
    )
    assert any(
        row["detector"] == "bola_detector"
        and row["severity"] == 90
        and row["ip"] == "10.0.0.4"
        for row in detection_rows
    )
    assert decision_rows["10.0.0.3"]["risk_score"] >= 50
    assert decision_rows["10.0.0.3"]["action"] in {"MONITOR", "THROTTLE"}
    assert decision_rows["10.0.0.4"]["risk_score"] >= 90
    assert decision_rows["10.0.0.4"]["action"] == "BLOCK"

    assert process_new_events(last_event_id) == last_event_id
    with get_connection() as conn:
        assert conn.execute("SELECT COUNT(*) FROM decisions").fetchone()[0] == len(
            decision_rows
        )


def test_analysis_inserts_are_idempotent_and_keep_distinct_detector_identity(
    monkeypatch,
    tmp_path,
):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "demo.db")
    init_db()

    detection = {
        "detector": "login_failure_detector",
        "attack_type": "Brute Force / Credential Guessing",
        "severity": 80,
        "ip": "10.0.0.50",
        "user_id": None,
        "evidence": "Five failed logins",
        "event_ids": [10, 11, 12, 13, 14],
    }
    original_detection_id = insert_detection(detection)
    replayed_detection_id = insert_detection(
        {**detection, "event_ids": [14, 13, 12, 11, 10]}
    )
    other_detector_id = insert_detection(
        {**detection, "detector": "credential_detector"}
    )
    other_window_id = insert_detection(
        {**detection, "event_ids": [11, 12, 13, 14, 15]}
    )

    decision = {
        "ip": "10.0.0.50",
        "risk_score": 80,
        "risk_level": "BLOCK",
        "action": "BLOCK",
        "reasons": ["Brute force detected"],
        "source": "analyzer",
        "event_ids": [10, 11, 12, 13, 14],
    }
    original_decision_id = insert_decision(decision)
    replayed_decision_id = insert_decision(
        {**decision, "event_ids": [14, 13, 12, 11, 10]}
    )
    other_window_decision_id = insert_decision(
        {**decision, "event_ids": [11, 12, 13, 14, 15]}
    )

    assert replayed_detection_id == original_detection_id
    assert other_detector_id != original_detection_id
    assert other_window_id not in {original_detection_id, other_detector_id}
    assert replayed_decision_id == original_decision_id
    assert other_window_decision_id != original_decision_id
    with get_connection() as conn:
        assert conn.execute("SELECT COUNT(*) FROM detections").fetchone()[0] == 3
        assert conn.execute("SELECT COUNT(*) FROM decisions").fetchone()[0] == 2


def test_init_db_adds_idempotency_columns_without_losing_existing_rows(
    monkeypatch,
    tmp_path,
):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "legacy.db")
    with get_connection() as conn:
        conn.execute(
            """
            CREATE TABLE detections (
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
            CREATE TABLE decisions (
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
        conn.execute(
            """
            INSERT INTO detections (
                detector, attack_type, severity, ip, evidence, event_ids
            ) VALUES ('login_failure_detector', 'Brute Force', 80, '10.0.0.1',
                      'Five failures', '[1,2,3,4,5]')
            """
        )
        conn.execute(
            """
            INSERT INTO decisions (ip, risk_score, risk_level, action, reasons, source)
            VALUES ('10.0.0.1', 80, 'BLOCK', 'BLOCK', '[]', 'analyzer')
            """
        )

    init_db()

    with get_connection() as conn:
        detection = conn.execute("SELECT * FROM detections").fetchone()
        decision = conn.execute("SELECT * FROM decisions").fetchone()
        detection_columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(detections)")
        }
        decision_columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(decisions)")
        }
        assert conn.execute("SELECT COUNT(*) FROM detections").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM decisions").fetchone()[0] == 1
        assert detection["event_ids"] == "[1,2,3,4,5]"
        assert decision["action"] == "BLOCK"
        assert {"analysis_key"} <= detection_columns
        assert {"event_ids", "analysis_key"} <= decision_columns


def test_reprocessing_same_event_window_does_not_duplicate_records(
    monkeypatch,
    tmp_path,
):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "demo.db")
    monkeypatch.setattr(anomaly_detector, "MODEL_PATH", tmp_path / "missing.joblib")
    monkeypatch.setattr(analyzer, "_RECENT_EVENTS_BY_IP", {})
    monkeypatch.setattr(analyzer, "score_anomalies", lambda events: 0)
    init_db()

    start_time = datetime.now(timezone.utc) - timedelta(seconds=5)
    for event_id in range(1, 6):
        insert_event(
            {
                "event_id": event_id,
                "timestamp": (
                    start_time + timedelta(milliseconds=event_id)
                ).isoformat(),
                "ip": "10.0.0.50",
                "method": "POST",
                "endpoint": "/api/auth/login",
                "endpoint_pattern": "/api/auth/{action}",
                "status_code": 401,
                "response_time_ms": 10.0,
                "sim_label": "normal",
            }
        )

    process_new_events()
    analyzer._RECENT_EVENTS_BY_IP = {}
    process_new_events()

    with get_connection() as conn:
        assert conn.execute("SELECT COUNT(*) FROM security_events").fetchone()[0] == 5
        assert conn.execute("SELECT COUNT(*) FROM detections").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM decisions").fetchone()[0] == 1
