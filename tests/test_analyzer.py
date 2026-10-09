import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import backend.database as database
import ml.anomaly_detector as anomaly_detector
from backend.analyzer import process_new_events
from backend.database import get_connection, init_db, insert_event
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
