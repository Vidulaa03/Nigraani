import json
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

import backend.analyzer as analyzer
import backend.database as database
import backend.main as main
import backend.security_logger as security_logger
from backend.detection import multi_rate_detector
from backend.detection.base import sample_event
from backend.incident_evidence import get_incident_evidence

START = datetime(2026, 10, 1, tzinfo=timezone.utc)


def events(count, *, seconds_apart, ip="198.51.100.5", **overrides):
    built = []
    for i in range(count):
        fields = {
            "event_id": i + 1,
            "timestamp": (START + timedelta(seconds=i * seconds_apart)).isoformat(),
            "ip": ip,
            "user_id": None,
            "resource_id": None,
            "resource_owner_id": None,
            "endpoint": "/",
            "endpoint_pattern": "/",
        }
        fields.update({k: (v(i) if callable(v) else v) for k, v in overrides.items()})
        built.append(sample_event(**fields))
    return built


def test_normal_traffic_and_single_signals_do_not_alert():
    assert multi_rate_detector.detect(events(8, seconds_apart=5)) == []
    # A burst alone (the rate detector's job) is one signal: no detection.
    assert multi_rate_detector.detect(events(30, seconds_apart=0.1)) == []


def test_two_signals_produce_an_explainable_detection():
    traffic = events(
        45,
        seconds_apart=1.1,
        user_id=101,
        endpoint=lambda i: f"/api/orders/{501 if i % 2 else 502}",
        endpoint_pattern="/api/orders/{order_id}",
    )

    (detection,) = multi_rate_detector.detect(traffic)

    assert detection["detector"] == "multi_rate_detector"
    assert detection["severity"] == 40
    assert detection["user_id"] == 101
    assert detection["owasp"] == "API4:2023"
    assert detection["evidence"].startswith("2 rate signals: ")
    assert "ip_rate: 45 requests" in detection["evidence"]
    assert "user_endpoint_rate: user 101 sent 45 requests to /api/orders/{order_id}" in detection["evidence"]
    assert detection["event_ids"] == list(range(1, 46))


def test_scanning_combines_failures_diversity_and_burst():
    traffic = events(
        15,
        seconds_apart=0.2,
        endpoint=lambda i: f"/admin/probe-{i}",
        endpoint_pattern=lambda i: f"/admin/probe-{i}",
        status_code=404,
    )

    (detection,) = multi_rate_detector.detect(traffic)

    assert detection["severity"] == 55
    for signal in ("failed_ratio: 15/15", "endpoint_diversity: 15", "burst: 15"):
        assert signal in detection["evidence"]


def test_end_to_end_api_spool_analyzer_detection_and_risk_decision(monkeypatch):
    monkeypatch.setattr(analyzer, "_RECENT_EVENTS_BY_IP", {})
    monkeypatch.setattr(analyzer, "score_anomalies", lambda events: 0)
    attacker = {"X-Forwarded-For": "198.51.100.77", "X-User-ID": "102", "X-Sim-Label": "enumeration"}
    http = TestClient(main.app, client=("127.0.0.1", 1))

    # The database fails for the first five requests: they go to the spool.
    real_insert = security_logger.insert_event
    calls = {"n": 0}

    def failing_then_ok(event, **kwargs):
        calls["n"] += 1
        if calls["n"] <= 5:
            raise sqlite3.OperationalError("database is locked")
        return real_insert(event, **kwargs)

    monkeypatch.setattr(security_logger, "insert_event", failing_then_ok)
    for i in range(25):
        assert http.get(f"/api/orders/{9000 + 7 * i}", headers=attacker).status_code == 404
    assert len(database.get_events_since()) == 20  # 5 are waiting in the spool

    analyzer.run_loop(interval_seconds=0, stop_after=1)  # replays, then analyzes

    stored = database.get_events_since()
    assert len(stored) == 25
    with database.get_connection() as conn:
        detection = dict(conn.execute(
            "SELECT * FROM detections WHERE detector = 'multi_rate_detector'"
        ).fetchone())
        decision = dict(conn.execute(
            "SELECT * FROM decisions WHERE ip = '198.51.100.77'"
        ).fetchone())

    assert detection["ip"] == "198.51.100.77"
    assert sorted(json.loads(detection["event_ids"])) == sorted(e["event_id"] for e in stored)
    for signal in ("user_endpoint_rate: user 102", "failed_ratio: 25/25", "endpoint_diversity: 25"):
        assert signal in detection["evidence"]
    assert decision["action"] in {"THROTTLE", "BLOCK"}
    assert "multi_rate_detector" in decision["reasons"]

    evidence = get_incident_evidence(detection["detection_id"])
    assert evidence["event_reference_status"] == "complete"
    assert len(evidence["linked_events"]) == 25
    assert analyzer.load_analyzer_state().pending_event_ids == set()
