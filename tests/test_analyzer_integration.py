from unittest.mock import Mock

import pytest

from backend import analyzer
from backend.detection.risk_engine import compute_risk


def test_analyzer_imports_from_project_package():
    assert analyzer.__name__ == "backend.analyzer"


def test_process_new_events_orchestrates_detectors_and_risk_engine(monkeypatch):
    events = [
        {
            "event_id": 1,
            "timestamp": "2026-10-08T22:30:00.000Z",
            "ip": "10.0.0.1",
            "user_id": 101,
            "method": "GET",
            "endpoint": "/api/items/1",
            "endpoint_pattern": "/api/items/{item_id}",
            "resource_id": 1,
            "resource_owner_id": 101,
            "status_code": 200,
            "response_time_ms": 10.0,
            "sim_label": "normal",
        }
    ]
    detections = [
        {
            "detector": "login_failure",
            "attack_type": "Brute Force / Credential Guessing",
            "severity": 80,
            "ip": "10.0.0.1",
            "user_id": 101,
            "evidence": "login integration detection",
            "event_ids": [1],
        },
        {
            "detector": "rate_spike",
            "attack_type": "API Rate Spike",
            "severity": 50,
            "ip": "10.0.0.1",
            "user_id": 101,
            "evidence": "rate integration detection",
            "event_ids": [1],
        },
        {
            "detector": "enumeration",
            "attack_type": "Resource Enumeration",
            "severity": 65,
            "ip": "10.0.0.1",
            "user_id": 101,
            "evidence": "enumeration integration detection",
            "event_ids": [1],
        },
        {
            "detector": "bola",
            "attack_type": "BOLA/IDOR",
            "severity": 70,
            "ip": "10.0.0.1",
            "user_id": 101,
            "evidence": "BOLA integration detection",
            "event_ids": [1],
        },
    ]
    detector_mocks = [
        Mock(return_value=[detection])
        for detection in detections
    ]
    monkeypatch.setattr(
        analyzer.login_failure_detector,
        "detect",
        detector_mocks[0],
    )
    monkeypatch.setattr(
        analyzer.rate_detector,
        "detect",
        detector_mocks[1],
    )
    monkeypatch.setattr(
        analyzer.enumeration_detector,
        "detect",
        detector_mocks[2],
    )
    monkeypatch.setattr(
        analyzer.bola_detector,
        "detect",
        detector_mocks[3],
    )

    persisted_detections = []
    persisted_decisions = []
    monkeypatch.setattr(
        analyzer,
        "get_events_since",
        lambda **kwargs: events,
    )
    monkeypatch.setattr(
        analyzer,
        "insert_detection",
        lambda detection: persisted_detections.append(detection),
    )
    monkeypatch.setattr(
        analyzer,
        "insert_decision",
        lambda decision: persisted_decisions.append(decision),
    )
    monkeypatch.setattr(analyzer, "score_anomalies", lambda events: 0)
    risk_engine_spy = Mock(wraps=compute_risk)
    monkeypatch.setattr(analyzer, "compute_risk", risk_engine_spy)

    last_event_id = analyzer.process_new_events()

    for detector_mock in detector_mocks:
        detector_mock.assert_called_once_with(events)
    risk_engine_spy.assert_called_once_with(detections, 0)
    assert last_event_id == 1
    assert persisted_detections == detections
    assert len(persisted_decisions) == 1
    assert persisted_decisions[0]["risk_score"] == 100
    assert persisted_decisions[0]["risk_level"] == "BLOCK"
    assert persisted_decisions[0]["action"] == "BLOCK"
    assert "login_failure" in persisted_decisions[0]["reasons"][0]
    assert "rate_spike" in persisted_decisions[0]["reasons"][0]
    assert "enumeration" in persisted_decisions[0]["reasons"][0]
    assert "bola" in persisted_decisions[0]["reasons"][0]


def test_polling_same_event_snapshot_does_not_duplicate_processing(monkeypatch):
    events = [
        {
            "event_id": 42,
            "timestamp": "2026-10-08T22:30:00.000Z",
            "ip": "10.0.0.42",
            "user_id": 101,
            "method": "POST",
            "endpoint": "/api/auth/login",
            "endpoint_pattern": "/api/auth/{action}",
            "resource_id": None,
            "resource_owner_id": None,
            "status_code": 401,
            "response_time_ms": 10.0,
            "sim_label": "normal",
        }
    ]
    detection = {
        "detector": "login_failure",
        "attack_type": "Brute Force / Credential Guessing",
        "severity": 50,
        "ip": "10.0.0.42",
        "user_id": 101,
        "evidence": "five failed login attempts",
        "event_ids": [42],
    }
    login_detector = Mock(return_value=[detection])
    monkeypatch.setattr(
        analyzer.login_failure_detector,
        "detect",
        login_detector,
    )
    for detector in (
        analyzer.rate_detector,
        analyzer.enumeration_detector,
        analyzer.bola_detector,
    ):
        monkeypatch.setattr(detector, "detect", Mock(return_value=[]))

    persisted_detections = []
    persisted_decisions = []
    monkeypatch.setattr(
        analyzer,
        "get_events_since",
        lambda **kwargs: events,
    )
    monkeypatch.setattr(
        analyzer,
        "insert_detection",
        lambda value: persisted_detections.append(value),
    )
    monkeypatch.setattr(
        analyzer,
        "insert_decision",
        lambda value: persisted_decisions.append(value),
    )
    monkeypatch.setattr(analyzer, "score_anomalies", lambda events: 0)
    monkeypatch.setattr(
        analyzer,
        "compute_risk",
        lambda detections, ml_score: {
            "risk_score": 50,
            "risk_level": "MONITOR",
            "action": "MONITOR",
            "reasons": ["login failure"],
        },
    )

    cursor = analyzer.process_new_events()
    assert cursor == 42
    assert analyzer.process_new_events(cursor) == cursor

    login_detector.assert_called_once_with(events)
    assert persisted_detections == [detection]
    assert len(persisted_decisions) == 1


def test_ml_only_anomaly_is_persisted_without_rule_detections(monkeypatch):
    events = [
        {
            "event_id": 99,
            "timestamp": "2026-10-08T22:30:00.000Z",
            "ip": "10.0.0.99",
            "user_id": None,
            "method": "GET",
            "endpoint": "/",
            "endpoint_pattern": "/",
            "resource_id": None,
            "resource_owner_id": None,
            "status_code": 200,
            "response_time_ms": 10.0,
            "sim_label": "normal",
        }
    ]
    for detector in (
        analyzer.login_failure_detector,
        analyzer.rate_detector,
        analyzer.enumeration_detector,
        analyzer.bola_detector,
    ):
        monkeypatch.setattr(detector, "detect", Mock(return_value=[]))

    persisted_detections = []
    persisted_decisions = []
    monkeypatch.setattr(analyzer, "get_events_since", lambda **kwargs: events)
    monkeypatch.setattr(
        analyzer,
        "insert_detection",
        lambda detection: persisted_detections.append(detection),
    )
    monkeypatch.setattr(
        analyzer,
        "insert_decision",
        lambda decision: persisted_decisions.append(decision),
    )
    monkeypatch.setattr(analyzer, "score_anomalies", lambda ip_events: 80)

    assert analyzer.process_new_events() == 99
    assert persisted_detections == []
    assert persisted_decisions == [
        {
            "ip": "10.0.0.99",
            "risk_score": 48,
            "risk_level": "MONITOR",
            "action": "MONITOR",
            "reasons": ["ML anomaly score 80.0"],
            "source": "analyzer",
        }
    ]


def test_run_loop_acquires_and_releases_single_instance_lock(monkeypatch):
    lock_file = object()
    acquire_lock = Mock(return_value=lock_file)
    release_lock = Mock()
    process_events = Mock(return_value=1)
    monkeypatch.setattr(analyzer, "_acquire_single_instance_lock", acquire_lock)
    monkeypatch.setattr(analyzer, "_release_single_instance_lock", release_lock)
    monkeypatch.setattr(analyzer, "process_new_events", process_events)

    analyzer.run_loop(interval_seconds=0, stop_after=1)

    acquire_lock.assert_called_once_with()
    process_events.assert_called_once_with(None)
    release_lock.assert_called_once_with(lock_file)


def test_single_instance_lock_rejects_a_second_lock(monkeypatch, tmp_path):
    monkeypatch.setattr(analyzer, "DB_PATH", tmp_path / "demo.db")
    lock_file = analyzer._acquire_single_instance_lock()
    try:
        with pytest.raises(RuntimeError, match="Another analyzer is already running"):
            analyzer._acquire_single_instance_lock()
    finally:
        analyzer._release_single_instance_lock(lock_file)
