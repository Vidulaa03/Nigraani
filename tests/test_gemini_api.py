import json
import time

from fastapi.testclient import TestClient

import backend.database as database
import backend.gemini_api as gemini_api
from backend.database import init_db, insert_detection, insert_event
from backend.gemini_investigator import InvestigationReport
from backend.main import app


def _event(event_id=41):
    return {
        "event_id": event_id,
        "timestamp": "2026-10-10T10:00:00+00:00",
        "ip": "192.0.2.11",
        "user_id": None,
        "method": "GET",
        "endpoint": "/api/orders/42",
        "endpoint_pattern": "/api/orders/{order_id}",
        "resource_id": 42,
        "resource_owner_id": 101,
        "status_code": 403,
        "response_time_ms": 8.0,
        "sim_label": "sql_injection",
    }


def _detection(event_ids=None):
    return {
        "detector": "injection_detector",
        "attack_type": "SQL injection",
        "severity": 85,
        "ip": "192.0.2.11",
        "user_id": None,
        "evidence": "Suspicious query pattern observed",
        "event_ids": [41] if event_ids is None else event_ids,
        "owasp": "API8:2023",
    }


def _setup(monkeypatch, tmp_path, *, linked_event=True):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "gemini.db")
    monkeypatch.setenv("GEMINI_API_KEY", "test-api-key")
    monkeypatch.setenv("GEMINI_MODEL", "test-model")
    init_db()
    if linked_event:
        insert_event(_event())
        return insert_detection(_detection())
    return insert_detection(_detection(event_ids=[]))


def _report():
    return InvestigationReport.model_validate(
        {
            "incident_summary": "One request triggered an injection detector.",
            "likely_attack_type": "SQL injection attempt",
            "severity": "high",
            "evidence": [
                {
                    "observation": "Saved event 41 returned HTTP 403.",
                    "significance": "The request was rejected.",
                }
            ],
            "confidence": 82,
            "recommended_actions": ["Review related source IP activity."],
            "limitations": ["Only linked event summaries were available."],
        }
    )


def _wait_for_status(client, investigation_id, status):
    for _ in range(100):
        response = client.get(
            f"/api/incidents/investigations/{investigation_id}"
        )
        if response.json()["status"] == status:
            return response.json()
        time.sleep(0.05)
    raise AssertionError(f"Investigation did not reach status {status!r}.")


def test_api_starts_without_token_and_persists_report_once(monkeypatch, tmp_path):
    detection_id = _setup(monkeypatch, tmp_path)
    calls = []

    def fake_investigator(evidence):
        calls.append(evidence)
        assert "sim_label" not in json.dumps(evidence)
        return _report(), "test-model"

    monkeypatch.setattr(gemini_api, "investigate_incident", fake_investigator)
    client = TestClient(app)

    started = client.post(
        f"/api/incidents/{detection_id}/investigate",
    )
    assert started.status_code == 202
    record = started.json()
    assert record["status"] in {"pending", "in_progress", "completed"}

    duplicate = client.post(
        f"/api/incidents/{detection_id}/investigate",
    )
    assert duplicate.status_code == 200
    assert duplicate.json()["investigation_id"] == record["investigation_id"]
    assert len(calls) == 1
    assert duplicate.json()["status"] == "completed"
    assert duplicate.json()["result"]["severity"] == "high"

    status = client.get(
        f"/api/incidents/investigations/{record['investigation_id']}",
    )
    assert status.status_code == 200
    assert status.json()["result"]["incident_summary"] == (
        "One request triggered an injection detector."
    )


def test_api_rejects_missing_evidence_before_provider_configuration(
    monkeypatch,
    tmp_path,
):
    detection_id = _setup(monkeypatch, tmp_path, linked_event=False)
    monkeypatch.delenv("GEMINI_API_KEY")
    client = TestClient(app)

    response = client.post(
        f"/api/incidents/{detection_id}/investigate",
    )

    assert response.status_code == 422
    assert "linked event evidence" in response.json()["detail"]


def test_api_returns_not_found_for_unknown_detection(monkeypatch, tmp_path):
    _setup(monkeypatch, tmp_path)
    client = TestClient(app)

    response = client.post(
        "/api/incidents/99999/investigate",
    )

    assert response.status_code == 404


def test_api_reports_missing_gemini_configuration(monkeypatch, tmp_path):
    detection_id = _setup(monkeypatch, tmp_path)
    monkeypatch.delenv("GEMINI_MODEL")
    client = TestClient(app)

    response = client.post(
        f"/api/incidents/{detection_id}/investigate",
    )

    assert response.status_code == 503
    assert "GEMINI_MODEL" in response.json()["detail"]


def test_api_retries_failed_investigation_and_keeps_active_results(
    monkeypatch,
    tmp_path,
):
    detection_id = _setup(monkeypatch, tmp_path)
    calls = 0

    def flaky_investigator(_evidence):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise gemini_api.GeminiInvestigationError("Temporary provider failure.")
        return _report(), "test-model"

    monkeypatch.setattr(gemini_api, "investigate_incident", flaky_investigator)
    client = TestClient(app)

    first_attempt = client.post(
        f"/api/incidents/{detection_id}/investigate"
    )
    failed_record = first_attempt.json()
    assert first_attempt.status_code == 202
    failed_record = _wait_for_status(
        client,
        failed_record["investigation_id"],
        "failed",
    )

    retried = client.post(
        f"/api/incidents/{detection_id}/investigate"
    )
    assert retried.status_code == 202
    assert retried.json()["investigation_id"] == failed_record["investigation_id"]
    completed_record = _wait_for_status(
        client,
        retried.json()["investigation_id"],
        "completed",
    )
    assert completed_record["result"]["severity"] == "high"
    assert calls == 2

    duplicate = client.post(
        f"/api/incidents/{detection_id}/investigate"
    )
    assert duplicate.status_code == 200
    assert duplicate.json()["status"] == "completed"
    assert calls == 2


def test_api_does_not_start_second_task_while_one_is_active(
    monkeypatch,
    tmp_path,
):
    detection_id = _setup(monkeypatch, tmp_path)
    calls = 0

    def fake_investigator(_evidence):
        nonlocal calls
        calls += 1
        return _report(), "test-model"

    monkeypatch.setattr(gemini_api, "investigate_incident", fake_investigator)
    client = TestClient(app)

    first_attempt = client.post(
        f"/api/incidents/{detection_id}/investigate"
    )
    second_attempt = client.post(
        f"/api/incidents/{detection_id}/investigate"
    )

    assert first_attempt.status_code == 202
    assert second_attempt.status_code == 200
    assert calls == 1
