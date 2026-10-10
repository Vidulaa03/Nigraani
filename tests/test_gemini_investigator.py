import json
import sys
import types

import pytest

from backend import gemini_investigator as investigator


def _evidence():
    return {
        "incident_id": "detection:11",
        "detection_id": 11,
        "detector": "injection_detector",
        "attack_type": "SQL injection",
        "severity": 85,
        "risk_score": 90,
        "action": "BLOCK",
        "risk_reasons": ["Authorization: Bearer private-value"],
        "time_window": {"start": "2026-10-10T10:00:00+00:00"},
        "client": {"ip_address": "192.0.2.11"},
        "endpoint_pattern": "/api/orders/{order_id}",
        "evidence_text": "token=private-value; suspicious query",
        "event_ids": [41],
        "event_reference_status": "complete",
        "owasp_mapping": ["API8:2023"],
        "sim_label": "sql_injection",
        "linked_events": [
            {
                "event_id": 41,
                "timestamp": "2026-10-10T10:00:00+00:00",
                "method": "GET",
                "endpoint": "/api/orders/42",
                "endpoint_pattern": "/api/orders/{order_id}",
                "status_code": 403,
                "summary": "Authorization: Bearer private-value",
                "sim_label": "sql_injection",
                "headers": {"Cookie": "private-value"},
            }
        ],
    }


def test_sanitize_evidence_excludes_labels_and_secrets():
    result = investigator.sanitize_evidence(_evidence())
    encoded = json.dumps(result)

    assert "sim_label" not in encoded
    assert "headers" not in encoded
    assert "private-value" not in encoded
    assert result["event_ids"] == [41]
    assert result["linked_events"][0]["event_id"] == 41


def test_sanitize_evidence_requires_complete_real_event_references():
    evidence = _evidence()
    evidence["event_reference_status"] = "incomplete"

    with pytest.raises(investigator.GeminiInvestigationError):
        investigator.sanitize_evidence(evidence)


def test_sanitize_evidence_marks_bounded_event_list():
    evidence = _evidence()
    evidence["linked_events"] = [
        {**evidence["linked_events"][0], "event_id": event_id}
        for event_id in range(1, 61)
    ]

    result = investigator.sanitize_evidence(evidence)

    assert len(result["linked_events"]) == 50
    assert len(result["event_ids"]) == 50
    assert result["events_truncated"] is True


def test_load_configuration_requires_key_and_model(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_MODEL", raising=False)

    with pytest.raises(investigator.GeminiConfigurationError):
        investigator.load_gemini_configuration()


def test_provider_call_uses_sanitized_evidence_and_validates_report(
    monkeypatch,
):
    calls = {}
    report = {
        "incident_summary": "A request triggered an injection detector.",
        "likely_attack_type": "SQL injection attempt",
        "severity": "high",
        "evidence": [
            {
                "observation": "A saved event returned HTTP 403.",
                "significance": "The request was rejected.",
            }
        ],
        "confidence": 82,
        "recommended_actions": ["Review the source IP's recent activity."],
        "limitations": ["Only linked event summaries were available."],
    }

    class FakeClient:
        def __init__(self, **_kwargs):
            calls["client"] = _kwargs
            self.models = self

        def generate_content(self, **_kwargs):
            calls["request"] = _kwargs
            return types.SimpleNamespace(text=json.dumps(report))

    fake_genai = types.ModuleType("google.genai")
    setattr(fake_genai, "Client", FakeClient)
    fake_types = types.ModuleType("google.genai.types")
    setattr(fake_types, "HttpOptions", lambda **_kwargs: _kwargs)
    setattr(
        fake_types,
        "GenerateContentConfig",
        lambda **_kwargs: _kwargs,
    )
    fake_google = types.ModuleType("google")
    setattr(fake_google, "genai", fake_genai)

    monkeypatch.setitem(sys.modules, "google", fake_google)
    monkeypatch.setitem(sys.modules, "google.genai", fake_genai)
    monkeypatch.setitem(sys.modules, "google.genai.types", fake_types)
    monkeypatch.setenv("GEMINI_API_KEY", "test-api-key")
    monkeypatch.setenv("GEMINI_MODEL", "test-model")

    validated, model = investigator.investigate_incident(_evidence())

    assert model == "test-model"
    assert validated.severity == "high"
    assert calls["client"]["api_key"] == "test-api-key"
    assert calls["client"]["http_options"]["timeout"] == 120_000
    assert "sim_label" not in calls["request"]["contents"]
    assert "private-value" not in calls["request"]["contents"]
    assert (
        calls["request"]["config"]["response_schema"]
        == investigator.GEMINI_RESPONSE_SCHEMA
    )
    assert "additionalProperties" not in json.dumps(
        investigator.GEMINI_RESPONSE_SCHEMA
    )


def test_provider_report_with_extra_fields_is_rejected(monkeypatch):
    class FakeClient:
        def __init__(self, **_kwargs):
            del _kwargs
            self.models = self

        def generate_content(self, **_kwargs):
            del _kwargs
            return types.SimpleNamespace(
                text=json.dumps({"unexpected": "field"})
            )

    fake_genai = types.ModuleType("google.genai")
    setattr(fake_genai, "Client", FakeClient)
    fake_types = types.ModuleType("google.genai.types")
    setattr(fake_types, "HttpOptions", lambda **_kwargs: _kwargs)
    setattr(
        fake_types,
        "GenerateContentConfig",
        lambda **_kwargs: _kwargs,
    )
    fake_google = types.ModuleType("google")
    setattr(fake_google, "genai", fake_genai)
    monkeypatch.setitem(sys.modules, "google", fake_google)
    monkeypatch.setitem(sys.modules, "google.genai", fake_genai)
    monkeypatch.setitem(sys.modules, "google.genai.types", fake_types)
    monkeypatch.setenv("GEMINI_API_KEY", "test-api-key")
    monkeypatch.setenv("GEMINI_MODEL", "test-model")

    with pytest.raises(investigator.GeminiInvestigationError):
        investigator.investigate_incident(_evidence())


def test_provider_5xx_error_has_safe_retryable_code(monkeypatch):
    class FakeServerError(Exception):
        code = 504

    class FakeClient:
        def __init__(self, **_kwargs):
            self.models = self

        def generate_content(self, **_kwargs):
            raise FakeServerError("provider detail")

    fake_genai = types.ModuleType("google.genai")
    setattr(fake_genai, "Client", FakeClient)
    fake_types = types.ModuleType("google.genai.types")
    setattr(fake_types, "HttpOptions", lambda **_kwargs: _kwargs)
    setattr(
        fake_types,
        "GenerateContentConfig",
        lambda **_kwargs: _kwargs,
    )
    fake_google = types.ModuleType("google")
    setattr(fake_google, "genai", fake_genai)
    monkeypatch.setitem(sys.modules, "google", fake_google)
    monkeypatch.setitem(sys.modules, "google.genai", fake_genai)
    monkeypatch.setitem(sys.modules, "google.genai.types", fake_types)
    monkeypatch.setenv("GEMINI_API_KEY", "test-api-key")
    monkeypatch.setenv("GEMINI_MODEL", "test-model")

    with pytest.raises(investigator.GeminiInvestigationError) as error:
        investigator.investigate_incident(_evidence())

    assert error.value.error_code == "gemini_provider_504"
    assert "provider detail" not in str(error.value)
