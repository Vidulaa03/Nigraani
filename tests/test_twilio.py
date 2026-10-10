import os
from unittest.mock import MagicMock, patch
import pytest

from backend.database import get_call_alert_by_sid, get_connection
from backend.notification_service import evaluate_and_notify_incident, get_unread_count
from backend.twilio_service import (
    generate_twiml_briefing,
    get_voice_config_status,
    handle_twilio_callback,
    initiate_voice_alert,
    mask_phone_number,
    should_initiate_call,
)


@pytest.fixture(autouse=True)
def clean_tables():
    with get_connection() as conn:
        conn.execute("DELETE FROM call_alerts")
        conn.execute("DELETE FROM notifications")
        conn.commit()
    yield
    with get_connection() as conn:
        conn.execute("DELETE FROM call_alerts")
        conn.execute("DELETE FROM notifications")
        conn.commit()


def test_mask_phone_number():
    assert mask_phone_number("+12025550199") == "+1***0199"
    assert mask_phone_number("+919876543210") == "+9***3210"
    assert mask_phone_number(None) == ""
    assert mask_phone_number("12") == "***"


def test_missing_twilio_config_safe_handling():
    with patch.dict(os.environ, {}, clear=True):
        status = get_voice_config_status()
        assert status["configured"] is False
        assert status["enabled"] is False

        allowed, reason = should_initiate_call("test-inc-1", severity=90)
        assert allowed is False
        assert "not configured" in reason


def test_twiml_briefing_valid_xml():
    twiml = generate_twiml_briefing(
        ip="203.0.113.13",
        risk_score=85,
        action="BLOCK",
        attack_types=["Rate Spike"],
        endpoint="/api/orders/501",
    )
    assert '<?xml version="1.0" encoding="UTF-8"?>' in twiml
    assert "<Response>" in twiml
    assert "<Say" in twiml
    assert "203 dot 0 dot 113 dot 13" in twiml
    assert "BLOCK" in twiml


def test_rate_spike_demo_qualifies_without_85_score():
    env = {
        "TWILIO_ACCOUNT_SID": "AC11111111111111111111111111111111",
        "TWILIO_AUTH_TOKEN": "secret_token_123",
        "TWILIO_FROM_NUMBER": "+12025550199",
        "TWILIO_TO_NUMBER": "+12025550188",
        "TWILIO_MIN_SEVERITY": "80",
    }
    with patch.dict(os.environ, env):
        # Score 50 normally fails threshold of 80
        normal_allowed, _ = should_initiate_call("test-inc-1", severity=50, is_rate_spike_demo=False)
        assert normal_allowed is True

        # Demo rate spike overrides severity check
        demo_allowed, reason = should_initiate_call("test-inc-1", severity=50, is_rate_spike_demo=True)
        assert demo_allowed is True
        assert reason == "Call authorized"


@patch("backend.twilio_service.TwilioClient")
def test_mocked_outbound_call_persistence(mock_client_cls):
    env = {
        "TWILIO_ACCOUNT_SID": "AC11111111111111111111111111111111",
        "TWILIO_AUTH_TOKEN": "secret_token_123",
        "TWILIO_FROM_NUMBER": "+12025550199",
        "TWILIO_TO_NUMBER": "+12025550188",
    }
    mock_instance = MagicMock()
    mock_call = MagicMock()
    mock_call.sid = "CAtest1234567890abcdef"
    mock_call.status = "queued"
    mock_instance.calls.create.return_value = mock_call
    mock_client_cls.return_value = mock_instance

    with patch.dict(os.environ, env):
        res = initiate_voice_alert(
            incident_id="incident-demo-99",
            decision={"ip": "203.0.113.13", "risk_score": 90, "action": "BLOCK"},
            detections=[{"detector": "rate_detector", "attack_type": "Rate Spike", "severity": 90}],
            endpoint="/api/orders/501",
        )

        assert res["success"] is True
        assert res["call_sid"] == "CAtest1234567890abcdef"
        mock_instance.calls.create.assert_called_once()

        # Check persistence
        persisted = get_call_alert_by_sid("CAtest1234567890abcdef")
        assert persisted is not None
        assert persisted["status"] == "queued"
        assert persisted["incident_id"] == "incident-demo-99"


def test_cooldown_duplicate_prevention():
    env = {
        "TWILIO_ACCOUNT_SID": "AC11111111111111111111111111111111",
        "TWILIO_AUTH_TOKEN": "secret_token_123",
        "TWILIO_FROM_NUMBER": "+12025550199",
        "TWILIO_TO_NUMBER": "+12025550188",
        "TWILIO_COOLDOWN_SECONDS": "300",
    }
    with patch.dict(os.environ, env):
        with get_connection() as conn:
            from datetime import datetime, timezone
            conn.execute(
                """
                INSERT INTO call_alerts (
                    call_sid, incident_id, to_number, from_number, trigger_reason, status, severity, initiated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                ("CAexisting123", "inc-cooldown", "+12025550188", "+12025550199", "reason", "in-progress", 90, datetime.now(timezone.utc).isoformat()),
            )
            conn.commit()

        allowed, reason = should_initiate_call("inc-cooldown", severity=90)
        assert allowed is False
        assert "cooldown active" in reason.lower()


def test_status_callback_processing():
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO call_alerts (
                call_sid, incident_id, to_number, from_number, trigger_reason, status, severity, initiated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            ("CAcallback999", "inc-call-99", "+12025550188", "+12025550199", "reason", "initiated", 90, "2026-10-10T00:00:00Z"),
        )
        conn.commit()

    form_data = {
        "CallSid": "CAcallback999",
        "CallStatus": "completed",
        "CallDuration": "42",
    }
    res = handle_twilio_callback(form_data)
    assert res["success"] is True

    record = get_call_alert_by_sid("CAcallback999")
    assert record["status"] == "completed"
    assert record["duration"] == 42
    assert record["completed_at"] is not None


def test_independent_channels_when_twilio_fails():
    env = {
        "TWILIO_ACCOUNT_SID": "AC11111111111111111111111111111111",
        "TWILIO_AUTH_TOKEN": "secret_token_123",
        "TWILIO_FROM_NUMBER": "+12025550199",
        "TWILIO_TO_NUMBER": "+12025550188",
    }
    with patch.dict(os.environ, env):
        with patch("backend.twilio_service.TwilioClient", side_effect=Exception("Twilio service unreachable")):
            # Step 1: Create notification
            decision = {"ip": "203.0.113.13", "risk_score": 85, "action": "BLOCK"}
            detections = [{"detector": "rate_detector", "attack_type": "Rate Spike", "severity": 85}]
            notif = evaluate_and_notify_incident(decision, detections, incident_id="inc-failover")
            assert notif is not None

            # Step 2: Attempt call which fails
            call_res = initiate_voice_alert(
                incident_id="inc-failover",
                decision=decision,
                detections=detections,
                notification_id=notif["notification_id"],
            )

            # Verification: call failed gracefully, but notification is still persisted!
            assert call_res["success"] is False
            assert call_res["status"] == "failed"
            assert get_unread_count() == 1
