import os
from unittest.mock import MagicMock, patch
import pytest

from backend import analyzer
from backend.database import get_calls_for_incident, get_connection, insert_event
from backend.notification_service import get_unread_count, list_notifications


@pytest.fixture(autouse=True)
def clean_db():
    with get_connection() as conn:
        conn.execute("DELETE FROM security_events")
        conn.execute("DELETE FROM detections")
        conn.execute("DELETE FROM decisions")
        conn.execute("DELETE FROM notifications")
        conn.execute("DELETE FROM call_alerts")
        conn.commit()
    analyzer._RECENT_EVENTS_BY_IP.clear()
    yield
    with get_connection() as conn:
        conn.execute("DELETE FROM security_events")
        conn.execute("DELETE FROM detections")
        conn.execute("DELETE FROM decisions")
        conn.execute("DELETE FROM notifications")
        conn.execute("DELETE FROM call_alerts")
        conn.commit()
    analyzer._RECENT_EVENTS_BY_IP.clear()


@patch("backend.twilio_service.TwilioClient")
def test_end_to_end_rate_spike_demo_workflow(mock_client_cls):
    """Mandatory demo rule verification:

    30 requests in 10s -> rate_detector detection -> persistent in-app notification
    -> automatic Twilio call to authorized recipient without requiring risk score 85.
    """
    env = {
        "TWILIO_ACCOUNT_SID": "AC11111111111111111111111111111111",
        "TWILIO_AUTH_TOKEN": "secret_token_123",
        "TWILIO_FROM_NUMBER": "+12025550199",
        "TWILIO_TO_NUMBER": "+12025550188",
        "TWILIO_MIN_SEVERITY": "80",
    }
    mock_instance = MagicMock()
    mock_call = MagicMock()
    mock_call.sid = "CAdemo30reqs10s"
    mock_call.status = "initiated"
    mock_instance.calls.create.return_value = mock_call
    mock_client_cls.return_value = mock_instance

    with patch.dict(os.environ, env):
        # 1. Simulate 30 requests from 203.0.113.13 within a 5-second window
        simulated_ip = "203.0.113.13"
        base_ts = "2026-10-10T04:00:00"
        for i in range(1, 31):
            sec = i * 0.1  # 30 requests across 3.0 seconds
            insert_event({
                "event_id": i,
                "timestamp": f"2026-10-10T04:00:0{sec:.1f}Z" if sec < 10 else f"2026-10-10T04:00:{sec:.1f}Z",
                "ip": simulated_ip,
                "method": "GET",
                "endpoint": "/api/orders/501",
                "endpoint_pattern": "/api/orders/{order_id}",
                "status_code": 200,
                "response_time_ms": 15.0,
                "sim_label": "rate_spike",
            })

        # 2. Run analyzer processing
        last_id = analyzer.process_new_events(None)
        assert last_id == 30

        # 3. Verify in-app notification was created & persisted
        assert get_unread_count() == 1
        notifs, total = list_notifications()
        assert total == 1
        assert "Rate Spike" in notifs[0]["message"] or "API Threat Detected" in notifs[0]["title"]
        assert simulated_ip in notifs[0]["title"] or simulated_ip in notifs[0]["message"]

        # 4. Verify Twilio call was automatically initiated
        mock_instance.calls.create.assert_called_once()
        call_kwargs = mock_instance.calls.create.call_args[1]
        assert call_kwargs["to"] == "+12025550188"
        assert call_kwargs["from_"] == "+12025550199"
        assert "203 dot 0 dot 113 dot 13" in call_kwargs["twiml"]

        # 5. Verify call persistence
        calls = get_calls_for_incident(notifs[0]["incident_id"])
        assert len(calls) == 1
        assert calls[0]["call_sid"] == "CAdemo30reqs10s"
        assert calls[0]["status"] == "initiated"

        # 6. Verify duplicate prevention: running analyzer again with no new events or same events
        analyzer.process_new_events(last_id)
        # Call count must still be exactly 1!
        assert mock_instance.calls.create.call_count == 1
        assert get_unread_count() == 1
