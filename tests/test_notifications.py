import pytest
from backend.database import (
    get_connection,
    get_notifications,
    get_unread_notifications_count,
    mark_all_notifications_read,
    mark_notification_read,
)
from backend.notification_service import (
    evaluate_and_notify_incident,
    get_notification,
    get_unread_count,
    list_notifications,
    set_all_notifications_read,
    set_notification_read,
)


@pytest.fixture(autouse=True)
def clean_notifications_table():
    with get_connection() as conn:
        conn.execute("DELETE FROM notifications")
        conn.commit()
    yield
    with get_connection() as conn:
        conn.execute("DELETE FROM notifications")
        conn.commit()


def test_notification_creation_and_persistence():
    decision = {
        "ip": "198.51.100.55",
        "risk_score": 85,
        "risk_level": "CRITICAL",
        "action": "BLOCK",
        "reasons": ["High confidence BOLA attack"],
    }
    detections = [
        {
            "detector": "bola_detector",
            "attack_type": "BOLA",
            "severity": 85,
            "ip": "198.51.100.55",
        }
    ]

    notif = evaluate_and_notify_incident(decision, detections, incident_id="test-inc-1")
    assert notif is not None
    assert notif["notification_id"] > 0
    assert notif["severity_band"] == "CRITICAL"
    assert "BLOCK" in notif["message"]

    # Verify retrieved from DB
    retrieved = get_notification(notif["notification_id"])
    assert retrieved is not None
    assert retrieved["incident_id"] == "test-inc-1"
    assert retrieved["is_read"] is False
    assert get_unread_count() == 1


def test_notification_idempotency():
    decision = {
        "ip": "198.51.100.55",
        "risk_score": 85,
        "risk_level": "CRITICAL",
        "action": "BLOCK",
        "reasons": ["BOLA"],
    }
    detections = [{"detector": "bola_detector", "attack_type": "BOLA", "severity": 85}]

    notif1 = evaluate_and_notify_incident(decision, detections, incident_id="test-inc-idem")
    notif2 = evaluate_and_notify_incident(decision, detections, incident_id="test-inc-idem")

    assert notif1 is not None
    assert notif2 is not None
    # Must have the same notification_id because of idempotency
    assert notif1["notification_id"] == notif2["notification_id"]
    assert get_unread_count() == 1


def test_notification_read_lifecycle():
    decision = {"ip": "10.0.0.1", "risk_score": 70, "action": "THROTTLE"}
    detections = [{"detector": "rate_detector", "attack_type": "Rate Spike", "severity": 70}]

    notif = evaluate_and_notify_incident(decision, detections, incident_id="test-read-1")
    assert get_unread_count() == 1

    # Mark as read
    res = set_notification_read(notif["notification_id"])
    assert res is True
    assert get_unread_count() == 0

    fresh = get_notification(notif["notification_id"])
    assert fresh["is_read"] is True


def test_mark_all_read():
    for i in range(3):
        decision = {"ip": f"10.0.0.{i}", "risk_score": 80, "action": "BLOCK"}
        detections = [{"detector": "test", "attack_type": "Test", "severity": 80}]
        evaluate_and_notify_incident(decision, detections, incident_id=f"test-bulk-{i}")

    assert get_unread_count() == 3
    updated = set_all_notifications_read()
    assert updated == 3
    assert get_unread_count() == 0


def test_rate_spike_demo_qualifies_regardless_of_score():
    # Score 50 is normally below 80, but Rate Spike must qualify
    decision = {"ip": "203.0.113.13", "risk_score": 50, "action": "MONITOR"}
    detections = [{"detector": "rate_detector", "attack_type": "Rate Spike", "severity": 50}]

    notif = evaluate_and_notify_incident(decision, detections, incident_id="test-demo-rate")
    assert notif is not None
    assert get_unread_count() == 1
