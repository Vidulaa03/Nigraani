from datetime import datetime, timedelta, timezone

from detection.bola_detector import detect as detect_bola
from detection.enumeration_detector import detect as detect_enumeration
from detection.login_failure_detector import detect as detect_login_failures
from detection.owasp_map import DETECTOR_OWASP_MAP
from detection.rate_detector import detect as detect_rate


def _event(event_id, timestamp, **overrides):
    event = {
        "event_id": event_id,
        "timestamp": timestamp.isoformat(),
        "ip": "10.0.0.1",
        "user_id": 101,
        "method": "GET",
        "endpoint": "/",
        "endpoint_pattern": "/",
        "resource_id": None,
        "resource_owner_id": None,
        "status_code": 200,
        "response_time_ms": 20.0,
        "sim_label": "normal",
    }
    event.update(overrides)
    return event


def _events(count, *, start=None, interval_ms=100, **overrides):
    start = start or datetime.now(timezone.utc)
    return [
        _event(
            index + 1,
            start + timedelta(milliseconds=index * interval_ms),
            **overrides,
        )
        for index in range(count)
    ]


def test_login_failure_detector_thresholds_and_60_second_window():
    one_failure = _events(
        1,
        method="POST",
        endpoint="/api/auth/login",
        status_code=401,
    )
    six_failures = _events(
        6,
        method="POST",
        endpoint="/api/auth/login",
        status_code=401,
    )
    twelve_failures = _events(
        12,
        method="POST",
        endpoint="/api/auth/login",
        status_code=401,
    )
    spread_failures = _events(
        12,
        interval_ms=60_000,
        method="POST",
        endpoint="/api/auth/login",
        status_code=401,
    )

    assert detect_login_failures(one_failure) == []
    assert detect_login_failures(six_failures)[0]["severity"] == 50
    assert detect_login_failures(twelve_failures)[0]["severity"] == 80
    assert detect_login_failures(spread_failures) == []


def test_rate_detector_uses_ten_second_thresholds():
    assert detect_rate(_events(5)) == []
    assert detect_rate(_events(40, interval_ms=100))[0]["severity"] == 50
    assert detect_rate(_events(100, interval_ms=50))[0]["severity"] == 80


def test_enumeration_detector_finds_sequential_ids_but_not_ordinary_repeats():
    sequential_ids = [
        _event(
            resource_id,
            datetime.now(timezone.utc) + timedelta(milliseconds=resource_id),
            resource_id=resource_id,
            endpoint=f"/api/users/{resource_id}",
            endpoint_pattern="/api/users/{user_id}",
        )
        for resource_id in range(1, 31)
    ]
    own_resource_repeats = _events(
        3,
        resource_id=501,
        endpoint="/api/orders/501",
        endpoint_pattern="/api/orders/{order_id}",
        resource_owner_id=101,
    )

    detection = detect_enumeration(sequential_ids)
    assert len(detection) == 1
    assert detection[0]["severity"] == 65
    assert detect_enumeration(own_resource_repeats) == []


def test_bola_detector_ignores_owned_orders_and_flags_foreign_orders():
    own_orders = _events(
        3,
        resource_id=501,
        endpoint="/api/orders/501",
        endpoint_pattern="/api/orders/{order_id}",
        resource_owner_id=101,
    )
    foreign_orders = [
        _event(
            600 + index,
            datetime.now(timezone.utc) + timedelta(milliseconds=index),
            endpoint=f"/api/orders/{600 + index}",
            endpoint_pattern="/api/orders/{order_id}",
            resource_id=600 + index,
            resource_owner_id=102 + index,
        )
        for index in range(1, 4)
    ]

    assert detect_bola(own_orders) == []
    assert detect_bola(foreign_orders[:1])[0]["severity"] == 70
    detection = detect_bola(foreign_orders)[0]
    assert detection["severity"] == 90
    assert detection["owasp"] == "API1:2023"
    assert json_ids(detection) == [601, 602, 603]


def json_ids(detection):
    return sorted(int(event_id) for event_id in detection["event_ids"])


def test_every_detector_has_an_owasp_mapping():
    assert {
        "bola_detector",
        "enumeration_detector",
        "login_failure_detector",
        "rate_detector",
    } <= DETECTOR_OWASP_MAP.keys()
