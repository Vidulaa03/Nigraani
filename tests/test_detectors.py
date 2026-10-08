from datetime import datetime, timedelta, timezone

from backend.detection.bola_detector import detect as detect_bola
from backend.detection.enumeration_detector import detect as detect_enumeration
from backend.detection.login_failure_detector import detect
from backend.detection.login_failure_detector import detect as detect_login_failures
from backend.detection.owasp_map import DETECTOR_OWASP_MAP, OWASP_MAP
from backend.detection.rate_detector import detect as detect_rate


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
    forbidden_failures = _events(
        5,
        method="POST",
        endpoint="/api/auth/login",
        status_code=403,
    )

    assert detect_login_failures(one_failure) == []
    assert detect_login_failures(six_failures)[0]["severity"] == 50
    assert detect_login_failures(twelve_failures)[0]["severity"] == 80
    assert detect_login_failures(spread_failures) == []
    assert detect_login_failures(forbidden_failures)[0]["severity"] == 50


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
            datetime.now(timezone.utc) - timedelta(milliseconds=index),
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
    assert OWASP_MAP["bola"]["owasp_id"] == "API1:2023"
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


def make_event(
    event_id: int,
    ip: str,
    seconds_ago: int,
):
    timestamp = (
        datetime.now(timezone.utc)
        - timedelta(seconds=seconds_ago)
    ).isoformat()

    return {
        "event_id": event_id,
        "timestamp": timestamp,
        "ip": ip,
        "user_id": None,
        "method": "POST",
        "endpoint": "/api/auth/login",
        "endpoint_pattern": "/api/auth/{action}",
        "resource_id": None,
        "resource_owner_id": None,
        "status_code": 401,
        "response_time_ms": 20.0,
        "sim_label": "normal",
    }


def make_rate_event(
    event_id: int,
    ip: str,
    seconds_ago: int,
):
    event = make_event(event_id, ip, seconds_ago)
    event.update({
        "method": "GET",
        "endpoint": "/api/items",
        "status_code": 200,
        "sim_label": "normal" if event_id % 2 else "attack",
    })
    return event


def make_enumeration_event(
    event_id: int,
    ip: str,
    seconds_ago: int,
    resource_id: int | None,
    endpoint_pattern: str = "/api/items/{item_id}",
    status_code: int = 200,
):
    event = make_event(event_id, ip, seconds_ago)
    event.update({
        "method": "GET",
        "endpoint": f"/api/items/{resource_id}",
        "endpoint_pattern": endpoint_pattern,
        "resource_id": resource_id,
        "status_code": status_code,
    })
    return event


def make_bola_event(
    event_id: int,
    ip: str,
    seconds_ago: int,
    resource_id: int,
    user_id: int | None = 101,
    resource_owner_id: int | None = 202,
    status_code: int = 200,
):
    event = make_event(event_id, ip, seconds_ago)
    event.update({
        "method": "GET",
        "endpoint": f"/api/orders/{resource_id}",
        "endpoint_pattern": "/api/orders/{order_id}",
        "resource_id": resource_id,
        "resource_owner_id": resource_owner_id,
        "status_code": status_code,
        "user_id": user_id,
        "sim_label": "normal",
    })
    return event


def test_one_failure_no_detection():
    events = [
        make_event(1, "10.0.0.1", 5)
    ]

    detections = detect(events)

    assert detections == []


def test_six_failures_medium_severity():
    events = [
        make_event(i, "10.0.0.1", i)
        for i in range(1, 7)
    ]

    detections = detect(events)

    assert len(detections) == 1
    assert detections[0]["severity"] == 50


def test_twelve_failures_high_severity():
    events = [
        make_event(i, "10.0.0.1", i)
        for i in range(1, 13)
    ]

    detections = detect(events)

    assert len(detections) == 1
    assert detections[0]["severity"] == 80


def test_failures_outside_window():
    events = [
        make_event(1, "10.0.0.1", 120),
        make_event(2, "10.0.0.1", 100),
        make_event(3, "10.0.0.1", 80),
        make_event(4, "10.0.0.1", 60),
        make_event(5, "10.0.0.1", 40),
        make_event(6, "10.0.0.1", 20),
    ]

    detections = detect(events)

    assert detections == []


def test_five_requests_no_rate_detection():
    events = [
        make_rate_event(i, "10.0.0.1", 1)
        for i in range(1, 6)
    ]

    assert detect_rate(events) == []


def test_forty_requests_medium_rate_severity():
    events = [
        make_rate_event(i, "10.0.0.1", i % 10)
        for i in range(1, 41)
    ]

    detections = detect_rate(events)

    assert len(detections) == 1
    assert detections[0]["severity"] == 50
    assert len(detections[0]["event_ids"]) == 40


def test_one_hundred_requests_high_rate_severity():
    events = [
        make_rate_event(i, "10.0.0.1", i % 10)
        for i in range(1, 101)
    ]

    detections = detect_rate(events)

    assert len(detections) == 1
    assert detections[0]["severity"] == 80
    assert len(detections[0]["event_ids"]) == 100


def test_rate_requests_outside_window_do_not_trigger():
    events = [
        make_rate_event(i, "10.0.0.1", i * 11)
        for i in range(1, 41)
    ]

    assert detect_rate(events) == []


def test_rate_spike_ips_are_evaluated_independently():
    events = [
        make_rate_event(i, "10.0.0.1", i % 10)
        for i in range(1, 41)
    ] + [
        make_rate_event(i + 100, "10.0.0.2", i % 10)
        for i in range(1, 6)
    ]

    detections = detect_rate(events)

    assert len(detections) == 1
    assert detections[0]["ip"] == "10.0.0.1"
    assert detections[0]["severity"] == 50


def test_repeated_requests_for_three_resource_ids_are_not_enumeration():
    events = [
        make_enumeration_event(
            i,
            "10.0.0.1",
            i % 10,
            resource_id=i % 3 + 1,
            status_code=404,
        )
        for i in range(1, 31)
    ]

    assert detect_enumeration(events) == []


def test_sequential_resource_ids_trigger_enumeration():
    events = [
        make_enumeration_event(i, "10.0.0.1", i % 30, resource_id=i)
        for i in range(1, 31)
    ]

    detections = detect_enumeration(events)

    assert len(detections) == 1
    assert detections[0]["severity"] == 65
    assert len(detections[0]["event_ids"]) == 30


def test_distinct_ids_with_at_least_thirty_percent_404_trigger():
    events = [
        make_enumeration_event(
            i,
            "10.0.0.1",
            i % 30,
            resource_id=i * 2,
            status_code=404 if i <= 6 else 200,
        )
        for i in range(1, 21)
    ]

    detections = detect_enumeration(events)

    assert len(detections) == 1
    assert detections[0]["severity"] == 65
    assert "20 distinct resource IDs" in detections[0]["evidence"]
    assert "6/20 requests returned 404" in detections[0]["evidence"]


def test_distinct_ids_below_404_threshold_without_sequence_do_not_trigger():
    events = [
        make_enumeration_event(
            i,
            "10.0.0.1",
            i % 30,
            resource_id=i * 2,
            status_code=404 if i <= 5 else 200,
        )
        for i in range(1, 21)
    ]

    assert detect_enumeration(events) == []


def test_enumeration_events_outside_window_do_not_trigger():
    events = [
        make_enumeration_event(
            i,
            "10.0.0.1",
            i * 5,
            resource_id=i * 2,
        )
        for i in range(1, 21)
    ]

    assert detect_enumeration(events) == []


def test_enumeration_ips_are_evaluated_independently():
    events = [
        make_enumeration_event(
            i,
            "10.0.0.1",
            i % 30,
            resource_id=i,
        )
        for i in range(1, 21)
    ] + [
        make_enumeration_event(
            i + 100,
            "10.0.0.2",
            i % 30,
            resource_id=i * 2,
        )
        for i in range(1, 21)
    ]

    detections = detect_enumeration(events)

    assert len(detections) == 1
    assert detections[0]["ip"] == "10.0.0.1"


def test_enumeration_endpoint_patterns_are_evaluated_independently():
    events = [
        make_enumeration_event(
            i,
            "10.0.0.1",
            i % 30,
            resource_id=i,
            endpoint_pattern="/api/items/{item_id}",
        )
        for i in range(1, 21)
    ] + [
        make_enumeration_event(
            i + 100,
            "10.0.0.1",
            i % 30,
            resource_id=i * 2,
            endpoint_pattern="/api/users/{user_id}",
        )
        for i in range(1, 21)
    ]

    detections = detect_enumeration(events)

    assert len(detections) == 1
    assert detections[0]["endpoint_pattern"] == "/api/items/{item_id}"


def test_bola_own_resource_access_is_not_detected():
    events = [
        make_bola_event(
            1,
            "10.0.0.1",
            1,
            resource_id=501,
            user_id=101,
            resource_owner_id=101,
        )
    ]

    assert detect_bola(events) == []


def test_bola_single_foreign_resource_access_has_medium_severity():
    events = [
        make_bola_event(1, "10.0.0.1", 1, resource_id=501)
    ]

    detections = detect_bola(events)

    assert len(detections) == 1
    assert detections[0]["severity"] == 70
    assert "501" in detections[0]["evidence"]
    assert detections[0]["event_ids"] == [1]


def test_bola_three_distinct_foreign_resources_have_high_severity():
    events = [
        make_bola_event(i, "10.0.0.1", i, resource_id=500 + i)
        for i in range(1, 4)
    ]

    detections = detect_bola(events)

    assert len(detections) == 1
    assert detections[0]["severity"] == 90
    assert set(detections[0]["event_ids"]) == {1, 2, 3}


def test_bola_foreign_resource_404_is_not_detected():
    events = [
        make_bola_event(
            1,
            "10.0.0.1",
            1,
            resource_id=501,
            status_code=404,
        )
    ]

    assert detect_bola(events) == []


def test_bola_missing_user_id_is_not_detected():
    events = [
        make_bola_event(
            1,
            "10.0.0.1",
            1,
            resource_id=501,
            user_id=None,
        )
    ]

    assert detect_bola(events) == []


def test_bola_missing_resource_owner_id_is_not_detected():
    events = [
        make_bola_event(
            1,
            "10.0.0.1",
            1,
            resource_id=501,
            resource_owner_id=None,
        )
    ]

    assert detect_bola(events) == []


def test_bola_events_older_than_sixty_seconds_are_not_detected():
    events = [
        make_bola_event(i, "10.0.0.1", 61 + i, resource_id=500 + i)
        for i in range(1, 4)
    ]

    assert detect_bola(events) == []


def test_bola_ips_are_evaluated_independently():
    events = [
        make_bola_event(i, "10.0.0.1", i, resource_id=500 + i)
        for i in range(1, 3)
    ] + [
        make_bola_event(i + 10, "10.0.0.2", i, resource_id=600 + i)
        for i in range(1, 3)
    ]

    detections = detect_bola(events)

    assert len(detections) == 2
    assert {detection["ip"] for detection in detections} == {
        "10.0.0.1",
        "10.0.0.2",
    }
    assert all(detection["severity"] == 70 for detection in detections)
