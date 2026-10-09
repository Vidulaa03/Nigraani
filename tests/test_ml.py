from datetime import datetime, timedelta, timezone

import pytest

from ml.anomaly_detector import score
from ml.features import FEATURE_COLUMNS, extract_features
from ml.train_model import train_model


def _normal_events(window_count=30):
    events = []
    event_id = 1
    start = datetime(2026, 10, 1, tzinfo=timezone.utc)
    for window_index in range(window_count):
        request_count = 3 + window_index % 5
        for request_index in range(request_count):
            user_id = 101 + window_index % 5
            login = (window_index + 1) % 9 == 0 and request_index == request_count - 1
            route_type = "login" if login else ("home", "user", "order")[request_index % 3]
            endpoint = {
                "login": "/api/auth/login",
                "home": "/",
                "user": f"/api/users/{user_id}",
                "order": f"/api/orders/{501 + window_index % 40}",
            }[route_type]
            events.append(
                {
                    "event_id": event_id,
                    "timestamp": (
                        start
                        + timedelta(seconds=30 * window_index + 10 + 0.25 * request_index)
                    ).isoformat(),
                    "ip": "10.0.0.1",
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
                        else 501 + window_index % 40
                        if endpoint.startswith("/api/orders/")
                        else None
                    ),
                    "resource_owner_id": (
                        user_id
                        if endpoint.startswith(("/api/users/", "/api/orders/"))
                        else None
                    ),
                    "status_code": (
                        401 if endpoint == "/api/auth/login" and window_index % 18 == 0 else 200
                    ),
                    "response_time_ms": 20 + (window_index * 7 + request_index * 3) % 35,
                    "sim_label": "normal",
                }
            )
            event_id += 1
    return events


def test_feature_extraction_returns_eight_features_and_ignores_labels():
    events = _normal_events(1)
    events.extend(
        [
            {
                **events[0],
                "event_id": 100,
                "timestamp": (
                    datetime.fromisoformat(events[0]["timestamp"])
                    + timedelta(seconds=1)
                ).isoformat(),
                "method": "POST",
                "endpoint": "/api/auth/login",
                "endpoint_pattern": "/api/auth/login",
                "status_code": 401,
                "sim_label": "login_bruteforce",
            },
            {
                **events[0],
                "event_id": 101,
                "timestamp": (
                    datetime.fromisoformat(events[0]["timestamp"])
                    + timedelta(seconds=2)
                ).isoformat(),
                "method": "POST",
                "endpoint": "/api/auth/login",
                "endpoint_pattern": "/api/auth/login",
                "status_code": 401,
                "sim_label": "login_bruteforce",
            },
        ]
    )

    features = extract_features(events)
    changed_labels = [{**event, "sim_label": "normal"} for event in events]
    features_with_changed_labels = extract_features(changed_labels)

    assert tuple(features.columns[2:]) == FEATURE_COLUMNS
    assert features.iloc[0]["login_attempts"] == 2
    assert features.iloc[0]["login_failures"] == 2
    assert features.iloc[0]["error_rate"] == pytest.approx(2 / 5)
    assert features.iloc[0]["max_requests_in_5s"] == len(events)
    assert features.equals(features_with_changed_labels)


def test_isolation_forest_training_and_scoring(tmp_path):
    model_path = tmp_path / "iforest.joblib"
    normal_events = _normal_events(300)
    train_model(normal_events, model_path)

    normal_score = score(normal_events[-3:], model_path)
    attack_events = [
        {
            **normal_events[-1],
            "event_id": index + 1000,
            "timestamp": (
                datetime.fromisoformat(normal_events[-1]["timestamp"])
                + timedelta(milliseconds=index * 400)
            ).isoformat(),
            "method": "POST",
            "endpoint": "/api/auth/login",
            "endpoint_pattern": "/api/auth/login",
            "resource_id": None,
            "status_code": 401,
            "response_time_ms": 1000,
            "sim_label": "normal",
        }
        for index in range(3)
    ]
    attack_score = score(attack_events, model_path)

    assert 0 <= normal_score <= 100
    assert 0 <= attack_score <= 100
    assert attack_score > normal_score


def test_scoring_without_a_trained_model_fails_explicitly(tmp_path):
    with pytest.raises(FileNotFoundError, match="Train it"):
        score(_normal_events(1), tmp_path / "missing.joblib")
