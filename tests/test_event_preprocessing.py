import json
import math
import sqlite3
import threading
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import backend.analyzer as analyzer
import backend.database as database
import backend.main as main
import backend.security_logger as security_logger
from backend.database import DuplicateEventError, get_events_since, insert_event
from backend.detection.base import MAX_ENDPOINT_LENGTH, sample_event, validate_event
from backend.event_preprocessing import (
    client_ip,
    normalize_sim_label,
    parse_identifier,
    resolve_resource,
    sanitize_endpoint,
)
from backend.gemini_investigator import sanitize_evidence
from backend.incident_evidence import get_incident_evidence
from backend.metrics import (
    SECURITY_EVENT_FIELDS_SANITIZED,
    SECURITY_EVENTS,
    SECURITY_LOG_WRITE_FAILURES,
)
from backend.security_logger import (
    SecurityEventPersistenceError,
    SecurityEventRejected,
    log_security_event,
)

HUGE = str(2**70)


def counter(metric, label):
    return metric.labels(label)._value.get()


def jsonl_events():
    if not security_logger.LOG_FILE.exists():
        return []
    return [
        json.loads(line)
        for line in security_logger.LOG_FILE.read_text(encoding="utf-8").splitlines()
    ]


def client():
    return TestClient(main.app, client=("127.0.0.1", 50000))


def valid_kwargs(**overrides):
    kwargs = {
        "ip": "10.0.0.1",
        "method": "GET",
        "endpoint": "/",
        "status_code": 200,
        "response_time_ms": 1.0,
    }
    kwargs.update(overrides)
    return kwargs


# --- preprocessing helpers -------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("101", 101),
        (" 7 ", 7),
        (str(2**63 - 1), 2**63 - 1),
        (str(2**63), None),
        (HUGE, None),
        ("-3", None),
        ("+5", None),
        ("abc", None),
        ("", None),
        (True, None),
        (None, None),
    ],
)
def test_parse_identifier_bounds(raw, expected):
    assert parse_identifier(raw) == expected


def test_client_ip_validates_forwarded_for_and_client_host():
    assert client_ip("10.0.0.1, 10.0.0.2", "127.0.0.1") == "10.0.0.1"
    assert client_ip("2001:db8:0:0::0001", "127.0.0.1") == "2001:db8::1"
    assert client_ip("<script>x</script>", "127.0.0.1") == "127.0.0.1"
    assert client_ip("10.0.0.1:8080", "127.0.0.1") == "127.0.0.1"
    assert client_ip(None, "testclient") == "unknown"
    assert client_ip(None, None) == "unknown"


def test_sim_label_allowlist_keeps_known_labels_only():
    for label in ("normal", "login_bruteforce", "bola", "enumeration", "rate_spike", "low_slow"):
        assert normalize_sim_label(label) == label
    assert normalize_sim_label("BOLA") == "bola"
    assert normalize_sim_label(None) == "normal"
    assert normalize_sim_label("anything goes") == "unknown"
    assert normalize_sim_label("normal; drop table") == "unknown"


def test_sanitize_endpoint_caps_length_and_encodes_control_characters():
    assert len(sanitize_endpoint("/" + "x" * 5000)) == MAX_ENDPOINT_LENGTH
    assert sanitize_endpoint("/a\nb\x00") == "/a%0Ab%00"
    assert sanitize_endpoint("/api/orders/501") == "/api/orders/501"


def test_resource_attribution_only_for_order_routes():
    assert resolve_resource("/api/orders/601") == (601, 102)
    assert resolve_resource("/api/orders/99999") == (99999, None)
    assert resolve_resource(f"/api/orders/{HUGE}") == (None, None)
    # A user route addresses a user: resource_id for enumeration, no owner.
    assert resolve_resource("/api/users/501") == (501, None)
    assert resolve_resource("/api/incidents/501") == (None, None)
    assert resolve_resource("/anything/501") == (None, None)


# --- validate_event --------------------------------------------------------


@pytest.mark.parametrize(
    "overrides",
    [
        {"event_id": True},
        {"event_id": 0},
        {"event_id": 2**63},
        {"user_id": True},
        {"user_id": -1},
        {"user_id": 2**63},
        {"resource_id": "501"},
        {"resource_owner_id": False},
        {"status_code": True},
        {"status_code": "200"},
        {"status_code": 99},
        {"status_code": 600},
        {"method": "FOO"},
        {"method": "get"},
        {"ip": "<script>x</script>"},
        {"ip": "testclient"},
        {"ip": None},
        {"endpoint": "/" + "x" * MAX_ENDPOINT_LENGTH},
        {"endpoint": "no-leading-slash"},
        {"endpoint": "/a\nb"},
        {"endpoint_pattern": None},
        {"timestamp": "yesterday"},
        {"timestamp": "2026-10-08T12:00:00"},
        {"response_time_ms": math.nan},
        {"response_time_ms": -1.0},
        {"response_time_ms": True},
        {"sim_label": "anything goes"},
    ],
)
def test_validate_event_rejects(overrides):
    with pytest.raises(ValueError):
        sample_event(**overrides)


def test_validate_event_accepts_existing_formats():
    fixture = Path(__file__).with_name("sample_events.json")
    for event in json.loads(fixture.read_text(encoding="utf-8")):
        validate_event(event)
    sample_event(timestamp="2026-10-08T12:00:00.000Z")
    sample_event(timestamp="2026-10-08T18:13:49.763962+00:00")
    sample_event(ip="unknown", user_id=None, resource_id=None, resource_owner_id=None)
    sample_event(ip="2001:db8::1", sim_label="sql_injection")


# --- persistence -----------------------------------------------------------


@pytest.mark.parametrize(
    "overrides",
    [
        {"user_id": 2**70},
        {"user_id": True},
        {"method": "FOO"},
        {"ip": "<script>x</script>"},
        {"sim_label": "anything goes"},
        {"endpoint": "/" + "x" * 5000},
        {"status_code": True},
        {"response_time_ms": "fast"},
        {"timestamp": "not a time"},
    ],
)
def test_invalid_events_reach_neither_destination(overrides):
    rejected_before = counter(SECURITY_EVENTS, "rejected")

    with pytest.raises(SecurityEventRejected):
        log_security_event(**valid_kwargs(**overrides))

    assert get_events_since() == []
    assert not security_logger.LOG_FILE.exists()
    assert counter(SECURITY_EVENTS, "rejected") == rejected_before + 1


def test_duplicate_event_id_keeps_original_evidence():
    log_security_event(**valid_kwargs(endpoint="/first"), event_id=42)

    with pytest.raises(SecurityEventRejected, match="already exists"):
        log_security_event(**valid_kwargs(endpoint="/second"), event_id=42)
    with pytest.raises(DuplicateEventError):
        insert_event(sample_event(event_id=42, endpoint="/third"))

    assert [event["endpoint"] for event in get_events_since()] == ["/first"]
    assert [event["endpoint"] for event in jsonl_events()] == ["/first"]


def test_assigned_id_taken_by_another_writer_is_retried(monkeypatch):
    fixed_ns = 1_800_000_000_000_000_000
    taken_id = fixed_ns // 1_000
    monkeypatch.setattr(security_logger.time, "time_ns", lambda: fixed_ns)
    monkeypatch.setattr(security_logger, "_last_event_id", 0)
    # Simulate a row written by another process after our max-ID lookup.
    monkeypatch.setattr(security_logger, "get_max_event_id", lambda: 0)
    insert_event(sample_event(event_id=taken_id, endpoint="/other-process"))

    event = log_security_event(**valid_kwargs(endpoint="/ours"))

    assert event["event_id"] == taken_id + 1
    stored = {e["event_id"]: e["endpoint"] for e in get_events_since()}
    assert stored == {taken_id: "/other-process", taken_id + 1: "/ours"}


def test_assigned_ids_start_above_stored_ids(monkeypatch):
    monkeypatch.setattr(security_logger, "_last_event_id", 0)
    future_id = 10**17  # beyond any current epoch-microsecond value
    insert_event(sample_event(event_id=future_id))

    assert log_security_event(**valid_kwargs())["event_id"] == future_id + 1


def test_concurrent_events_get_unique_ids_in_commit_order(monkeypatch):
    # Same clock reading for every call: uniqueness must come from the lock.
    monkeypatch.setattr(security_logger.time, "time_ns", lambda: 1_800_000_000_000_000_000)
    errors = []

    def worker():
        for _ in range(25):
            try:
                log_security_event(**valid_kwargs())
            except SecurityEventPersistenceError as error:
                # Waited too long for the write lock: spooled, not lost.
                if not error.spooled:
                    errors.append(error)
            except Exception as error:  # pragma: no cover - reported below
                errors.append(error)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    stored_ids = [event["event_id"] for event in get_events_since()]
    jsonl_ids = [event["event_id"] for event in jsonl_events()]
    # JSONL is appended in commit order; increasing IDs mean the analyzer's
    # "event_id > last seen" cursor cannot skip a late commit.
    assert jsonl_ids == sorted(jsonl_ids) == stored_ids

    from backend.event_recovery import replay_spool

    replay_spool()
    all_ids = [event["event_id"] for event in get_events_since()]
    assert len(all_ids) == len(set(all_ids)) == 200


def test_database_failure_is_reported_and_not_written_to_jsonl(monkeypatch, caplog):
    def locked(event, **kwargs):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(security_logger, "insert_event", locked)
    failed_before = counter(SECURITY_EVENTS, "failed")
    db_failures_before = counter(SECURITY_LOG_WRITE_FAILURES, "database")

    with pytest.raises(SecurityEventPersistenceError):
        log_security_event(**valid_kwargs())

    assert not security_logger.LOG_FILE.exists()
    assert counter(SECURITY_EVENTS, "failed") == failed_before + 1
    assert counter(SECURITY_LOG_WRITE_FAILURES, "database") == db_failures_before + 1
    assert "was not stored" in caplog.text


def test_jsonl_failure_after_store_is_reported(monkeypatch, tmp_path, caplog):
    unwritable = tmp_path / "is-a-directory"
    unwritable.mkdir()
    monkeypatch.setattr(security_logger, "LOG_FILE", unwritable)
    jsonl_failures_before = counter(SECURITY_LOG_WRITE_FAILURES, "jsonl")
    stored_before = counter(SECURITY_EVENTS, "stored")

    event = log_security_event(**valid_kwargs())

    assert [e["event_id"] for e in get_events_since()] == [event["event_id"]]
    assert counter(SECURITY_LOG_WRITE_FAILURES, "jsonl") == jsonl_failures_before + 1
    assert counter(SECURITY_EVENTS, "stored") == stored_before + 1
    assert "stored but not appended" in caplog.text


def test_log_path_is_absolute_and_project_based():
    assert security_logger.LOG_DIR.is_absolute()


# --- middleware ------------------------------------------------------------


def test_oversized_identifiers_are_logged_not_crashing():
    sanitized_before = counter(SECURITY_EVENT_FIELDS_SANITIZED, "user_id")
    http = client()

    assert http.get("/", headers={"X-User-ID": HUGE}).status_code == 200
    assert http.get(f"/api/users/{HUGE}").status_code == 404
    assert http.get(f"/api/orders/{HUGE}", headers={"X-User-ID": "101"}).status_code == 404

    events = get_events_since()
    assert [(e["user_id"], e["resource_id"], e["resource_owner_id"]) for e in events] == [
        (None, None, None),
        (None, None, None),
        (101, None, None),
    ]
    assert counter(SECURITY_EVENT_FIELDS_SANITIZED, "user_id") == sanitized_before + 1


def test_untrusted_headers_and_paths_are_sanitized():
    http = client()
    http.get("/", headers={"X-Forwarded-For": "<script>x</script>"})
    http.get("/", headers={"X-Sim-Label": "anything goes"})
    http.get("/" + "x" * 5000)

    events = get_events_since()
    assert events[0]["ip"] == "127.0.0.1"
    assert events[1]["sim_label"] == "unknown"
    assert len(events[2]["endpoint"]) == MAX_ENDPOINT_LENGTH
    assert events[2]["status_code"] == 404


def test_user_routes_ending_in_digits_do_not_inherit_order_owner():
    http = client()
    http.get("/api/users/501", headers={"X-User-ID": "101"})
    http.get("/api/orders/601", headers={"X-User-ID": "101"})

    user_event, order_event = get_events_since()
    assert (user_event["resource_id"], user_event["resource_owner_id"]) == (501, None)
    assert (order_event["resource_id"], order_event["resource_owner_id"]) == (601, 102)


def test_invalid_http_method_is_rejected_without_changing_response():
    rejected_before = counter(SECURITY_EVENTS, "rejected")

    response = client().request("FOO", "/")

    assert response.status_code == 405
    assert get_events_since() == []
    assert counter(SECURITY_EVENTS, "rejected") == rejected_before + 1


def test_cors_preflight_is_not_logged():
    response = client().options(
        "/api/users/101",
        headers={"Origin": "http://localhost:3000", "Access-Control-Request-Method": "GET"},
    )

    assert response.status_code == 200
    assert get_events_since() == []


def _app_with_failing_route():
    app = FastAPI()
    app.middleware("http")(main.security_logging_middleware)

    @app.get("/boom")
    def boom():
        raise RuntimeError("boom")

    return app


def test_route_exception_is_logged_and_reraised():
    with pytest.raises(RuntimeError, match="boom"):
        TestClient(_app_with_failing_route(), client=("127.0.0.1", 1)).get("/boom")

    (event,) = get_events_since()
    assert (event["endpoint"], event["status_code"]) == ("/boom", 500)


def test_logging_failure_does_not_replace_route_exception(monkeypatch):
    def broken_logger(**kwargs):
        raise RuntimeError("logger broke")

    monkeypatch.setattr(main, "log_security_event", broken_logger)

    with pytest.raises(RuntimeError, match="^boom$"):
        TestClient(_app_with_failing_route()).get("/boom")


@pytest.mark.parametrize(
    "error",
    [SecurityEventPersistenceError("db down"), RuntimeError("unexpected")],
)
def test_logging_failure_does_not_turn_success_into_500(monkeypatch, error, caplog):
    def broken_logger(**kwargs):
        raise error

    monkeypatch.setattr(main, "log_security_event", broken_logger)

    response = client().get("/api/users/101")

    assert response.status_code == 200
    assert response.json()["user_id"] == 101
    if type(error) is RuntimeError:
        # Unexpected errors are reported by the middleware; typed ones were
        # already reported by backend.security_logger (mocked out here).
        assert "Security event logging failed" in caplog.text


def test_logging_runs_off_the_event_loop(monkeypatch):
    threads = {}

    def recording_logger(**kwargs):
        threads["logger"] = threading.get_ident()

    monkeypatch.setattr(main, "log_security_event", recording_logger)
    app = FastAPI()
    app.middleware("http")(main.security_logging_middleware)

    @app.get("/where")
    async def where():
        threads["loop"] = threading.get_ident()
        return {}

    TestClient(app).get("/where")

    assert threads["logger"] != threads["loop"]


# --- downstream compatibility ---------------------------------------------


def test_logged_events_feed_detectors_incident_evidence_and_gemini(monkeypatch):
    monkeypatch.setattr(analyzer, "score_anomalies", lambda events: 0)
    monkeypatch.setattr(analyzer, "_RECENT_EVENTS_BY_IP", {})
    http = client()
    for order_id in (601, 602, 701):
        http.get(
            f"/api/orders/{order_id}",
            headers={"X-User-ID": "101", "X-Forwarded-For": "10.0.0.32", "X-Sim-Label": "bola"},
        )
    for user_id in range(201, 216):
        http.get(f"/api/users/{user_id}", headers={"X-Forwarded-For": "10.0.0.33"})
    for _ in range(5):
        http.post(
            "/api/auth/login",
            json={"username": "admin", "password": "wrong"},
            headers={"X-Forwarded-For": "10.0.0.31"},
        )

    analyzer.process_new_events()

    with database.get_connection() as conn:
        detections = {
            (row["ip"], row["detector"]): row["detection_id"]
            for row in conn.execute("SELECT detection_id, ip, detector FROM detections")
        }
    assert ("10.0.0.32", "bola_detector") in detections
    assert ("10.0.0.33", "enumeration_detector") in detections
    assert ("10.0.0.31", "login_failure_detector") in detections

    evidence = get_incident_evidence(detections[("10.0.0.32", "bola_detector")])
    assert evidence["event_reference_status"] == "complete"
    assert {e["endpoint"] for e in evidence["linked_events"]} == {
        "/api/orders/601", "/api/orders/602", "/api/orders/701",
    }
    payload = sanitize_evidence(evidence)
    assert len(payload["linked_events"]) == 3
