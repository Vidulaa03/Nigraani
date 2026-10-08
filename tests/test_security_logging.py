import asyncio
import json
from typing import Any

import backend.database as database
import backend.security_logger as security_logger
import backend.analyzer as analyzer
from backend.database import get_events_since, init_db
from backend.main import app


async def _asgi_request(
    method: str,
    path: str,
    *,
    headers: dict[str, str] | None = None,
    body: bytes = b"",
) -> tuple[int, bytes]:
    request_message: dict[str, Any] | None = {
        "type": "http.request",
        "body": body,
        "more_body": False,
    }
    response_messages: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        nonlocal request_message
        if request_message is not None:
            message = request_message
            request_message = None
            return message
        return {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        response_messages.append(message)

    raw_headers = [(b"host", b"testserver")]
    raw_headers.extend(
        (name.lower().encode(), value.encode())
        for name, value in (headers or {}).items()
    )
    raw_path = path.encode()
    await app(
        {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": method,
            "scheme": "http",
            "path": path,
            "raw_path": raw_path,
            "query_string": b"",
            "root_path": "",
            "headers": raw_headers,
            "client": ("127.0.0.1", 12345),
            "server": ("testserver", 80),
        },
        receive,
        send,
    )

    status = next(
        message["status"]
        for message in response_messages
        if message["type"] == "http.response.start"
    )
    response_body = b"".join(
        message.get("body", b"")
        for message in response_messages
        if message["type"] == "http.response.body"
    )
    return status, response_body


def test_middleware_logs_requests_and_failed_login_status(monkeypatch, tmp_path):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "demo.db")
    monkeypatch.setattr(security_logger, "LOG_FILE", tmp_path / "api_events.jsonl")
    init_db()

    requests = [
        ("GET", "/", {}),
        ("GET", "/api/users/101", {
            "X-User-ID": "101",
            "X-Forwarded-For": "10.0.0.1",
            "X-Sim-Label": "normal",
        }),
        ("GET", "/api/orders/501", {
            "X-User-ID": "101",
            "X-Forwarded-For": "10.0.0.2",
            "X-Sim-Label": "normal",
        }),
        ("GET", "/api/orders/601", {
            "X-User-ID": "101",
            "X-Forwarded-For": "10.0.0.3",
            "X-Sim-Label": "bola",
        }),
        ("POST", "/api/auth/login", {
            "X-User-ID": "101",
            "X-Forwarded-For": "10.0.0.4",
            "X-Sim-Label": "login_bruteforce",
            "Content-Type": "application/json",
        }),
    ]

    responses = []
    for method, path, headers in requests:
        body = (
            json.dumps({"username": "admin", "password": "wrong"}).encode()
            if path == "/api/auth/login"
            else b""
        )
        responses.append(
            asyncio.run(_asgi_request(method, path, headers=headers, body=body))
        )

    assert [status for status, _ in responses] == [200, 200, 200, 200, 401]
    assert json.loads(responses[-1][1]) == {
        "detail": "Invalid username or password",
    }

    events = get_events_since()
    assert len(events) == 5
    assert events[0]["ip"] == "127.0.0.1"
    assert events[1]["ip"] == "10.0.0.1"
    assert events[1]["user_id"] == 101
    assert events[2]["endpoint_pattern"] == "/api/orders/{order_id}"
    assert events[2]["resource_owner_id"] == 101
    assert events[3]["resource_owner_id"] == 102
    assert events[3]["sim_label"] == "bola"
    assert events[4]["status_code"] == 401
    assert events[4]["sim_label"] == "login_bruteforce"

    logged_events = [
        json.loads(line)
        for line in security_logger.LOG_FILE.read_text(encoding="utf-8").splitlines()
    ]
    assert len(logged_events) == 5
    assert logged_events[-1]["status_code"] == 401
    assert len({event["event_id"] for event in events}) == 5


def test_security_event_ids_do_not_collide_within_one_clock_tick(monkeypatch, tmp_path):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "demo.db")
    monkeypatch.setattr(security_logger, "LOG_FILE", tmp_path / "api_events.jsonl")
    monkeypatch.setattr(security_logger.time, "time_ns", lambda: 1_800_000_000_000_000_000)
    init_db()

    event_ids = [
        security_logger.log_security_event(
            ip="10.0.0.10",
            method="GET",
            endpoint="/",
            status_code=200,
            response_time_ms=1.0,
        )["event_id"]
        for _ in range(3)
    ]

    assert len(set(event_ids)) == 3
    assert len(get_events_since()) == 3


def test_full_demo_scenarios_flow_from_api_requests_to_analyzer(
    monkeypatch,
    tmp_path,
):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "demo.db")
    monkeypatch.setattr(security_logger, "LOG_FILE", tmp_path / "api_events.jsonl")
    monkeypatch.setattr(analyzer, "score_anomalies", lambda events: 0)
    init_db()

    for _ in range(5):
        status, _ = asyncio.run(
            _asgi_request(
                "POST",
                "/api/auth/login",
                headers={
                    "Content-Type": "application/json",
                    "X-Forwarded-For": "10.0.0.31",
                },
                body=json.dumps(
                    {"username": "admin", "password": "wrong"}
                ).encode(),
            )
        )
        assert status == 401

    for order_id in (601, 602, 701):
        status, _ = asyncio.run(
            _asgi_request(
                "GET",
                f"/api/orders/{order_id}",
                headers={
                    "X-User-ID": "101",
                    "X-Forwarded-For": "10.0.0.32",
                },
            )
        )
        assert status == 200

    for user_id in range(201, 216):
        status, _ = asyncio.run(
            _asgi_request(
                "GET",
                f"/api/users/{user_id}",
                headers={"X-Forwarded-For": "10.0.0.33"},
            )
        )
        assert status == 404

    for _ in range(30):
        status, _ = asyncio.run(
            _asgi_request(
                "GET",
                "/",
                headers={"X-Forwarded-For": "10.0.0.34"},
            )
        )
        assert status == 200

    analyzer.process_new_events()

    with database.get_connection() as conn:
        detections = conn.execute(
            "SELECT detector, severity, ip FROM detections"
        ).fetchall()
        decisions = conn.execute(
            "SELECT ip, action FROM decisions"
        ).fetchall()

    detection_pairs = {(row["ip"], row["detector"]) for row in detections}
    decision_actions = {row["ip"]: row["action"] for row in decisions}
    assert ("10.0.0.31", "login_failure_detector") in detection_pairs
    assert ("10.0.0.32", "bola_detector") in detection_pairs
    assert ("10.0.0.33", "enumeration_detector") in detection_pairs
    assert ("10.0.0.34", "rate_detector") in detection_pairs
    assert decision_actions["10.0.0.31"] == "MONITOR"
    assert decision_actions["10.0.0.32"] == "BLOCK"
    assert decision_actions["10.0.0.33"] == "THROTTLE"
    assert decision_actions["10.0.0.34"] == "MONITOR"
