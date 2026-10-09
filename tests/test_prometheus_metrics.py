import asyncio

import backend.analyzer as analyzer
from backend.main import app
from backend.metrics import (
    ANALYSIS_RUNS,
    DETECTIONS,
    HTTP_REQUESTS,
    RISK_DECISIONS,
)


def request_asgi(path: str):
    async def run():
        sent = []
        request_sent = False

        async def receive():
            nonlocal request_sent
            if not request_sent:
                request_sent = True
                return {"type": "http.request", "body": b"", "more_body": False}
            return {"type": "http.disconnect"}

        async def send(message):
            sent.append(message)

        raw_path = path.encode("ascii")
        await app(
            {
                "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
                "method": "GET", "scheme": "http", "path": path, "raw_path": raw_path,
                "query_string": b"", "root_path": "", "headers": [],
                "server": ("testserver", 80), "client": ("127.0.0.1", 12345),
            },
            receive,
            send,
        )
        start = next(message for message in sent if message["type"] == "http.response.start")
        body = b"".join(message.get("body", b"") for message in sent if message["type"] == "http.response.body")
        return start["status"], body.decode("utf-8")

    return asyncio.run(run())


def test_http_metrics_use_route_template_and_metrics_scrape_is_excluded(monkeypatch):
    # Avoid writing test traffic to the user's security event database/log.
    monkeypatch.setattr("backend.main.log_security_event", lambda **kwargs: None)
    ok_before = HTTP_REQUESTS.labels("GET", "/api/users/{user_id}", "200")._value.get()
    missing_before = HTTP_REQUESTS.labels("GET", "/api/users/{user_id}", "404")._value.get()

    assert request_asgi("/api/users/101")[0] == 200
    assert request_asgi("/api/users/999999")[0] == 404
    after_requests = HTTP_REQUESTS.labels("GET", "/api/users/{user_id}", "200")._value.get()
    assert after_requests == ok_before + 1
    assert HTTP_REQUESTS.labels("GET", "/api/users/{user_id}", "404")._value.get() == missing_before + 1

    before_scrape = sum(sample.value for sample in HTTP_REQUESTS.collect()[0].samples if sample.name.endswith("_total"))
    metrics_status, metrics_text = request_asgi("/metrics")
    after_scrape = sum(sample.value for sample in HTTP_REQUESTS.collect()[0].samples if sample.name.endswith("_total"))

    assert metrics_status == 200
    assert "nigraani_http_requests_total" in metrics_text
    assert before_scrape == after_scrape
    assert "/api/users/101" not in metrics_text


def test_analysis_increments_real_detection_and_risk_metrics(monkeypatch):
    events = [
        {
            "event_id": i,
            "timestamp": f"2026-10-09T12:00:{i:02d}+00:00",
            "ip": "127.0.0.42",
            "user_id": None,
            "method": "POST",
            "endpoint": "/api/auth/login",
            "endpoint_pattern": "/api/auth/{action}",
            "resource_id": None,
            "resource_owner_id": None,
            "status_code": 401,
            "response_time_ms": 2.0,
            "sim_label": "test",
        }
        for i in range(1, 6)
    ]
    monkeypatch.setattr(analyzer, "get_events_since", lambda last_id: events)
    monkeypatch.setattr(analyzer, "_ANOMALY_DETECTOR", None)
    monkeypatch.setattr(analyzer, "insert_detection", lambda detection: 1)
    monkeypatch.setattr(analyzer, "insert_decision", lambda decision: 1)
    monkeypatch.setattr(analyzer, "_RECENT_EVENTS_BY_IP", {})
    detection_before = DETECTIONS.labels("login_failure_detector", "medium")._value.get()
    monitor_before = RISK_DECISIONS.labels("MONITOR")._value.get()
    runs_before = ANALYSIS_RUNS._value.get()

    assert analyzer.process_new_events() == 5

    assert DETECTIONS.labels("login_failure_detector", "medium")._value.get() == detection_before + 1
    assert RISK_DECISIONS.labels("MONITOR")._value.get() == monitor_before + 1
    assert ANALYSIS_RUNS._value.get() == runs_before + 1
