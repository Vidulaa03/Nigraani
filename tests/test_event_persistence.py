import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import backend.analyzer as analyzer
import backend.database as database
import backend.event_recovery as event_recovery
import backend.main as main
import backend.security_logger as security_logger
from backend.analyzer import AnalyzerState, load_analyzer_state, save_analyzer_state
from backend.database import get_events_since, insert_event
from backend.detection.base import sample_event
from backend.event_recovery import replay_spool, spool_event
from backend.metrics import ANALYSIS_FAILURES, SECURITY_EVENT_SPOOL, SECURITY_EVENTS
from backend.security_logger import SecurityEventPersistenceError, log_security_event

PROJECT_ROOT = Path(__file__).resolve().parent.parent
START = datetime(2026, 10, 1, tzinfo=timezone.utc)
IP = "203.0.113.50"


def value(metric, *labels):
    return (metric.labels(*labels) if labels else metric)._value.get()


def failed_login(event_id, seconds, ip=IP):
    return sample_event(
        event_id=event_id,
        timestamp=(START + timedelta(seconds=seconds)).isoformat(),
        ip=ip,
        user_id=None,
        method="POST",
        endpoint="/api/auth/login",
        endpoint_pattern="/api/auth/{action}",
        resource_id=None,
        resource_owner_id=None,
        status_code=401,
        sim_label="login_bruteforce",
    )


def rows(table):
    with database.get_connection() as conn:
        return [dict(row) for row in conn.execute(f"SELECT * FROM {table}")]


def detection_event_sets():
    return sorted(
        sorted(json.loads(row["event_ids"]))
        for row in rows("detections")
        if row["detector"] == "login_failure_detector"
    )


def spool_lines(path=None):
    path = path or event_recovery.SPOOL_FILE
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


@pytest.fixture(autouse=True)
def fresh_analyzer(monkeypatch):
    monkeypatch.setattr(analyzer, "_RECENT_EVENTS_BY_IP", {})
    monkeypatch.setattr(analyzer, "_ACTIVE_STATE", None)
    monkeypatch.setattr(analyzer, "score_anomalies", lambda events: 0)


# --- runtime files stay in temporary storage --------------------------------


def test_spool_and_cursor_paths_are_temporary(tmp_path):
    assert event_recovery.SPOOL_FILE.is_relative_to(tmp_path)
    assert analyzer.cursor_path().is_relative_to(tmp_path)


# --- analyzer: backlog windows ----------------------------------------------


def test_backlog_spanning_minutes_is_analyzed_in_chronological_windows():
    for i in range(5):
        insert_event(failed_login(i + 1, seconds=i))
    for i in range(5):
        insert_event(failed_login(i + 6, seconds=240 + i))

    assert analyzer.process_new_events() == 10

    # Previously only the newest minute (events 6-10) was analyzed.
    assert detection_event_sets() == [[1, 2, 3, 4, 5], [6, 7, 8, 9, 10]]
    assert len(rows("decisions")) == 2


def test_window_spanning_a_restart_reads_earlier_events_from_the_database(monkeypatch):
    for i in range(3):
        insert_event(failed_login(i + 1, seconds=i))
    assert analyzer.process_new_events() == 3
    assert detection_event_sets() == []  # 3 failures: below the threshold

    monkeypatch.setattr(analyzer, "_RECENT_EVENTS_BY_IP", {})  # restart
    for i in range(3, 5):
        insert_event(failed_login(i + 1, seconds=i))

    assert analyzer.process_new_events(3) == 5
    assert detection_event_sets() == [[1, 2, 3, 4, 5]]


# --- analyzer: failures and retries -----------------------------------------


def test_failed_decision_save_leaves_batch_uncommitted_and_retry_is_idempotent(monkeypatch):
    for i in range(5):
        insert_event(failed_login(i + 1, seconds=i))
    real_insert_decision = analyzer.insert_decision
    calls = []

    def flaky_insert_decision(decision):
        calls.append(decision)
        if len(calls) == 1:
            raise sqlite3.OperationalError("database is locked")
        return real_insert_decision(decision)

    monkeypatch.setattr(analyzer, "insert_decision", flaky_insert_decision)
    failures_before = value(ANALYSIS_FAILURES)

    with pytest.raises(sqlite3.OperationalError):
        analyzer.process_new_events()

    assert value(ANALYSIS_FAILURES) == failures_before + 1
    assert analyzer._RECENT_EVENTS_BY_IP == {}  # cache not committed
    assert len(rows("detections")) == 1  # partial result
    assert rows("decisions") == []

    assert analyzer.process_new_events() == 5
    assert len(rows("detections")) == 1  # not duplicated
    assert len(rows("decisions")) == 1


def test_run_loop_survives_failures_with_bounded_backoff(monkeypatch, caplog):
    outcomes = [RuntimeError("down"), RuntimeError("down"), RuntimeError("down"), 7]
    seen_cursors = []

    def process(cursor):
        seen_cursors.append(cursor)
        outcome = outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    sleeps = []
    insert_event(sample_event(event_id=7))  # so cursor 7 is not "ahead of the database"
    monkeypatch.setattr(analyzer, "process_new_events", process)
    monkeypatch.setattr(analyzer.time, "sleep", sleeps.append)

    analyzer.run_loop(interval_seconds=5, stop_after=4, max_backoff_seconds=12)

    assert seen_cursors == [None, None, None, None]  # cursor held while failing
    assert sleeps == [5, 10, 12]
    assert "Analyzer batch failed (3 in a row)" in caplog.text
    assert load_analyzer_state().last_event_id == 7


# --- analyzer: cursor file ----------------------------------------------------


def test_cursor_is_saved_atomically_and_restart_resumes(monkeypatch):
    for i in range(3):
        insert_event(sample_event(event_id=i + 1, timestamp=(START + timedelta(seconds=i)).isoformat()))
    analyzer.run_loop(interval_seconds=0, stop_after=1)

    path = analyzer.cursor_path()
    saved = json.loads(path.read_text(encoding="utf-8"))
    assert saved["last_event_id"] == 3
    assert saved["database"] == str(database.DB_PATH.resolve())
    assert not path.with_name(f"{path.name}.tmp").exists()

    insert_event(sample_event(event_id=4, timestamp=(START + timedelta(seconds=4)).isoformat()))
    requested = []
    real_get_events_since = analyzer.get_events_since

    def spy(**kwargs):
        requested.append(kwargs)
        return real_get_events_since(**kwargs)

    monkeypatch.setattr(analyzer, "get_events_since", spy)
    analyzer.run_loop(interval_seconds=0, stop_after=1)

    assert requested[0]["last_event_id"] == 3
    assert load_analyzer_state().last_event_id == 4


def test_malformed_cursor_is_kept_aside_and_analysis_restarts(caplog):
    path = analyzer.cursor_path()
    path.write_text("{not json", encoding="utf-8")

    state = load_analyzer_state()

    assert state.last_event_id is None
    assert not path.exists()
    (kept,) = path.parent.glob(f"{path.name}.corrupt-*")
    assert kept.read_text(encoding="utf-8") == "{not json"
    assert "unreadable" in caplog.text


def test_cursor_ahead_of_database_or_for_another_database_restarts(caplog):
    insert_event(sample_event(event_id=5))
    save_analyzer_state(AnalyzerState(last_event_id=10**12))
    assert load_analyzer_state().last_event_id is None
    assert "ahead of the newest stored event" in caplog.text

    path = analyzer.cursor_path()
    data = json.loads(path.read_text(encoding="utf-8"))
    data.update(last_event_id=5, database="C:/somewhere/else.db")
    path.write_text(json.dumps(data), encoding="utf-8")
    assert load_analyzer_state().last_event_id is None
    assert "another database" in caplog.text


# --- analyzer: late and replayed events -------------------------------------


def test_late_event_below_cursor_is_analyzed_exactly_once(monkeypatch):
    state = AnalyzerState()
    monkeypatch.setattr(analyzer, "_ACTIVE_STATE", state)
    base = 1_000_000_000
    for i in range(1, 5):
        insert_event(failed_login(base + i, seconds=i))
    cursor = analyzer.process_new_events(None)
    assert cursor == base + 4
    assert detection_event_sets() == []

    # Another API process commits an earlier ID after the cursor passed it.
    insert_event(failed_login(base, seconds=0))
    assert analyzer.process_new_events(cursor) == cursor
    assert detection_event_sets() == [[base + i for i in range(5)]]

    assert analyzer.process_new_events(cursor) == cursor
    assert len(rows("detections")) == 1
    assert len(rows("decisions")) == 1


def test_run_loop_replays_spool_and_analyzes_events_far_below_cursor():
    high_id = 10**15
    insert_event(sample_event(event_id=high_id, ip="198.51.100.1"))
    save_analyzer_state(AnalyzerState(last_event_id=high_id))
    for i in range(5):
        assert spool_event(failed_login(i + 1, seconds=i), sqlite3.OperationalError("locked"))

    analyzer.run_loop(interval_seconds=0, stop_after=1)

    assert detection_event_sets() == [[1, 2, 3, 4, 5]]
    state = load_analyzer_state()
    assert state.last_event_id == high_id
    assert state.pending_event_ids == set()
    assert spool_lines() == []


# --- logger: recovery spool -------------------------------------------------


def _fail_inserts(monkeypatch):
    def locked(event, **kwargs):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(security_logger, "insert_event", locked)


def test_database_failure_spools_validated_event_with_original_id_and_timestamp(monkeypatch):
    _fail_inserts(monkeypatch)
    stored_before = value(SECURITY_EVENTS, "stored")
    failed_before = value(SECURITY_EVENTS, "failed")
    queued_before = value(SECURITY_EVENT_SPOOL, "queued")

    with pytest.raises(SecurityEventPersistenceError) as raised:
        log_security_event(
            ip="10.0.0.1", method="GET", endpoint="/api/users/101", status_code=200,
            response_time_ms=1.5, timestamp="2026-10-01T00:00:00+00:00",
        )

    assert raised.value.spooled is True
    (entry,) = spool_lines()
    assert entry["event"]["timestamp"] == "2026-10-01T00:00:00+00:00"
    assert entry["event"]["resource_id"] == 101
    assert entry["attempts"] == 0
    assert entry["checksum"] == event_recovery._checksum(entry["event"])
    assert get_events_since() == []
    assert not security_logger.LOG_FILE.exists()
    assert value(SECURITY_EVENTS, "stored") == stored_before  # never "stored"
    assert value(SECURITY_EVENTS, "failed") == failed_before + 1
    assert value(SECURITY_EVENT_SPOOL, "queued") == queued_before + 1


def test_replay_stores_spooled_event_once_and_appends_jsonl():
    event = sample_event(event_id=77)
    assert spool_event(event, sqlite3.OperationalError("locked"))

    summary = replay_spool()

    assert summary.replayed == [77]
    assert [e["event_id"] for e in get_events_since()] == [77]
    jsonl = security_logger.LOG_FILE.read_text(encoding="utf-8").splitlines()
    assert [json.loads(line)["event_id"] for line in jsonl] == [77]
    assert spool_lines() == []
    assert list(event_recovery.SPOOL_FILE.parent.glob("*replaying*")) == []

    again = replay_spool()
    assert again.replayed == [] and again.already_present == 0
    assert len(get_events_since()) == 1


def test_replay_of_an_already_stored_event_is_idempotent():
    event = sample_event(event_id=78)
    insert_event(event)
    spool_event(event, sqlite3.OperationalError("locked"))

    summary = replay_spool()

    assert summary.already_present == 1
    assert summary.replayed == []
    assert len(get_events_since()) == 1
    assert spool_lines() == []


def test_replay_never_overwrites_a_different_event_with_the_same_id():
    insert_event(sample_event(event_id=79, endpoint="/stored"))
    spool_event(sample_event(event_id=79, endpoint="/spooled"), sqlite3.OperationalError("x"))

    summary = replay_spool()

    assert summary.quarantined == {"conflict": 1}
    assert [e["endpoint"] for e in get_events_since()] == ["/stored"]
    (kept,) = spool_lines(event_recovery.quarantine_file("conflict"))
    assert kept["event"]["endpoint"] == "/spooled"


def test_corrupt_and_incomplete_entries_are_quarantined_and_valid_ones_replayed():
    spool_event(sample_event(event_id=80), sqlite3.OperationalError("x"))
    good = event_recovery.SPOOL_FILE.read_text(encoding="utf-8")
    tampered = json.loads(good)
    tampered["event"]["endpoint"] = "/tampered"
    with open(event_recovery.SPOOL_FILE, "a", encoding="utf-8") as file:
        file.write("this is not json\n")
        file.write(json.dumps(tampered) + "\n")
        file.write(good.strip()[:40])  # crash mid-write: no newline

    summary = replay_spool()

    assert summary.replayed == [80]
    assert summary.quarantined == {"corrupt": 3}
    assert spool_lines() == []
    corrupt = event_recovery.quarantine_file("corrupt").read_text(encoding="utf-8")
    assert len(corrupt.splitlines()) == 3


def test_failed_replay_keeps_entries_and_gives_up_after_max_attempts(monkeypatch):
    spool_event(sample_event(event_id=81), sqlite3.OperationalError("x"))
    spool_event(sample_event(event_id=82), sqlite3.OperationalError("x"))

    def still_locked(event, **kwargs):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(event_recovery, "insert_event", still_locked)

    first = replay_spool()
    assert first.stopped_early and first.requeued == 2
    assert [(e["event"]["event_id"], e["attempts"]) for e in spool_lines()] == [(81, 1), (82, 0)]

    for _ in range(event_recovery.MAX_REPLAY_ATTEMPTS - 1):
        replay_spool()

    assert [(e["event"]["event_id"], e["attempts"]) for e in spool_lines()] == [(82, 0)]
    (exhausted,) = spool_lines(event_recovery.quarantine_file("exhausted"))
    assert (exhausted["event"]["event_id"], exhausted["attempts"]) == (81, 10)
    assert get_events_since() == []


def test_spool_refuses_invalid_events_and_respects_its_size_limit(monkeypatch, caplog):
    assert not spool_event(sample_event(event_id=83) | {"ip": "bad"}, RuntimeError())

    monkeypatch.setattr(event_recovery, "MAX_SPOOL_BYTES", 10)
    full_before = value(SECURITY_EVENT_SPOOL, "spool_full")
    assert not spool_event(sample_event(event_id=84), RuntimeError())
    assert value(SECURITY_EVENT_SPOOL, "spool_full") == full_before + 1
    assert "spool" in caplog.text and "is full" in caplog.text
    assert spool_lines() == []


def test_real_sqlite_lock_spools_request_event_and_replay_recovers(monkeypatch):
    monkeypatch.setattr(security_logger, "EVENT_WRITE_TIMEOUT_SECONDS", 0.2)
    monkeypatch.setattr(database, "SQLITE_TIMEOUT_SECONDS", 0.2)
    blocker = sqlite3.connect(database.DB_PATH)
    blocker.execute("BEGIN EXCLUSIVE")
    try:
        response = TestClient(main.app, client=("127.0.0.1", 1)).get("/api/users/101")
        assert response.status_code == 200
    finally:
        blocker.rollback()
        blocker.close()

    assert get_events_since() == []
    (entry,) = spool_lines()
    assert entry["event"]["endpoint"] == "/api/users/101"

    assert len(replay_spool().replayed) == 1
    assert [e["endpoint"] for e in get_events_since()] == ["/api/users/101"]


def test_two_processes_logging_concurrently_lose_and_duplicate_nothing(tmp_path):
    env = {
        **os.environ,
        "NIGRAANI_DB_PATH": str(database.DB_PATH),
        "NIGRAANI_LOG_DIR": str(security_logger.LOG_FILE.parent),
        "NIGRAANI_EVENT_SPOOL_PATH": str(event_recovery.SPOOL_FILE),
    }
    script = (
        "import sys, backend.security_logger as s\n"
        "for i in range(150):\n"
        "    try:\n"
        "        s.log_security_event(ip='10.9.0.' + sys.argv[1], method='GET',\n"
        "                             endpoint='/', status_code=200, response_time_ms=1)\n"
        "    except s.SecurityEventPersistenceError as error:\n"
        "        assert error.spooled, error\n"
    )
    processes = [
        subprocess.Popen([sys.executable, "-c", script, str(n)], cwd=PROJECT_ROOT, env=env)
        for n in (1, 2)
    ]
    assert [process.wait(timeout=120) for process in processes] == [0, 0]

    replay_spool()

    events = get_events_since()
    assert len(events) == 300
    assert len({e["event_id"] for e in events}) == 300
    jsonl = security_logger.LOG_FILE.read_text(encoding="utf-8").splitlines()
    assert sorted(json.loads(line)["event_id"] for line in jsonl) == sorted(
        e["event_id"] for e in events
    )


# --- JSONL integrity --------------------------------------------------------


def test_jsonl_append_starts_a_new_line_after_a_partial_line():
    security_logger.LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    security_logger.LOG_FILE.write_text('{"event_id": 1, "trunc', encoding="utf-8")

    event = log_security_event(ip="10.0.0.1", method="GET", endpoint="/", status_code=200, response_time_ms=1)

    lines = security_logger.LOG_FILE.read_text(encoding="utf-8").splitlines()
    assert lines[0] == '{"event_id": 1, "trunc'
    assert json.loads(lines[1])["event_id"] == event["event_id"]


def test_reconcile_reports_differences_without_writing():
    insert_event(sample_event(event_id=2))
    insert_event(sample_event(event_id=3))
    jsonl = security_logger.LOG_FILE
    jsonl.parent.mkdir(parents=True, exist_ok=True)
    jsonl.write_text(
        '{"event_id": 1}\n{"event_id": 2}\n{"event_id": 2}\nnot json\n{"event_id": 4',
        encoding="utf-8",
    )
    before = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in (jsonl, database.DB_PATH)}

    report = event_recovery.reconcile()

    assert report["jsonl_lines"] == 5
    assert report["duplicate_jsonl_ids"] == 1
    assert report["malformed_jsonl_lines"] == [4, 5]
    assert report["only_in_jsonl"] == [1]
    assert report["only_in_database"] == [3]
    assert {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in before} == before


# --- bounded logging wait and recovery bookkeeping ---------------------------


def test_busy_writer_spools_within_bounded_time(monkeypatch):
    import time as clock

    monkeypatch.setattr(security_logger, "LOCK_WAIT_SECONDS", 0.2)
    security_logger._write_lock.acquire()  # simulate writers stuck on a locked database
    try:
        started = clock.perf_counter()
        with pytest.raises(SecurityEventPersistenceError) as raised:
            log_security_event(ip="10.0.0.1", method="GET", endpoint="/", status_code=200, response_time_ms=1)
        elapsed = clock.perf_counter() - started
    finally:
        security_logger._write_lock.release()

    assert raised.value.spooled is True
    assert elapsed < 1.0
    (entry,) = spool_lines()
    assert entry["last_error"] == "TimeoutError"
    assert get_events_since() == []
    assert len(replay_spool().replayed) == 1
    assert len(get_events_since()) == 1


def test_recovered_ids_survive_a_crash_before_they_were_recorded():
    spool_event(sample_event(event_id=90), sqlite3.OperationalError("x"))

    def crash(ids):
        raise OSError("simulated crash before the analyzer saved pending IDs")

    with pytest.raises(OSError):
        replay_spool(on_recovered=crash)
    assert [e["event_id"] for e in get_events_since()] == [90]  # inserted
    assert list(event_recovery.SPOOL_FILE.parent.glob("*replaying*"))  # claim kept

    recorded = []
    summary = replay_spool(on_recovered=recorded.extend)

    assert summary.already_present == 1
    assert recorded == [90]  # still handed to the analyzer
    assert list(event_recovery.SPOOL_FILE.parent.glob("*replaying*")) == []
    assert len(get_events_since()) == 1
