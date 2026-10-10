"""Keep every test away from the real demo.db and logs/api_events.jsonl.

The environment overrides below run when pytest loads this file, before any
test module imports backend.database (which calls init_db() on import) or
backend.security_logger. The autouse fixture then gives each test its own
database and JSONL log under tmp_path. Tests that monkeypatch these paths
themselves still work; they just override the per-test defaults.
"""

import hashlib
import os
import tempfile
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
# Real files that must not change, plus runtime files that must not appear.
REAL_DATA_FILES = (
    PROJECT_ROOT / "demo.db",
    PROJECT_ROOT / "logs" / "api_events.jsonl",
    PROJECT_ROOT / "logs" / "event_recovery_spool.jsonl",
    PROJECT_ROOT / "demo.db.analyzer-cursor.json",
)

_SESSION_DIR = Path(tempfile.mkdtemp(prefix="nigraani-tests-"))
os.environ["NIGRAANI_DB_PATH"] = str(_SESSION_DIR / "session.db")
os.environ["NIGRAANI_LOG_DIR"] = str(_SESSION_DIR / "logs")
os.environ["NIGRAANI_EVENT_SPOOL_PATH"] = str(_SESSION_DIR / "logs" / "event_recovery_spool.jsonl")
# The cursor defaults to a file next to the (temporary) database.
os.environ.pop("NIGRAANI_ANALYZER_CURSOR_PATH", None)
# Never place real Twilio calls from tests, and never let the developer's real
# .env change test behaviour: every alerting setting gets a fixed test value
# here, and load_dotenv() does not replace variables that are already set.
# Tests that exercise calling provide fake credentials and a mocked client.
os.environ.update(
    {
        "TWILIO_ACCOUNT_SID": "",
        "TWILIO_AUTH_TOKEN": "",
        "TWILIO_FROM_NUMBER": "",
        "TWILIO_TO_NUMBER": "",
        "TWILIO_CALLBACK_BASE_URL": "",
        "TWILIO_TRIAL_MODE": "false",
        "TWILIO_VOICE_ENABLED": "true",
        "TWILIO_MIN_SEVERITY": "80",
        "TWILIO_COOLDOWN_SECONDS": "300",
        "NOTIFICATION_MIN_SEVERITY": "50",
    }
)


def fingerprint_real_data() -> dict[Path, str | None]:
    return {
        path: hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None
        for path in REAL_DATA_FILES
    }


_REAL_DATA_AT_START = fingerprint_real_data()


@pytest.fixture(autouse=True)
def isolated_storage(monkeypatch, tmp_path):
    import backend.database as database
    import backend.event_recovery as event_recovery
    import backend.security_logger as security_logger

    monkeypatch.setattr(database, "DB_PATH", tmp_path / "nigraani-test.db")
    monkeypatch.setattr(security_logger, "LOG_FILE", tmp_path / "logs" / "api_events.jsonl")
    monkeypatch.setattr(
        event_recovery, "SPOOL_FILE", tmp_path / "logs" / "event_recovery_spool.jsonl"
    )
    database.init_db()
    yield


def pytest_sessionfinish(session, exitstatus):
    changed = [
        str(path)
        for path, digest in fingerprint_real_data().items()
        if digest != _REAL_DATA_AT_START[path]
    ]
    if changed:
        reporter = session.config.pluginmanager.get_plugin("terminalreporter")
        if reporter is not None:
            reporter.write_line(f"ERROR: tests modified real data files: {changed}", red=True)
        session.exitstatus = pytest.ExitCode.TESTS_FAILED
