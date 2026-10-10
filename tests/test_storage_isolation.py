import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

from fastapi.testclient import TestClient

import backend.database as database
import backend.security_logger as security_logger
from backend.main import app

PROJECT_ROOT = Path(__file__).resolve().parent.parent
REAL_DATA_FILES = (
    PROJECT_ROOT / "demo.db",
    PROJECT_ROOT / "logs" / "api_events.jsonl",
)


def fingerprint_real_data() -> dict[Path, str | None]:
    return {
        path: hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None
        for path in REAL_DATA_FILES
    }


def test_storage_paths_are_temporary(tmp_path):
    real_db, real_log = REAL_DATA_FILES
    assert database.DB_PATH.resolve() != real_db.resolve()
    assert security_logger.LOG_FILE.resolve() != real_log.resolve()
    assert database.DB_PATH.is_relative_to(tmp_path)
    assert security_logger.LOG_FILE.is_relative_to(tmp_path)


def test_environment_override_applies_before_import(tmp_path):
    env = {
        **os.environ,
        "NIGRAANI_DB_PATH": str(tmp_path / "fresh.db"),
        "NIGRAANI_LOG_DIR": str(tmp_path / "fresh-logs"),
    }
    output = subprocess.run(
        [
            sys.executable,
            "-c",
            "import backend.security_logger as s, backend.database as d;"
            "print(d.DB_PATH); print(s.LOG_FILE)",
        ],
        cwd=PROJECT_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.splitlines()

    assert output[-2:] == [
        str(tmp_path / "fresh.db"),
        str(tmp_path / "fresh-logs" / "api_events.jsonl"),
    ]
    assert (tmp_path / "fresh.db").exists()


def test_logged_requests_reach_only_temporary_storage():
    before = fingerprint_real_data()

    response = TestClient(app).get("/api/users/101", headers={"X-User-ID": "101"})

    assert response.status_code == 200
    assert [event["endpoint"] for event in database.get_events_since()] == ["/api/users/101"]
    lines = security_logger.LOG_FILE.read_text(encoding="utf-8").splitlines()
    assert [json.loads(line)["endpoint"] for line in lines] == ["/api/users/101"]
    assert fingerprint_real_data() == before
