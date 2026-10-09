import pytest
from fastapi.testclient import TestClient

import backend.database as database
import backend.security_logger as security_logger
from backend.main import app
from simulation.attacks import low_slow_anomaly as sim


@pytest.mark.parametrize("seed", range(10))
def test_plan_stays_below_every_rule_detector(seed):
    plan = sim.build_plan(120, sim.DEFAULT_INTERVAL_SECONDS, sim.DEFAULT_JITTER_SECONDS, seed)
    assert sim.rule_detections_for_plan(plan) == []


def test_plan_is_paced_varied_and_mostly_errors():
    plan = sim.build_plan(90, 2.5, 0.5, 7)
    gaps = [b["offset"] - a["offset"] for a, b in zip(plan, plan[1:])]
    assert min(gaps) >= sim.MIN_INTERVAL_SECONDS
    assert len({item["pattern"] for item in plan}) >= 6
    assert sum(item["expected"] == 404 for item in plan) / len(plan) >= 0.5
    assert sim.build_plan(90, 2.5, 0.5, 7) == plan


def test_plan_requests_return_expected_status_from_the_api(monkeypatch, tmp_path):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "demo.db")
    monkeypatch.setattr(security_logger, "LOG_FILE", tmp_path / "api_events.jsonl")
    database.init_db()
    client = TestClient(app)
    for item in sim.build_plan(90, 2.5, 0.5, 7):
        response = client.request(
            item["method"],
            item["path"],
            headers={**item["headers"], "X-Forwarded-For": sim.SIMULATED_IP, "X-Sim-Label": sim.SCENARIO},
            json=item["body"],
        )
        assert response.status_code == item["expected"], item["path"]


def test_script_only_targets_the_local_api():
    assert sim.BASE_URL == "http://127.0.0.1:8000"
