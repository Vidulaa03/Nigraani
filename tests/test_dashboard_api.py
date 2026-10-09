import json

import backend.database as database
import backend.dashboard_api as dashboard_api
from backend.database import get_connection, init_db


def test_dashboard_counts_legacy_duplicates_and_latest_ip_recommendations(
    monkeypatch,
    tmp_path,
):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "dashboard.db")
    monkeypatch.setattr(dashboard_api, "get_detector", lambda: None)
    init_db()

    with get_connection() as conn:
        conn.executemany(
            """
            INSERT INTO detections (
                detector, attack_type, severity, ip, evidence, event_ids
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    "login_failure",
                    "Brute Force / Credential Guessing",
                    80,
                    "203.0.113.10",
                    "10 failed logins",
                    json.dumps(event_ids),
                )
                for event_ids in ([1, 2], [1, 2], [1, 2], [2, 3])
            ],
        )
        conn.execute(
            """
            INSERT INTO detections (
                detector, attack_type, severity, ip, evidence, event_ids
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                "alternate_login_detector",
                "Brute Force / Credential Guessing",
                80,
                "203.0.113.10",
                "Five failed logins",
                json.dumps([1, 2]),
            ),
        )
        conn.executemany(
            """
            INSERT INTO decisions (ip, risk_score, risk_level, action, reasons, source)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    "203.0.113.10",
                    80,
                    "BLOCK",
                    "BLOCK",
                    json.dumps(["brute force"]),
                    "analyzer",
                ),
                (
                    "203.0.113.10",
                    80,
                    "BLOCK",
                    "BLOCK",
                    json.dumps(["brute force"]),
                    "analyzer",
                ),
                (
                    "203.0.113.10",
                    80,
                    "BLOCK",
                    "BLOCK",
                    json.dumps(["brute force"]),
                    "analyzer",
                ),
                (
                    "203.0.113.11",
                    90,
                    "BLOCK",
                    "BLOCK",
                    json.dumps(["BOLA"]),
                    "analyzer",
                ),
                (
                    "203.0.113.10",
                    50,
                    "MONITOR",
                    "MONITOR",
                    json.dumps(["rate returned to normal"]),
                    "analyzer",
                ),
            ],
        )

    summary = dashboard_api.get_summary()
    threats = dashboard_api.get_threats()
    health = dashboard_api.get_health()

    assert summary["kpis"]["api_requests"] == 0
    assert summary["kpis"]["security_detections"] == 3
    assert summary["kpis"]["blocked_requests"] == 1
    assert summary["decision_distribution"] == {
        "ALLOW": 0,
        "MONITOR": 1,
        "THROTTLE": 0,
        "BLOCK": 1,
    }
    assert threats["summary"]["total_detections"] == 3
    assert health["database"]["counts"]["detections"] == 3
    assert health["database"]["counts"]["decisions"] == 3

    with get_connection() as conn:
        assert conn.execute("SELECT COUNT(*) FROM detections").fetchone()[0] == 5
        assert conn.execute("SELECT COUNT(*) FROM decisions").fetchone()[0] == 5
