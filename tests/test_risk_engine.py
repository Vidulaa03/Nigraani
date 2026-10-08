from detection.risk_engine import compute_risk


def test_compute_risk_allows_clean_activity():
    result = compute_risk([], 0)
    assert result["risk_score"] == 0
    assert result["risk_level"] == "ALLOW"
    assert result["action"] == "ALLOW"


def test_compute_risk_blocks_for_high_rule_and_ml_agreement():
    result = compute_risk(
        [
            {"detector": "bola", "severity": 90},
            {"detector": "rate_spike", "severity": 75},
        ],
        80,
    )
    assert result["risk_score"] >= 80
    assert result["action"] in {"BLOCK", "THROTTLE"}
    assert "bola" in result["reasons"][0].lower()


def test_compute_risk_monitors_when_only_ml_is_high():
    result = compute_risk([], 80)
    assert result["risk_level"] == "MONITOR"
    assert result["action"] == "MONITOR"
