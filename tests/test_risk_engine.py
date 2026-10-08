from detection.risk_engine import compute_risk


def test_compute_risk_allows_clean_activity():
    result = compute_risk([], 0)
    assert result["risk_score"] == 0
    assert result["risk_level"] == "ALLOW"
    assert result["action"] == "ALLOW"


def test_compute_risk_blocks_for_one_strong_bola_detection():
    result = compute_risk([{"detector": "bola", "severity": 90}], 0)
    assert result["risk_score"] == 90
    assert result["risk_level"] == "BLOCK"
    assert result["action"] == "BLOCK"
    assert "bola" in result["reasons"][0].lower()


def test_compute_risk_monitors_when_only_ml_is_high():
    result = compute_risk([], 80)
    assert result["risk_score"] == 48
    assert result["risk_level"] == "MONITOR"
    assert result["action"] == "MONITOR"


def test_compute_risk_adds_points_for_distinct_detectors_only():
    result = compute_risk(
        [
            {"detector": "bola", "severity": 50},
            {"detector": "bola", "severity": 40},
            {"detector": "rate_spike", "severity": 45},
        ],
        0,
    )
    assert result["risk_score"] == 60
    assert result["risk_level"] == "THROTTLE"
    assert result["action"] == "THROTTLE"
    assert "2 distinct detectors" in result["reasons"][1]


def test_compute_risk_adds_agreement_bonus_for_rules_and_ml():
    result = compute_risk(
        [
            {"detector": "bola", "severity": 45},
            {"detector": "rate_spike", "severity": 40},
        ],
        60,
    )
    assert result["risk_score"] == 70
    assert result["risk_level"] == "THROTTLE"
    assert result["action"] == "THROTTLE"
    assert result["reasons"][-1] == "ML anomaly score 60.0"
