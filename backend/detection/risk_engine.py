from __future__ import annotations

from typing import Any


def _rule_score(detections: list[dict[str, Any]]) -> tuple[int, list[str]]:
    if not detections:
        return 0, []

    highest_severity = max(int(item.get("severity", 0)) for item in detections)
    detector_names = sorted({str(item.get("detector", "unknown")) for item in detections})
    extra_detectors = max(len(detector_names) - 1, 0)
    rule_score = highest_severity + (extra_detectors * 10)
    reasons = [
        f"Detected by {', '.join(detector_names)} with highest severity {highest_severity}",
        f"Detected across {len(detector_names)} distinct detectors",
    ]
    return min(rule_score, 100), reasons


def compute_risk(detections: list[dict[str, Any]], ml_score: float | int = 0) -> dict[str, Any]:
    """Compute the aggregated risk score and recommend an enforcement action."""
    ml_value = max(0, min(float(ml_score), 100))

    if not detections and ml_value == 0:
        return {
            "risk_score": 0,
            "risk_level": "ALLOW",
            "action": "ALLOW",
            "reasons": ["No detections and no anomaly signal"],
        }

    rule_score, rule_reasons = _rule_score(detections)
    ml_component = 0.6 * ml_value
    combined = max(rule_score, ml_component)

    if rule_score >= 30 and ml_value >= 60:
        combined += 15

    risk_score = min(int(round(combined)), 100)

    if risk_score <= 29:
        risk_level = "ALLOW"
        action = "ALLOW"
    elif risk_score <= 59:
        risk_level = "MONITOR"
        action = "MONITOR"
    elif risk_score <= 79:
        risk_level = "THROTTLE"
        action = "THROTTLE"
    else:
        risk_level = "BLOCK"
        action = "BLOCK"

    reasons = rule_reasons + [f"ML anomaly score {ml_value:.1f}"]
    if rule_score == 0:
        reasons = [f"ML anomaly score {ml_value:.1f}"]

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "action": action,
        "reasons": reasons,
    }
