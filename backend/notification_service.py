"""In-app notification service for NIGRAANI security incidents.

Provides persistent notification storage, idempotency, unread tracking,
and integration with the incident decision lifecycle.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

from backend.database import (
    get_notification_by_id,
    get_notifications,
    get_unread_notifications_count,
    insert_notification,
    mark_all_notifications_read,
    mark_notification_read,
)

# Minimum risk score to trigger an in-app notification (default: 50)
NOTIFICATION_MIN_SEVERITY = int(os.environ.get("NOTIFICATION_MIN_SEVERITY", "50"))


def _determine_severity_band(severity: int) -> str:
    if severity >= 80:
        return "CRITICAL"
    if severity >= 60:
        return "HIGH"
    if severity >= 30:
        return "MEDIUM"
    return "LOW"


def evaluate_and_notify_incident(
    decision: dict[str, Any],
    detections: list[dict[str, Any]],
    incident_id: str | int | None = None,
) -> dict[str, Any] | None:
    """Evaluate an incident decision and persist a notification if qualifying.

    Idempotent: Re-processing the same incident at the same severity level
    will not create duplicate records. Escalations (higher severity) will
    safely generate an updated notification.
    """
    risk_score = int(decision.get("risk_score", 0))
    action = str(decision.get("action", "ALLOW")).upper()
    ip = str(decision.get("ip", "unknown"))

    # Determine whether incident qualifies
    # Hackathon demo rule: rate_detector / Rate Spike always qualifies.
    has_rate_spike = any(
        d.get("detector") == "rate_detector" or d.get("attack_type") == "Rate Spike"
        for d in detections
    )
    if not has_rate_spike and risk_score < NOTIFICATION_MIN_SEVERITY and action not in {"THROTTLE", "BLOCK"}:
        return None

    actual_incident_id = str(incident_id if incident_id is not None else f"ip-{ip}-{risk_score}")
    severity_band = _determine_severity_band(risk_score)

    # Primary attack type and detector from detections
    attack_types = list(dict.fromkeys(d.get("attack_type", "Suspicious Activity") for d in detections))
    attack_summary = ", ".join(attack_types) if attack_types else "Suspicious API Activity"

    title = f"{severity_band} API Threat Detected — {ip}"
    message = (
        f"Recommended Action: {action} (Risk Score: {risk_score}/100). "
        f"Attacks: {attack_summary}."
    )

    # Idempotency key binds incident id, severity band, and action
    idempotency_key = f"{actual_incident_id}-{severity_band}-{action}"
    created_at = datetime.now(timezone.utc).isoformat()

    notification_payload = {
        "incident_id": actual_incident_id,
        "title": title,
        "message": message,
        "severity": risk_score,
        "severity_band": severity_band,
        "created_at": created_at,
        "is_read": False,
        "recipient": "soc-analyst",
        "idempotency_key": idempotency_key,
        "metadata": {
            "ip": ip,
            "action": action,
            "risk_score": risk_score,
            "risk_level": decision.get("risk_level", severity_band),
            "reasons": decision.get("reasons", []),
            "attack_types": attack_types,
            "detector_count": len(detections),
        },
    }

    notification_id = insert_notification(notification_payload)
    if notification_id is None:
        return None

    notification_payload["notification_id"] = notification_id
    return notification_payload


def list_notifications(
    limit: int = 50,
    offset: int = 0,
    unread_only: bool = False,
    severity_band: str | None = None,
) -> tuple[list[dict[str, Any]], int]:
    return get_notifications(
        limit=limit,
        offset=offset,
        unread_only=unread_only,
        severity_band=severity_band,
    )


def get_notification(notification_id: int) -> dict[str, Any] | None:
    return get_notification_by_id(notification_id)


def get_unread_count() -> int:
    return get_unread_notifications_count()


def set_notification_read(notification_id: int) -> bool:
    return mark_notification_read(notification_id)


def set_all_notifications_read() -> int:
    return mark_all_notifications_read()
