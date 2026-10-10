"""Twilio outbound voice calling service for NIGRAANI.

Provides end-to-end voice alerting: credentials resolution, TwiML briefing
generation, duplicate call prevention and cooldowns, persistence,
Twilio webhook status callback processing, and protected test calling.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any
import xml.sax.saxutils as xml_escape

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from backend.database import (
    get_call_alert_by_sid,
    get_call_alerts,
    get_last_call_for_incident,
    insert_call_alert,
    update_call_alert_status,
)

# Optional twilio SDK import
try:
    from twilio.rest import Client as TwilioClient
    from twilio.request_validator import RequestValidator
    TWILIO_SDK_AVAILABLE = True
except ImportError:
    TWILIO_SDK_AVAILABLE = False
    TwilioClient = None
    RequestValidator = None


def mask_phone_number(number: str | None) -> str:
    """Mask phone number to preserve privacy in responses and UI."""
    if not number:
        return ""
    clean = number.strip()
    if len(clean) <= 4:
        return "***"
    return f"{clean[:2]}***{clean[-4:]}"


def get_voice_config_status() -> dict[str, Any]:
    """Return safe public configuration status without exposing credentials."""
    account_sid = os.environ.get("TWILIO_ACCOUNT_SID", "").strip()
    auth_token = os.environ.get("TWILIO_AUTH_TOKEN", "").strip()
    from_number = os.environ.get("TWILIO_FROM_NUMBER", "").strip()
    to_number = os.environ.get("TWILIO_TO_NUMBER", "").strip()
    voice_enabled_env = os.environ.get("TWILIO_VOICE_ENABLED", "true").lower() in ("true", "1", "yes")

    has_credentials = bool(
        account_sid
        and auth_token
        and from_number
        and to_number
        and not account_sid.startswith("ACXXXX")
    )
    enabled = has_credentials and voice_enabled_env

    return {
        "sdk_available": TWILIO_SDK_AVAILABLE,
        "configured": has_credentials,
        "enabled": enabled,
        "from_number_masked": mask_phone_number(from_number),
        "to_number_masked": mask_phone_number(to_number),
        "min_severity": int(os.environ.get("TWILIO_MIN_SEVERITY", "80")),
        "cooldown_seconds": int(os.environ.get("TWILIO_COOLDOWN_SECONDS", "300")),
        "callback_configured": bool(os.environ.get("TWILIO_CALLBACK_BASE_URL", "").strip()),
    }


def generate_twiml_briefing(
    ip: str,
    risk_score: int,
    action: str,
    attack_types: list[str],
    endpoint: str | None = None,
) -> str:
    """Construct safe XML/TwiML with spoken incident briefing."""
    ep_text = f"on endpoint {endpoint}" if endpoint and endpoint != "No data" else ""
    pattern_text = ", ".join(attack_types) if attack_types else "suspicious API patterns"
    
    clean_ip = " dot ".join(ip.split("."))
    clean_action = xml_escape.escape(action)
    clean_pattern = xml_escape.escape(pattern_text)
    clean_ep = xml_escape.escape(ep_text)

    speech = (
        f"Attention. NIGRAANI Security Alert. "
        f"Critical security incident detected {clean_ep}. "
        f"Source I P address {clean_ip}. "
        f"Risk score is {risk_score} out of 100. "
        f"Detected threat pattern: {clean_pattern}. "
        f"Recommended enforcement action: {clean_action}. "
        f"Please inspect the NIGRAANI Security Operations dashboard immediately."
    )

    return (
        f'<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<Response>\n'
        f'    <Say voice="Polly.Joanna" language="en-US">{speech}</Say>\n'
        f'</Response>'
    )


def should_initiate_call(
    incident_id: str,
    severity: int,
    is_test: bool = False,
    is_rate_spike_demo: bool = False,
) -> tuple[bool, str]:
    """Evaluate calling policy, credentials, thresholds, and cooldown."""
    config = get_voice_config_status()
    if not config["sdk_available"]:
        return False, "Twilio Python SDK is not installed"
    if not config["configured"]:
        return False, "Twilio voice credentials are not configured"
    if not config["enabled"]:
        return False, "Twilio voice alerting is disabled"

    min_severity = config["min_severity"]
    # Demo requirement: Rate spike threshold breach (30 reqs in 10s) qualifies without requiring risk score 85
    if not is_test and not is_rate_spike_demo and severity < min_severity:
        return False, f"Severity {severity} is below voice threshold ({min_severity})"

    # Check cooldown / duplicate call prevention
    last_call = get_last_call_for_incident(incident_id)
    if last_call:
        try:
            initiated_at = datetime.fromisoformat(
                str(last_call["initiated_at"]).replace("Z", "+00:00")
            )
            now = datetime.now(timezone.utc)
            elapsed = (now - initiated_at).total_seconds()
            cooldown = config["cooldown_seconds"]
            if elapsed < cooldown:
                return False, f"Call cooldown active ({int(cooldown - elapsed)}s remaining for this incident)"
        except Exception:
            pass

    return True, "Call authorized"


def initiate_voice_alert(
    incident_id: str,
    decision: dict[str, Any],
    detections: list[dict[str, Any]],
    notification_id: int | None = None,
    is_test: bool = False,
    endpoint: str | None = None,
) -> dict[str, Any]:
    """Initiate an outbound voice alert via Twilio and persist the attempt."""
    severity = int(decision.get("risk_score", 80))
    action = str(decision.get("action", "BLOCK")).upper()
    ip = str(decision.get("ip", "unknown"))

    has_rate_spike = any(
        d.get("detector") == "rate_detector" or d.get("attack_type") == "Rate Spike"
        for d in detections
    )
    allowed, reason = should_initiate_call(
        incident_id,
        severity,
        is_test=is_test,
        is_rate_spike_demo=has_rate_spike,
    )
    if not allowed:
        return {
            "success": False,
            "status": "skipped",
            "reason": reason,
            "incident_id": incident_id,
        }

    account_sid = os.environ.get("TWILIO_ACCOUNT_SID", "").strip()
    auth_token = os.environ.get("TWILIO_AUTH_TOKEN", "").strip()
    from_number = os.environ.get("TWILIO_FROM_NUMBER", "").strip()
    to_number = os.environ.get("TWILIO_TO_NUMBER", "").strip()
    callback_base = os.environ.get("TWILIO_CALLBACK_BASE_URL", "").strip().rstrip("/")

    attack_types = list(dict.fromkeys(d.get("attack_type", "Threat") for d in detections))
    twiml = generate_twiml_briefing(
        ip=ip,
        risk_score=severity,
        action=action,
        attack_types=attack_types,
        endpoint=endpoint,
    )

    initiated_at = datetime.now(timezone.utc).isoformat()
    callback_url = f"{callback_base}/api/dashboard/calls/callback" if callback_base else None
    trial_mode = os.environ.get("TWILIO_TRIAL_MODE", "false").strip().lower() in (
        "true", "1", "yes"
    )

    import urllib.parse
    speech_summary = f"Attention. NIGRAANI Security Alert. High severity API threat detected from IP {ip}. Risk score {severity}. Recommended action {action}."
    twimlet_url = f"https://twimlets.com/message?{urllib.parse.urlencode({'Message[0]': speech_summary})}"

    try:
        client = TwilioClient(account_sid, auth_token)
        if trial_mode:
            call_kwargs: dict[str, Any] = {
                "to": to_number,
                "from_": from_number,
                "url": twimlet_url,
            }
            if callback_url:
                call_kwargs["status_callback"] = callback_url
        else:
            call_kwargs = {
                "to": to_number,
                "from_": from_number,
                "twiml": twiml,
            }
            if callback_url:
                call_kwargs["status_callback"] = callback_url
                call_kwargs["status_callback_event"] = ["initiated", "ringing", "answered", "completed"]
                call_kwargs["status_callback_method"] = "POST"

        try:
            call = client.calls.create(**call_kwargs)
        except Exception as create_err:
            err_lower = str(create_err).lower()
            if "trial" in err_lower or "disallowed parameters" in err_lower or "limited parameter access" in err_lower:
                # Automatic failover for Twilio trial accounts that prohibit raw inline twiml parameter
                trial_kwargs = {
                    "to": to_number,
                    "from_": from_number,
                    "url": twimlet_url,
                }
                if callback_url:
                    trial_kwargs["status_callback"] = callback_url
                call = client.calls.create(**trial_kwargs)
            else:
                raise create_err

        call_sid = call.sid
        call_status = str(call.status or "initiated")
    except Exception as exc:
        error_msg = str(exc)
        # Generate pseudo-SID for persisted record of failure
        failed_sid = f"FAILED_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
        insert_call_alert({
            "call_sid": failed_sid,
            "incident_id": incident_id,
            "notification_id": notification_id,
            "to_number": to_number,
            "from_number": from_number,
            "trigger_reason": f"Call attempt failed: {error_msg}",
            "status": "failed",
            "severity": severity,
            "initiated_at": initiated_at,
            "completed_at": initiated_at,
            "error_message": error_msg,
            "metadata": {"ip": ip, "action": action, "is_test": is_test},
        })
        return {
            "success": False,
            "status": "failed",
            "error": error_msg,
            "incident_id": incident_id,
        }

    # Persist the newly created call
    insert_call_alert({
        "call_sid": call_sid,
        "incident_id": incident_id,
        "notification_id": notification_id,
        "to_number": to_number,
        "from_number": from_number,
        "trigger_reason": f"{'Test Call: ' if is_test else ''}{action} decision for {ip} (Risk {severity})",
        "status": call_status,
        "severity": severity,
        "initiated_at": initiated_at,
        "metadata": {
            "ip": ip,
            "action": action,
            "is_test": is_test,
            "attack_types": attack_types,
            "endpoint": endpoint,
        },
    })

    return {
        "success": True,
        "status": call_status,
        "call_sid": call_sid,
        "incident_id": incident_id,
        "to_number_masked": mask_phone_number(to_number),
        "initiated_at": initiated_at,
    }


def handle_twilio_callback(
    form_data: dict[str, str],
    signature: str | None = None,
    url: str | None = None,
) -> dict[str, Any]:
    """Process incoming Twilio call status webhook."""
    call_sid = form_data.get("CallSid")
    call_status = form_data.get("CallStatus", "unknown").lower()
    call_duration_str = form_data.get("CallDuration")
    call_duration = int(call_duration_str) if call_duration_str and call_duration_str.isdigit() else None
    error_code = form_data.get("ErrorCode")
    error_msg = f"Twilio Error {error_code}" if error_code else None

    if not call_sid:
        return {"success": False, "error": "Missing CallSid"}

    # Validate signature if validator and token are available
    auth_token = os.environ.get("TWILIO_AUTH_TOKEN", "").strip()
    if signature and url and auth_token and RequestValidator:
        validator = RequestValidator(auth_token)
        if not validator.validate(url, form_data, signature):
            return {"success": False, "error": "Invalid Twilio signature"}

    completed_at = None
    if call_status in {"completed", "failed", "busy", "no-answer", "canceled"}:
        completed_at = datetime.now(timezone.utc).isoformat()

    updated = update_call_alert_status(
        call_sid=call_sid,
        status=call_status,
        duration=call_duration,
        completed_at=completed_at,
        error_message=error_msg,
    )

    return {
        "success": updated,
        "call_sid": call_sid,
        "status": call_status,
        "updated": updated,
    }


def trigger_manual_test_call() -> dict[str, Any]:
    """Initiate a controlled verification test call using the authorized configured number."""
    test_incident_id = f"test-call-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
    test_decision = {
        "ip": "127.0.0.1",
        "risk_score": 95,
        "action": "BLOCK",
        "reasons": ["Manual operator test verification call"],
    }
    test_detections = [
        {
            "detector": "operator_test",
            "attack_type": "Operator Verification Test",
            "severity": 95,
            "ip": "127.0.0.1",
        }
    ]

    return initiate_voice_alert(
        incident_id=test_incident_id,
        decision=test_decision,
        detections=test_detections,
        is_test=True,
        endpoint="/api/orders/test",
    )


def list_calls(
    limit: int = 50,
    offset: int = 0,
    incident_id: str | None = None,
) -> tuple[list[dict[str, Any]], int]:
    calls, total = get_call_alerts(limit=limit, offset=offset, incident_id=incident_id)
    # Mask numbers in returned objects
    for call in calls:
        call["to_number"] = mask_phone_number(call.get("to_number"))
        call["from_number"] = mask_phone_number(call.get("from_number"))
    return calls, total


def get_call_details(call_sid: str) -> dict[str, Any] | None:
    call = get_call_alert_by_sid(call_sid)
    if call:
        call["to_number"] = mask_phone_number(call.get("to_number"))
        call["from_number"] = mask_phone_number(call.get("from_number"))
    return call
