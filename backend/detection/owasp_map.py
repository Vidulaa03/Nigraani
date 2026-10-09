"""OWASP API Security Top 10 classifications for project detection signals."""

_BOLA_MAPPING = {
    "owasp_id": "API1:2023",
    "name": "Broken Object Level Authorization",
    "what_we_detect": (
        "Successful access to another user's resource when both user and "
        "resource ownership are available."
    ),
    "what_we_dont": (
        "Authorization failures where ownership information is unavailable "
        "or the request does not succeed."
    ),
}
_ENUMERATION_MAPPING = {
    "owasp_id": "API1:2023",
    "name": "Broken Object Level Authorization",
    "what_we_detect": (
        "Suspicious resource-ID probing patterns within an endpoint pattern."
    ),
    "what_we_dont": (
        "Every form of object-level authorization failure or probing."
    ),
}
_LOGIN_FAILURE_MAPPING = {
    "owasp_id": "API2:2023",
    "name": "Broken Authentication",
    "what_we_detect": "Repeated failed login attempts.",
    "what_we_dont": (
        "All authentication weaknesses, account takeover, or successful "
        "credential abuse."
    ),
}
_RATE_SPIKE_MAPPING = {
    "owasp_id": "API4:2023",
    "name": "Unrestricted Resource Consumption",
    "what_we_detect": "Abnormally high request volume.",
    "what_we_dont": (
        "All forms of resource exhaustion or the business impact of requests."
    ),
}
_ML_MAPPING = {
    "owasp_id": "N/A",
    "name": "No single OWASP category",
    "what_we_detect": "Behavioral anomalies identified by the ML score.",
    "what_we_dont": (
        "A specific OWASP API Security Top 10 category or a confirmed attack."
    ),
}

OWASP_MAP = {
    "bola": _BOLA_MAPPING,
    "bola_detector": _BOLA_MAPPING,
    "enumeration": _ENUMERATION_MAPPING,
    "enumeration_detector": _ENUMERATION_MAPPING,
    "login_failure": _LOGIN_FAILURE_MAPPING,
    "login_failure_detector": _LOGIN_FAILURE_MAPPING,
    "rate_spike": _RATE_SPIKE_MAPPING,
    "rate_detector": _RATE_SPIKE_MAPPING,
    "ml_score": _ML_MAPPING,
}

# Backwards-compatible public name used by the analyzer integration tests.
DETECTOR_OWASP_MAP = OWASP_MAP
