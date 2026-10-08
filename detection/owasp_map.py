DETECTOR_OWASP_MAP = {
    "bola_detector": {
        "owasp_id": "API1:2023",
        "name": "Broken Object Level Authorization",
        "what_we_detect": "Cross-user access to resources with known ownership data.",
        "what_we_dont": "Does not fix the vulnerability or detect objects without owner data.",
    },
    "enumeration_detector": {
        "owasp_id": "API1:2023",
        "name": "Broken Object Level Authorization",
        "what_we_detect": "Rapid or error-heavy probing of distinct resource IDs.",
        "what_we_dont": "Enumeration is a probing signal, not proof of an authorization flaw.",
    },
    "login_failure_detector": {
        "owasp_id": "API2:2023",
        "name": "Broken Authentication",
        "what_we_detect": "Repeated failed login attempts from one source IP.",
        "what_we_dont": "Does not detect weak tokens, password policies, or JWT flaws.",
    },
    "rate_detector": {
        "owasp_id": "API4:2023",
        "name": "Unrestricted Resource Consumption",
        "what_we_detect": "Unusually high request volume from one source IP.",
        "what_we_dont": "Does not measure CPU, memory, or monetary resource consumption.",
    },
    "anomaly_detector": {
        "owasp_id": None,
        "name": "Behavioral anomaly",
        "what_we_detect": "Unusual activity compared with the trained normal baseline.",
        "what_we_dont": "Cannot identify a specific attack category or prove exploitation.",
    },
}
