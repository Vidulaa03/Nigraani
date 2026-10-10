"""Prometheus metrics for NIGRAANI's HTTP and analysis pipelines."""

from prometheus_client import Counter, Histogram


HTTP_REQUESTS = Counter(
    "nigraani_http_requests_total",
    "HTTP requests served (the /metrics scrape endpoint is excluded).",
    ("method", "route", "status_code"),
)
HTTP_DURATION = Histogram(
    "nigraani_http_request_duration_seconds",
    "HTTP request duration in seconds (the /metrics scrape endpoint is excluded).",
    ("method", "route"),
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
)
ANALYSIS_RUNS = Counter("nigraani_analysis_runs_total", "IP analysis operations completed.")
ANALYSIS_FAILURES = Counter("nigraani_analysis_failures_total", "IP analysis operations that failed.")
ANALYSIS_DURATION = Histogram(
    "nigraani_analysis_duration_seconds", "Time spent analyzing an IP event window.",
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5),
)
DETECTIONS = Counter(
    "nigraani_detections_total", "Genuine detections produced by the rule pipeline.",
    ("detector", "severity"),
)
RISK_DECISIONS = Counter(
    "nigraani_risk_decisions_total", "Risk actions returned by the existing risk engine.", ("action",)
)
RISK_SCORE = Histogram(
    "nigraani_risk_score", "Risk score returned by the existing risk engine (range 0-100).",
    buckets=(0, 10, 20, 29, 30, 40, 50, 59, 60, 70, 79, 80, 90, 100),
)
ML_SCORE = Histogram(
    "nigraani_ml_anomaly_score", "ML anomaly score returned by the configured model (range 0-100).",
    buckets=(0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100),
)
ML_CLASSIFICATIONS = Counter(
    "nigraani_ml_classifications_total", "Model classifications for scored windows.", ("classification",)
)
SECURITY_EVENTS = Counter(
    "nigraani_security_events_total",
    "Security events handled by the logging pipeline: stored, rejected (invalid or duplicate), or failed.",
    ("outcome",),
)
SECURITY_LOG_WRITE_FAILURES = Counter(
    "nigraani_security_log_write_failures_total",
    "Failed security event writes by destination (database or jsonl).",
    ("sink",),
)
SECURITY_EVENT_SPOOL = Counter(
    "nigraani_security_event_spool_total",
    "Recovery spool activity: queued, spool_full, spool_failed, replayed, already_present, requeued, quarantined.",
    ("result",),
)
SECURITY_EVENT_FIELDS_SANITIZED = Counter(
    "nigraani_security_event_fields_sanitized_total",
    "Untrusted request values replaced or trimmed before logging, by field.",
    ("field",),
)


def route_label(request) -> str:
    """Return a registered route template, never the raw path."""
    route = request.scope.get("route")
    path = getattr(route, "path", None)
    return path if path else "unmatched"
