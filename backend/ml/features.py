"""Feature extraction for the NIGRAANI Isolation Forest.

Input is the *existing* ``security_events`` contract (see
``backend/detection/base.py``); no new event format is introduced.

Events are grouped into fixed 30-second windows per source IP. Each window
with at least ``MIN_REQUESTS_PER_WINDOW`` requests is summarised by the 8
features in ``FEATURE_NAMES`` (the order is part of the model contract).

``sim_label`` is NEVER used as a feature. It is only carried along as
metadata (``WindowFeatures.sim_labels``) so that training can select normal
traffic and a later evaluation step can compare against ground truth.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Sequence

import numpy as np

WINDOW_SECONDS = 30
MIN_REQUESTS_PER_WINDOW = 3
BURST_SECONDS = 5
LOGIN_ENDPOINT = "/api/auth/login"
LOGIN_FAILURE_STATUSES = frozenset({401, 403})  # same rule as backend/analyzer.py

# The order below is the model's feature order. Do not reorder without retraining.
FEATURE_NAMES: tuple[str, ...] = (
    "request_count",
    "unique_endpoints",
    "unique_resource_ids",
    "error_rate",
    "login_attempts",
    "login_failures",
    "avg_response_time_ms",
    "max_requests_in_5s",
)


@dataclass
class WindowFeatures:
    """Features (plus bookkeeping metadata) for one IP / 30-second window."""

    ip: str
    window_start: datetime
    window_end: datetime
    features: dict[str, float]
    event_ids: list[int] = field(default_factory=list)
    # Metadata only - must never be fed to the model.
    sim_labels: frozenset[str] = frozenset()

    @property
    def is_normal(self) -> bool:
        """True when every event in the window carries sim_label 'normal'."""
        return self.sim_labels <= {"normal"}

    def vector(self) -> list[float]:
        """Feature values in ``FEATURE_NAMES`` order."""
        return [float(self.features[name]) for name in FEATURE_NAMES]


def parse_timestamp(value: Any) -> datetime:
    """Parse an event timestamp (ISO-8601, ``Z`` or offset) to an aware datetime."""
    if isinstance(value, datetime):
        parsed = value
    else:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _max_in_burst(times: Sequence[float], span: float = BURST_SECONDS) -> int:
    """Largest number of requests inside any ``span``-second sliding interval."""
    ordered = sorted(times)
    best = 0
    left = 0
    for right, current in enumerate(ordered):
        while current - ordered[left] > span:
            left += 1
        best = max(best, right - left + 1)
    return best


def compute_window_features(events: Sequence[dict[str, Any]]) -> dict[str, float]:
    """Compute the 8 features for the events of ONE ip/window (non-empty)."""
    if not events:
        raise ValueError("compute_window_features requires at least one event")

    count = len(events)
    errors = sum(1 for e in events if int(e["status_code"]) >= 400)
    logins = [e for e in events if e.get("endpoint") == LOGIN_ENDPOINT]
    login_failures = sum(1 for e in logins if int(e["status_code"]) in LOGIN_FAILURE_STATUSES)
    times = [parse_timestamp(e["timestamp"]).timestamp() for e in events]

    return {
        "request_count": float(count),
        "unique_endpoints": float(len({e["endpoint"] for e in events})),
        "unique_resource_ids": float(
            len({e["resource_id"] for e in events if e.get("resource_id") is not None})
        ),
        "error_rate": errors / count,
        "login_attempts": float(len(logins)),
        "login_failures": float(login_failures),
        "avg_response_time_ms": float(np.mean([float(e["response_time_ms"]) for e in events])),
        "max_requests_in_5s": float(_max_in_burst(times)),
    }


def extract_windows(
    events: Iterable[dict[str, Any]],
    window_seconds: int = WINDOW_SECONDS,
    min_requests: int = MIN_REQUESTS_PER_WINDOW,
) -> list[WindowFeatures]:
    """Group events into per-IP epoch-aligned windows and compute features.

    Windows with fewer than ``min_requests`` requests are ignored. The result
    is sorted by window start, then IP.
    """
    buckets: dict[tuple[str, int], list[dict[str, Any]]] = {}
    for event in events:
        ts = parse_timestamp(event["timestamp"]).timestamp()
        bucket = int(ts // window_seconds)
        buckets.setdefault((str(event["ip"]), bucket), []).append(event)

    windows: list[WindowFeatures] = []
    for (ip, bucket), bucket_events in buckets.items():
        if len(bucket_events) < min_requests:
            continue
        start = datetime.fromtimestamp(bucket * window_seconds, tz=timezone.utc)
        end = datetime.fromtimestamp((bucket + 1) * window_seconds, tz=timezone.utc)
        windows.append(
            WindowFeatures(
                ip=ip,
                window_start=start,
                window_end=end,
                features=compute_window_features(bucket_events),
                event_ids=sorted(int(e["event_id"]) for e in bucket_events),
                sim_labels=frozenset(str(e.get("sim_label") or "normal") for e in bucket_events),
            )
        )
    windows.sort(key=lambda w: (w.window_start, w.ip))
    return windows


def windows_to_matrix(windows: Sequence[WindowFeatures]) -> np.ndarray:
    """Stack window feature vectors into an (n_windows, 8) float array."""
    if not windows:
        return np.empty((0, len(FEATURE_NAMES)), dtype=float)
    return np.asarray([w.vector() for w in windows], dtype=float)


def load_events_from_db() -> list[dict[str, Any]]:
    """Read all rows of the EXISTING ``security_events`` table.

    Uses ``backend.database.get_events_since`` so no second DB access path or
    schema is introduced.
    """
    from backend.database import get_events_since

    return get_events_since(None)


if __name__ == "__main__":  # quick manual look at real events
    for win in extract_windows(load_events_from_db()):
        print(win.ip, win.window_start.isoformat(), win.features, sorted(win.sim_labels))
