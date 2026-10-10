"""Multi-dimensional rate analysis.

Looks at one IP's events (the analyzer passes a 60-second window) along five
dimensions and reports a detection only when at least two of them are
abnormal at the same time, so one noisy dimension alone does not alert:

  * ip_rate            requests from the IP in the window
  * user_endpoint_rate requests by one user to one endpoint pattern
  * failed_ratio       share of 4xx/5xx responses
  * endpoint_diversity distinct endpoints requested (scanning)
  * burst              most requests inside any 5 seconds

The evidence lists every triggered signal with its measured value and
threshold, so the detection explains itself. Severity grows with the number
of agreeing signals and stays below the single-purpose detectors' top
severities, so it adds weight in the risk engine without dominating it.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import timedelta
from typing import Any

from backend.detection._utils import event_time

IP_RATE_THRESHOLD = 40
USER_ENDPOINT_RATE_THRESHOLD = 20
FAILED_RATIO_THRESHOLD = 0.5
MIN_REQUESTS_FOR_RATIO = 10
DISTINCT_ENDPOINTS_THRESHOLD = 12
BURST_SECONDS = 5
BURST_THRESHOLD = 10
MIN_SIGNALS = 2
SEVERITY_BY_SIGNALS = {2: 40, 3: 55, 4: 70, 5: 85}


def _max_burst(events: list[dict[str, Any]]) -> int:
    times = sorted(event_time(event) for event in events)
    best = start = 0
    for end, end_time in enumerate(times):
        while end_time - times[start] > timedelta(seconds=BURST_SECONDS):
            start += 1
        best = max(best, end - start + 1)
    return best


def _signals(events: list[dict[str, Any]]) -> list[str]:
    total = len(events)
    signals: list[str] = []

    if total >= IP_RATE_THRESHOLD:
        signals.append(f"ip_rate: {total} requests in window (threshold {IP_RATE_THRESHOLD})")

    per_user_endpoint = Counter(
        (event["user_id"], event.get("endpoint_pattern"))
        for event in events
        if event.get("user_id") is not None
    )
    if per_user_endpoint:
        (user_id, pattern), count = per_user_endpoint.most_common(1)[0]
        if count >= USER_ENDPOINT_RATE_THRESHOLD:
            signals.append(
                f"user_endpoint_rate: user {user_id} sent {count} requests to {pattern} "
                f"(threshold {USER_ENDPOINT_RATE_THRESHOLD})"
            )

    if total >= MIN_REQUESTS_FOR_RATIO:
        failed = sum(1 for event in events if int(event.get("status_code", 0)) >= 400)
        if failed / total >= FAILED_RATIO_THRESHOLD:
            signals.append(
                f"failed_ratio: {failed}/{total} requests failed "
                f"({failed / total:.0%}, threshold {FAILED_RATIO_THRESHOLD:.0%})"
            )

    distinct = len({event.get("endpoint") for event in events})
    if distinct >= DISTINCT_ENDPOINTS_THRESHOLD:
        signals.append(
            f"endpoint_diversity: {distinct} distinct endpoints "
            f"(threshold {DISTINCT_ENDPOINTS_THRESHOLD})"
        )

    burst = _max_burst(events)
    if burst >= BURST_THRESHOLD:
        signals.append(
            f"burst: {burst} requests within {BURST_SECONDS}s (threshold {BURST_THRESHOLD})"
        )
    return signals


def detect(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Report IPs where at least MIN_SIGNALS rate dimensions are abnormal."""
    events_by_ip: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        if event.get("ip"):
            events_by_ip[event["ip"]].append(event)

    detections: list[dict[str, Any]] = []
    for ip, ip_events in events_by_ip.items():
        signals = _signals(ip_events)
        if len(signals) < MIN_SIGNALS:
            continue
        users = {event["user_id"] for event in ip_events if event.get("user_id") is not None}
        detections.append(
            {
                "detector": "multi_rate_detector",
                "attack_type": "Multi-Signal Rate Abuse",
                "severity": SEVERITY_BY_SIGNALS[min(len(signals), 5)],
                "ip": ip,
                "user_id": next(iter(users)) if len(users) == 1 else None,
                "evidence": f"{len(signals)} rate signals: " + "; ".join(signals),
                "event_ids": sorted(int(event["event_id"]) for event in ip_events),
                "owasp": "API4:2023",
            }
        )
    return detections
