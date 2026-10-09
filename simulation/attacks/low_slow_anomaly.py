"""Low-and-slow anomaly scenario (plan scenario 5): intended for the ML model only.

Sends a paced, varied mix of requests from one simulated IP to the local API
(127.0.0.1:8000). The mix is shaped to stay below every rule detector -- few failed
logins, a handful of distinct IDs per endpoint pattern, no successful access to other
users' orders, a gentle request rate -- while producing an unusual 30-second window
profile: many distinct endpoints and a high share of 404s.

Before sending anything, the planned timeline is replayed through the real rule
detectors; the script aborts if any of them would fire. Whether the Isolation Forest
flags the traffic is NOT guaranteed -- see the hints printed at the end of a run.

Run (API and analyzer already running):
    python -m simulation.attacks.low_slow_anomaly
    python -m simulation.attacks.low_slow_anomaly --duration 120 --interval 2 --seed 3
    python -m simulation.attacks.low_slow_anomaly --dry-run
"""
from __future__ import annotations

import argparse
import random
import re
import time
from datetime import datetime, timedelta, timezone
from urllib.error import URLError

from backend.detection import (
    bola_detector,
    enumeration_detector,
    login_failure_detector,
    rate_detector,
)
from simulation.attacks.login_bruteforce import BASE_URL, _send_request

SCENARIO = "low_slow"
SIMULATED_IP = "203.0.113.14"
OWN_USER_ID = 101
OWN_ORDER_IDS = (501, 502)
LOGIN_BODY = {"username": "invalid-user", "password": "wrong-password"}

DEFAULT_DURATION_SECONDS = 90
DEFAULT_INTERVAL_SECONDS = 2.5
DEFAULT_JITTER_SECONDS = 0.5
MIN_INTERVAL_SECONDS = 1.0
DEFAULT_SEED = 7

# Stay clearly under the rule detectors' own thresholds (read from the detector modules).
MAX_LOGIN_FAILURES_PER_MINUTE = login_failure_detector.FAILURE_THRESHOLD_MEDIUM - 2
MAX_DISTINCT_IDS_PER_PATTERN = enumeration_detector.MIN_DISTINCT_IDS - 6
HISTORY_SECONDS = 60

# (kind, weight): roughly 60% of requests are expected to return 4xx.
REQUEST_MIX = (
    ("user_404", 25),
    ("order_404", 15),
    ("other_404", 20),
    ("login_fail", 15),
    ("home", 10),
    ("own_order", 10),
    ("own_user", 5),
)
OTHER_404_PREFIXES = ("products", "invoices", "payments", "reports", "tickets")


def _pattern(endpoint: str) -> str:
    """Mirror of how the API's security logger derives endpoint_pattern."""
    if re.match(r"^/api/orders/\d+$", endpoint):
        return "/api/orders/{order_id}"
    if re.match(r"^/api/users/\d+$", endpoint):
        return "/api/users/{user_id}"
    if endpoint.startswith("/api/auth/"):
        return "/api/auth/{action}"
    return endpoint


def _spaced_missing_id(rng: random.Random) -> int:
    """A nonexistent ID; never adjacent to the previous picks (avoids sequential runs)."""
    return rng.randrange(900, 1000, 7) + rng.choice((0, 2, 4))


def build_plan(
    duration: float,
    interval: float,
    jitter: float,
    seed: int,
) -> list[dict]:
    """Deterministic request timeline: [{offset, method, path, headers, body, expected}]."""
    rng = random.Random(seed)
    kinds = [kind for kind, _ in REQUEST_MIX]
    weights = [weight for _, weight in REQUEST_MIX]
    plan: list[dict] = []
    offset = 0.0
    while offset <= duration:
        kind = rng.choices(kinds, weights)[0]
        recent = [item for item in plan if offset - item["offset"] <= HISTORY_SECONDS]
        entry = _make_request(kind, rng, recent)
        if entry is None:  # a cap was hit; fall back to the always-safe home page
            entry = _make_request("home", rng, recent)
        entry["offset"] = round(offset, 3)
        plan.append(entry)
        offset += max(MIN_INTERVAL_SECONDS, interval + rng.uniform(-jitter, jitter))
    return plan


def _make_request(kind: str, rng: random.Random, recent: list[dict]) -> dict | None:
    def distinct_ids(pattern: str) -> set[int]:
        return {
            item["resource_id"]
            for item in recent
            if item["pattern"] == pattern and item["resource_id"] is not None
        }

    def pick_id(pattern: str) -> int:
        seen = distinct_ids(pattern)
        if len(seen) >= MAX_DISTINCT_IDS_PER_PATTERN:
            return rng.choice(sorted(seen))
        return _spaced_missing_id(rng)

    if kind == "user_404":
        resource_id = pick_id("/api/users/{user_id}")
        return _entry("GET", f"/api/users/{resource_id}", 404, resource_id)
    if kind == "order_404":
        resource_id = pick_id("/api/orders/{order_id}")
        return _entry(
            "GET", f"/api/orders/{resource_id}", 404, resource_id,
            headers={"X-User-ID": str(OWN_USER_ID)},
        )
    if kind == "other_404":
        resource_id = rng.randrange(1, 500)
        prefix = rng.choice(OTHER_404_PREFIXES)
        return _entry("GET", f"/api/{prefix}/{resource_id}", 404, resource_id)
    if kind == "login_fail":
        failures = sum(1 for item in recent if item["expected"] == 401)
        if failures >= MAX_LOGIN_FAILURES_PER_MINUTE:
            return None
        return _entry(
            "POST", "/api/auth/login", 401, None,
            headers={"Content-Type": "application/json"}, body=LOGIN_BODY,
        )
    if kind == "home":
        return _entry("GET", rng.choice(("/", "/docs")), 200, None)
    if kind == "own_order":
        resource_id = rng.choice(OWN_ORDER_IDS)
        return _entry(
            "GET", f"/api/orders/{resource_id}", 200, resource_id,
            headers={"X-User-ID": str(OWN_USER_ID)},
        )
    return _entry("GET", f"/api/users/{OWN_USER_ID}", 200, OWN_USER_ID)


def _entry(method, path, expected, resource_id, headers=None, body=None) -> dict:
    return {
        "method": method,
        "path": path,
        "headers": headers or {},
        "body": body,
        "expected": expected,
        "resource_id": resource_id,
        "pattern": _pattern(path),
    }


def rule_detections_for_plan(plan: list[dict]) -> list[dict]:
    """Replay the plan through the real rule detectors using the logged-event format."""
    # Place the whole timeline in the recent past (bola_detector ignores future/old events).
    start = datetime.now(timezone.utc) - timedelta(seconds=plan[-1]["offset"] + 1)
    events = []
    for index, item in enumerate(plan, start=1):
        events.append(
            {
                "event_id": index,
                "timestamp": (start + timedelta(seconds=item["offset"])).isoformat(),
                "ip": SIMULATED_IP,
                "user_id": OWN_USER_ID if "X-User-ID" in item["headers"] else None,
                "method": item["method"],
                "endpoint": item["path"],
                "endpoint_pattern": item["pattern"],
                "resource_id": item["resource_id"],
                "resource_owner_id": OWN_USER_ID if item["expected"] == 200 and item["resource_id"] else None,
                "status_code": item["expected"],
                "response_time_ms": 5.0,
            }
        )
    detections = []
    for detector in (login_failure_detector, rate_detector, enumeration_detector, bola_detector):
        detections.extend(detector.detect(events))
    return detections


def _print_hints() -> None:
    print(
        "\nThis scenario is meant to be flagged by the Isolation Forest only, but that is not\n"
        "guaranteed. If no ML-driven decision appears for the simulated IP, inspect:\n"
        "  - security_events for this IP: status mix, endpoint_pattern spread, timestamps\n"
        "  - ml.features.extract_features(events) for this IP's 30-second windows: request_count,\n"
        "    unique_endpoints, unique_resource_ids, error_rate, login_failures, max_requests_in_5s\n"
        "  - backend.ml.anomaly_detector.AnomalyDetector.score_ip_events(events) vs the expected\n"
        "    model output, and how far\n"
        "    these feature values sit from the normal training windows\n"
        "  - decisions / detections rows for this IP (detector 'ml_score' or ML reasons)\n"
        "  - that the analyzer is running and its 60-second window still contained the events"
    )


def run(duration: float, interval: float, jitter: float, seed: int, dry_run: bool) -> int:
    plan = build_plan(duration, interval, jitter, seed)
    fired = rule_detections_for_plan(plan)
    if fired:
        print("Aborting: the planned traffic would trigger rule detectors:")
        for detection in fired:
            print(f"  {detection['detector']}: {detection['evidence']}")
        return 2

    expected_4xx = sum(1 for item in plan if 400 <= item["expected"] < 500)
    print(f"Scenario: {SCENARIO}   Target: {BASE_URL}   Simulated IP: {SIMULATED_IP}")
    print(
        f"Planned {len(plan)} requests over ~{plan[-1]['offset']:.0f}s "
        f"({expected_4xx / len(plan):.0%} expected 4xx); no rule detector fires on the plan."
    )
    if dry_run:
        for item in plan:
            print(f"  t+{item['offset']:6.1f}s  {item['method']:4} {item['path']}  -> {item['expected']}")
        return 0

    started = time.monotonic()
    statuses: list[int] = []
    unexpected = 0
    for number, item in enumerate(plan, start=1):
        wait = item["offset"] - (time.monotonic() - started)
        if wait > 0:
            time.sleep(wait)
        try:
            status = _send_request(
                item["method"], item["path"], SIMULATED_IP, SCENARIO, item["headers"], item["body"]
            )
        except (URLError, TimeoutError, OSError) as error:
            print(f"Request {number}: ERROR {error}")
            print("Is the API running at 127.0.0.1:8000?")
            return 1
        statuses.append(status)
        if status != item["expected"]:
            unexpected += 1
        print(f"Request {number}/{len(plan)}: {item['method']} {item['path']} -> HTTP {status}")

    errors = sum(1 for status in statuses if 400 <= status < 600)
    print("Simulation summary:")
    print(f"Total requests: {len(statuses)}")
    print(f"4xx/5xx responses: {errors} ({errors / len(statuses):.0%})")
    print(f"Unexpected responses: {unexpected}")
    _print_hints()
    return 1 if unexpected else 0


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Send paced low-and-slow suspicious traffic to the local NIGRAANI API."
    )
    parser.add_argument("--duration", type=float, default=DEFAULT_DURATION_SECONDS,
                        help="seconds of traffic to schedule (default %(default)s)")
    parser.add_argument("--interval", type=float, default=DEFAULT_INTERVAL_SECONDS,
                        help="average seconds between requests (default %(default)s)")
    parser.add_argument("--jitter", type=float, default=DEFAULT_JITTER_SECONDS,
                        help="+/- random seconds added to each gap (default %(default)s)")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED,
                        help="random seed for a reproducible request sequence")
    parser.add_argument("--dry-run", action="store_true",
                        help="print the verified plan without sending any request")
    args = parser.parse_args()
    if args.duration <= 0 or args.interval <= 0 or args.jitter < 0:
        parser.error("duration and interval must be positive; jitter must not be negative")
    raise SystemExit(run(args.duration, args.interval, args.jitter, args.seed, args.dry_run))


if __name__ == "__main__":
    main()
