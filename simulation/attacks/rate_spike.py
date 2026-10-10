"""Repeatable burst-traffic demo generator for NIGRAANI.

Sends 30+ requests within a 10-second rolling window from a single simulated IP
through the standard application middleware to trigger rate detection,
incident creation, persistent in-app notification, and automatic Twilio calling.
"""

from __future__ import annotations

import argparse
import json
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

DEFAULT_TARGET = "http://127.0.0.1:8000"
DEFAULT_IP = "203.0.113.13"
DEFAULT_REQUESTS = 30
DEFAULT_WINDOW_SECONDS = 10
DEFAULT_ENDPOINT = "/"


def send_burst(
    target: str = DEFAULT_TARGET,
    ip: str = DEFAULT_IP,
    count: int = DEFAULT_REQUESTS,
    endpoint: str = DEFAULT_ENDPOINT,
    window_seconds: float = DEFAULT_WINDOW_SECONDS,
) -> dict[str, any]:
    """Execute rapid burst of HTTP requests to monitored endpoint."""
    url = f"{target.rstrip('/')}{endpoint}"
    status_counts: dict[int, int] = {}
    errors: list[str] = []

    print(f"\n=================================================================")
    print(f" NIGRAANI Demo Burst Generator: 30 Requests / 10s Window")
    print(f"=================================================================")
    print(f"Target URL:        {url}")
    print(f"Simulated IP:      {ip}")
    print(f"Planned Requests:  {count}")
    print(f"Max Window:        {window_seconds}s")
    print(f"-----------------------------------------------------------------")

    start_time = time.perf_counter()

    for i in range(1, count + 1):
        req = Request(
            url,
            headers={
                "X-Forwarded-For": ip,
                "X-Sim-Label": "rate_spike",
                "User-Agent": "Nigraani-RateSpike-Demo/1.0",
                "Accept": "application/json",
            },
            method="GET",
        )
        try:
            with urlopen(req, timeout=5) as resp:
                code = resp.status
                status_counts[code] = status_counts.get(code, 0) + 1
        except HTTPError as http_err:
            code = http_err.code
            status_counts[code] = status_counts.get(code, 0) + 1
        except (URLError, TimeoutError, OSError) as net_err:
            errors.append(str(net_err))

    duration = time.perf_counter() - start_time
    print(f"\nRequests Sent:     {count} completed in {duration:.3f}s")
    print(f"Status Codes:      {status_counts}")
    if errors:
        print(f"Network Errors:    {len(errors)} ({errors[0]})")

    # Verify through API if analyzer has processed
    print(f"\nVerifying telemetry on NIGRAANI dashboard API...")
    verification = {
        "rate_detection_found": False,
        "notification_found": False,
        "call_found": False,
        "call_status": None,
    }

    # Give analyzer up to 6 seconds to run its 5-second cycle
    for poll_attempt in range(6):
        time.sleep(1)
        try:
            threats_req = Request(f"{target.rstrip('/')}/api/dashboard/threats")
            with urlopen(threats_req, timeout=3) as t_resp:
                t_data = json.loads(t_resp.read().decode())
                for d in t_data.get("detections", []):
                    if d.get("ip") == ip and d.get("detector") == "rate_detector":
                        verification["rate_detection_found"] = True
                        break

            notif_req = Request(f"{target.rstrip('/')}/api/dashboard/notifications?limit=10")
            with urlopen(notif_req, timeout=3) as n_resp:
                n_data = json.loads(n_resp.read().decode())
                for n in n_data.get("notifications", []):
                    if ip in n.get("title", "") or ip in n.get("message", ""):
                        verification["notification_found"] = True
                        break

            calls_req = Request(f"{target.rstrip('/')}/api/dashboard/calls?limit=10")
            with urlopen(calls_req, timeout=3) as c_resp:
                c_data = json.loads(c_resp.read().decode())
                for c in c_data.get("calls", []):
                    meta = c.get("metadata", {})
                    if meta.get("ip") == ip or ip in c.get("trigger_reason", ""):
                        verification["call_found"] = True
                        verification["call_status"] = c.get("status")
                        break

            if verification["rate_detection_found"]:
                break
        except Exception:
            pass

    print(f"Rate Detection:    {'[CONFIRMED]' if verification['rate_detection_found'] else '[PENDING ANALYZER CYCLE]'}")
    print(f"In-App Alert:      {'[PERSISTED]' if verification['notification_found'] else '[PENDING]'}")
    print(f"Twilio Voice Call: {'[' + str(verification['call_status']).upper() + ']' if verification['call_found'] else '[CHECKING CONFIG]'}")
    print(f"=================================================================\n")

    return {
        "target": target,
        "ip": ip,
        "count": count,
        "duration_seconds": round(duration, 3),
        "status_counts": status_counts,
        "verification": verification,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="NIGRAANI Repeatable Burst-Traffic Generator (30 requests in 10s)"
    )
    parser.add_argument("--target", default=DEFAULT_TARGET, help="Base URL of target NIGRAANI instance")
    parser.add_argument("--ip", default=DEFAULT_IP, help="Simulated client IP address")
    parser.add_argument("--requests", type=int, default=DEFAULT_REQUESTS, help="Number of requests in burst")
    parser.add_argument("--endpoint", default=DEFAULT_ENDPOINT, help="Monitored endpoint path")
    parser.add_argument("--window", type=float, default=DEFAULT_WINDOW_SECONDS, help="Observation window in seconds")
    args = parser.parse_args()

    send_burst(
        target=args.target,
        ip=args.ip,
        count=args.requests,
        endpoint=args.endpoint,
        window_seconds=args.window,
    )


if __name__ == "__main__":
    main()
