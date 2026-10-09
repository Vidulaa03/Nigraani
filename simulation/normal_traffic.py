"""Generate realistic NORMAL traffic against the running NIGRAANI API.

Run from the repository root (API must already be running)::

    python -m simulation.normal_traffic
    python -m simulation.normal_traffic --duration 300 --clients 6 --seed 42

Every request goes through the real FastAPI app over HTTP, so the existing
logging middleware writes the events to ``security_events``; nothing is
written to the database directly. Clients are distinguished with the
``X-Forwarded-For`` header (supported by ``backend/main.py``), users with
``X-User-ID``, and ground truth is tagged with ``X-Sim-Label: normal``.

Requests are issued one at a time from a single thread (clients are
interleaved by a small scheduler). This keeps traffic realistic per client
and avoids duplicate millisecond ``event_id`` values, which the existing
logger derives from the current time.

Only endpoints that exist in the API are used:
    GET  /                      GET /api/users/{id}
    GET  /api/orders/{id}       POST /api/auth/login
"""

from __future__ import annotations

import argparse
import heapq
import json
import random
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from backend.database import ORDERS, USERS  # reference data only; no DB writes

DEFAULT_BASE_URL = "http://127.0.0.1:8000"
DEMO_USERNAME = "admin"  # documented demo login in README.md
DEMO_PASSWORD = "admin123"
MIN_THINK_SECONDS = 0.8

# Mean "think time" (seconds between user actions) per client profile.
PROFILES: dict[str, float] = {"light": 6.0, "medium": 3.5, "heavy": 2.0}

OWNED_ORDERS: dict[int, list[int]] = {}
for _order_id, _order in ORDERS.items():
    OWNED_ORDERS.setdefault(_order["owner_id"], []).append(_order_id)


@dataclass
class Step:
    """One HTTP request to send, `offset` seconds after the action starts."""

    offset: float
    method: str
    path: str
    body: dict[str, Any] | None = None
    send_user: bool = True


@dataclass
class Client:
    ip: str
    user_id: int
    profile: str
    rng: random.Random
    sent: int = field(default=0)

    def think_time(self) -> float:
        mean = PROFILES[self.profile]
        return max(MIN_THINK_SECONDS, self.rng.expovariate(1.0 / mean))

    def _own_order(self) -> int | None:
        orders = OWNED_ORDERS.get(self.user_id)
        return self.rng.choice(orders) if orders else None

    def next_action(self) -> list[Step]:
        """Pick a realistic user action and expand it to timed requests."""
        r = self.rng
        roll = r.random()
        own_order = self._own_order()

        if roll < 0.35:  # page load: profile, then 1-2 order views a moment apart
            steps = [Step(0.0, "GET", f"/api/users/{self.user_id}")]
            offset = 0.0
            for _ in range(r.randint(1, 2)):
                if own_order is None:
                    break
                offset += r.uniform(0.3, 1.0)
                steps.append(Step(offset, "GET", f"/api/orders/{self._own_order()}"))
            return steps
        if roll < 0.65 and own_order is not None:  # view one of my orders
            return [Step(0.0, "GET", f"/api/orders/{own_order}")]
        if roll < 0.75:  # view my profile
            return [Step(0.0, "GET", f"/api/users/{self.user_id}")]
        if roll < 0.80:  # look at a colleague's public profile
            return [Step(0.0, "GET", f"/api/users/{r.choice(list(USERS))}")]
        if roll < 0.87:  # landing / health page
            return [Step(0.0, "GET", "/", send_user=False)]
        if roll < 0.95:  # occasional login (mostly correct, sometimes a typo)
            password = DEMO_PASSWORD if r.random() < 0.85 else DEMO_PASSWORD + "x"
            return [Step(0.0, "POST", "/api/auth/login",
                         {"username": DEMO_USERNAME, "password": password}, send_user=False)]
        # stale bookmark / typo: an order id that does not exist (404)
        return [Step(0.0, "GET", f"/api/orders/{r.choice([503, 603, 999])}")]


def send_request(base_url: str, client: Client, step: Step, timeout: float = 10.0) -> int:
    """Send one request to the real API and return the HTTP status code."""
    headers = {"X-Forwarded-For": client.ip, "X-Sim-Label": "normal"}
    if step.send_user:
        headers["X-User-ID"] = str(client.user_id)
    data = None
    if step.body is not None:
        data = json.dumps(step.body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(base_url + step.path, data=data, headers=headers, method=step.method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            resp.read()
            return resp.status
    except urllib.error.HTTPError as exc:  # 4xx/5xx are valid, loggable responses
        exc.read()
        return exc.code


def build_clients(count: int, seed: int) -> list[Client]:
    user_ids = list(USERS)
    profile_names = list(PROFILES)
    clients = []
    for i in range(count):
        clients.append(Client(
            ip=f"192.168.10.{11 + i}",
            user_id=user_ids[i % len(user_ids)],
            profile=profile_names[i % len(profile_names)],
            rng=random.Random(seed * 1000 + i),
        ))
    return clients


def run(base_url: str, duration: float, num_clients: int, seed: int) -> Counter:
    """Run the simulation; returns a Counter of HTTP status codes sent."""
    # Pre-flight (single request from a dedicated IP; far below the 3-request window minimum).
    probe = Client("192.168.10.250", 101, "light", random.Random(0))
    try:
        send_request(base_url, probe, Step(0.0, "GET", "/", send_user=False))
    except (urllib.error.URLError, OSError) as exc:
        raise SystemExit(
            f"Cannot reach the API at {base_url} ({exc}).\n"
            "Start it first: uvicorn backend.main:app --host 127.0.0.1 --port 8000"
        )

    clients = build_clients(num_clients, seed)
    start = time.monotonic()
    heap: list[tuple[float, int, int, list[Step], int]] = []
    seq = 0

    def schedule(client_idx: int, at: float, steps: list[Step]) -> None:
        nonlocal seq
        for idx, step in enumerate(steps):
            heapq.heappush(heap, (at + step.offset, seq, client_idx, steps, idx))
            seq += 1

    for ci, client in enumerate(clients):  # stagger client start-up
        schedule(ci, client.rng.uniform(0, client.think_time()), client.next_action())

    statuses: Counter = Counter()
    failures = 0
    try:
        while heap:
            when, _, ci, steps, idx = heapq.heappop(heap)
            if when > duration:
                break
            delay = start + when - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            client = clients[ci]
            try:
                status = send_request(base_url, client, steps[idx])
                failures = 0
            except (urllib.error.URLError, OSError) as exc:
                failures += 1
                print(f"request failed ({exc})", file=sys.stderr)
                if failures >= 5:
                    raise SystemExit("API unreachable; aborting.")
                continue
            statuses[status] += 1
            client.sent += 1
            if idx == len(steps) - 1:  # action finished: schedule the next one
                schedule(ci, when + client.think_time(), client.next_action())
    except KeyboardInterrupt:
        print("\nInterrupted; stopping early.")

    print(f"Sent {sum(statuses.values())} requests in {time.monotonic() - start:.0f}s "
          f"from {num_clients} clients.")
    print("Status codes:", dict(sorted(statuses.items())))
    for client in clients:
        print(f"  {client.ip:<15} user={client.user_id} profile={client.profile:<6} requests={client.sent}")
    return statuses


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Send normal traffic to the NIGRAANI API.")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--duration", type=float, default=300.0,
                        help="seconds of traffic to generate (default 300 = ~10 windows per client)")
    parser.add_argument("--clients", type=int, default=6, help="number of simulated client IPs (default 6)")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args(argv)
    run(args.base_url.rstrip("/"), args.duration, args.clients, args.seed)
    return 0


if __name__ == "__main__":
    sys.exit(main())
