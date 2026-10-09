import argparse
import json
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

BASE_URL = "http://127.0.0.1:8000"
REQUEST_TIMEOUT_SECONDS = 5
DELAY_SECONDS = 0.2
SCENARIO_IPS = {
    "normal": "198.51.100.10",
    "login_bruteforce": "203.0.113.10",
    "bola": "203.0.113.11",
    "enumeration": "203.0.113.12",
    "rate_spike": "203.0.113.13",
}


def _scenario_requests(scenario: str) -> list[tuple[str, str, dict[str, str], dict | None, int]]:
    ip = SCENARIO_IPS[scenario]
    if scenario == "normal":
        return [
            ("GET", "/", {}, None, 200),
            ("GET", "/api/users/101", {"X-User-ID": "101"}, None, 200),
            ("GET", "/api/orders/501", {"X-User-ID": "101"}, None, 200),
        ]
    if scenario == "login_bruteforce":
        return [
            (
                "POST",
                "/api/auth/login",
                {"Content-Type": "application/json"},
                {"username": "invalid-user", "password": "wrong-password"},
                401,
            )
            for _ in range(15)
        ]
    if scenario == "bola":
        return [
            ("GET", f"/api/orders/{order_id}", {"X-User-ID": "101"}, None, 200)
            for order_id in (601, 602, 701)
        ]
    if scenario == "enumeration":
        return [
            ("GET", f"/api/users/{user_id}", {}, None, 404)
            for user_id in range(201, 216)
        ]
    return [("GET", "/", {}, None, 200) for _ in range(30)]


def _send_request(
    method: str,
    path: str,
    ip: str,
    scenario: str,
    headers: dict[str, str],
    body: dict | None,
) -> int:
    request_headers = {
        **headers,
        "X-Forwarded-For": ip,
        "X-Sim-Label": scenario,
    }
    payload = json.dumps(body).encode("utf-8") if body is not None else None
    request = Request(
        f"{BASE_URL}{path}",
        data=payload,
        headers=request_headers,
        method=method,
    )
    try:
        with urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            return response.status
    except HTTPError as error:
        return error.code


def run_scenario(scenario: str) -> None:
    if scenario not in SCENARIO_IPS:
        raise ValueError(f"Unknown scenario: {scenario}")

    ip = SCENARIO_IPS[scenario]
    requests = _scenario_requests(scenario)
    unexpected_responses_or_errors = 0

    for attempt, (method, path, headers, body, expected_status) in enumerate(
        requests,
        start=1,
    ):
        try:
            status_code = _send_request(
                method,
                path,
                ip,
                scenario,
                headers,
                body,
            )
            print(f"Request {attempt}: HTTP {status_code}")
            if status_code != expected_status:
                unexpected_responses_or_errors += 1
        except (URLError, TimeoutError, OSError) as error:
            print(f"Request {attempt}: ERROR {error}")
            unexpected_responses_or_errors += 1

        if attempt < len(requests) and scenario == "login_bruteforce":
            time.sleep(DELAY_SECONDS)

    print("Simulation summary:")
    print(f"Scenario: {scenario}")
    print(f"Target: {BASE_URL}")
    print(f"Simulated IP: {ip}")
    print(f"Total requests: {len(requests)}")
    print(f"Unexpected responses/errors: {unexpected_responses_or_errors}")
    if unexpected_responses_or_errors:
        raise SystemExit(1)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Send one controlled NIGRAANI scenario to the local API."
    )
    parser.add_argument(
        "--scenario",
        choices=SCENARIO_IPS,
        default="login_bruteforce",
    )
    run_scenario(parser.parse_args().scenario)


if __name__ == "__main__":
    main()
