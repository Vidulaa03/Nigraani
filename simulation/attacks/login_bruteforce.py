import time

import requests


# Intended only for the user's local NIGRAANI test API.
URL = "http://127.0.0.1:8000/api/auth/login"
HEADERS = {
    "Content-Type": "application/json",
    "X-Forwarded-For": "203.0.113.10",
    "X-Sim-Label": "normal",
}
REQUEST_BODY = {
    "username": "invalid-user",
    "password": "wrong-password",
}
REQUEST_COUNT = 15
REQUEST_TIMEOUT_SECONDS = 5
DELAY_SECONDS = 0.2


def main() -> None:
    failed_logins = 0
    unexpected_responses_or_errors = 0

    for attempt in range(1, REQUEST_COUNT + 1):
        try:
            response = requests.post(
                URL,
                json=REQUEST_BODY,
                headers=HEADERS,
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
            print(f"Attempt {attempt}: HTTP {response.status_code}")
            if response.status_code == 401:
                failed_logins += 1
            else:
                unexpected_responses_or_errors += 1
        except requests.RequestException as error:
            print(f"Attempt {attempt}: ERROR {error}")
            unexpected_responses_or_errors += 1

        if attempt < REQUEST_COUNT:
            time.sleep(DELAY_SECONDS)

    print("Simulation summary:")
    print(f"Total requests: {REQUEST_COUNT}")
    print(f"401 responses: {failed_logins}")
    print(f"Unexpected responses/errors: {unexpected_responses_or_errors}")


if __name__ == "__main__":
    main()
