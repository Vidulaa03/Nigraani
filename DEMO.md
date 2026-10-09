# NIGRAANI demo rehearsal

This walkthrough runs the API and analyzer locally, exercises normal and
simulated-abuse requests, then checks the persisted detections and decisions.
Use this only with the local demo. The app intentionally has vulnerable
behavior and trusts `X-Forwarded-For`; do not expose it to an untrusted network.

## Prepare and start

From the project root, install dependencies in a virtual environment:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r backend\requirements.txt
```

The analyzer requires a trained Isolation Forest model at
`models\iforest.joblib`. Train it first using a JSON file containing only
verified normal traffic:

```powershell
python -m ml.train_model path\to\normal_events.json
```

Start both the API and analyzer in separate terminal windows:

```powershell
.\run_all.bat
```

The launcher reuses an API already responding at <http://127.0.0.1:8000> or
waits up to 30 seconds for it to become ready before starting the analyzer.
The analyzer checks for new events every five seconds and prevents a second
instance from processing the same database.

## Rehearse normal requests

Open a PowerShell terminal in the project root and run:

```powershell
python -m simulation.attacks.normal_traffic
```

The script sends a normal request, a user lookup, and an order request owned by
user 101.

## Rehearse BOLA detection

User 101 requests three orders owned by other users:

```powershell
python -m simulation.attacks.bola
```

The intentionally vulnerable API returns the orders. The analyzer should
record a `bola_detector` detection for `203.0.113.11` and recommend `BLOCK`.

## Rehearse failed-login detection

Send five invalid logins from one simulated IP:

```powershell
python -m simulation.attacks.login_bruteforce
```

The script sends 15 failed logins. Each response should be HTTP 401. The
analyzer should record a
`login_failure_detector` detection for `203.0.113.10` and recommend at least `MONITOR`.

## Rehearse ID enumeration

Probe 15 sequential, nonexistent user IDs:

```powershell
python -m simulation.attacks.enumeration
```

The analyzer should record an `enumeration_detector` detection for
`203.0.113.12`.

## Rehearse a request-rate spike

Send 30 requests in a short burst from one simulated IP:

```powershell
python -m simulation.attacks.rate_spike
```

The analyzer should record a `rate_detector` detection for `203.0.113.13`.

Wait at least six seconds after the last scenario for the analyzer to process
the requests, then inspect the database:

```powershell
python -c "import sqlite3; c=sqlite3.connect('demo.db'); print(*c.execute('SELECT ip, detector, severity, attack_type FROM detections ORDER BY detection_id DESC LIMIT 20'), sep='\n')"
python -c "import sqlite3; c=sqlite3.connect('demo.db'); print(*c.execute('SELECT ip, risk_score, risk_level, action, reasons FROM decisions ORDER BY decision_id DESC LIMIT 20'), sep='\n')"
```

Expected rule detections include:

| Simulated IP | Expected detection | Expected action |
|---|---|---|
| `203.0.113.10` | `login_failure_detector` | At least `MONITOR` |
| `203.0.113.11` | `bola_detector` | `BLOCK` |
| `203.0.113.12` | `enumeration_detector` | At least `THROTTLE` |
| `203.0.113.13` | `rate_detector` | At least `MONITOR` |

`X-Sim-Label` is not needed: detector and model decisions are based on request
events and extracted features, not simulation labels.

## Stop and troubleshoot

Stop the API and analyzer with **Ctrl+C** in their respective terminal windows.
If `run_all.bat` reports a missing model, train it using the normal-only JSON
dataset first. If requests work but no detections appear, keep the analyzer
running and verify that requests use the documented simulated IPs and that the
analyzer's 60-second window has not elapsed.

Run the automated suite from the project root to rehearse the same detector
scenarios without starting separate processes:

```powershell
python -m pytest -q
```
