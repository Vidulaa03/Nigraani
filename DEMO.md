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

Wait until the API is available at <http://127.0.0.1:8000/docs>. The analyzer
checks for new events every five seconds. Keep both terminal windows open.

## Rehearse normal requests

Open a PowerShell terminal in the project root and send a normal request and
an order request owned by user 101:

```powershell
$base = "http://127.0.0.1:8000"
curl.exe -sS "$base/"
curl.exe -sS -H "X-User-ID: 101" "$base/api/orders/501"
```

The order response should identify user 101 as the requester and owner.

## Rehearse BOLA detection

User 101 requests three orders owned by other users:

```powershell
601, 602, 701 | ForEach-Object {
    curl.exe -sS -H "X-User-ID: 101" -H "X-Forwarded-For: 10.0.0.32" `
        "$base/api/orders/$_"
}
```

The intentionally vulnerable API returns the orders. The analyzer should
record a `bola_detector` detection for `10.0.0.32` and recommend `BLOCK`.

## Rehearse failed-login detection

Send five invalid logins from one simulated IP:

```powershell
1..5 | ForEach-Object {
    curl.exe -sS -o NUL -w "%{http_code}`n" -X POST `
        -H "Content-Type: application/json" `
        -H "X-Forwarded-For: 10.0.0.31" `
        -d '{"username":"admin","password":"wrong"}' `
        "$base/api/auth/login"
}
```

Each response should be HTTP 401. The analyzer should record a
`login_failure_detector` detection and recommend at least `MONITOR`.

## Rehearse ID enumeration

Probe 15 sequential, nonexistent user IDs:

```powershell
201..215 | ForEach-Object {
    curl.exe -sS -o NUL -H "X-Forwarded-For: 10.0.0.33" `
        "$base/api/users/$_"
}
```

The analyzer should record an `enumeration_detector` detection for
`10.0.0.33`.

## Rehearse a request-rate spike

Send 30 requests in a short burst from one simulated IP:

```powershell
1..30 | ForEach-Object {
    curl.exe -sS -o NUL -H "X-Forwarded-For: 10.0.0.34" "$base/"
}
```

The analyzer should record a `rate_detector` detection for `10.0.0.34`.

Wait at least six seconds after the last scenario for the analyzer to process
the requests, then inspect the database:

```powershell
python -c "import sqlite3; c=sqlite3.connect('demo.db'); print(*c.execute('SELECT ip, detector, severity, attack_type FROM detections ORDER BY detection_id DESC LIMIT 20'), sep='\n')"
python -c "import sqlite3; c=sqlite3.connect('demo.db'); print(*c.execute('SELECT ip, risk_score, risk_level, action, reasons FROM decisions ORDER BY decision_id DESC LIMIT 20'), sep='\n')"
```

Expected rule detections include:

| Simulated IP | Expected detection | Expected action |
|---|---|---|
| `10.0.0.31` | `login_failure_detector` | At least `MONITOR` |
| `10.0.0.32` | `bola_detector` | `BLOCK` |
| `10.0.0.33` | `enumeration_detector` | At least `THROTTLE` |
| `10.0.0.34` | `rate_detector` | At least `MONITOR` |

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
