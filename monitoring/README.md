# NIGRAANI local monitoring on native Windows

This setup runs the existing FastAPI app on port **8000**, the existing analyzer metrics endpoint on **8001**, Prometheus on **9090**, Grafana on **3001**, and preserves the Next.js frontend on **3000**. It uses native Windows processes and the Grafana Windows service; it does not use containers. Grafana reads `conf/custom.ini` (never edit `defaults.ini`) and must be restarted after configuration changes. See [Grafana's Windows startup and configuration instructions](https://grafana.com/docs/grafana/latest/setup-grafana/start-restart-grafana/) and [configuration locations](https://grafana.com/docs/grafana/latest/setup-grafana/configure-grafana/).

## Prerequisites and ports

- Project virtual environment `.venv` and backend dependencies from `backend\requirements.txt`.
- Native Grafana OSS Windows installer/service from Grafana Labs.
- Prometheus **Windows AMD64 ZIP** from <https://prometheus.io/download/>. Choose the `windows-amd64` archive, not a `darwin-amd64` macOS build. Do not commit the ZIP or extracted binaries.
- Ports 3000 (Next.js), 3001 (Grafana), 8000 (FastAPI), 8001 (analyzer metrics), and 9090 (Prometheus). Check availability in PowerShell before starting:

```powershell
Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
  Where-Object { $_.LocalPort -in 3000, 3001, 8000, 8001, 9090 } |
  Select-Object LocalAddress, LocalPort, OwningProcess
```

The checked in Prometheus FastAPI scrape target is `127.0.0.1:8000`, matching the existing README command (`uvicorn backend.main:app --reload`) and its default port. The separately started analyzer serves its own process-local metrics on `127.0.0.1:8001/metrics`; this is necessary because its real detection and risk calculations run in a separate process. If you deliberately start Uvicorn on another port, update `monitoring\prometheus.yml` accordingly. The expected app URLs are `http://localhost:3000`, `http://localhost:3001`, and `http://localhost:9090`; FastAPI metrics are at `http://localhost:8000/metrics` and analyzer metrics at `http://localhost:8001/metrics`.

## 1. Install dependencies and start FastAPI

Run in PowerShell from the repository root (`Nigraani`):

```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install -r backend\requirements.txt
uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000
```

Leave the terminal running. In a second PowerShell window from the repository root, verify metrics:

```powershell
(Invoke-WebRequest http://127.0.0.1:8000/metrics -UseBasicParsing).Content | Select-String 'nigraani_http_requests_total|nigraani_risk_score'
```

Prometheus' own scrape of `/metrics` is excluded from the app HTTP and security event counters. The endpoint exposes aggregate operational data only; it does not require auth and should remain bound to localhost for this development setup. Do not expose it publicly.

## 2. Start Prometheus (native Windows)

Download the **Windows AMD64** ZIP from the official Prometheus downloads page and extract its contents to `monitoring\prometheus-<version>.windows-amd64\` (the default optional script path is `monitoring\prometheus-3.15.0.windows-amd64\`). Verify that the extracted folder contains `prometheus.exe` and `promtool.exe`:

```powershell
Get-ChildItem .\monitoring\prometheus-*.windows-amd64\prometheus.exe
Get-ChildItem .\monitoring\prometheus-*.windows-amd64\promtool.exe
```

From the repository root start it with the exact executable path (adjust version folder to the one extracted):

```powershell
.\monitoring\prometheus-3.15.0.windows-amd64\prometheus.exe --config.file="$PWD\monitoring\prometheus.yml" --web.listen-address=127.0.0.1:9090
```

Or from the root run the convenience script:

```powershell
.\monitoring\start-prometheus.ps1
```

For another Prometheus folder, pass its path: `.monitoringstart-prometheus.ps1 -PrometheusDir 'D:\Tools\prometheus-<version>.windows-amd64'`. Stop with Ctrl+C in that window. Open <http://localhost:9090>, then visit **Status → Targets** and confirm `nigraani-backend` is **UP**.

Validate the repository configuration with the extracted Windows tool (run from the root):

```powershell
.\monitoring\prometheus-3.15.0.windows-amd64\promtool.exe check config .\monitoring\prometheus.yml
```

## 3. Set Grafana's native Windows port to 3001

Next.js retains its existing port 3000. The repository file `monitoring\grafana\custom.ini` records the Grafana settings; copying a repo config alone does not reconfigure an already installed Windows service.

1. Find the installed Grafana folder. This machine's service uses `C:\Program Files\GrafanaLabs\grafana`, with config at `C:\Program Files\GrafanaLabs\grafana\conf\custom.ini`. For another installation, inspect **Services → Grafana → Properties → Path to executable** (or locate `grafana-server.exe`). The executable's working/install directory contains `conf`.
2. Stop the Windows service from an elevated PowerShell: `Stop-Service -Name Grafana`.
3. In the installed folder's `conf\custom.ini`, preserve existing settings and merge this section (create `custom.ini` by copying `conf\sample.ini` if it is absent):

   ```ini
   [server]
   http_port = 3001
   ```

   The matching snippet is in `monitoring\grafana\custom.ini`. Do not edit `defaults.ini`.
4. Restart the service: `Start-Service -Name Grafana`. If Grafana is not installed as a service, from its installation directory run ` .\bin\grafana-server.exe --config ".\conf\custom.ini" --homepath .` in its own PowerShell window.
5. Verify the service responds and the port is listening:

   ```powershell
   (Invoke-WebRequest http://127.0.0.1:3001/api/health -UseBasicParsing).StatusCode
   Get-NetTCPConnection -State Listen -LocalPort 3001
   ```

   Also confirm Next.js remains available at `http://localhost:3000`. If the running service continues to bind another port, inspect its service executable arguments for a `--config` override and edit that configured INI file instead. Do not change the frontend's port.

## 4. Configure Grafana and load the dashboard

Open <http://localhost:3001> and sign in using the credentials set by your Grafana installation. In **Connections → Data sources → Add data source**, select Prometheus and set URL to `http://localhost:9090`, then **Save & test**. This avoids assuming the service reads files inside this repository. A version controlled Prometheus data-source provisioning example is at `monitoring\grafana\provisioning\datasources\prometheus.yml`; to provision it, copy it into the installed Grafana `conf\provisioning\datasources\` folder and restart Grafana.

Import `monitoring\grafana\dashboards\nigraani-overview.json` via **Dashboards → New → Import** and select the Prometheus data source. Dashboard refresh is 10 seconds, default range is the last hour. Panels cover request rate and range total, p50/p95/p99 latency, status distribution, 4xx/5xx rate, requests by route/method, real rule detections by detector/severity, existing risk decisions and score distribution, observed ML scores, analysis duration/failures, and backend scrape health. ML and detection panels remain empty until actual scoring or detection runs occur.

## 5. Generate and check real activity

Start the Next.js app from `Frontend` in another terminal with `npm run dev` (`http://localhost:3000`). The directory uses this capitalization in Git; Windows paths are case-insensitive. The existing Next.js default remains unchanged. Visit it and make regular API calls to FastAPI, for example:

```powershell
Invoke-WebRequest http://127.0.0.1:8000/ -UseBasicParsing
Invoke-WebRequest http://127.0.0.1:8000/api/users/101 -UseBasicParsing
```

Check all endpoints and the Prometheus target from the project root:

```powershell
.\monitoring\check-monitoring.ps1
```

The analyzer is a separate existing process (`python -m backend.analyzer`). It consumes persisted request events and produces the genuine detector, ML, and risk results measured by the security metrics. Starting it also starts its local-only Prometheus endpoint on port 8001. To run it, start it from the repository root in its own activated-venv terminal. For safe repeatable detection traffic, use the project's existing simulation/test facilities; the analyzer does not manufacture observations. Stop analyzer, backend, Prometheus, and Next.js with Ctrl+C; restart by repeating their commands. Restart Grafana with `Restart-Service -Name '<service-name>'` after its config changes.

## Metrics and labels

- `nigraani_http_requests_total{method,route,status_code}` counts completed HTTP responses; `/metrics` scrapes are excluded. `route` is a FastAPI route template (unmatched requests use a single `unmatched` label), never raw URL/query/user/IP data.
- `nigraani_http_request_duration_seconds` is the request latency histogram, with the same method/route labels.
- `nigraani_detections_total{detector,severity}` increments only after an existing rule detection is persisted; severity is grouped into low/medium/high/critical bands. Detector label is limited to the four known detector names. These process-local analyzer metrics are exported at port 8001.
- `nigraani_risk_decisions_total{action}` and `nigraani_risk_score` record the actual `compute_risk` result for each successfully analyzed IP window, without changing scores or thresholds.
- `nigraani_ml_anomaly_score` and `nigraani_ml_classifications_total{classification}` record model-returned scores/classifications only when the configured model returns a scoreable window. ML score range is 0–100.
- `nigraani_analysis_runs_total`, `nigraani_analysis_failures_total`, and `nigraani_analysis_duration_seconds` measure actual analyzer work and exceptions.

No metrics include request bodies, credentials, identity values, IPs, query strings, or exception text. Grafana should retain its login enabled; keep all services bound to localhost for this demo.

## Troubleshooting

- **Prometheus target DOWN / connection refused:** make sure Uvicorn is still running at port 8000 and `/metrics` returns exposition text. Start `python -m backend.analyzer` for the analyzer target at port 8001. Confirm `monitoring\prometheus.yml` targets and Uvicorn port match. Check Windows listeners with `Get-NetTCPConnection -State Listen`.
- **`/metrics` returns 404:** confirm the updated backend process imports `backend.main:app`, then restart Uvicorn.
- **Grafana cannot connect to Prometheus:** use `http://localhost:9090` as data source URL; confirm Prometheus `/-/ready` responds locally and no port conflict.
- **Grafana or Next.js port conflict:** keep Grafana on 3001 and Next.js on 3000. Check listeners with `Get-NetTCPConnection -State Listen` and verify both URLs independently.
- **Prometheus YAML parse error:** run `promtool.exe check config .\monitoring\prometheus.yml` from the repository root; use the repository YAML, not the distribution's example file.
- **Windows executable/PATH problem:** invoke `prometheus.exe` and `promtool.exe` by explicit extracted paths and ensure the ZIP folder name ends in `windows-amd64`.
- **Windows firewall/localhost:** keep services bound to loopback as configured. Do not disable Windows Defender or open public firewall rules for this local setup.
- **Metrics look empty:** first make HTTP requests and allow at least one Prometheus scrape interval. A fresh in-memory counter begins at zero after backend restart.
- **No detection/ML series:** these appear only after the separate analyzer processes sufficient actual events and its rule/model produces results. Dashboard panels do not seed example data.
- **Python dependency installation fails:** ensure `.venv` is activated and run `python -m pip install -r backend\requirements.txt`; check the active interpreter with `python -c "import sys; print(sys.executable)"`.
