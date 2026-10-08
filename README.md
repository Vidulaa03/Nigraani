# NIGRAANI

NIGRAANI is a FastAPI demo for API abuse detection and monitoring. It logs API
activity, detects patterns such as login brute force, request spikes, ID
enumeration, and BOLA/IDOR, then calculates a risk score and enforcement
recommendation.

## Run locally

From the project root, create and activate a virtual environment, then install
the dependencies:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r backend\requirements.txt
```

Start the API:

```powershell
uvicorn backend.main:app --reload
```

The API documentation is available at <http://127.0.0.1:8000/docs>.

## Tests

```powershell
python -m pip install pytest
python -m pytest
```

## Demo warning

This project intentionally includes vulnerable behavior and a demo login
(`admin` / `admin123`) for security testing. Do not expose it to the internet or
use it with real credentials or production data.