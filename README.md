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

## Demo rehearsal

After training the anomaly model, use [`DEMO.md`](./DEMO.md) for the
end-to-end scenarios and run `.\run_all.bat` to start the API and analyzer in
separate terminal windows.

## Tests

```powershell
python -m pip install pytest
python -m pytest
```

## Train the anomaly model

Collect normal API traffic, then save an event JSON file containing only
verified normal events. Do not use attack traffic in the training file.

```powershell
python -m ml.train_model path\to\normal_events.json
```

The analyzer uses the saved model at `models\iforest.joblib` and reports a
clear error if it has not been trained. Event labels are not used by detectors,
feature extraction, training, or inference.

After training, run the analyzer in a separate terminal:

```powershell
python -m backend.analyzer
```

## Demo warning

This project intentionally includes vulnerable behavior and a demo login
(`admin` / `admin123`) for security testing. Do not expose it to the internet or
use it with real credentials or production data.