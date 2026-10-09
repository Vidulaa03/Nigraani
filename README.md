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
python -m pip install -r backend\requirements-dev.txt
python -m pytest
```

## Train the anomaly model

Collect verified normal API traffic in the local database before training.
The trainer uses the existing `sim_label` field only to select normal windows;
it does not feed labels into the model as features.

```powershell
python -m backend.ml.train_model
```

The dashboard and analyzer load the saved model at `models\iforest.joblib`.
If it is absent, the analyzer logs a warning and continues with rule detection;
the dashboard reports that ML is unavailable. Event labels are not used by
detectors, feature extraction, or inference.

After training, run the analyzer in a separate terminal:

```powershell
python -m backend.analyzer
```

## Demo warning

This project intentionally includes vulnerable behavior and a demo login
(`admin` / `admin123`) for security testing. Do not expose it to the internet or
use it with real credentials or production data.
