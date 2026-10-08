@echo off
setlocal
cd /d "%~dp0"

set "PYTHON=python"
if exist ".venv\Scripts\python.exe" set "PYTHON=%~dp0.venv\Scripts\python.exe"

"%PYTHON%" --version >nul 2>&1
if errorlevel 1 (
    echo Python was not found. Install Python or create the project .venv first.
    exit /b 1
)

"%PYTHON%" -c "import fastapi, uvicorn, pandas, sklearn, joblib" >nul 2>&1
if errorlevel 1 (
    echo Required packages are missing. Run:
    echo   "%PYTHON%" -m pip install -r backend\requirements.txt
    exit /b 1
)

if not exist "models\iforest.joblib" (
    echo The trained model is missing: models\iforest.joblib
    echo Train on verified normal traffic before starting the analyzer:
    echo   "%PYTHON%" -m ml.train_model path\to\normal_events.json
    exit /b 1
)

start "NIGRAANI API" "%ComSpec%" /k ""%PYTHON%" -m uvicorn backend.main:app --reload"
timeout /t 2 /nobreak >nul
start "NIGRAANI Analyzer" "%ComSpec%" /k ""%PYTHON%" -m backend.analyzer"

echo Started the API and analyzer in separate terminal windows.
echo API docs: http://127.0.0.1:8000/docs
endlocal
