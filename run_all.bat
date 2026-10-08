@echo off
setlocal
cd /d "%~dp0"

set "PYTHON=python"
if exist ".venv\Scripts\python.exe" set "PYTHON=%~dp0.venv\Scripts\python.exe"
if not exist ".venv\Scripts\python.exe" if exist "venv\Scripts\python.exe" set "PYTHON=%~dp0venv\Scripts\python.exe"

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

curl.exe -fsS --max-time 2 http://127.0.0.1:8000/ >nul 2>&1
if not errorlevel 1 goto api_ready

start "NIGRAANI API" "%ComSpec%" /k ""%PYTHON%" -m uvicorn backend.main:app --reload"
set /a ATTEMPT=0

:wait_for_api
curl.exe -fsS --max-time 2 http://127.0.0.1:8000/ >nul 2>&1
if not errorlevel 1 goto api_ready
set /a ATTEMPT+=1
if %ATTEMPT% GEQ 30 goto api_timeout
timeout /t 1 /nobreak >nul
goto wait_for_api

:api_timeout
echo API did not become ready at http://127.0.0.1:8000 within 30 seconds.
exit /b 1

:api_ready
echo API is ready at http://127.0.0.1:8000

start "NIGRAANI Analyzer" "%ComSpec%" /k ""%PYTHON%" -m backend.analyzer"

echo Started the analyzer after confirming the API is ready.
echo The analyzer allows only one running instance per database.
echo API docs: http://127.0.0.1:8000/docs
endlocal
