@echo off
setlocal
cd /d %~dp0
if not exist .venv (
  echo Creating virtual environment...
  py -m venv .venv
)
call .venv\Scripts\activate.bat
python -m pip install -r requirements.txt
if errorlevel 1 (
  echo.
  echo Dependency installation failed. Check your internet connection and Python installation.
  pause
  exit /b 1
)
echo.
echo Starting CyberGraud AI...
echo Open http://127.0.0.1:8000 in your browser.
python -m uvicorn app.main:app --reload
pause
