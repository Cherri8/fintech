@echo off
echo Starting Fintech Application...
echo Please wait while the server starts...

REM Change to the project directory
cd /d "%~dp0"

REM Start the Flask server
start cmd /k "python app.py"

REM Wait for the server to start
timeout /t 3 /nobreak

REM Open the application in the default browser
start http://127.0.0.1:5000

echo Application started! You can close this window.
