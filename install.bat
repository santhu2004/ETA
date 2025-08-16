@echo off
echo ========================================
echo Encrypted Traffic Analysis System
echo ========================================
echo.

echo Creating virtual environment...
python -m venv venv

echo Activating virtual environment...
call venv\Scripts\activate.bat

echo Installing dependencies...
pip install -r requirements.txt

echo.
echo ========================================
echo Installation Complete!
echo ========================================
echo.
echo To get started:
echo 1. Activate the virtual environment: venv\Scripts\activate.bat
echo 2. Clear any existing logs: python -m cli.main clear-logs
echo 3. Generate test data: python -m cli.main simulate --count 50 --malicious-ratio 0.3
echo 4. Run analysis: python -m cli.main capture --replay
echo 5. View help: python -m cli.main --help
echo.
echo All outputs will be organized in the 'outputs/' directory:
echo   - outputs/data/     (simulated flows and captured data)
echo   - outputs/logs/     (detection logs and databases)
echo   - outputs/state/    (blocked IPs and system state)
echo   - outputs/exports/  (exported data files)
echo.
echo For more information, see README.md
echo.
pause
