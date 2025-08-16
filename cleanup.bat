@echo off
echo ========================================
echo Cleaning up test outputs...
echo ========================================

if exist "outputs" (
    echo Removing outputs directory...
    rmdir /s /q outputs
    echo Outputs directory removed.
) else (
    echo No outputs directory found.
)

if exist "venv" (
    echo Removing virtual environment...
    rmdir /s /q venv
    echo Virtual environment removed.
) else (
    echo No virtual environment found.
)

echo.
echo ========================================
echo Cleanup Complete!
echo ========================================
echo.
echo To reinstall:
echo 1. Run install.bat
echo 2. Or manually: python -m venv venv && venv\Scripts\activate && pip install -r requirements.txt
echo.
pause
