@echo off
:: AcerbE™ Launcher — Windows
:: Double-click this file to launch

title AcerbE™ — Military-Grade Digital Fingerprinter
cd /d "%~dp0"

echo.
echo ==================================================
echo   AcerbE™ — Military-Grade Digital Fingerprinter
echo ==================================================
echo.

:: Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo   ERROR: Python 3 is not installed.
    echo   Please install it from https://python.org
    echo   Make sure to check "Add Python to PATH" during install.
    echo.
    pause
    exit /b 1
)

echo   Checking dependencies...
python -c "import PIL, cryptography, pikepdf" >nul 2>&1
if errorlevel 1 (
    echo   Installing required packages (first run only^)...
    pip install Pillow cryptography pikepdf --quiet
)

echo   Launching AcerbE(TM)...
echo   Your browser will open automatically.
echo   To stop AcerbE(TM), close this window.
echo.

python server.py
pause
