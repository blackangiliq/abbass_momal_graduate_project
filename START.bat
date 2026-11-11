@echo off
setlocal EnableExtensions EnableDelayedExpansion
title Secure File Transfer - E2E Encrypted
cd /d "%~dp0"

echo ===============================================================
echo    Secure File Transfer System with End-to-End Encryption
echo ===============================================================
echo.

REM ---------------------------------------------------------------- 1) find Python 3.9+
set "PY="
for %%P in ("py -3" "python" "python3" "%LOCALAPPDATA%\Programs\Python\Python313\python.exe" "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" "%LOCALAPPDATA%\Programs\Python\Python311\python.exe") do (
    if not defined PY (
        %%~P -c "import sys; sys.exit(0 if sys.version_info>=(3,9) else 1)" >nul 2>nul && set "PY=%%~P"
    )
)

if not defined PY (
    echo [!] Python 3.9+ was not found. Trying to install it with winget...
    winget install -e --id Python.Python.3.12 --scope user --accept-package-agreements --accept-source-agreements
    if exist "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" (
        set "PY=%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
    ) else (
        echo.
        echo [!] Please install Python from https://www.python.org/downloads/
        echo     IMPORTANT: tick "Add python.exe to PATH" during setup, then run START.bat again.
        start "" "https://www.python.org/downloads/"
        pause
        exit /b 1
    )
)
echo [+] Python found: !PY!

REM ---------------------------------------------------------------- 2) virtual environment + packages
if not exist ".venv\Scripts\python.exe" (
    echo [+] Creating virtual environment ^(first run only^)...
    !PY! -m venv .venv
    if errorlevel 1 ( echo [!] Could not create virtual environment & pause & exit /b 1 )
)
if not exist ".venv\.installed" (
    echo [+] Installing required packages ^(first run only, needs internet^)...
    ".venv\Scripts\python.exe" -m pip install --upgrade pip >nul
    ".venv\Scripts\python.exe" -m pip install -r requirements.txt
    if errorlevel 1 ( echo [!] pip install failed - check your internet connection & pause & exit /b 1 )
    echo ok> ".venv\.installed"
)

REM ---------------------------------------------------------------- 3) Windows Firewall rules (one time, needs admin)
netsh advfirewall firewall show rule name="SecureTransfer TCP 5001" >nul 2>nul
if errorlevel 1 (
    echo [+] Opening Windows Firewall ports TCP 5001 and UDP 50505 ^(Administrator permission is requested once^)...
    powershell -NoProfile -Command "Start-Process -FilePath '%~dp0firewall_setup.bat' -Verb RunAs -Wait" 2>nul
)

REM ---------------------------------------------------------------- 4) run
echo [+] Starting... the dashboard will open in your browser.
echo.
".venv\Scripts\python.exe" -m secure_transfer %*
echo.
pause
