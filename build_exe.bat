@echo off
REM Optional: build a single SecureTransfer.exe (no Python needed on the target PC).
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" ( echo Run START.bat once first. & pause & exit /b 1 )
".venv\Scripts\python.exe" -m pip install pyinstaller
".venv\Scripts\python.exe" -m PyInstaller --noconfirm --onefile --console --name SecureTransfer ^
  --add-data "secure_transfer\templates;secure_transfer\templates" ^
  --add-data "secure_transfer\static;secure_transfer\static" ^
  run_app.py
echo.
echo Done: dist\SecureTransfer.exe  (copy it with firewall_setup.bat to the other PC)
pause
