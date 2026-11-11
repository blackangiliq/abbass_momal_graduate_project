@echo off
REM Removes the firewall rules added by firewall_setup.bat
net session >nul 2>&1
if errorlevel 1 (
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)
netsh advfirewall firewall delete rule name="SecureTransfer TCP 5001"
netsh advfirewall firewall delete rule name="SecureTransfer UDP 50505"
pause
