@echo off
REM Adds inbound Windows Firewall rules for Secure File Transfer (run as Administrator).
net session >nul 2>&1
if errorlevel 1 (
    echo Requesting administrator rights...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)
netsh advfirewall firewall delete rule name="SecureTransfer TCP 5001" >nul 2>&1
netsh advfirewall firewall delete rule name="SecureTransfer UDP 50505" >nul 2>&1
netsh advfirewall firewall add rule name="SecureTransfer TCP 5001" dir=in action=allow protocol=TCP localport=5001 profile=any
netsh advfirewall firewall add rule name="SecureTransfer UDP 50505" dir=in action=allow protocol=UDP localport=50505 profile=any
echo.
echo Firewall rules added: TCP 5001 (encrypted transfer) and UDP 50505 (discovery).
timeout /t 3 >nul
