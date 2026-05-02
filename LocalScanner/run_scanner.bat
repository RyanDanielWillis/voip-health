@echo off
:: Use the portable folder located inside VoipScan/
set PATH=%~dp0nmap;%PATH%

echo Starting VoIPScan Local Auditor...
local_scanner.exe

echo.
echo Audit complete. Results are saved in scan.log.
pause
