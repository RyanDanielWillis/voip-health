@echo off
:: Use the portable folder located inside VoipScan/
set PATH=%~dp0nmap;%PATH%

echo Starting VoIPScan Local Auditor...
advanced_scanner.exe

pause
