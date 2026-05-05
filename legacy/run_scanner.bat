@echo off
:: ============================================================
::  LEGACY LAUNCHER — DO NOT RUN.
::
::  This batch file used to start the pre-2.2.0 advanced_scanner
::  which kicked off the broad nmap sweep across
::    192.168.1.0/24 192.168.41.0/24
::  and frequently appeared to hang. The active launcher is now
::  LocalScanner\run.bat in the parent folder.
:: ============================================================
echo.
echo This launcher is LEGACY and has been disabled.
echo Run ..\run.bat (or VoIPHealthCheck.exe from the latest
echo GitHub Actions artifact) instead.
echo.
echo If you are seeing logs that contain:
echo     Running Quick Scan: ... 192.168.1.0/24 192.168.41.0/24 ...
echo you are running an OLD copy of this folder. Download the
echo latest VoIPHealthCheck-windows-package artifact.
echo.
pause
exit /b 1
