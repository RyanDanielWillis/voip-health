@echo off
REM Launch the VoIP Health Check client from source on Windows.
REM Useful for development; end-users get the PyInstaller .exe instead.

setlocal
pushd "%~dp0"

REM Make the bundled nmap discoverable to child processes too.
set "PATH=%~dp0nmap;%PATH%"

python voipscan_app.py
set RC=%ERRORLEVEL%

popd
endlocal
exit /b %RC%
