@echo off
REM Build the portable Windows .exe for VoIP Health Check.
REM Run from the LocalScanner directory:  build_tools\build_windows.bat

setlocal
pushd "%~dp0.."

echo [build] Creating venv if missing...
if not exist .venv (
    python -m venv .venv || goto :err
)
call .venv\Scripts\activate.bat || goto :err

echo [build] Installing build dependencies...
python -m pip install --upgrade pip >nul
python -m pip install pyinstaller || goto :err

echo [build] Running PyInstaller...
pyinstaller build_tools\voipscan.spec --noconfirm || goto :err

echo.
echo [build] Done. Portable exe is at: dist\VoIPHealthCheck.exe
echo [build] Remember to distribute the adjacent ^"nmap\^" folder beside the exe.
popd
endlocal
exit /b 0

:err
echo [build] FAILED. See output above.
popd
endlocal
exit /b 1
