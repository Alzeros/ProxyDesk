@echo off
rem Debug launcher: keeps the console open so Python errors are visible.
setlocal
set "PY=%USERPROFILE%\.workbuddy\binaries\python\versions\3.13.12\python.exe"
if not exist "%PY%" set "PY=python"
"%PY%" "%~dp0desk.py"
echo.
echo ProxyDesk stopped. Press any key to close.
pause >nul
