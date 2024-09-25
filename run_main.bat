@echo off
setlocal

REM Set absolute paths
set SCRIPT_DIR=%~dp0
set MAIN_PY=%SCRIPT_DIR%main.py

REM Check if python3 is installed
where python3 >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: python3 could not be found. Please install Python 3.
    exit /b 1
)

REM Check if main.py exists
if not exist "%MAIN_PY%" (
    echo ERROR: %MAIN_PY% does not exist.
    exit /b 1
)

REM Check if main.py is already running
tasklist /FI "IMAGENAME eq python.exe" /FI "WINDOWTITLE eq main.py" 2>nul | find /I /N "python.exe">nul
if "%ERRORLEVEL%"=="0" (
    echo ERROR: %MAIN_PY% is already running.
    exit /b 1
)

REM Run the main.py script
python3 "%MAIN_PY%"
if %errorlevel% neq 0 (
    echo ERROR: main.py failed with exit code %errorlevel%
    exit /b 1
) else (
    echo main.py completed successfully.
)

endlocal
