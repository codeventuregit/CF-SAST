@echo off
REM CFML SAST Baseline Creation Script
REM Creates a baseline of current findings to suppress in future scans

echo Creating CFML SAST baseline...

REM Check if scanner exists
if not exist "CFSAST\cfml_sast_simple.py" (
    echo Error: CFML SAST scanner not found. Run install first.
    exit /b 1
)

REM Find Python
set "python_cmd="
python --version >nul 2>&1
if not errorlevel 1 set "python_cmd=python"

if "%python_cmd%"=="" (
    py -3 --version >nul 2>&1
    if not errorlevel 1 set "python_cmd=py -3"
)

if "%python_cmd%"=="" (
    echo Error: Python not found
    exit /b 1
)

REM Get all CFML files
set "cfml_files="
for /r %%f in (*.cfm *.cfc *.cfml *.cfinclude) do (
    set "cfml_files=!cfml_files! "%%f""
)

if "%cfml_files%"=="" (
    echo No CFML files found
    exit /b 0
)

REM Create baseline
echo Scanning all CFML files to create baseline...
%python_cmd% "CFSAST\cfml_sast_simple.py" --files%cfml_files% --baseline ".sast-baseline.json" --update-baseline

if errorlevel 1 (
    echo Baseline creation failed
    exit /b 1
)

echo.
echo ✅ Baseline created successfully!
echo Future scans will only show NEW findings.
echo.
echo Usage:
echo   %python_cmd% CFSAST\cfml_sast_simple.py --files *.cfm --baseline .sast-baseline.json
echo.
pause