@echo off
REM Run CrossPlatformVerify with a fixed seed and write output to a file.
REM Use the same seed on Windows and Linux, then diff the two output files.
REM Usage: run_cross_platform_verify.bat [seed] [output_file]
REM Example: run_cross_platform_verify.bat 12345 results_windows.txt

set SCRIPT_DIR=%~dp0
cd /d "%SCRIPT_DIR%"
set SEED=%1
if "%SEED%"=="" set SEED=12345
set OUT=%2
if "%OUT%"=="" set OUT=cross_platform_verify_output.txt

echo Building and running with SEED=%SEED%, output to %OUT%
dotnet run --project CrossPlatformVerify.csproj -- %SEED% > "%OUT%" 2>&1
if errorlevel 1 (
  echo Build or run failed. Check %OUT% for details.
  type "%OUT%"
  exit /b 1
)
type "%OUT%"
echo.
echo Output saved to %OUT%. On Linux run with the same seed and compare:
echo   diff results_windows.txt results_linux.txt
