@echo off
rem ============================================================
rem  Merge-copy upgrade files into the target project.
rem  Each overwritten file gets a .bak-v01 backup first.
rem  ASCII only on purpose (cmd.exe OEM code page).
rem  Usage:
rem    apply-upgrade.cmd "C:\path\to\Web--main" dry   :: preview only
rem    apply-upgrade.cmd "C:\path\to\Web--main"       :: real write
rem ============================================================
setlocal
set "TARGET=%~1"
set "MODE=%~2"

if "%TARGET%"=="" (
  echo Usage: apply-upgrade.cmd "C:\path\to\Web--main" [dry]
  exit /b 2
)

set "EXTRA="
if /I "%MODE%"=="dry" set "EXTRA=-DryRun"

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0apply-upgrade.ps1" -Target "%TARGET%" %EXTRA%
exit /b %errorlevel%
