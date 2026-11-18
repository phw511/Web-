@echo off
rem ============================================================
rem  One-click verification: env -> compile -> pytest -> sim-demo
rem  ASCII only on purpose: cmd.exe reads this file with the OEM
rem  code page (CP932/CP936/...), non-ASCII bytes break parsing.
rem  Usage: verify.cmd
rem ============================================================
setlocal
cd /d "%~dp0.."

echo == 0. Environment ==
python --version
if errorlevel 1 goto fail
python -c "import fastapi, pydantic, pytest, httpx; print('deps ok')"
if errorlevel 1 goto deps

echo.
echo == 1. Compile check (webvuln + tests) ==
python -m compileall -q webvuln tests
if errorlevel 1 goto fail
echo compile ok

echo.
echo == 2. Unit tests ==
python -m pytest -q
if errorlevel 1 goto fail

echo.
echo == 3. Offline demo (sim-demo) ==
python -m webvuln.cli sim-demo --out .\sim_out
if errorlevel 1 goto fail
if exist sim_out\report.md (
  echo.
  echo --- sim_out\report.md ---
  type sim_out\report.md
)

echo.
echo == ALL PASSED ==
echo Paste this full output back; it is used to write batch 2 docs.
exit /b 0

:deps
echo.
echo [ERROR] Missing dependencies. Run: python -m pip install -r requirements.txt
exit /b 1

:fail
echo.
echo == FAILED == paste the error output above
exit /b 1
