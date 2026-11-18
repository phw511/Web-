# One-click verification (ASCII only: Windows PowerShell 5.1 reads BOM-less
# UTF-8 files as ANSI, so keep this file free of non-ASCII characters).
# Usage (from anywhere):
#   .\scripts\verify.ps1
#   .\scripts\verify.ps1 -SkipSim
param([switch]$SkipSim)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

Write-Host '== 0. Environment ==' -ForegroundColor Cyan
python --version
if ($LASTEXITCODE -ne 0) { throw 'python not available' }
python -c "import fastapi, pydantic, pytest, httpx; print('deps ok')"
if ($LASTEXITCODE -ne 0) { throw 'missing deps: python -m pip install -r requirements.txt' }

Write-Host '== 1. Compile check (webvuln + tests) ==' -ForegroundColor Cyan
python -m compileall -q webvuln tests
if ($LASTEXITCODE -ne 0) { throw 'compileall failed: syntax error' }
Write-Host 'compile ok' -ForegroundColor DarkGray

Write-Host '== 2. Unit tests ==' -ForegroundColor Cyan
python -m pytest -q
$pytestExit = $LASTEXITCODE
if ($pytestExit -ne 0) { throw "pytest failed (exit $pytestExit)" }

if (-not $SkipSim) {
    Write-Host '== 3. Offline demo (sim-demo) ==' -ForegroundColor Cyan
    $out = Join-Path $root 'sim_out'
    python -m webvuln.cli sim-demo --out $out
    if ($LASTEXITCODE -ne 0) { throw 'sim-demo failed' }
    Write-Host '--- sim_out/report.md ---' -ForegroundColor DarkGray
    Get-Content (Join-Path $out 'report.md')
    $chain = Join-Path $out 'evidence\chain.jsonl'
    if (Test-Path $chain) {
        $lines = (Get-Content $chain | Measure-Object -Line).Lines
        Write-Host ("chain.jsonl records: " + $lines) -ForegroundColor DarkGray
    }
}

Write-Host '== ALL PASSED ==' -ForegroundColor Green
Write-Host 'Paste this full output back; it is used to write batch 2 docs.' -ForegroundColor Green
