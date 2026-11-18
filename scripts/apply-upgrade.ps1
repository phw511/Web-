# Merge-copy this upgrade directory into the target project.
# Overwrites same-named files only; every overwritten file is first backed up
# as <name>.bak-v01. Untouched files (unchanged __init__.py, db/, detector/)
# stay as they are, so NEVER delete the target webvuln/ folder before copying.
#
# ASCII only on purpose (PowerShell 5.1 reads BOM-less UTF-8 as ANSI).
#
# Usage (cwd does not matter):
#   .\scripts\apply-upgrade.ps1 -Target C:\Users\Lenovo\Desktop\Web--main -DryRun
#   .\scripts\apply-upgrade.ps1 -Target C:\Users\Lenovo\Desktop\Web--main
param(
    [Parameter(Mandatory = $true)][string]$Target,
    [string]$Source = '',
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'

# NOTE: $PSScriptRoot is empty inside a param() default value (PowerShell 5.1
# binds parameters before automatic variables exist), so resolve it here.
if ([string]::IsNullOrWhiteSpace($Source)) {
    if ($PSScriptRoot) { $Source = Split-Path -Parent $PSScriptRoot }
    else { $Source = (Get-Location).Path }
}
$Source = [System.IO.Path]::GetFullPath($Source)
$Target = [System.IO.Path]::GetFullPath($Target)

if (-not (Test-Path $Target)) { throw "target directory not found: $Target" }
if (-not (Test-Path (Join-Path $Target 'webvuln'))) {
    throw "-Target does not look like the Web--main project root (missing webvuln/)"
}
if (-not (Test-Path (Join-Path $Source 'webvuln'))) {
    throw "source directory is wrong (no webvuln/ in $Source)"
}

$files = Get-ChildItem -Path $Source -Recurse -File | Where-Object {
    $_.Name -ne 'CHANGES.md' -and
    $_.FullName -notlike '*\scripts\apply-upgrade.ps1' -and
    $_.FullName -notlike '*\scripts\apply-upgrade.cmd' -and
    $_.FullName -notlike '*.bak-v01'
}

Write-Host "source: $Source"
Write-Host "target: $Target"
Write-Host ("files:  " + $files.Count)
Write-Host ''

$written = 0
foreach ($f in $files) {
    $rel = $f.FullName.Substring($Source.Length).TrimStart('\')
    $dest = Join-Path $Target $rel
    if ($DryRun) {
        $mark = if (Test-Path $dest) { 'overwrite' } else { 'new      ' }
        Write-Host ("[{0}] {1}" -f $mark, $rel)
        continue
    }
    $dir = Split-Path -Parent $dest
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    if (Test-Path $dest) { Copy-Item -LiteralPath $dest -Destination "$dest.bak-v01" -Force }
    Copy-Item -LiteralPath $f.FullName -Destination $dest -Force
    $written++
    Write-Host "wrote $rel"
}

if ($DryRun) {
    Write-Host ''
    Write-Host 'DRY RUN: nothing written. Re-run without -DryRun to apply.'
} else {
    Write-Host ''
    Write-Host ("Done. $written file(s) written. Rollback: rename every *.bak-v01 back.")
    Write-Host 'Next: python -m pip install -r requirements.txt ; .\scripts\verify.cmd'
}
