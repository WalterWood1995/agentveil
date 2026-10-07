# AgentVeil online installer.
#   powershell -ExecutionPolicy Bypass -File scripts\install.ps1            # default sources
#   powershell -ExecutionPolicy Bypass -File scripts\install.ps1 -Mirror https://<pypi-mirror>/simple
# (ASCII-only on purpose: Windows PowerShell 5.1 misreads UTF-8 scripts without a BOM.)
param([string]$Mirror)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

if ($Mirror) {
    $env:PIP_INDEX_URL = $Mirror
    $env:UV_INDEX_URL = $Mirror
    Write-Host "Using PyPI mirror $Mirror"
}

$py = Join-Path $root '.venv\Scripts\python.exe'
$hasUv = [bool](Get-Command uv -ErrorAction SilentlyContinue)
if (-not (Test-Path $py)) {
    if ($hasUv) { uv venv --python 3.13 .venv }
    elseif (Get-Command py -ErrorAction SilentlyContinue) { py -3.13 -m venv .venv }
    else { throw 'Python 3.13 not found. Install it first (see INSTALL.md).' }
}
if ($hasUv) { uv pip install --python $py -e ".[dev]" }
else { & $py -m pip install -e ".[dev]" }

# Playwright's Firefox (~90 MB). Set PLAYWRIGHT_DOWNLOAD_HOST beforehand to use a mirror.
& $py -m playwright install firefox
if ($LASTEXITCODE -ne 0) { throw 'Firefox download failed. Use the offline bundle instead (INSTALL.md).' }

& (Join-Path $PSScriptRoot 'write-config.ps1') -Root $root
