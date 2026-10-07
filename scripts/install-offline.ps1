# AgentVeil offline installer (no internet needed). Requires Python 3.13 (x64) installed.
#   Unzip AgentVeil-offline-win64.zip to C:\AgentVeil, then:
#   powershell -ExecutionPolicy Bypass -File C:\AgentVeil\install-offline.ps1
$ErrorActionPreference = 'Stop'
$root = if (Test-Path (Join-Path $PSScriptRoot 'wheels')) { $PSScriptRoot } else { Split-Path -Parent $PSScriptRoot }
Set-Location $root
if ($root -match '\s' -or $root -match '[^\x00-\x7F]') {
    Write-Warning "Path '$root' has spaces or non-ASCII characters; Tor cannot use it. Recommended: C:\AgentVeil"
}

Write-Host '[1/4] virtual environment'
if (-not (Get-Command py -ErrorAction SilentlyContinue)) {
    throw 'Python launcher "py" not found. Install Python 3.13 x64 first (see INSTALL.md), tick "Add to PATH".'
}
py -3.13 -m venv .venv
if ($LASTEXITCODE -ne 0) { throw 'Python 3.13 not found. Install Python 3.13 x64 first (see INSTALL.md).' }
$py = Join-Path $root '.venv\Scripts\python.exe'

Write-Host '[2/4] packages (offline)'
& $py -m pip install --quiet --no-index --find-links wheels setuptools
& $py -m pip install --quiet --no-index --find-links wheels -e ".[dev]"
if ($LASTEXITCODE -ne 0) { throw 'offline package install failed' }

Write-Host '[3/4] Firefox'
$dest = Join-Path $env:LOCALAPPDATA 'ms-playwright'
New-Item -ItemType Directory -Force $dest | Out-Null
foreach ($d in Get-ChildItem (Join-Path $root 'ms-playwright') -Directory) {
    if (-not (Test-Path (Join-Path $dest $d.Name))) { Copy-Item -Recurse $d.FullName $dest }
}

Write-Host '[4/4] Tor'
$tgz = Get-ChildItem (Join-Path $root 'tor') -Filter '*.tar.gz' -ErrorAction SilentlyContinue | Select-Object -First 1
if ($tgz) {
    $torHome = Join-Path $root 'tor-bundle'
    New-Item -ItemType Directory -Force $torHome | Out-Null
    tar -xzf $tgz.FullName -C $torHome
    Write-Host "      Tor extracted to $torHome"
}

& (Join-Path $root 'scripts\write-config.ps1') -Root $root
