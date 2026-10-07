# AgentVeil online installer.
#   powershell -ExecutionPolicy Bypass -File scripts\install.ps1            # default sources
#   powershell -ExecutionPolicy Bypass -File scripts\install.ps1 -China     # mainland China mirrors
# (ASCII-only on purpose: Windows PowerShell 5.1 misreads UTF-8 scripts without a BOM.)
param([switch]$China)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

if ($China) {
    $env:PIP_INDEX_URL = 'https://pypi.tuna.tsinghua.edu.cn/simple'
    $env:UV_INDEX_URL = 'https://pypi.tuna.tsinghua.edu.cn/simple'
    $env:UV_PYTHON_INSTALL_MIRROR = 'https://registry.npmmirror.com/-/binary/python-build-standalone'
    Write-Host 'Using mainland-China mirrors (Tsinghua PyPI, npmmirror).'
}

$py = Join-Path $root '.venv\Scripts\python.exe'
$hasUv = [bool](Get-Command uv -ErrorAction SilentlyContinue)
if (-not (Test-Path $py)) {
    if ($hasUv) { uv venv --python 3.13 .venv }
    elseif (Get-Command py -ErrorAction SilentlyContinue) { py -3.13 -m venv .venv }
    else { throw 'Python 3.13 not found. Install it first (see INSTALL-CN.md).' }
}
if ($hasUv) { uv pip install --python $py -e ".[dev]" }
else { & $py -m pip install -e ".[dev]" }

# Playwright's Firefox (~90 MB). Retry through the npmmirror copy if the default CDN fails.
& $py -m playwright install firefox
if ($LASTEXITCODE -ne 0 -and $China) {
    $env:PLAYWRIGHT_DOWNLOAD_HOST = 'https://cdn.npmmirror.com/binaries/playwright'
    & $py -m playwright install firefox
}
if ($LASTEXITCODE -ne 0) { throw 'Firefox download failed. Use the offline bundle instead (INSTALL-CN.md).' }

& (Join-Path $PSScriptRoot 'write-config.ps1') -Root $root
