# Builds dist\AgentVeil-offline-win64.zip: source + all Python wheels + Playwright Firefox
# (+ the official Tor Expert Bundle, sha256-checked). Run on a machine with normal internet.
#   powershell -ExecutionPolicy Bypass -File scripts\build-offline-bundle.ps1 [-NoTor]
param([switch]$NoTor)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$root = Split-Path -Parent $PSScriptRoot
$out = Join-Path $root 'dist'
$name = 'AgentVeil-offline-win64'
$stage = Join-Path $out $name
if (Test-Path $stage) { Remove-Item -Recurse -Force $stage }
New-Item -ItemType Directory -Force $stage | Out-Null

Write-Host '[1/5] source'
foreach ($item in 'agentveil', 'scripts', 'tunnels', 'tests', 'pyproject.toml', 'README.md', 'INSTALL.md', 'LICENSE', 'agentveil.example.toml') {
    Copy-Item -Recurse (Join-Path $root $item) $stage
}
Get-ChildItem $stage -Recurse -Directory -Filter '__pycache__' | Remove-Item -Recurse -Force
Copy-Item (Join-Path $PSScriptRoot 'install-offline.ps1') $stage

Write-Host '[2/5] Python wheels (Windows x64, CPython 3.13)'
$venvPy = Join-Path $root '.venv\Scripts\python.exe'
$pwVersion = (& $venvPy -c "import importlib.metadata as m; print(m.version('playwright'))").Trim()
py -3.13 -m pip download --quiet --only-binary=:all: --platform win_amd64 --python-version 3.13 --implementation cp `
    -d (Join-Path $stage 'wheels') "httpx[socks]>=0.27" "beautifulsoup4>=4.12" "playwright==$pwVersion" "pynacl>=1.5" "mcp>=2.0" "setuptools>=68" pytest pytest-asyncio
if ($LASTEXITCODE -ne 0) { throw 'pip download failed' }

Write-Host "[3/5] Playwright Firefox (playwright $pwVersion)"
$pwDir = Join-Path $env:LOCALAPPDATA 'ms-playwright'
$ff = Get-ChildItem $pwDir -Directory -Filter 'firefox-*' | Sort-Object Name -Descending | Select-Object -First 1
if (-not $ff) { throw 'Playwright Firefox not installed; run scripts\install.ps1 first' }
New-Item -ItemType Directory -Force (Join-Path $stage 'ms-playwright') | Out-Null
Copy-Item -Recurse $ff.FullName (Join-Path $stage 'ms-playwright')

if (-not $NoTor) {
    Write-Host '[4/5] Tor Expert Bundle'
    $base = 'https://dist.torproject.org/torbrowser/'
    $listing = (Invoke-WebRequest -UseBasicParsing $base).Content
    $versions = [regex]::Matches($listing, 'href="(\d+\.\d+(?:\.\d+)?)/"') | ForEach-Object { $_.Groups[1].Value }
    $ver = $versions | Sort-Object { [version]$_ } -Descending | Select-Object -First 1
    $file = "tor-expert-bundle-windows-x86_64-$ver.tar.gz"
    $torDir = Join-Path $stage 'tor'
    New-Item -ItemType Directory -Force $torDir | Out-Null
    Invoke-WebRequest -UseBasicParsing "$base$ver/$file" -OutFile (Join-Path $torDir $file)
    $sums = (Invoke-WebRequest -UseBasicParsing "$base$ver/sha256sums-signed-build.txt").Content
    if ($sums -is [byte[]]) { $sums = [Text.Encoding]::ASCII.GetString($sums) }
    $line = ($sums -split "`n") | Where-Object { $_ -match [regex]::Escape($file) } | Select-Object -First 1
    if (-not $line) { throw "no checksum published for $file" }
    $expected = ($line -split '\s+')[0].ToLower()
    $actual = (Get-FileHash -Algorithm SHA256 (Join-Path $torDir $file)).Hash.ToLower()
    if ($expected -ne $actual) { throw "Tor bundle checksum mismatch: $actual vs $expected" }
    Set-Content -Encoding ascii (Join-Path $torDir 'SHA256SUM.txt') "$actual  $file"
    Write-Host "      Tor $ver verified: $actual"
} else {
    Write-Host '[4/5] Tor skipped'
}

Write-Host '[5/5] zip'
$zip = Join-Path $out "$name.zip"
if (Test-Path $zip) { Remove-Item -Force $zip }
Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zip -CompressionLevel Optimal
$hash = (Get-FileHash -Algorithm SHA256 $zip).Hash.ToLower()
Set-Content -Encoding ascii "$zip.sha256" "$hash  $name.zip"
Write-Host "done: $zip"
Write-Host "sha256: $hash"
