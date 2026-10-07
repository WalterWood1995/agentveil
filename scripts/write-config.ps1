# Creates agentveil.toml (if missing) and .mcp.json for Claude Code with this machine's paths.
param([Parameter(Mandatory = $true)][string]$Root)
$ErrorActionPreference = 'Stop'
$cfg = Join-Path $Root 'agentveil.toml'
if (-not (Test-Path $cfg)) { Copy-Item (Join-Path $Root 'agentveil.example.toml') $cfg }
$py = Join-Path $Root '.venv\Scripts\python.exe'
$mcp = @{ mcpServers = @{ agentveil = @{ command = $py; args = @('-m', 'agentveil', '-c', $cfg, 'mcp') } } }
$json = $mcp | ConvertTo-Json -Depth 5
[IO.File]::WriteAllText((Join-Path $Root '.mcp.json'), $json, (New-Object Text.UTF8Encoding $false))
Write-Host ''
Write-Host 'Installed. Next steps:'
Write-Host '  1. Start your tunnel (Tor or sing-box), see INSTALL.md'
Write-Host "  2. Self-test:  `"$py`" -m agentveil status --deep"
