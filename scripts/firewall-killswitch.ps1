<#
.SYNOPSIS
  Optional OS-level kill switch for AgentVeil (Windows Defender Firewall).

  Blocks the Python interpreter that runs AgentVeil, Playwright's Firefox and Playwright's
  node driver from connecting to ANY non-loopback address. They can then only reach the local
  tunnel client (Tor / sing-box on 127.0.0.1), which is a different program and keeps working.
  Even a bug in AgentVeil or in Firefox could not leak a direct connection.

  WARNING: Windows venvs run the *base* interpreter, so every program using that same Python
  installation loses direct internet access too (including pip). Use a Python installation
  dedicated to AgentVeil, or remove the rules with -Remove when you need pip.

.EXAMPLE
  # elevated PowerShell:
  powershell -ExecutionPolicy Bypass -File scripts\firewall-killswitch.ps1
  powershell -ExecutionPolicy Bypass -File scripts\firewall-killswitch.ps1 -Remove
#>
param(
    [switch]$Remove,
    [string]$PythonExe
)
$ErrorActionPreference = 'Stop'
$group = 'AgentVeil Kill Switch'

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an elevated (Administrator) PowerShell.'
}

Get-NetFirewallRule -Group $group -ErrorAction SilentlyContinue | Remove-NetFirewallRule
if ($Remove) {
    Write-Host 'AgentVeil kill-switch rules removed.'
    return
}

$root = Split-Path -Parent $PSScriptRoot
$venvPy = Join-Path $root '.venv\Scripts\python.exe'
if (-not $PythonExe) {
    $PythonExe = (& $venvPy -c "import sys; print(sys._base_executable)").Trim()
}

$programs = @($PythonExe, $venvPy)
$pwRoot = Join-Path $env:LOCALAPPDATA 'ms-playwright'
if (Test-Path $pwRoot) {
    $programs += Get-ChildItem $pwRoot -Recurse -Filter 'firefox.exe' -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName }
}
$driver = Join-Path $root '.venv\Lib\site-packages\playwright\driver'
if (Test-Path $driver) {
    $programs += Get-ChildItem $driver -Recurse -Filter 'node.exe' -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName }
}

# Everything except 127.0.0.0/8 and ::1
$nonLoopback = @('0.0.0.0-126.255.255.255', '128.0.0.0-255.255.255.255', '::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff')

foreach ($p in ($programs | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique)) {
    $name = 'AgentVeil block direct egress: ' + (Split-Path $p -Leaf)
    New-NetFirewallRule -DisplayName $name -Group $group -Direction Outbound -Action Block `
        -Program $p -RemoteAddress $nonLoopback -Protocol Any -Profile Any | Out-Null
    Write-Host "blocked direct egress: $p"
}
Write-Host ''
Write-Host 'Done. Verify with:  Get-NetFirewallRule -Group "AgentVeil Kill Switch"'
Write-Host 'Remove with:        scripts\firewall-killswitch.ps1 -Remove'
