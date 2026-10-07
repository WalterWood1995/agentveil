# Installing AgentVeil (Windows 10/11 x64)

About 15 minutes. Two options: the **offline bundle** (no package downloads during install) or the **online installer**.

## Option 1 — Offline bundle (recommended)

`AgentVeil-offline-win64.zip` on the [Releases](../../releases) page contains the source, all Python wheels (CPython 3.13, win_amd64), Playwright's Firefox build, and the official Tor Expert Bundle (SHA256-checked against torproject.org).

1. Verify the download against the published `.sha256`:
   ```powershell
   Get-FileHash -Algorithm SHA256 .\AgentVeil-offline-win64.zip
   ```
2. Install **Python 3.13 (64-bit)** from python.org — tick *Add python.exe to PATH*.
3. Unzip to **`C:\AgentVeil`** (avoid spaces and non-ASCII characters in the path; Tor and `tar` cannot handle them).
4. Run:
   ```powershell
   powershell -ExecutionPolicy Bypass -File C:\AgentVeil\install-offline.ps1
   ```

## Option 2 — Online installer

```powershell
git clone https://github.com/WalterWood1995/agentveil C:\AgentVeil
powershell -ExecutionPolicy Bypass -File C:\AgentVeil\scripts\install.ps1
```

`install.ps1 -Mirror <pypi-index-url>` lets you use an alternative PyPI mirror.

## Start a tunnel

AgentVeil only sends traffic through a local SOCKS5 tunnel. Pick one:

**A. Tor**

```powershell
C:\AgentVeil\.venv\Scripts\agentveil.exe tor-config --bundle C:\AgentVeil\tor-bundle --bridges none
C:\AgentVeil\tor-bundle\tor\tor.exe -f $HOME\.agentveil\torrc
```

Keep the window open; wait for `Bootstrapped 100% (done)`.
If direct Tor connections don't work on your network, use Tor bridges: `--bridges snowflake`, or save bridge lines from bridges.torproject.org to a file and pass `--bridge-file bridges.txt`.

**B. An existing SOCKS5 proxy** (sing-box, Xray, Clash, …)

Edit `C:\AgentVeil\agentveil.toml`:

```toml
[upstream]
kind = "socks"
port = 1080        # your proxy's local SOCKS5 port
control_port = 0
```

Route everything from that port through the proxy (no "direct" rules), otherwise some requests may bypass it. Templates are in [tunnels/](tunnels).

**C. Both chained** (Tor over your own proxy):

```powershell
C:\AgentVeil\.venv\Scripts\agentveil.exe tor-config --bundle C:\AgentVeil\tor-bundle --bridges none --via-socks 127.0.0.1:1080
```

## Self-test

```powershell
C:\AgentVeil\.venv\Scripts\agentveil.exe status --deep
```

Expect `Tunnel reachable: yes`, an exit IP, and `[OK]` for WebRTC / WebGL / timezone. `FAIL-CLOSED` means the tunnel isn't running — nothing is sent in that state.

## Use

```powershell
C:\AgentVeil\.venv\Scripts\agentveil.exe search "query"
C:\AgentVeil\.venv\Scripts\agentveil.exe fetch "https://www.torproject.org/"
C:\AgentVeil\.venv\Scripts\agentveil.exe open "https://en.wikipedia.org/wiki/Tor_(network)" --screenshot shot.png
```

For agents, the installer writes `C:\AgentVeil\.mcp.json`; any MCP client can use it. Keep in mind your model provider sees what the agent reads.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `py` is not recognized | Reinstall Python with *Add to PATH* |
| "running scripts is disabled" | Use `powershell -ExecutionPolicy Bypass -File …` as shown |
| `tor-config`: "contains spaces or non-ASCII" | Move the folder to `C:\AgentVeil` and reinstall |
| Tor stuck below 100% | Try bridges (`--bridges snowflake` or `--bridge-file`) or option B |
| `fetch` returns 403 | The site rejects script clients; use `open` |
| Search reports a bot challenge | Run `new-identity` and retry |
