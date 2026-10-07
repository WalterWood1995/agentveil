# AgentVeil

**A privacy-first browser built for AI agents.**

AgentVeil gives an AI agent everything it needs to work on the web — search, page fetching, interactive browsing, screenshots, and end-to-end encrypted agent-to-agent messaging — exposed as an [MCP](https://modelcontextprotocol.io) server that Claude Code and other MCP clients can use directly. A command-line tool (`agentveil`) is included as well.

Its core design rule: **all traffic leaves through one local proxy tunnel you choose (Tor, or your own SOCKS5 proxy); if the tunnel is unavailable, requests are refused rather than sent directly.**

MIT licensed · Windows 10/11 x64 · Python 3.11+

---

## Why a dedicated browser for agents?

Agents browse differently from people: they read untrusted pages at machine speed, follow links they did not choose, and can be manipulated by text hidden in a page. AgentVeil is built around that:

| Concern | What AgentVeil does |
|---|---|
| Traffic bypassing the configured proxy | The only egress path is the local SOCKS5 tunnel; there is no direct-connection code path. If the tunnel is down, nothing is sent (fail-closed). Tests confirm the browser process opens no non-loopback TCP sockets. |
| DNS leaks | Hostnames are handed to the tunnel unresolved (SOCKS5 DOMAIN); DoH, DNS prefetch and speculative connects are disabled. |
| WebRTC IP leaks | WebRTC is disabled entirely; the local shim refuses UDP, so no side channel exists. |
| Fingerprinting & tracking | Firefox `resistFingerprinting`, WebGL/sensors/geolocation/notifications/service workers off, UTC + en-US, a throw-away context per page. |
| Linking unrelated tasks | With Tor, each identity uses random SOCKS credentials → its own circuit and exit IP. `new_identity` rotates instantly. |
| Interception at the exit | HTTPS-only by default; TLS failures abort. |
| Prompt injection | Hidden elements, zero-width and Unicode tag characters are stripped; external content is fenced with unforgeable "untrusted" markers; loopback / LAN / cloud-metadata addresses are unreachable. |
| Agent-to-agent communication | Ed25519 signatures + X25519 sealed boxes + length padding; the relay sees only ciphertext and never learns the sender. |

### Limits

- Privacy from websites and the network is not privacy from your **model provider**: a cloud LLM sees the agent's prompts and what it reads.
- Disable your agent's built-in web tools (they do not go through AgentVeil). For Claude Code: `{ "permissions": { "deny": ["WebFetch", "WebSearch"] } }` in `.claude/settings.json`.
- Messaging has no forward secrecy; rotate identities for long-lived secrets.
- JavaScript widens the attack surface; use `javascript=false` for untrusted sites and keep Playwright updated.
- `web_fetch` has a Python TLS fingerprint; some sites (e.g. Wikipedia) reject it — use `browser_open` instead.
- AgentVeil never solves CAPTCHAs; it switches engines or suggests `new_identity`.
- Only AgentVeil's own traffic is covered, not the rest of the system.
- You are responsible for complying with the laws that apply to you.

---

## Architecture

```
 Agent (Claude Code / any MCP client)
        │ MCP (stdio)
        ▼
 ┌──────────────────────────── AgentVeil ────────────────────────────┐
 │ web_search / web_fetch ──┐                                        │
 │ browser_* (hardened FF) ─┼─► EgressPolicy                         │
 │ msg_* (E2E messaging) ───┘   · http(s) only, HTTPS enforced       │
 │                              · no loopback / LAN / metadata       │
 │                              · tunnel down → refuse (fail-closed) │
 │ Firefox ─► isolation shim (local SOCKS: TCP CONNECT only,         │
 │            per-connection policy check, per-identity credentials) │
 └───────────────────────────────┬───────────────────────────────────┘
                                 │ SOCKS5 (hostnames resolved remotely)
                                 ▼
                 Local tunnel: Tor  /  sing-box / Xray  /  both chained
```

| File | Role |
|---|---|
| [agentveil/egress.py](agentveil/egress.py) | Egress policy, tunnel health check, the only HTTP client factory |
| [agentveil/socks_shim.py](agentveil/socks_shim.py) | Isolation shim between Firefox and the tunnel |
| [agentveil/browser.py](agentveil/browser.py) | Hardened Firefox (90+ privacy/security prefs) and page interaction |
| [agentveil/fetcher.py](agentveil/fetcher.py), [extract.py](agentveil/extract.py) | JS-free fetching, per-hop redirect checks, text extraction & sanitizing |
| [agentveil/search.py](agentveil/search.py) | DuckDuckGo (onion service under Tor) / DDG Lite / Mojeek / SearXNG |
| [agentveil/messaging/](agentveil/messaging) | E2E messaging: crypto, blind relay, client |
| [agentveil/mcp_server.py](agentveil/mcp_server.py) | MCP server (14 tools) |
| [agentveil/torconfig.py](agentveil/torconfig.py) | Generates a torrc from the Tor Expert Bundle |

---

## Quick start (Windows)

See [INSTALL.md](INSTALL.md) for the full guide, including the offline installer.

```powershell
powershell -ExecutionPolicy Bypass -File scripts\install.ps1
```

**Start a tunnel** — either:

- **Tor** (no server needed):
  ```powershell
  .venv\Scripts\agentveil.exe tor-config --bundle C:\tor --bridges none
  C:\tor\tor\tor.exe -f $HOME\.agentveil\torrc
  ```
- **Your own SOCKS5 proxy** (sing-box, Xray, …): set `kind = "socks"`, `port = <port>`, `control_port = 0` in `agentveil.toml`. Templates: [tunnels/](tunnels).

**Self-test:**

```powershell
.venv\Scripts\agentveil.exe status --deep
```

**Connect your agent:** the installer writes `.mcp.json` in the project folder (Claude Code picks it up), or:

```powershell
claude mcp add agentveil -- "C:\AgentVeil\.venv\Scripts\python.exe" -m agentveil -c "C:\AgentVeil\agentveil.toml" mcp
```

---

## Tools

| Tool | Purpose |
|---|---|
| `web_search` | Search with no account or API key |
| `web_fetch` | Fetch a page as clean text + links, paged via `offset` |
| `browser_open` | Open a page in hardened Firefox → `page_id`, text, numbered elements |
| `browser_act` | click / type / press / select / check / hover / scroll / back / forward / reload / goto / wait |
| `browser_read` | Re-read a page (paged) |
| `browser_screenshot` | Screenshot |
| `browser_close` | Close a page and destroy its storage |
| `new_identity` | New circuit / exit IP; discard all pages and cookies |
| `security_status` | Tunnel, exit IP and policy check; `deep=true` adds a browser self-test |
| `msg_whoami` | This agent's messaging identity, fingerprint and contact card |
| `msg_add_contact` | Add a peer's contact card (verify the fingerprint out of band) |
| `msg_contacts` | List contacts |
| `msg_send` / `msg_receive` | Send / receive end-to-end encrypted messages |

CLI equivalents: `agentveil search …`, `agentveil fetch URL`, `agentveil open URL --screenshot a.png`, `agentveil new-identity`, `agentveil msg …`.

---

## Agent-to-agent messaging

1. Run a relay: `agentveil relay --port 8787` (in-memory, no logs, sender-blind).
2. Optionally publish it as a Tor onion service (`HiddenServiceDir` / `HiddenServicePort 80 127.0.0.1:8787` in torrc).
3. Set `relay_url` in `agentveil.toml` on both sides.
4. Exchange contact cards from `msg_whoami` (`avc1.…`), add them with `msg_add_contact`, and compare fingerprints over another channel.
5. `msg_send` / `msg_receive`. Incoming messages are labelled verified/unknown and always presented as untrusted data.

Set `AGENTVEIL_PASSPHRASE` before first use to store the identity key encrypted (Argon2id + XSalsa20-Poly1305).

---

## Optional OS-level kill switch

[scripts/firewall-killswitch.ps1](scripts/firewall-killswitch.ps1) adds Windows Firewall rules that block AgentVeil's Python interpreter, Playwright's Firefox and its driver from reaching any non-loopback address — only the tunnel client (a separate program) can go online. Run from an elevated PowerShell; `-Remove` undoes it. The rule applies to the *base* Python interpreter used by the venv, so other programs on that interpreter (including pip) are affected too.

---

## Tests

```powershell
.venv\Scripts\python.exe -m pytest -q
```

The suite uses a recording SOCKS5 proxy and hostnames that exist only in that proxy (`site.test`) to prove that:

- hostnames always reach the tunnel unresolved (the local resolver cannot resolve `site.test`);
- with the tunnel down, zero requests reach the target and Firefox is never started;
- Firefox contacts nothing but the requested site — no telemetry, update or safe-browsing traffic;
- Firefox and its driver hold no non-loopback TCP sockets at the OS level;
- WebRTC is absent, WebGL is off, timezone is UTC+0, language en-US;
- tracking pixels to 127.0.0.1, redirects into private networks and environment proxy variables are all blocked/ignored;
- messages resist tampering, forgery, re-forwarding and replay; nobody else can read or drain a mailbox;
- the MCP server works end-to-end over stdio and reports clear `FAIL-CLOSED` / `BLOCKED` errors.
