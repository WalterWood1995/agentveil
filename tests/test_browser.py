"""Integration tests for the hardened Firefox (needs `playwright install firefox`)."""

import asyncio
import json
import os
import subprocess

import pytest

from agentveil.browser import SecureBrowser
from agentveil.egress import EgressPolicy, Identity, UpstreamUnavailable


def _firefox_installed() -> bool:
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            import os
            return os.path.exists(p.firefox.executable_path)
    except Exception:  # noqa: BLE001
        return False


pytestmark = pytest.mark.skipif(not _firefox_installed(), reason="Playwright Firefox not installed")


@pytest.fixture
async def browser_env(socks, make_cfg):
    cfg = make_cfg(socks.server_address[1])
    b = SecureBrowser(cfg, EgressPolicy(cfg))
    yield cfg, b
    await b.close()


async def test_browser_goes_only_through_tunnel(browser_env, socks, web):
    cfg, b = browser_env
    ident = Identity(cfg)
    snap = await b.open(ident, "http://site.test/")
    assert "Hello agent" in snap.text and snap.title == "Test Page"

    # site.test does not exist in real DNS: it loaded only because the hostname went to the tunnel.
    site = [e for e in socks.log if e["host"] == "site.test"]
    assert site and all(e["atyp"] == 3 for e in site)
    assert all(e["user"] == ident.username for e in site), "per-identity circuit isolation credentials"

    # Hidden prompt-injection text is not part of the visible text.
    assert "IGNORE ALL PREVIOUS" not in snap.text
    # The 127.0.0.1 tracking pixel was blocked by policy and never reached the server.
    assert any("127.0.0.1" in x for x in snap.blocked)
    assert "/track.png" not in web.hits

    # Nothing else was contacted through the tunnel (no telemetry / update / safebrowsing pings).
    print("hosts requested through tunnel:", sorted({e["host"] for e in socks.log}))
    assert {e["host"] for e in socks.log} <= {"site.test"}

    fp = await b.evaluate(snap.page_id, """() => ({
        webrtc: typeof RTCPeerConnection, tz: Intl.DateTimeFormat().resolvedOptions().timeZone,
        lang: navigator.language, webgl: !!document.createElement('canvas').getContext('webgl')})""")
    print("fingerprint surface:", fp)
    assert fp["webrtc"] == "undefined"
    assert fp["webgl"] is False
    assert fp["tz"] in ("UTC", "Etc/UTC", "Atlantic/Reykjavik")
    assert fp["lang"].startswith("en")


async def test_browser_interaction(browser_env):
    cfg, b = browser_env
    snap = await b.open(Identity(cfg), "http://site.test/")
    link = next(e for e in snap.elements if e["label"] == "Go to page two")
    snap2 = await b.act(snap.page_id, "click", element=link["id"])
    assert "Second page reached" in snap2.text
    snap3 = await b.act(snap.page_id, "back")
    box = next(e for e in snap3.elements if e["tag"] == "input")
    await b.act(snap.page_id, "type", element=box["id"], text="tor bridges")
    snap4 = await b.act(snap.page_id, "press", element=box["id"], text="Enter")
    assert "Submitted /submit?q=tor+bridges" in snap4.text
    png, fmt = await b.screenshot(snap.page_id)
    assert fmt == "png" and png[:8] == b"\x89PNG\r\n\x1a\n"


async def test_javascript_off_still_reads(browser_env):
    cfg, b = browser_env
    snap = await b.open(Identity(cfg), "http://site.test/", javascript=False)
    assert "Visible paragraph" in snap.text


def _descendant_tcp_remotes() -> set[str]:
    """Remote addresses of all TCP sockets owned by processes spawned by this test (Windows)."""
    ps = ("Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId | ConvertTo-Json -Compress; "
          "'---'; Get-NetTCPConnection -ErrorAction SilentlyContinue | "
          "Select-Object OwningProcess,RemoteAddress | ConvertTo-Json -Compress")
    out = subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, text=True,
                         timeout=120).stdout
    procs_json, conns_json = out.split("---", 1)
    children: dict[int, list[int]] = {}
    for p in json.loads(procs_json):
        children.setdefault(p["ParentProcessId"], []).append(p["ProcessId"])
    tree, stack = set(), [os.getpid()]
    while stack:
        pid = stack.pop()
        for c in children.get(pid, []):
            if c not in tree:
                tree.add(c)
                stack.append(c)
    return {c["RemoteAddress"] for c in json.loads(conns_json) if c["OwningProcess"] in tree}


@pytest.mark.skipif(os.name != "nt", reason="uses Get-NetTCPConnection")
async def test_firefox_opens_no_direct_internet_sockets(browser_env):
    cfg, b = browser_env
    snap = await b.open(Identity(cfg), "http://site.test/")
    await b.act(snap.page_id, "reload")
    remotes = await asyncio.to_thread(_descendant_tcp_remotes)
    print("remote addresses of Firefox/driver sockets:", sorted(remotes))
    assert remotes, "expected to observe the browser's loopback sockets"
    assert remotes <= {"127.0.0.1", "::1", "0.0.0.0", "::"}


async def test_browser_fail_closed(make_cfg, dead_port):
    cfg = make_cfg(dead_port)
    b = SecureBrowser(cfg, EgressPolicy(cfg))
    try:
        with pytest.raises(UpstreamUnavailable):
            await b.open(Identity(cfg), "https://example.com/")
        assert b._browser is None  # Firefox was never even started
    finally:
        await b.close()
