"""Wires the components together and renders agent-friendly text. Used by MCP server and CLI."""

from __future__ import annotations

import json
import time
from collections import OrderedDict
from datetime import datetime, timezone

import httpx

from . import __version__
from .browser import BrowserError, SecureBrowser, Snapshot
from .config import Config
from .egress import EgressBlocked, EgressPolicy, Identity, UpstreamUnavailable, check_upstream
from .extract import html_to_text, strip_invisible, wrap_untrusted
from .fetcher import Fetcher, describe_http_error
from .messaging.client import Messenger, MessagingError, describe_identity
from .messaging.crypto import CryptoError, fingerprint
from .search import Searcher
from .torctl import TorControl, TorControlError

TOR_CHECK = "https://check.torproject.org/api/ip"


class AgentVeilError(Exception):
    """Anticipated failure with a message meant for the agent."""


def _err(e: Exception) -> AgentVeilError:
    if isinstance(e, UpstreamUnavailable):
        return AgentVeilError(f"FAIL-CLOSED: {e}")
    if isinstance(e, EgressBlocked):
        return AgentVeilError(f"BLOCKED by egress policy (nothing was sent): {e}")
    if isinstance(e, httpx.HTTPError):
        return AgentVeilError(describe_http_error(e))
    if isinstance(e, (BrowserError, MessagingError, CryptoError, TorControlError)):
        return AgentVeilError(str(e))
    return AgentVeilError(f"{e.__class__.__name__}: {str(e).splitlines()[0][:300] if str(e) else ''}")


class Runtime:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.policy = EgressPolicy(cfg)
        self.identity = Identity(cfg)
        self.fetcher = Fetcher(cfg, self.policy)
        self.searcher = Searcher(cfg, self.fetcher)
        self.browser = SecureBrowser(cfg, self.policy)
        self.messenger = Messenger(cfg, self.policy)
        self._docs: OrderedDict[str, tuple[float, str, str]] = OrderedDict()

    def _route_label(self) -> str:
        up = self.cfg.upstream
        iso = f", circuit {self.identity.serial}" if up.kind == "tor" and up.isolate else ""
        return f"via {up.kind} {up.host}:{up.port}{iso}"

    # ---- search & fetch ------------------------------------------------------------------
    async def search(self, query: str, max_results: int = 8) -> str:
        query = query.strip()
        if not query:
            raise AgentVeilError("empty query")
        try:
            provider, hits, errors = await self.searcher.search(self.identity, query, max(1, min(max_results, 25)))
        except Exception as e:  # noqa: BLE001
            raise _err(e) from None
        if not hits:
            raise AgentVeilError("no results. " + "; ".join(errors) +
                                 " — engines often challenge Tor exits; try new_identity and search again.")
        body = "\n\n".join(f"[{i}] {h.title}\n{h.url}\n{h.snippet}" for i, h in enumerate(hits, 1))
        head = f"Search: {query!r} · engine: {provider} · {len(hits)} results · {self._route_label()}"
        if errors:
            head += f"\n(fallback used; earlier engines failed: {'; '.join(errors)})"
        return head + "\n" + wrap_untrusted(provider, body, kind="SEARCH RESULTS")

    async def fetch(self, url: str, *, max_chars: int = 20000, offset: int = 0, allow_insecure_http: bool = False) -> str:
        key = f"{url}|{allow_insecure_http}"
        cached = self._docs.get(key)
        if cached and time.time() - cached[0] < 600 and offset > 0:
            _, header, doc = cached
        else:
            try:
                res, charset = await self.fetcher.fetch(self.identity, url, allow_http=allow_insecure_http)
            except Exception as e:  # noqa: BLE001
                raise _err(e) from None
            header, doc = self._render(res, charset)
            self._docs[key] = (time.time(), header, doc)
            while len(self._docs) > 20:
                self._docs.popitem(last=False)
        offset = max(0, offset)
        chunk = doc[offset:offset + max_chars]
        end = offset + len(chunk)
        more = f"\n[{len(doc) - end} more characters — call web_fetch again with offset={end}]" if end < len(doc) else ""
        return (f"{header}\nShowing characters {offset}–{end} of {len(doc)}.\n"
                + wrap_untrusted(url, chunk) + more)

    def _render(self, res, charset) -> tuple[str, str]:
        lines = [f"URL: {res.url}", f"Status: {res.status} · {res.content_type or 'unknown type'} · {self._route_label()}"]
        if res.redirects:
            lines.append("Redirects: " + " → ".join(res.redirects + [res.url]))
        if res.truncated:
            lines.append(f"Note: body truncated at {len(res.body)} bytes (policy.max_response_bytes).")
        if res.is_html:
            ex = html_to_text(res.text(charset), res.url)
            notes = []
            if ex.hidden_removed:
                notes.append(f"{ex.hidden_removed} hidden elements removed")
            if ex.invisible_chars_removed:
                notes.append(f"{ex.invisible_chars_removed} invisible characters removed")
            if notes:
                lines.append("Sanitized: " + ", ".join(notes) + " (possible hidden-prompt carriers).")
            doc = (f"# {ex.title}\n\n" if ex.title else "") + ex.text
            if ex.links:
                doc += "\n\nLinks:\n" + "\n".join(f"- {t or '(no text)'} — {u}" for t, u in ex.links)
            return "\n".join(lines), doc
        if res.is_textual:
            text, n = strip_invisible(res.text(charset))
            if "json" in res.content_type:
                try:
                    text = json.dumps(json.loads(text), indent=1, ensure_ascii=False)
                except ValueError:
                    pass
            return "\n".join(lines), text
        return "\n".join(lines), (f"[binary content: {res.content_type or 'unknown'}, {len(res.body)} bytes — not shown. "
                                  "Open it with browser_open if it is a PDF or page.]")

    # ---- browser -------------------------------------------------------------------------
    def _render_snapshot(self, s: Snapshot, *, header: str = "") -> str:
        parts = [header] if header else []
        parts.append(f"page_id: {s.page_id} · {s.url} · {self._route_label()}")
        if s.blocked:
            parts.append("Blocked/failed requests:\n" + "\n".join(f"  - {b}" for b in s.blocked[:15]))
        body = (f"# {s.title}\n\n" if s.title else "") + s.text
        end = s.offset + len(s.text)
        if end < s.total_chars:
            body += f"\n[{s.total_chars - end} more characters — browser_read with offset={end}]"
        if s.elements:
            els = []
            for e in s.elements:
                desc = e["tag"] + (f"[{e['type']}]" if e.get("type") else "") + (f"({e['role']})" if e.get("role") else "")
                extra = f" → {e['href']}" if e.get("href") else ""
                dis = " (disabled)" if e.get("disabled") else ""
                els.append(f"[{e['id']}] {desc} {e.get('label', '')!r}{extra}{dis}")
            body += "\n\nInteractive elements (use the number with browser_act):\n" + "\n".join(els)
        parts.append(wrap_untrusted(s.url, body, kind="PAGE CONTENT"))
        return "\n".join(parts)

    async def browser_open(self, url: str, *, javascript: bool | None = None, allow_insecure_http: bool = False,
                           max_chars: int = 12000) -> str:
        try:
            snap = await self.browser.open(self.identity, url, javascript=javascript,
                                           allow_http=allow_insecure_http, max_chars=max_chars)
        except Exception as e:  # noqa: BLE001
            raise _err(e) from None
        return self._render_snapshot(snap)

    async def browser_act(self, page_id: str, action: str, element: int | None = None, text: str | None = None,
                          max_chars: int = 8000) -> str:
        try:
            snap = await self.browser.act(page_id, action, element=element, text=text, max_chars=max_chars)
        except Exception as e:  # noqa: BLE001
            raise _err(e) from None
        return self._render_snapshot(snap, header=f"Did: {action}" + (f" on [{element}]" if element is not None else ""))

    async def browser_read(self, page_id: str, *, offset: int = 0, max_chars: int = 12000) -> str:
        try:
            snap = await self.browser.snapshot(page_id, offset=max(0, offset), max_chars=max_chars)
        except Exception as e:  # noqa: BLE001
            raise _err(e) from None
        return self._render_snapshot(snap)

    async def browser_screenshot(self, page_id: str, full_page: bool = False) -> tuple[bytes, str]:
        try:
            return await self.browser.screenshot(page_id, full_page=full_page)
        except Exception as e:  # noqa: BLE001
            raise _err(e) from None

    async def browser_close(self, page_id: str) -> str:
        return "closed" if await self.browser.close_page(page_id) else "no such page"

    # ---- identity & diagnostics -----------------------------------------------------------
    async def new_identity(self) -> str:
        old = self.identity.serial
        self.identity.rotate()
        closed = await self.browser.reset()
        self._docs.clear()
        lines = [f"New identity: circuit {old} → {self.identity.serial}; {closed} browser page(s) and all cookies discarded."]
        up = self.cfg.upstream
        if up.kind == "tor" and up.control_port:
            try:
                async with TorControl(self.cfg) as tc:
                    await tc.newnym()
                lines.append("Tor NEWNYM sent: new circuits for all new connections.")
            except TorControlError as e:
                lines.append(f"Tor NEWNYM not sent ({e}); SOCKS isolation alone still gives a fresh circuit.")
        elif up.kind != "tor":
            lines.append("Note: with a VPN-style tunnel the exit IP is your server's and does not change.")
        return "\n".join(lines)

    async def status(self, *, deep: bool = False) -> str:
        cfg, up, pol = self.cfg, self.cfg.upstream, self.cfg.policy
        out = [f"AgentVeil {__version__} · config: {cfg.source}",
               f"Tunnel: {up.kind} SOCKS5 at {up.host}:{up.port} (remote DNS; no direct fallback)"]
        try:
            await check_upstream(cfg, force=True)
            out.append("Tunnel reachable: yes")
        except UpstreamUnavailable as e:
            out.append(f"Tunnel reachable: NO — {e}")
            out.append("Verdict: FAIL-CLOSED. All web tools refuse to run until the tunnel is up. Nothing leaks.")
            return "\n".join(out)
        if up.kind == "tor" and up.control_port:
            try:
                async with TorControl(cfg) as tc:
                    out.append(f"Tor bootstrap: {await tc.bootstrap()}")
            except TorControlError as e:
                out.append(f"Tor control: unavailable ({e})")
        exit_ip = None
        try:
            res, cs = await self.fetcher.fetch(self.identity, TOR_CHECK, max_bytes=10_000)
            data = json.loads(res.text(cs))
            exit_ip = data.get("IP")
            out.append(f"Exit IP seen by websites: {exit_ip} · Tor exit: {'yes' if data.get('IsTor') else 'no'}")
            if up.kind == "tor" and not data.get("IsTor"):
                out.append("WARNING: upstream.kind is 'tor' but traffic is NOT exiting via Tor. Check the tunnel.")
        except Exception as e:  # noqa: BLE001
            out.append(f"Exit check failed: {_err(e)}")
        out.append(
            f"Policy: https_only={pol.https_only} · block_private_networks={pol.block_private_networks} · "
            f"onion={'allowed' if cfg.onion_allowed else 'blocked'} · JS default={'on' if cfg.browser.javascript else 'off'}")
        if deep:
            out += await self._browser_selftest(exit_ip)
        out.append(f"Checked at {datetime.now(timezone.utc):%Y-%m-%d %H:%M:%S} UTC")
        return "\n".join(out)

    async def _browser_selftest(self, fetch_ip: str | None) -> list[str]:
        out = ["Browser self-test:"]
        pid = None
        try:
            snap = await self.browser.open(self.identity, TOR_CHECK, javascript=True, max_chars=2000)
            pid = snap.page_id
            fp = await self.browser.evaluate(pid, """() => ({
                webrtc: typeof RTCPeerConnection, tz: Intl.DateTimeFormat().resolvedOptions().timeZone,
                langs: (navigator.languages || []).join(','), ua: navigator.userAgent,
                webgl: !!document.createElement('canvas').getContext('webgl'),
                cores: navigator.hardwareConcurrency, sw: 'serviceWorker' in navigator })""")
            try:
                bip = json.loads(snap.text).get("IP")
            except ValueError:
                bip = None
            ok = lambda b: "OK" if b else "CHECK"  # noqa: E731
            out.append(f"  WebRTC API present: {fp['webrtc'] != 'undefined'} [{ok(fp['webrtc'] == 'undefined')}]")
            out.append(f"  WebGL available: {fp['webgl']} [{ok(not fp['webgl'])}]")
            out.append(f"  Timezone: {fp['tz']} [{ok(fp['tz'] in ('UTC', 'Etc/UTC', 'Atlantic/Reykjavik'))}] · languages: {fp['langs']}")
            out.append(f"  CPU cores reported: {fp['cores']} · ServiceWorker API: {fp['sw']}")
            out.append(f"  User-Agent: {fp['ua']}")
            out.append(f"  Browser exit IP: {bip} [{ok(bip and (fetch_ip is None or bip == fetch_ip or self.cfg.upstream.kind == 'tor'))}]")
        except Exception as e:  # noqa: BLE001
            out.append(f"  failed: {_err(e)}")
        finally:
            if pid:
                await self.browser.close_page(pid)
        return out

    # ---- messaging -----------------------------------------------------------------------
    def msg_whoami(self) -> str:
        try:
            return describe_identity(self.messenger)
        except Exception as e:  # noqa: BLE001
            raise _err(e) from None

    def msg_add_contact(self, card: str, alias: str = "") -> str:
        try:
            alias, c, replaced = self.messenger.add_contact(card, alias)
        except Exception as e:  # noqa: BLE001
            raise _err(e) from None
        warn = "\nWARNING: this alias previously had a DIFFERENT key — verify before trusting!" if replaced else ""
        return (f"Saved contact '{alias}' (claims name {c.name!r}).\nFingerprint: {fingerprint(c.id)}\n"
                f"Relay: {c.relay}\nVerify this fingerprint with the owner through another channel.{warn}")

    def msg_contacts(self) -> str:
        cs = self.messenger.contacts()
        if not cs:
            return "No contacts yet."
        return "\n".join(f"- {a}: {fingerprint(c.id)} · relay {c.relay}" for a, c in cs.items())

    async def msg_send(self, to: str, text: str) -> str:
        try:
            c = await self.messenger.send(to, text)
        except Exception as e:  # noqa: BLE001
            raise _err(e) from None
        return f"Sent end-to-end encrypted message to {to} ({fingerprint(c.id)[:19]}…) via their relay."

    async def msg_receive(self) -> str:
        try:
            msgs, notes = await self.messenger.receive()
        except Exception as e:  # noqa: BLE001
            raise _err(e) from None
        if not msgs:
            return "No new messages." + ("\n" + "\n".join(notes) if notes else "")
        blocks = []
        for m, alias in msgs:
            who = (f"verified contact '{alias}'" if alias else
                   f"UNKNOWN sender claiming name {m.sender_name!r}, fingerprint {fingerprint(m.sender_id)} — not in contacts")
            ts = datetime.fromtimestamp(m.ts, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
            blocks.append(f"From: {who} · {ts}\n" + wrap_untrusted(alias or m.sender_id, m.body, kind="AGENT MESSAGE"))
        return "\n\n".join(blocks) + ("\n" + "\n".join(notes) if notes else "")

    async def close(self) -> None:
        await self.browser.close()
