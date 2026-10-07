"""Hardened, tunnel-only Firefox (via Playwright) for pages that need JavaScript.

* Firefox talks only to a local isolation shim (Playwright proxy + prefs, remote DNS, no direct
  failover; DNS prefetch / speculative connects / HTTP3 / DoH off). The shim re-checks every
  destination and forwards it, unresolved, into the tunnel with per-identity credentials.
* WebRTC is disabled entirely (no STUN/ICE => no real-IP leak).
* resistFingerprinting, WebGL off, sensors/geo/notifications/service workers off, UTC, en-US.
* Every request is re-checked by EgressPolicy (no LAN / loopback / plain-HTTP targets).
* One throw-away browser context per page: no cookies or storage shared between tasks,
  nothing written to disk, downloads refused.
"""

from __future__ import annotations

import asyncio
import secrets
import time
from dataclasses import dataclass, field

from .config import Config
from .egress import EgressBlocked, EgressPolicy, Identity, check_upstream
from .extract import html_to_text, strip_invisible
from .socks_shim import SocksShim


def hardened_prefs(host: str, port: int, https_only: bool) -> dict:
    return {
        # --- every connection through the SOCKS5 tunnel; hostnames resolved by the tunnel
        "network.proxy.type": 1,
        "network.proxy.socks": host,
        "network.proxy.socks_port": port,
        "network.proxy.socks_version": 5,
        "network.proxy.socks_remote_dns": True,
        "network.proxy.socks5_remote_dns": True,
        "network.proxy.no_proxies_on": "",
        "network.proxy.allow_hijacking_localhost": True,
        "network.proxy.failover_direct": False,
        "network.trr.mode": 5,
        "network.dns.disablePrefetch": True,
        "network.dns.disablePrefetchFromHTTPS": True,
        "network.dns.disableIPv6": True,
        "network.prefetch-next": False,
        "network.predictor.enabled": False,
        "network.predictor.enable-prefetch": False,
        "network.http.speculative-parallel-limit": 0,
        "browser.urlbar.speculativeConnect.enabled": False,
        "browser.places.speculativeConnect.enabled": False,
        "network.http.http3.enable": False,
        "network.captive-portal-service.enabled": False,
        "network.connectivity-service.enabled": False,
        # --- WebRTC / media devices off
        "media.peerconnection.enabled": False,
        "media.peerconnection.ice.default_address_only": True,
        "media.peerconnection.ice.no_host": True,
        "media.peerconnection.ice.proxy_only_if_behind_proxy": True,
        "media.navigator.enabled": False,
        "media.eme.enabled": False,
        "media.gmp-provider.enabled": False,
        "media.autoplay.default": 5,
        # --- fingerprinting resistance: every AgentVeil instance looks the same
        "privacy.resistFingerprinting": True,
        "privacy.resistFingerprinting.block_mozAddonManager": True,
        "privacy.resistFingerprinting.letterboxing": False,
        "privacy.spoof_english": 2,
        "intl.accept_languages": "en-US, en",
        "javascript.use_us_english_locale": True,
        "webgl.disabled": True,
        "dom.webgpu.enabled": False,
        "geo.enabled": False,
        "dom.battery.enabled": False,
        "dom.gamepad.enabled": False,
        "dom.vr.enabled": False,
        "device.sensors.enabled": False,
        "dom.webnotifications.enabled": False,
        "dom.push.enabled": False,
        "dom.serviceWorkers.enabled": False,
        "dom.event.clipboardevents.enabled": False,
        "beacon.enabled": False,
        "browser.send_pings": False,
        "network.cookie.cookieBehavior": 5,
        "privacy.partition.network_state": True,
        "privacy.trackingprotection.enabled": True,
        "privacy.trackingprotection.socialtracking.enabled": True,
        "privacy.query_stripping.enabled": True,
        "network.http.referer.XOriginTrimmingPolicy": 2,
        "network.IDN_show_punycode": True,
        "permissions.default.geo": 2,
        "permissions.default.camera": 2,
        "permissions.default.microphone": 2,
        "permissions.default.desktop-notification": 2,
        "permissions.default.xr": 2,
        # --- transport security
        "dom.security.https_only_mode": https_only,
        "dom.security.https_only_mode_send_http_background_request": False,
        "security.tls.version.min": 3,
        "security.mixed_content.block_display_content": True,
        # --- nothing persisted
        "browser.cache.disk.enable": False,
        "browser.cache.offline.enable": False,
        "browser.sessionstore.resume_from_crash": False,
        "browser.sessionstore.privacy_level": 2,
        "signon.rememberSignons": False,
        "browser.formfill.enable": False,
        "places.history.enabled": False,
        # --- no phoning home
        "toolkit.telemetry.enabled": False,
        "toolkit.telemetry.unified": False,
        "toolkit.telemetry.archive.enabled": False,
        "datareporting.healthreport.uploadEnabled": False,
        "datareporting.policy.dataSubmissionEnabled": False,
        "app.normandy.enabled": False,
        "app.shield.optoutstudies.enabled": False,
        "browser.safebrowsing.malware.enabled": False,
        "browser.safebrowsing.phishing.enabled": False,
        "browser.safebrowsing.downloads.enabled": False,
        "browser.safebrowsing.downloads.remote.enabled": False,
        "browser.safebrowsing.blockedURIs.enabled": False,
        "extensions.update.enabled": False,
        "extensions.getAddons.cache.enabled": False,
        "app.update.auto": False,
        "browser.search.update": False,
        "browser.region.network.url": "",
        "browser.region.update.enabled": False,
        "devtools.jsonview.enabled": False,  # show JSON as plain text to the agent
    }


# Collects visible text and numbers the interactive elements so an agent can say "click 7".
_SNAPSHOT_JS = """
(maxEls) => {
  const sel = 'a[href], button, input, textarea, select, summary, [role="button"], [role="link"],' +
              '[role="checkbox"], [role="tab"], [role="menuitem"], [role="option"], [contenteditable="true"]';
  document.querySelectorAll('[data-av-id]').forEach(e => e.removeAttribute('data-av-id'));
  const els = [];
  for (const el of document.querySelectorAll(sel)) {
    if (els.length >= maxEls) break;
    if ((el.getAttribute('type') || '').toLowerCase() === 'hidden') continue;
    const r = el.getBoundingClientRect();
    const st = getComputedStyle(el);
    if (r.width < 2 || r.height < 2 || st.visibility === 'hidden' || st.display === 'none' || parseFloat(st.opacity) === 0) continue;
    const id = els.length;
    el.setAttribute('data-av-id', String(id));
    const tag = el.tagName.toLowerCase();
    const label = (el.innerText || el.value || el.getAttribute('aria-label') || el.getAttribute('title') ||
                   el.getAttribute('placeholder') || el.getAttribute('alt') || el.getAttribute('name') || '')
                   .toString().replace(/\\s+/g, ' ').trim().slice(0, 80);
    els.push({id, tag, type: (el.getAttribute('type') || '').toLowerCase(), role: el.getAttribute('role') || '',
              label, href: tag === 'a' ? el.href : '', disabled: !!el.disabled});
  }
  return {text: document.body ? document.body.innerText : '', elements: els};
}
"""


@dataclass
class PageEntry:
    id: str
    context: object
    page: object
    javascript: bool
    allow_http: bool
    created: float = field(default_factory=time.time)
    last_used: float = field(default_factory=time.time)
    blocked: list[str] = field(default_factory=list)


@dataclass
class Snapshot:
    page_id: str
    url: str
    title: str
    text: str
    elements: list[dict]
    blocked: list[str]
    total_chars: int
    offset: int


class BrowserError(Exception):
    pass


class SecureBrowser:
    def __init__(self, cfg: Config, policy: EgressPolicy):
        self.cfg = cfg
        self.policy = policy
        self._pw = None
        self._browser = None
        self._lock = asyncio.Lock()
        self.pages: dict[str, PageEntry] = {}
        self.shim = SocksShim(cfg, policy)

    async def _ensure(self):
        async with self._lock:
            if self._browser is not None and self._browser.is_connected():
                return self._browser
            from playwright.async_api import async_playwright

            if self._pw is None:
                self._pw = await async_playwright().start()
            # Browser-internal traffic gets its own isolated "background" circuit.
            bg = secrets.token_hex(8)
            port = await self.shim.port_for("background", f"av-bg-{bg}" if self._isolate else None, bg)
            self._browser = await self._pw.firefox.launch(
                headless=self.cfg.browser.headless,
                proxy={"server": f"socks5://127.0.0.1:{port}"},
                firefox_user_prefs=hardened_prefs("127.0.0.1", port, self.cfg.policy.https_only),
            )
            return self._browser

    @property
    def _isolate(self) -> bool:
        return self.cfg.upstream.kind == "tor" and self.cfg.upstream.isolate

    async def _gc(self) -> None:
        now = time.time()
        for pid, e in list(self.pages.items()):
            if now - e.last_used > self.cfg.browser.page_idle_timeout:
                await self.close_page(pid)
        while len(self.pages) >= self.cfg.browser.max_pages:
            oldest = min(self.pages.values(), key=lambda e: e.last_used)
            await self.close_page(oldest.id)

    async def open(self, identity: Identity, url: str, *, javascript: bool | None = None,
                   allow_http: bool = False, max_chars: int = 12000) -> Snapshot:
        url = self.policy.check_url(url, allow_http=allow_http)
        await check_upstream(self.cfg)
        browser = await self._ensure()
        await self._gc()
        js = self.cfg.browser.javascript if javascript is None else javascript
        port = await self.shim.port_for(f"id-{identity.serial}", identity.username, identity.password)
        ctx = await browser.new_context(
            proxy={"server": f"socks5://127.0.0.1:{port}"},
            java_script_enabled=js,
            accept_downloads=False,
            service_workers="block",
            locale="en-US",
            timezone_id="UTC",
            viewport={"width": self.cfg.browser.viewport_width, "height": self.cfg.browser.viewport_height},
            permissions=[],
        )
        entry = PageEntry(id=secrets.token_hex(4), context=ctx, page=None, javascript=js, allow_http=allow_http)

        async def route_guard(route):
            req = route.request
            u = req.url
            if u.startswith(("data:", "blob:", "about:")):
                await route.continue_()
                return
            rtype = req.resource_type
            if (rtype == "media" and self.cfg.browser.block_media) or (rtype == "image" and self.cfg.browser.block_images):
                await route.abort("blockedbyclient")
                return
            try:
                checked = self.policy.check_url(u, allow_http=entry.allow_http)
            except EgressBlocked as e:
                entry.blocked.append(f"{u[:150]} — {e}")
                await route.abort("blockedbyclient")
                return
            if checked != u and u.lower().startswith("http:"):
                entry.blocked.append(f"{u[:150]} — plain HTTP blocked (https_only)")
                await route.abort("blockedbyclient")
                return
            await route.continue_()

        await ctx.route("**/*", route_guard)
        ctx.on("page", lambda p: self._adopt(entry, p))
        page = await ctx.new_page()
        self._adopt(entry, page)
        self.pages[entry.id] = entry
        try:
            await self._goto(entry, url)
        except Exception:
            # Keep the page so the agent can still inspect what loaded; report via snapshot.
            pass
        return await self.snapshot(entry.id, max_chars=max_chars)

    def _adopt(self, entry: PageEntry, page) -> None:
        """Follow popups/new tabs: the newest page becomes the entry's active page."""
        if entry.page is page:
            return
        page.set_default_timeout(30_000)
        page.set_default_navigation_timeout(self.cfg.browser.navigation_timeout * 1000)
        page.on("dialog", lambda d: asyncio.ensure_future(d.dismiss()))
        entry.page = page

    async def _goto(self, entry: PageEntry, url: str) -> None:
        try:
            await entry.page.goto(url, wait_until="domcontentloaded")
        except Exception as e:  # noqa: BLE001
            entry.blocked.append(f"navigation error: {str(e).splitlines()[0][:200]}")
            raise
        try:
            await entry.page.wait_for_load_state("load", timeout=8000)
        except Exception:  # noqa: BLE001 — slow subresources are fine
            pass

    def _get(self, page_id: str) -> PageEntry:
        entry = self.pages.get(page_id)
        if entry is None:
            raise BrowserError(f"unknown page_id '{page_id}' (closed or expired); open the URL again")
        entry.last_used = time.time()
        return entry

    async def snapshot(self, page_id: str, *, max_chars: int = 12000, offset: int = 0, max_elements: int = 150) -> Snapshot:
        entry = self._get(page_id)
        page = entry.page
        title, text, elements = "", "", []
        try:
            title = await page.title()
            data = await page.evaluate(_SNAPSHOT_JS, max_elements)
            text, elements = data.get("text", ""), data.get("elements", [])
        except Exception:  # noqa: BLE001 — JS disabled or page mid-navigation: fall back to static HTML
            try:
                ex = html_to_text(await page.content(), page.url)
                title, text = title or ex.title, ex.text
            except Exception:  # noqa: BLE001
                pass
        text = strip_invisible(text)[0]
        title = strip_invisible(title)[0]
        for el in elements:
            el["label"] = strip_invisible(el.get("label", ""))[0]
        blocked, entry.blocked = entry.blocked + [f"[tunnel] {b}" for b in self.shim.drain_blocked()], []
        return Snapshot(page_id=page_id, url=page.url, title=title, text=text[offset:offset + max_chars],
                        elements=elements, blocked=blocked, total_chars=len(text), offset=offset)

    async def act(self, page_id: str, action: str, *, element: int | None = None, text: str | None = None,
                  max_chars: int = 8000) -> Snapshot:
        entry = self._get(page_id)
        page = entry.page
        loc = page.locator(f'[data-av-id="{int(element)}"]').first if element is not None else None

        def need_loc():
            if loc is None:
                raise BrowserError(f"action '{action}' needs an element number from the last snapshot")
            return loc

        action = action.lower().strip()
        if action == "click":
            await need_loc().click(timeout=15_000)
        elif action in ("type", "fill"):
            await need_loc().fill(text or "", timeout=15_000)
        elif action == "press":
            if loc is not None:
                await loc.press(text or "Enter")
            else:
                await page.keyboard.press(text or "Enter")
        elif action == "select":
            try:
                await need_loc().select_option(label=text or "", timeout=10_000)
            except Exception:  # noqa: BLE001
                await need_loc().select_option(value=text or "", timeout=10_000)
        elif action in ("check", "uncheck"):
            await (need_loc().check() if action == "check" else need_loc().uncheck())
        elif action == "hover":
            await need_loc().hover()
        elif action in ("scroll_down", "scroll_up"):
            dy = 800 if action == "scroll_down" else -800
            await page.mouse.wheel(0, dy)
        elif action == "back":
            await page.go_back(wait_until="domcontentloaded")
        elif action == "forward":
            await page.go_forward(wait_until="domcontentloaded")
        elif action == "reload":
            await page.reload(wait_until="domcontentloaded")
        elif action == "goto":
            await self._goto(entry, self.policy.check_url(text or "", allow_http=entry.allow_http))
        elif action == "wait":
            await page.wait_for_timeout(min(float(text or 2), 15) * 1000)
        else:
            raise BrowserError(
                "unknown action; use click|type|press|select|check|uncheck|hover|scroll_down|scroll_up|back|forward|reload|goto|wait")
        try:
            await entry.page.wait_for_load_state("domcontentloaded", timeout=10_000)
        except Exception:  # noqa: BLE001
            pass
        await asyncio.sleep(0.4)  # let client-side rendering settle
        return await self.snapshot(page_id, max_chars=max_chars)

    async def screenshot(self, page_id: str, *, full_page: bool = False) -> tuple[bytes, str]:
        entry = self._get(page_id)
        if full_page:
            return await entry.page.screenshot(full_page=True, type="jpeg", quality=70), "jpeg"
        return await entry.page.screenshot(type="png"), "png"

    async def evaluate(self, page_id: str, expression: str):
        return await self._get(page_id).page.evaluate(expression)

    async def close_page(self, page_id: str) -> bool:
        entry = self.pages.pop(page_id, None)
        if entry is None:
            return False
        try:
            await asyncio.wait_for(entry.context.close(), 10)
        except Exception:  # noqa: BLE001 — includes timeout; the browser close below reaps it
            pass
        return True

    async def reset(self) -> int:
        ids = list(self.pages)
        for pid in ids:
            await self.close_page(pid)
        for key in list(self.shim._listeners):
            if key.startswith("id-"):
                await self.shim.close_listener(key)
        return len(ids)

    async def close(self) -> None:
        await self.reset()
        if self._browser is not None:
            try:
                await asyncio.wait_for(self._browser.close(), 15)
            except Exception:  # noqa: BLE001
                pass
            self._browser = None
        if self._pw is not None:
            try:
                await asyncio.wait_for(self._pw.stop(), 15)
            except Exception:  # noqa: BLE001
                pass
            self._pw = None
        await self.shim.close()
