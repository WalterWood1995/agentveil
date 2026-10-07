"""Egress guard: the single choke point for every outbound connection.

Guarantees enforced here:
  * Traffic only ever leaves through the configured local SOCKS5 tunnel. There is no
    direct-connection fallback: if the tunnel is down, requests are refused (fail-closed).
  * Hostnames are sent to the tunnel unresolved (SOCKS5 DOMAIN address type), so no DNS
    query for a visited site is ever made by this machine's resolver.
  * Environment proxy variables / .netrc are ignored (trust_env=False).
  * URLs pointing at loopback / LAN / link-local / cloud-metadata addresses are refused
    (a prompt-injected agent cannot be steered into your local network).
  * HTTPS-only by default, so the tunnel exit (Tor exit relay / VPS) sees no plaintext.
"""

from __future__ import annotations

import asyncio
import ipaddress
import secrets
import time
from urllib.parse import urlsplit, urlunsplit

import httpx

from .config import Config


class EgressBlocked(Exception):
    """The request was refused by policy and was never sent."""


class UpstreamUnavailable(EgressBlocked):
    """The tunnel is not reachable; nothing was sent (fail-closed)."""


_BLOCKED_NAMES = {"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback", "broadcasthost"}
_BLOCKED_SUFFIXES = (
    ".localhost", ".local", ".lan", ".home", ".internal", ".intranet", ".corp",
    ".home.arpa", ".localdomain", ".private",
)


def _whatwg_ipv4(host: str) -> ipaddress.IPv4Address | None:
    """Parse IPv4 the way browsers do (127.1, 0x7f.0.0.1, 2130706433, 0177.0.0.1 ...)."""
    parts = host.split(".")
    if parts and parts[-1] == "":
        parts.pop()
    if not 1 <= len(parts) <= 4:
        return None
    nums = []
    for p in parts:
        if p == "":
            return None
        try:
            if p.lower().startswith("0x"):
                n = int(p[2:] or "0", 16)
            elif len(p) > 1 and p.startswith("0"):
                n = int(p, 8)
            else:
                n = int(p, 10)
        except ValueError:
            return None
        nums.append(n)
    *head, last = nums
    if any(n > 255 for n in head) or last >= 256 ** (5 - len(nums)):
        return None
    value = 0
    for n in head:
        value = value * 256 + n
    value = value * 256 ** (5 - len(nums)) + last
    return ipaddress.IPv4Address(value)


def _ip_is_public(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(ip, ipaddress.IPv6Address):
        mapped = ip.ipv4_mapped or ip.sixtofour
        if mapped is not None:
            return _ip_is_public(mapped)
    return ip.is_global and not ip.is_multicast


class EgressPolicy:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self._allow = {h.lower() for h in cfg.policy.allow_hosts}

    def check_url(self, url: str, *, allow_http: bool = False) -> str:
        """Return the (possibly HTTPS-upgraded) URL, or raise EgressBlocked."""
        try:
            parts = urlsplit(url.strip())
        except ValueError as e:
            raise EgressBlocked(f"malformed URL: {e}") from None
        scheme = parts.scheme.lower()
        if scheme not in ("http", "https"):
            raise EgressBlocked(f"scheme '{scheme or '(none)'}' not allowed; only http(s)")
        if parts.username is not None or parts.password is not None:
            raise EgressBlocked("credentials embedded in URLs are not allowed")
        try:
            host = (parts.hostname or "").rstrip(".").lower()
            port = parts.port
        except ValueError as e:
            raise EgressBlocked(f"malformed host/port: {e}") from None
        if not host:
            raise EgressBlocked("URL has no host")

        self.check_host(host, port)

        if scheme == "http" and self.cfg.policy.https_only and not allow_http and not host.endswith(".onion"):
            # Onion services are end-to-end encrypted by Tor itself; everything else is upgraded.
            netloc = parts.netloc.rsplit(":", 1)[0] if port == 80 else parts.netloc
            return urlunsplit(("https", netloc, parts.path, parts.query, parts.fragment))
        return urlunsplit((scheme, parts.netloc, parts.path, parts.query, parts.fragment))

    def check_host(self, host: str, port: int | None = None) -> None:
        host = host.strip("[]").rstrip(".").lower()
        if host in self._allow or (port is not None and f"{host}:{port}" in self._allow):
            return
        if host.endswith(".onion"):
            if not self.cfg.onion_allowed:
                raise EgressBlocked(".onion addresses require upstream.kind = 'tor'")
            return
        if not self.cfg.policy.block_private_networks:
            return
        ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            ip = _whatwg_ipv4(host)
        if ip is not None:
            if not _ip_is_public(ip):
                raise EgressBlocked(f"address {ip} is private/loopback/reserved — blocked")
            return
        if host in _BLOCKED_NAMES or host.endswith(_BLOCKED_SUFFIXES):
            raise EgressBlocked(f"host '{host}' is a local name — blocked")
        if "." not in host:
            raise EgressBlocked(f"single-label host '{host}' is not a public name — blocked")


class Identity:
    """A network identity. With Tor + IsolateSOCKSAuth, each identity's random SOCKS
    credentials get their own circuit (and exit IP), so separate identities can't be
    linked by exit address. Rotating = new circuit for all new connections."""

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.rotate()

    def rotate(self) -> None:
        up = self.cfg.upstream
        if up.kind == "tor" and up.isolate:
            self.username: str | None = "av-" + secrets.token_hex(8)
            self.password: str | None = secrets.token_hex(12)
        else:
            self.username, self.password = up.username, up.password
        self.created = time.time()
        self.serial = secrets.token_hex(4)

    def proxy_url(self) -> str:
        up = self.cfg.upstream
        auth = f"{self.username}:{self.password}@" if self.username else ""
        return f"socks5://{auth}{up.host}:{up.port}"


_upstream_ok_until: dict[tuple[str, int], float] = {}


async def check_upstream(cfg: Config, *, force: bool = False) -> None:
    """Confirm the local tunnel speaks SOCKS5. Raises UpstreamUnavailable otherwise."""
    up = cfg.upstream
    key = (up.host, up.port)
    if not force and time.monotonic() < _upstream_ok_until.get(key, 0.0):
        return
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(up.host, up.port), 5)
    except (OSError, asyncio.TimeoutError) as e:
        raise UpstreamUnavailable(
            f"tunnel not reachable at {up.host}:{up.port} ({e.__class__.__name__}). "
            "Nothing was sent. Start Tor / sing-box / Xray first."
        ) from None
    try:
        writer.write(b"\x05\x02\x00\x02")  # SOCKS5, offer: no-auth, user/pass
        await writer.drain()
        reply = await asyncio.wait_for(reader.readexactly(2), 5)
    except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError):
        reply = b""
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass
    if len(reply) != 2 or reply[0] != 5 or reply[1] not in (0, 2):
        raise UpstreamUnavailable(f"{up.host}:{up.port} is not a SOCKS5 tunnel; nothing was sent")
    _upstream_ok_until[key] = time.monotonic() + 15


def reset_upstream_cache() -> None:
    _upstream_ok_until.clear()


def base_headers(cfg: Config) -> dict[str, str]:
    return {
        "User-Agent": cfg.policy.user_agent,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": cfg.policy.accept_language,
        "Upgrade-Insecure-Requests": "1",
    }


def make_client(cfg: Config, identity: Identity, *, timeout: float | None = None) -> httpx.AsyncClient:
    """The only way this package creates an internet-facing HTTP client."""
    t = timeout or cfg.policy.timeout
    return httpx.AsyncClient(
        proxy=identity.proxy_url(),
        trust_env=False,
        follow_redirects=False,  # every redirect hop is re-checked by EgressPolicy
        timeout=httpx.Timeout(t, connect=min(t, 45)),
        headers=base_headers(cfg),
    )


def make_loopback_client(url: str, *, timeout: float = 30) -> httpx.AsyncClient:
    """Client for a service on 127.0.0.1/::1 only (e.g. your own relay). Loopback traffic
    never leaves the machine, so it does not need the tunnel. Anything else is refused."""
    host = (urlsplit(url).hostname or "").strip("[]")
    try:
        if not ipaddress.ip_address(host).is_loopback:
            raise ValueError
    except ValueError:
        raise EgressBlocked(f"direct connections are only allowed to loopback IPs, not '{host}'") from None
    return httpx.AsyncClient(trust_env=False, follow_redirects=False, timeout=timeout)
