"""Configuration loading and validation.

Search order: explicit path > $AGENTVEIL_CONFIG > ./agentveil.toml > ~/.agentveil/config.toml.
Missing file => safe defaults (Tor on 127.0.0.1:9050, HTTPS-only, private networks blocked).
"""

from __future__ import annotations

import ipaddress
import os
import tomllib
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any


class ConfigError(ValueError):
    pass


@dataclass
class UpstreamConfig:
    # "tor": a Tor client SocksPort (enables per-identity circuit isolation and NEWNYM)
    # "socks": any other local SOCKS5 tunnel (sing-box / Xray / Clash / Hysteria ...)
    kind: str = "tor"
    host: str = "127.0.0.1"
    port: int = 9050
    username: str | None = None  # only for kind="socks" when the local tunnel requires auth
    password: str | None = None
    isolate: bool = True  # tor: random SOCKS credentials per identity => separate circuits
    control_host: str = "127.0.0.1"
    control_port: int | None = 9051
    control_password: str | None = None
    control_cookie_path: str | None = None
    # A plain SOCKS5 server across the internet is cleartext and trivially fingerprinted by DPI.
    # Only loopback/LAN tunnels are accepted unless this is explicitly enabled.
    allow_remote_upstream: bool = False


@dataclass
class PolicyConfig:
    https_only: bool = True
    block_private_networks: bool = True
    allow_onion: bool | None = None  # None => allowed only when upstream.kind == "tor"
    max_response_bytes: int = 5_000_000
    timeout: float = 60.0
    max_redirects: int = 8
    # Uniform, common header set (matches Firefox ESR with resistFingerprinting).
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; rv:140.0) Gecko/20100101 Firefox/140.0"
    accept_language: str = "en-US,en;q=0.5"
    # Hosts exempt from the private-network block (tests / a relay on your own LAN). Use sparingly.
    allow_hosts: list[str] = field(default_factory=list)


@dataclass
class BrowserConfig:
    headless: bool = True
    javascript: bool = True
    block_images: bool = False
    block_media: bool = True
    viewport_width: int = 1400
    viewport_height: int = 900
    page_idle_timeout: int = 900
    max_pages: int = 8
    navigation_timeout: float = 90.0


@dataclass
class SearchConfig:
    providers: list[str] = field(default_factory=lambda: ["duckduckgo", "duckduckgo_lite", "mojeek"])
    searxng_url: str = ""
    prefer_onion: bool = True  # with Tor, use DuckDuckGo's onion service (never leaves the Tor network)


@dataclass
class MessagingConfig:
    relay_url: str = ""
    # Allow talking to a relay on 127.0.0.1 without the tunnel (loopback never leaves this machine).
    allow_direct_loopback_relay: bool = False


@dataclass
class Config:
    upstream: UpstreamConfig = field(default_factory=UpstreamConfig)
    policy: PolicyConfig = field(default_factory=PolicyConfig)
    browser: BrowserConfig = field(default_factory=BrowserConfig)
    search: SearchConfig = field(default_factory=SearchConfig)
    messaging: MessagingConfig = field(default_factory=MessagingConfig)
    data_dir: Path = field(default_factory=lambda: Path.home() / ".agentveil")
    source: str = "<defaults>"

    @property
    def onion_allowed(self) -> bool:
        if self.policy.allow_onion is None:
            return self.upstream.kind == "tor"
        return self.policy.allow_onion


def _fill(cls: type, data: dict[str, Any], section: str):
    known = {f.name for f in fields(cls)}
    unknown = set(data) - known
    if unknown:
        raise ConfigError(f"[{section}] unknown keys: {', '.join(sorted(unknown))}")
    return cls(**data)


def validate(cfg: Config) -> Config:
    up = cfg.upstream
    if up.kind not in ("tor", "socks"):
        raise ConfigError("upstream.kind must be 'tor' or 'socks'")
    if up.host == "localhost":
        up.host = "127.0.0.1"
    try:
        ip = ipaddress.ip_address(up.host)
    except ValueError:
        # A hostname would require a local DNS lookup before the tunnel exists.
        raise ConfigError("upstream.host must be an IP literal (e.g. 127.0.0.1)") from None
    if not (ip.is_loopback or ip.is_private) and not up.allow_remote_upstream:
        raise ConfigError(
            f"upstream.host {up.host} is not on this machine/LAN. Plain SOCKS5 over the internet is "
            "unencrypted and easily detected; run a local tunnel client (Tor/sing-box/Xray) instead. "
            "Set upstream.allow_remote_upstream = true only if you understand this."
        )
    if not 0 < up.port < 65536:
        raise ConfigError("upstream.port out of range")
    if up.control_port == 0:
        up.control_port = None
    if up.control_port is not None:
        try:
            if not ipaddress.ip_address(up.control_host).is_loopback:
                raise ValueError
        except ValueError:
            raise ConfigError("upstream.control_host must be a loopback IP (127.0.0.1)") from None
    if up.kind == "socks" and up.isolate and up.username:
        up.isolate = False  # fixed credentials given; isolation via credentials is Tor-only anyway
    if cfg.search.providers:
        bad = set(cfg.search.providers) - {"duckduckgo", "duckduckgo_lite", "mojeek", "searxng"}
        if bad:
            raise ConfigError(f"unknown search providers: {bad}")
    return cfg


def load_config(path: str | os.PathLike | None = None) -> Config:
    candidates: list[Path] = []
    if path:
        candidates.append(Path(path))
    elif os.environ.get("AGENTVEIL_CONFIG"):
        candidates.append(Path(os.environ["AGENTVEIL_CONFIG"]))
    else:
        candidates += [Path.cwd() / "agentveil.toml", Path.home() / ".agentveil" / "config.toml"]

    for p in candidates:
        if p.is_file():
            with open(p, "rb") as fh:
                raw = tomllib.load(fh)
            return validate(config_from_dict(raw, source=str(p)))
        if path:  # an explicitly requested file must exist
            raise ConfigError(f"config file not found: {p}")
    return validate(Config())


def config_from_dict(raw: dict[str, Any], source: str = "<dict>") -> Config:
    raw = dict(raw)
    sections = {
        "upstream": UpstreamConfig,
        "policy": PolicyConfig,
        "browser": BrowserConfig,
        "search": SearchConfig,
        "messaging": MessagingConfig,
    }
    kwargs: dict[str, Any] = {}
    for name, cls in sections.items():
        kwargs[name] = _fill(cls, raw.pop(name, {}) or {}, name)
    if "data_dir" in raw:
        kwargs["data_dir"] = Path(os.path.expanduser(raw.pop("data_dir")))
    if raw:
        raise ConfigError(f"unknown top-level keys: {', '.join(sorted(raw))}")
    return Config(**kwargs, source=source)
