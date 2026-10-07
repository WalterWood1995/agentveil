"""Minimal Tor control-port client (loopback only): NEWNYM and bootstrap status."""

from __future__ import annotations

import asyncio
import re
from pathlib import Path

from .config import Config


class TorControlError(Exception):
    pass


class TorControl:
    def __init__(self, cfg: Config):
        up = cfg.upstream
        if up.control_port is None:
            raise TorControlError("upstream.control_port not configured")
        self.host, self.port = up.control_host, up.control_port
        self.password, self.cookie_path = up.control_password, up.control_cookie_path
        self._r: asyncio.StreamReader | None = None
        self._w: asyncio.StreamWriter | None = None

    async def __aenter__(self) -> "TorControl":
        try:
            self._r, self._w = await asyncio.wait_for(asyncio.open_connection(self.host, self.port), 5)
        except (OSError, asyncio.TimeoutError) as e:
            raise TorControlError(f"control port {self.host}:{self.port} unreachable ({e.__class__.__name__})") from None
        await self._authenticate()
        return self

    async def __aexit__(self, *exc) -> None:
        if self._w:
            try:
                self._w.write(b"QUIT\r\n")
                await self._w.drain()
            except OSError:
                pass
            self._w.close()

    async def command(self, line: str) -> list[str]:
        assert self._r and self._w
        self._w.write(line.encode() + b"\r\n")
        await self._w.drain()
        lines: list[str] = []
        while True:
            raw = await asyncio.wait_for(self._r.readline(), 15)
            if not raw:
                raise TorControlError("control connection closed")
            text = raw.decode("utf-8", "replace").rstrip("\r\n")
            lines.append(text)
            if len(text) >= 4 and text[3] == " ":
                if not text.startswith("250"):
                    raise TorControlError(text)
                return lines

    async def _authenticate(self) -> None:
        info = " ".join(await self.command("PROTOCOLINFO 1"))
        methods = re.search(r"METHODS=([A-Z,]+)", info)
        methods_set = set(methods.group(1).split(",")) if methods else set()
        if self.password:
            esc = self.password.replace("\\", "\\\\").replace('"', '\\"')
            await self.command(f'AUTHENTICATE "{esc}"')
            return
        if "COOKIE" in methods_set or "SAFECOOKIE" in methods_set:
            path = self.cookie_path
            if not path:
                m = re.search(r'COOKIEFILE="((?:[^"\\]|\\.)*)"', info)
                path = m.group(1).encode().decode("unicode_escape") if m else None
            if not path:
                raise TorControlError("cookie auth required but no cookie file path known")
            try:
                cookie = Path(path).read_bytes()
            except OSError as e:
                raise TorControlError(f"cannot read control cookie {path}: {e}") from None
            await self.command(f"AUTHENTICATE {cookie.hex()}")
            return
        if "NULL" in methods_set:
            await self.command("AUTHENTICATE")
            return
        raise TorControlError(f"no usable auth method (offered: {sorted(methods_set) or 'none'}); set control_password")

    async def newnym(self) -> None:
        await self.command("SIGNAL NEWNYM")

    async def bootstrap(self) -> str:
        lines = await self.command("GETINFO status/bootstrap-phase")
        for line in lines:
            if "status/bootstrap-phase=" in line:
                m = re.search(r"PROGRESS=(\d+).*?SUMMARY=\"([^\"]*)\"", line)
                return f"{m.group(1)}% {m.group(2)}" if m else line.split("=", 1)[1]
        return "unknown"
