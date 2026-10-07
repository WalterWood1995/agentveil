"""Local SOCKS5 isolation shim between Firefox and the tunnel.

Firefox (via Playwright) cannot authenticate to a SOCKS5 proxy, so it connects here instead
(no auth, loopback only). For every connection the shim:
  * refuses anything but TCP CONNECT (no UDP ASSOCIATE / BIND => no QUIC/WebRTC side doors),
  * re-applies EgressPolicy to the destination host — this covers WebSockets and any other
    traffic that never passes Playwright's request router,
  * forwards the *unresolved* hostname to the real tunnel using the identity's SOCKS
    credentials, so Tor puts each identity on its own circuit (IsolateSOCKSAuth).
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import struct
from collections import deque

from .config import Config
from .egress import EgressBlocked, EgressPolicy

_REP_NOT_ALLOWED = 0x02
_REP_HOST_UNREACHABLE = 0x04
_REP_CMD_UNSUPPORTED = 0x07


class SocksShim:
    def __init__(self, cfg: Config, policy: EgressPolicy):
        self.cfg = cfg
        self.policy = policy
        self._listeners: dict[str, tuple[asyncio.AbstractServer, int]] = {}
        self.blocked: deque[str] = deque(maxlen=50)
        self._conns: set[asyncio.StreamWriter] = set()

    async def port_for(self, key: str, username: str | None, password: str | None) -> int:
        if key in self._listeners:
            return self._listeners[key][1]

        async def handler(r, w):
            await self._handle(r, w, username, password)

        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        self._listeners[key] = (server, port)
        return port

    async def close_listener(self, key: str) -> None:
        item = self._listeners.pop(key, None)
        if item:
            item[0].close()

    async def close(self) -> None:
        for key in list(self._listeners):
            await self.close_listener(key)
        for w in list(self._conns):
            try:
                w.close()
            except OSError:
                pass
        self._conns.clear()

    def drain_blocked(self) -> list[str]:
        items = list(self.blocked)
        self.blocked.clear()
        return items

    @staticmethod
    async def _reply(w: asyncio.StreamWriter, rep: int) -> None:
        w.write(b"\x05" + bytes([rep]) + b"\x00\x01" + b"\x00" * 6)
        try:
            await w.drain()
        except OSError:
            pass

    async def _handle(self, cr: asyncio.StreamReader, cw: asyncio.StreamWriter,
                      username: str | None, password: str | None) -> None:
        uw = None
        self._conns.add(cw)
        try:
            ver, n = await asyncio.wait_for(cr.readexactly(2), 30)
            await cr.readexactly(n)
            if ver != 5:
                return
            cw.write(b"\x05\x00")
            await cw.drain()
            head = await asyncio.wait_for(cr.readexactly(4), 30)
            _, cmd, _, atyp = head
            if atyp == 1:
                raw = await cr.readexactly(4)
                host = socket.inet_ntoa(raw)
            elif atyp == 3:
                ln = await cr.readexactly(1)
                raw = ln + await cr.readexactly(ln[0])
                host = raw[1:].decode("ascii")  # browsers send punycode; anything else is refused
            elif atyp == 4:
                raw = await cr.readexactly(16)
                host = str(ipaddress.IPv6Address(raw))
            else:
                return
            port_raw = await cr.readexactly(2)
            (port,) = struct.unpack(">H", port_raw)
            if cmd != 1:
                await self._reply(cw, _REP_CMD_UNSUPPORTED)
                return
            try:
                self.policy.check_host(host, port)
            except EgressBlocked as e:
                self.blocked.append(f"{host}:{port} — {e}")
                await self._reply(cw, _REP_NOT_ALLOWED)
                return

            up = self.cfg.upstream
            try:
                ur, uw = await asyncio.wait_for(asyncio.open_connection(up.host, up.port), 15)
            except (OSError, asyncio.TimeoutError):
                self.blocked.append(f"{host}:{port} — tunnel unreachable (fail-closed)")
                await self._reply(cw, _REP_HOST_UNREACHABLE)
                return
            if username:
                uw.write(b"\x05\x01\x02")
                await uw.drain()
                if await asyncio.wait_for(ur.readexactly(2), 30) != b"\x05\x02":
                    raise ConnectionError("tunnel refused user/pass auth")
                u, p = username.encode(), (password or "").encode()
                uw.write(b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p)
                await uw.drain()
                if (await asyncio.wait_for(ur.readexactly(2), 30))[1] != 0:
                    raise ConnectionError("tunnel rejected credentials")
            else:
                uw.write(b"\x05\x01\x00")
                await uw.drain()
                if await asyncio.wait_for(ur.readexactly(2), 30) != b"\x05\x00":
                    raise ConnectionError("tunnel requires authentication")
            uw.write(head + raw + port_raw)  # same CONNECT, hostname still unresolved
            await uw.drain()
            rhead = await asyncio.wait_for(ur.readexactly(4), 120)
            ratyp = rhead[3]
            rlen = 4 if ratyp == 1 else 16 if ratyp == 4 else (await ur.readexactly(1))[0]
            rest = await ur.readexactly(rlen + 2)
            prefix = b"" if ratyp in (1, 4) else bytes([rlen])
            cw.write(rhead + prefix + rest)
            await cw.drain()
            if rhead[1] != 0:
                return
            self._conns.add(uw)
            await asyncio.gather(_pipe(cr, uw), _pipe(ur, cw))
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError, OSError, UnicodeError):
            pass
        finally:
            for w in (cw, uw):
                self._conns.discard(w)
                if w is not None:
                    try:
                        w.close()
                    except OSError:
                        pass


async def _pipe(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
    try:
        while data := await r.read(65536):
            w.write(data)
            await w.drain()
        if w.can_write_eof():
            w.write_eof()
    except (ConnectionError, OSError):
        try:
            w.close()
        except OSError:
            pass
