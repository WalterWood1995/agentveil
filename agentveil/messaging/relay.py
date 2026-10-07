"""Blind store-and-forward relay for AgentVeil messages.

The relay only ever holds sealed ciphertexts keyed by mailbox id. It keeps nothing on disk,
logs nothing, and can't tell who sent a message. Run it on loopback and publish it as a Tor
onion service (see README), so neither the relay nor its users reveal their IP addresses.
"""

from __future__ import annotations

import base64
import json
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .crypto import CryptoError, verify_fetch_request

MAX_REQUEST = 256 * 1024
MAX_BLOB_B64 = 200_000
MAX_PER_MAILBOX = 500
MAX_TOTAL = 20_000
TTL = 7 * 86400


class RelayStore:
    def __init__(self):
        self._lock = threading.Lock()
        self._boxes: dict[str, list[tuple[str, str, float]]] = {}
        self._nonces: dict[str, float] = {}
        self._total = 0

    def _expire(self, now: float) -> None:
        for box, items in list(self._boxes.items()):
            keep = [it for it in items if now - it[2] < TTL]
            self._total -= len(items) - len(keep)
            if keep:
                self._boxes[box] = keep
            else:
                del self._boxes[box]
        self._nonces = {n: t for n, t in self._nonces.items() if t > now}

    def put(self, mailbox: str, blob_b64: str) -> str:
        now = time.time()
        with self._lock:
            self._expire(now)
            items = self._boxes.setdefault(mailbox, [])
            if len(items) >= MAX_PER_MAILBOX or self._total >= MAX_TOTAL:
                raise OverflowError("mailbox full")
            rid = secrets.token_hex(8)
            items.append((rid, blob_b64, now))
            self._total += 1
            return rid

    def fetch(self, doc: dict) -> list[dict]:
        req = verify_fetch_request(doc)
        now = time.time()
        with self._lock:
            if req["nonce"] in self._nonces:
                raise CryptoError("replayed fetch request")
            self._nonces[req["nonce"]] = now + 600
            self._expire(now)
            ack = set(map(str, req["ack"]))
            items = [it for it in self._boxes.get(req["mailbox"], []) if it[0] not in ack]
            self._total -= len(self._boxes.get(req["mailbox"], [])) - len(items)
            if items:
                self._boxes[req["mailbox"]] = items
            else:
                self._boxes.pop(req["mailbox"], None)
            return [{"rid": rid, "blob": blob, "t": int(t)} for rid, blob, t in items[:100]]


def _is_mailbox(s) -> bool:
    return isinstance(s, str) and len(s) == 40 and all(c in "0123456789abcdef" for c in s)


def make_handler(store: RelayStore):
    class Handler(BaseHTTPRequestHandler):
        server_version = "relay"
        sys_version = ""

        def log_message(self, *args) -> None:  # no access logs, ever
            pass

        def _reply(self, code: int, obj: dict) -> None:
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            if self.path == "/v1/health":
                self._reply(200, {"ok": True, "service": "agentveil-relay", "v": 1})
            else:
                self._reply(404, {"error": "not found"})

        def do_POST(self) -> None:
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = -1
            if not 0 < length <= MAX_REQUEST:
                self._reply(413, {"error": "bad request size"})
                return
            try:
                doc = json.loads(self.rfile.read(length))
            except ValueError:
                self._reply(400, {"error": "bad json"})
                return
            if self.path == "/v1/send":
                to, blob = doc.get("to"), doc.get("blob")
                if not _is_mailbox(to) or not isinstance(blob, str) or not 0 < len(blob) <= MAX_BLOB_B64:
                    self._reply(400, {"error": "bad message"})
                    return
                try:
                    base64.urlsafe_b64decode(blob + "=" * (-len(blob) % 4))
                    store.put(to, blob)
                except OverflowError:
                    self._reply(507, {"error": "mailbox full"})
                    return
                except ValueError:
                    self._reply(400, {"error": "bad blob"})
                    return
                self._reply(202, {"ok": True})
            elif self.path == "/v1/fetch":
                try:
                    self._reply(200, {"messages": store.fetch(doc)})
                except CryptoError as e:
                    self._reply(403, {"error": str(e)})
            else:
                self._reply(404, {"error": "not found"})

    return Handler


def make_server(host: str = "127.0.0.1", port: int = 8787) -> ThreadingHTTPServer:
    srv = ThreadingHTTPServer((host, port), make_handler(RelayStore()))
    srv.daemon_threads = True
    return srv


def serve(host: str = "127.0.0.1", port: int = 8787) -> None:
    srv = make_server(host, port)
    print(f"AgentVeil relay listening on http://{host}:{srv.server_address[1]} (in-memory, no logs)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
