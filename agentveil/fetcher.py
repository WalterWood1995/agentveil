"""Lightweight HTTP retrieval through the tunnel (no JavaScript)."""

from __future__ import annotations

import codecs
import re
from dataclasses import dataclass, field
from urllib.parse import urljoin

import httpx

from .config import Config
from .egress import EgressBlocked, EgressPolicy, Identity, check_upstream, make_client


@dataclass
class FetchResult:
    url: str
    status: int
    content_type: str
    body: bytes
    truncated: bool
    redirects: list[str] = field(default_factory=list)

    @property
    def is_html(self) -> bool:
        return "html" in self.content_type or (not self.content_type and self.body[:200].lstrip().lower().startswith((b"<!doctype html", b"<html")))

    @property
    def is_textual(self) -> bool:
        ct = self.content_type
        return (not ct or ct.startswith("text/") or "json" in ct or "xml" in ct or "javascript" in ct
                or "html" in ct or ct in ("application/x-www-form-urlencoded",))

    def text(self, header_charset: str | None = None) -> str:
        return decode_body(self.body, header_charset)


_META_CHARSET = re.compile(rb"""<meta[^>]+charset\s*=\s*["']?\s*([a-zA-Z0-9_\-]+)""", re.I)


def decode_body(body: bytes, header_charset: str | None) -> str:
    charset = header_charset
    if not charset:
        m = _META_CHARSET.search(body[:4096])
        if m:
            charset = m.group(1).decode("ascii", "ignore")
    charset = (charset or "utf-8").strip().lower()
    if charset in ("gb2312", "gbk", "x-gbk"):
        charset = "gb18030"
    try:
        codecs.lookup(charset)
    except LookupError:
        charset = "utf-8"
    return body.decode(charset, errors="replace")


class Fetcher:
    def __init__(self, cfg: Config, policy: EgressPolicy):
        self.cfg = cfg
        self.policy = policy

    async def fetch(
        self,
        identity: Identity,
        url: str,
        *,
        method: str = "GET",
        data: dict | None = None,
        allow_http: bool = False,
        max_bytes: int | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[FetchResult, str | None]:
        """Returns (result, header_charset). Raises EgressBlocked / httpx.HTTPError."""
        limit = max_bytes or self.cfg.policy.max_response_bytes
        url = self.policy.check_url(url, allow_http=allow_http)
        await check_upstream(self.cfg)
        redirects: list[str] = []
        async with make_client(self.cfg, identity) as client:
            for _ in range(self.cfg.policy.max_redirects + 1):
                req = client.build_request(method, url, data=data, headers=headers)
                resp = await client.send(req, stream=True)
                try:
                    if resp.is_redirect and "location" in resp.headers:
                        nxt = urljoin(str(resp.url), resp.headers["location"])
                        redirects.append(url)
                        url = self.policy.check_url(nxt, allow_http=allow_http)
                        if resp.status_code in (301, 302, 303) and method != "GET":
                            method, data = "GET", None
                        continue
                    chunks, size, truncated = [], 0, False
                    async for chunk in resp.aiter_bytes():
                        chunks.append(chunk)
                        size += len(chunk)
                        if size >= limit:
                            truncated = True
                            break
                    body = b"".join(chunks)[:limit]
                    ctype = resp.headers.get("content-type", "").split(";")[0].strip().lower()
                    return (
                        FetchResult(url=str(resp.url), status=resp.status_code, content_type=ctype,
                                    body=body, truncated=truncated, redirects=redirects),
                        resp.charset_encoding,
                    )
                finally:
                    await resp.aclose()
        raise EgressBlocked(f"too many redirects (>{self.cfg.policy.max_redirects})")


def describe_http_error(e: Exception) -> str:
    if isinstance(e, httpx.ProxyError):
        return f"the tunnel refused or failed the connection ({e}). For Tor this often means the site/port is unreachable from the exit; try again or new_identity."
    if isinstance(e, httpx.ConnectTimeout):
        return "connection timed out inside the tunnel (slow circuit or blocked destination)."
    if isinstance(e, httpx.ConnectError):
        msg = str(e)
        if "CERTIFICATE" in msg.upper() or "SSL" in msg.upper():
            return f"TLS verification failed ({msg}). Possible interception at the exit — the request was aborted."
        return f"connection failed inside the tunnel ({msg})."
    if isinstance(e, httpx.ReadTimeout):
        return "the server stopped responding (read timeout)."
    return f"{e.__class__.__name__}: {e}"
