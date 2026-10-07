"""Privacy-respecting web search over the tunnel (no API keys, no accounts)."""

from __future__ import annotations

import json
from dataclasses import dataclass
from urllib.parse import parse_qs, quote_plus, urlsplit

from bs4 import BeautifulSoup

from .config import Config
from .egress import Identity
from .extract import strip_invisible
from .fetcher import Fetcher

DDG_ONION = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion"


class SearchBlocked(Exception):
    """The engine answered with a bot challenge instead of results."""


@dataclass
class SearchHit:
    title: str
    url: str
    snippet: str


def _clean(s: str) -> str:
    return strip_invisible(" ".join(s.split()))[0]


def _ddg_target(href: str) -> str:
    if href.startswith("//"):
        href = "https:" + href
    parts = urlsplit(href)
    if parts.path.startswith("/l/"):
        uddg = parse_qs(parts.query).get("uddg")
        if uddg:
            return uddg[0]
    return href


def parse_duckduckgo(html: str) -> list[SearchHit]:
    soup = BeautifulSoup(html, "html.parser")
    hits: list[SearchHit] = []
    for res in soup.select("div.result, div.web-result"):
        classes = res.get("class") or []
        if "result--ad" in classes or "result--no-result" in classes:
            continue
        a = res.select_one("a.result__a")
        if not a or not a.get("href"):
            continue
        url = _ddg_target(str(a["href"]))
        if not url.startswith(("http://", "https://")) or "duckduckgo.com/y.js" in url:
            continue
        snip = res.select_one(".result__snippet")
        hits.append(SearchHit(_clean(a.get_text(" ")), url, _clean(snip.get_text(" ")) if snip else ""))
    if not hits and (soup.select_one(".anomaly-modal__title, #challenge-form, form[action*='anomaly']")
                     or "bots use DuckDuckGo too" in html):
        raise SearchBlocked("DuckDuckGo served a bot challenge")
    return hits


def parse_duckduckgo_lite(html: str) -> list[SearchHit]:
    soup = BeautifulSoup(html, "html.parser")
    hits: list[SearchHit] = []
    for a in soup.select("a.result-link"):
        url = _ddg_target(str(a.get("href", "")))
        if not url.startswith(("http://", "https://")) or "duckduckgo.com/y.js" in url:
            continue
        snippet = ""
        row = a.find_parent("tr")
        nxt = row.find_next_sibling("tr") if row else None
        cell = nxt.select_one("td.result-snippet") if nxt else None
        if cell:
            snippet = _clean(cell.get_text(" "))
        hits.append(SearchHit(_clean(a.get_text(" ")), url, snippet))
    if not hits and ("anomaly" in html or "bots use DuckDuckGo too" in html):
        raise SearchBlocked("DuckDuckGo Lite served a bot challenge")
    return hits


def parse_mojeek(html: str) -> list[SearchHit]:
    soup = BeautifulSoup(html, "html.parser")
    hits: list[SearchHit] = []
    for li in soup.select("ul.results-standard > li"):
        a = li.select_one("h2 a[href], a.title[href]")
        if not a:
            continue
        url = str(a["href"])
        if not url.startswith(("http://", "https://")):
            continue
        snip = li.select_one("p.s") or li.select_one("p")
        hits.append(SearchHit(_clean(a.get_text(" ")), url, _clean(snip.get_text(" ")) if snip else ""))
    if not hits and (soup.select_one("form[action*='captcha']") or "Verification required" in html):
        raise SearchBlocked("Mojeek demands a CAPTCHA (not solved by design)")
    return hits


def parse_searxng(payload: str) -> list[SearchHit]:
    data = json.loads(payload)
    return [
        SearchHit(_clean(r.get("title", "")), r["url"], _clean(r.get("content", "") or ""))
        for r in data.get("results", [])
        if str(r.get("url", "")).startswith(("http://", "https://"))
    ]


class Searcher:
    def __init__(self, cfg: Config, fetcher: Fetcher):
        self.cfg = cfg
        self.fetcher = fetcher

    async def search(self, identity: Identity, query: str, max_results: int = 10) -> tuple[str, list[SearchHit], list[str]]:
        """Try providers in order. Returns (provider_used, hits, errors_from_failed_providers)."""
        errors: list[str] = []
        for provider in self.cfg.search.providers:
            try:
                hits = await getattr(self, f"_{provider}")(identity, query)
            except Exception as e:  # noqa: BLE001 — fall through to the next engine
                errors.append(f"{provider}: {e.__class__.__name__}: {e}")
                continue
            if hits:
                return provider, _dedupe(hits)[:max_results], errors
            errors.append(f"{provider}: no results")
        return "", [], errors

    async def _get(self, identity: Identity, url: str, **kw) -> str:
        res, charset = await self.fetcher.fetch(identity, url, max_bytes=2_000_000, **kw)
        if res.status >= 400 and res.status != 403:
            raise RuntimeError(f"HTTP {res.status}")
        return res.text(charset)

    async def _duckduckgo(self, identity: Identity, query: str) -> list[SearchHit]:
        use_onion = self.cfg.search.prefer_onion and self.cfg.upstream.kind == "tor" and self.cfg.onion_allowed
        host = DDG_ONION if use_onion else "html.duckduckgo.com"
        html = await self._get(identity, f"https://{host}/html/", method="POST",
                               data={"q": query, "kl": "wt-wt", "b": ""})
        return parse_duckduckgo(html)

    async def _duckduckgo_lite(self, identity: Identity, query: str) -> list[SearchHit]:
        use_onion = self.cfg.search.prefer_onion and self.cfg.upstream.kind == "tor" and self.cfg.onion_allowed
        host = DDG_ONION if use_onion else "lite.duckduckgo.com"
        html = await self._get(identity, f"https://{host}/lite/", method="POST", data={"q": query, "kl": "wt-wt"})
        return parse_duckduckgo_lite(html)

    async def _mojeek(self, identity: Identity, query: str) -> list[SearchHit]:
        return parse_mojeek(await self._get(identity, f"https://www.mojeek.com/search?q={quote_plus(query)}"))

    async def _searxng(self, identity: Identity, query: str) -> list[SearchHit]:
        base = self.cfg.search.searxng_url.rstrip("/")
        if not base:
            raise RuntimeError("search.searxng_url not configured")
        return parse_searxng(await self._get(identity, f"{base}/search?q={quote_plus(query)}&format=json"))


def _dedupe(hits: list[SearchHit]) -> list[SearchHit]:
    seen, out = set(), []
    for h in hits:
        if h.url not in seen:
            seen.add(h.url)
            out.append(h)
    return out
