"""Pluggable search backend for the OSINT dork module.

Backend is chosen by ``RECON_SEARCH_BACKEND``:
  * ``searxng``     - a self-hosted SearXNG instance (``RECON_SEARXNG_URL``);
                      its JSON output format must be enabled in settings.yml.
                      The only backend with a viable free path in 2026 - see
                      docs/GUIDE.md section 7 for a hardened engine config.
  * ``google_cse``  - Google Programmable Search JSON API
                      (``RECON_GOOGLE_CSE_KEY`` + ``RECON_GOOGLE_CSE_ID``).
                      LEGACY: closed to new customers, whole-web engines can no
                      longer be created, and Google retires the API on
                      2027-01-01. Only usable with a pre-2026 CSE.
  * ``off`` / unset - the search module no-ops.

If the primary backend is ``searxng`` **and** Google CSE credentials are also
configured, CSE is used as an automatic fallback whenever a SearXNG query comes
back empty. (Kept for anyone holding a legacy CSE; not an option for new setups.)

Every request goes through ``ctx.http.request(..., is_target=False)`` so it is
audited, rate-limited and jittered like any other OSINT call.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import quote_plus

from recon.config import get_settings
from recon.modules.base import ModuleContext
from recon.modules.osint._common import fetch_json


@dataclass(frozen=True)
class SearchResult:
    url: str
    title: str
    snippet: str
    engine: str


def search_backend() -> str | None:
    """The configured, usable backend name, or None."""
    s = get_settings()
    b = (s.search_backend or "off").strip().lower()
    if b == "searxng" and s.searxng_url.strip():
        return "searxng"
    if b == "google_cse" and s.google_cse_key.strip() and s.google_cse_id.strip():
        return "google_cse"
    if b in ("auto", "on"):
        if s.searxng_url.strip():
            return "searxng"
        if s.google_cse_key.strip() and s.google_cse_id.strip():
            return "google_cse"
    return None


def _cse_configured() -> bool:
    s = get_settings()
    return bool(s.google_cse_key.strip() and s.google_cse_id.strip())


async def run_query(ctx: ModuleContext, query: str, *, limit: int = 10) -> list[SearchResult]:
    backend = search_backend()
    if backend == "searxng":
        results = await _searxng(ctx, query, limit)
        # SearXNG's scraped engines get throttled - fall back to CSE on an empty
        # result if a key is configured (100 queries/day free, so only on misses).
        if not results and _cse_configured():
            await ctx.progress(f"search: SearXNG empty for {query!r}, trying Google CSE")
            return await _google_cse(ctx, query, limit)
        return results
    if backend == "google_cse":
        return await _google_cse(ctx, query, limit)
    return []


async def _searxng(ctx: ModuleContext, query: str, limit: int) -> list[SearchResult]:
    base = get_settings().searxng_url.rstrip("/")
    url = f"{base}/search?q={quote_plus(query)}&format=json&safesearch=0"
    data = await fetch_json(ctx, url, subject=query, source="SearXNG", timeout=30.0)
    out: list[SearchResult] = []
    seen: set[str] = set()
    for r in (data or {}).get("results", []) if isinstance(data, dict) else []:
        u = str(r.get("url") or "")
        if not u or u in seen:
            continue
        seen.add(u)
        out.append(SearchResult(
            url=u, title=str(r.get("title") or ""),
            snippet=str(r.get("content") or ""),
            engine=str(r.get("engine") or "searxng"),
        ))
        if len(out) >= limit:
            break
    return out


async def _google_cse(ctx: ModuleContext, query: str, limit: int) -> list[SearchResult]:
    s = get_settings()
    url = (
        "https://www.googleapis.com/customsearch/v1"
        f"?key={s.google_cse_key}&cx={s.google_cse_id}"
        f"&q={quote_plus(query)}&num={min(limit, 10)}"
    )
    data = await fetch_json(ctx, url, subject=query, source="Google CSE", timeout=30.0)
    out: list[SearchResult] = []
    for r in (data or {}).get("items", []) if isinstance(data, dict) else []:
        u = str(r.get("link") or "")
        if not u:
            continue
        out.append(SearchResult(
            url=u, title=str(r.get("title") or ""),
            snippet=str(r.get("snippet") or ""), engine="google_cse",
        ))
    return out
