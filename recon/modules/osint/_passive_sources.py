"""Source adapters for ``passive_subdomains`` (Honey's adapter table, §3).

Each adapter is a thin wrapper over one keyless public endpoint: fetch, parse,
yield ``SourceHit`` rows. The module (`passive_subdomains.py`) owns the
try/except + timeout + per-source-error bookkeeping - an adapter just raises on
failure and lets the module record it.

``SourceHit.source`` (== the adapter's ``name``) is what the correlation
engine's ``_confidence()`` fix keys on, so the names here are a stable public
contract - do not rename.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Literal
from urllib.parse import urlsplit

from recon.modules.base import ModuleContext

SourceKind = Literal["ct", "passive_dns", "archive", "aggregator", "scan_index"]


@dataclass
class SourceHit:
    name: str                              # a discovered hostname
    resolved: list[str] = field(default_factory=list)  # IPs, if the source gave them


class SourceDegraded(Exception):
    """The source answered with an explicit quota / rate-limit signal. Not a
    crash - the module records it as a degraded outcome and moves on."""


class PassiveSource:
    name: str = ""
    kind: SourceKind = "aggregator"
    default_enabled: bool = True

    async def fetch(self, ctx: ModuleContext, domain: str) -> list[SourceHit]:
        raise NotImplementedError


# --- shared helpers -----------------------------------------------------
async def _get(ctx: ModuleContext, url: str, *, timeout: float,
               headers: dict[str, str] | None = None):
    return await ctx.http.request(
        "GET", url, is_target=False, timeout=timeout,
        headers=headers or {}, follow_redirects=True,
    )


def _norm(host: str) -> str:
    host = (host or "").strip().lower().strip(".")
    if host.startswith("*."):
        host = host[2:]
    if host.startswith(("http://", "https://")):
        host = urlsplit(host).hostname or ""
    return host.strip(".")


def _in_domain(host: str, domain: str) -> bool:
    return bool(host) and (host == domain or host.endswith("." + domain))


def _loads(text: str):
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None


# --- CT sources -------------------------------------------------------
class CrtShSource(PassiveSource):
    name, kind, default_enabled = "crtsh", "ct", True

    async def fetch(self, ctx, domain):
        r = await _get(ctx, f"https://crt.sh/?q=%25.{domain}&output=json", timeout=90.0)
        if r.status_code != 200:
            raise RuntimeError(f"HTTP {r.status_code}")
        rows = _loads(r.text) or []
        out: dict[str, SourceHit] = {}
        for row in rows:
            for chunk in str(row.get("name_value", "")).split("\n"):
                h = _norm(chunk)
                if _in_domain(h, domain):
                    out.setdefault(h, SourceHit(h))
        return list(out.values())


class CertSpotterSource(PassiveSource):
    name, kind, default_enabled = "certspotter", "ct", True

    async def fetch(self, ctx, domain):
        r = await _get(
            ctx,
            "https://api.certspotter.com/v1/issuances"
            f"?domain={domain}&include_subdomains=true&expand=dns_names",
            timeout=30.0,
        )
        if r.status_code == 429:
            raise SourceDegraded("certspotter rate limit (429)")
        if r.status_code != 200:
            raise RuntimeError(f"HTTP {r.status_code}")
        out: dict[str, SourceHit] = {}
        for row in _loads(r.text) or []:
            for n in row.get("dns_names", []) or []:
                h = _norm(n)
                if _in_domain(h, domain):
                    out.setdefault(h, SourceHit(h))
        return list(out.values())


class DigitorusSource(PassiveSource):
    name, kind, default_enabled = "digitorus", "ct", False

    async def fetch(self, ctx, domain):
        r = await _get(ctx, f"https://certificatedetails.com/{domain}", timeout=30.0)
        if r.status_code != 200:
            raise RuntimeError(f"HTTP {r.status_code}")
        from bs4 import BeautifulSoup

        soup = BeautifulSoup(r.text, "html.parser")
        out: dict[str, SourceHit] = {}
        for a in soup.find_all("a", href=True):
            for token in (a.get_text(" ", strip=True), a["href"]):
                h = _norm(token)
                if _in_domain(h, domain):
                    out.setdefault(h, SourceHit(h))
        return list(out.values())


# --- passive-DNS sources --------------------------------------------
class HackerTargetSource(PassiveSource):
    name, kind, default_enabled = "hackertarget", "passive_dns", True

    async def fetch(self, ctx, domain):
        r = await _get(ctx, f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=30.0)
        body = r.text.strip()
        low = body.lower()
        if "api count exceeded" in low or low.startswith("error"):
            raise SourceDegraded("hackertarget quota exceeded")
        if r.status_code != 200:
            raise RuntimeError(f"HTTP {r.status_code}")
        out: dict[str, SourceHit] = {}
        for line in body.splitlines():
            host, _, ip = line.partition(",")
            h = _norm(host)
            if _in_domain(h, domain):
                hit = out.setdefault(h, SourceHit(h))
                ip = ip.strip()
                if ip and ip not in hit.resolved:
                    hit.resolved.append(ip)
        return list(out.values())


class OTXSource(PassiveSource):
    name, kind, default_enabled = "otx", "passive_dns", True

    async def fetch(self, ctx, domain):
        r = await _get(
            ctx,
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
            timeout=30.0,
        )
        if r.status_code == 429:
            raise SourceDegraded("otx rate limit (429)")
        if r.status_code != 200:
            raise RuntimeError(f"HTTP {r.status_code}")
        data = _loads(r.text) or {}
        out: dict[str, SourceHit] = {}
        for rec in data.get("passive_dns", []) or []:
            h = _norm(str(rec.get("hostname", "")))
            if not _in_domain(h, domain):
                continue
            hit = out.setdefault(h, SourceHit(h))
            addr = str(rec.get("address", "")).strip()
            if addr and _looks_like_ip(addr) and addr not in hit.resolved:
                hit.resolved.append(addr)
        return list(out.values())


class ThreatMinerSource(PassiveSource):
    name, kind, default_enabled = "threatminer", "passive_dns", False

    async def fetch(self, ctx, domain):
        r = await _get(
            ctx, f"https://api.threatminer.org/v2/domain.php?q={domain}&rt=5", timeout=30.0
        )
        if r.status_code != 200:
            raise RuntimeError(f"HTTP {r.status_code}")
        data = _loads(r.text) or {}
        out: dict[str, SourceHit] = {}
        for n in data.get("results", []) or []:
            h = _norm(str(n))
            if _in_domain(h, domain):
                out.setdefault(h, SourceHit(h))
        return list(out.values())


class RapidDNSSource(PassiveSource):
    name, kind, default_enabled = "rapiddns", "passive_dns", True

    async def fetch(self, ctx, domain):
        r = await _get(ctx, f"https://rapiddns.io/subdomain/{domain}?full=1", timeout=30.0)
        if r.status_code != 200:
            raise RuntimeError(f"HTTP {r.status_code}")
        from bs4 import BeautifulSoup

        soup = BeautifulSoup(r.text, "html.parser")
        out: dict[str, SourceHit] = {}
        for row in soup.select("table tr"):
            cells = [td.get_text(" ", strip=True) for td in row.find_all("td")]
            if not cells:
                continue
            h = _norm(cells[0])
            if not _in_domain(h, domain):
                continue
            hit = out.setdefault(h, SourceHit(h))
            for c in cells[1:]:
                for tok in c.replace(",", " ").split():
                    if _looks_like_ip(tok) and tok not in hit.resolved:
                        hit.resolved.append(tok)
        return list(out.values())


# --- aggregator DBs ------------------------------------------------
class AnubisSource(PassiveSource):
    name, kind, default_enabled = "anubis", "aggregator", True

    async def fetch(self, ctx, domain):
        r = await _get(ctx, f"https://jldc.me/anubis/subdomains/{domain}", timeout=30.0)
        if r.status_code == 404:
            return []  # anubis 404s for domains it has never seen
        if r.status_code != 200:
            raise RuntimeError(f"HTTP {r.status_code}")
        return _bare_list_hits(r.text, domain)


class SubdomainCenterSource(PassiveSource):
    name, kind, default_enabled = "subdomain_center", "aggregator", True

    async def fetch(self, ctx, domain):
        r = await _get(ctx, f"https://api.subdomain.center/?domain={domain}", timeout=40.0)
        if r.status_code == 429:
            raise SourceDegraded("subdomain.center rate limit (429)")
        if r.status_code != 200:
            raise RuntimeError(f"HTTP {r.status_code}")
        return _bare_list_hits(r.text, domain)


# --- archive / scan index ----------------------------------------
class WaybackCDXSource(PassiveSource):
    name, kind, default_enabled = "wayback_cdx", "archive", True

    async def fetch(self, ctx, domain):
        r = await _get(
            ctx,
            f"https://web.archive.org/cdx/search/cdx?url=*.{domain}"
            "&output=json&fl=original&collapse=urlkey&limit=50000",
            timeout=60.0,
        )
        if r.status_code != 200:
            raise RuntimeError(f"HTTP {r.status_code}")
        rows = _loads(r.text) or []
        out: dict[str, SourceHit] = {}
        for row in rows:
            if not row or (isinstance(row, list) and row[0] == "original"):
                continue
            url = row[0] if isinstance(row, list) else row
            try:
                h = _norm(urlsplit(str(url)).hostname or "")
            except ValueError:
                continue
            if _in_domain(h, domain):
                out.setdefault(h, SourceHit(h))
        return list(out.values())


class CommonCrawlSource(PassiveSource):
    name, kind, default_enabled = "commoncrawl", "scan_index", False

    async def fetch(self, ctx, domain):
        info = await _get(ctx, "https://index.commoncrawl.org/collinfo.json", timeout=30.0)
        if info.status_code != 200:
            raise RuntimeError(f"collinfo HTTP {info.status_code}")
        collections = _loads(info.text) or []
        if not collections:
            raise RuntimeError("no Common Crawl collections listed")
        cdx_api = collections[0].get("cdx-api")
        if not cdx_api:
            raise RuntimeError("collection has no cdx-api url")
        r = await _get(ctx, f"{cdx_api}?url=*.{domain}&output=json&limit=10000", timeout=120.0)
        if r.status_code != 200:
            raise RuntimeError(f"HTTP {r.status_code}")
        out: dict[str, SourceHit] = {}
        for line in r.text.splitlines():
            rec = _loads(line) or {}
            try:
                h = _norm(urlsplit(str(rec.get("url", ""))).hostname or "")
            except ValueError:
                continue
            if _in_domain(h, domain):
                out.setdefault(h, SourceHit(h))
        return list(out.values())


def _bare_list_hits(text: str, domain: str) -> list[SourceHit]:
    data = _loads(text)
    if not isinstance(data, list):
        raise RuntimeError("expected a JSON array")
    out: dict[str, SourceHit] = {}
    for n in data:
        h = _norm(str(n))
        if _in_domain(h, domain):
            out.setdefault(h, SourceHit(h))
    return list(out.values())


def _looks_like_ip(value: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


# Order matters only for readable progress output; the module dedupes results.
ALL_SOURCES: tuple[PassiveSource, ...] = (
    CrtShSource(), CertSpotterSource(), HackerTargetSource(), OTXSource(),
    AnubisSource(), RapidDNSSource(), WaybackCDXSource(), SubdomainCenterSource(),
    ThreatMinerSource(), CommonCrawlSource(), DigitorusSource(),
)


def select_sources(disable: set[str], enable: set[str]) -> list[PassiveSource]:
    """Enabled adapters: every ``default_enabled`` one, plus anything in
    ``enable``, minus anything in ``disable`` (disable wins)."""
    out = []
    for s in ALL_SOURCES:
        on = s.default_enabled or s.name in enable
        if on and s.name not in disable:
            out.append(s)
    return out
