"""Shared helpers for the OSINT phase.

Every OSINT module queries public third-party sources only - never the target's
own infrastructure. All outbound calls go through ``ctx.http.request(...,
is_target=False)``, which audits them as ``n/a`` scope and still applies the
RoE's rate limit + jitter.
"""

from __future__ import annotations

import json
import re
from typing import Any

from recon.modules.base import ModuleContext

# file extensions worth flagging when found in an archive / search result
_DOC_EXT = re.compile(
    r"\.(pdf|docx?|xlsx?|pptx?|csv|txt|rtf|odt|ods|"
    r"sql|db|bak|old|zip|tar|gz|7z|conf|cfg|ini|env|yml|yaml|log|xml|json)"
    r"(?:$|\?)",
    re.IGNORECASE,
)

# standard web plumbing - present on almost every site, never an "exposure"
_BORING_FILE = re.compile(
    r"(?:^|/)("
    r"robots\.txt|humans\.txt|ads\.txt|app-ads\.txt|security\.txt|trust\.txt|"
    r"dnt-policy\.txt|gpc\.json|ai-plugin\.json|assetlinks\.json|apple-app-site-association|"
    r"sitemap[\w-]*\.xml|sitemap[\w-]*\.xml\.gz|sitemapindex\.xml|"
    r"(?:atom|rss|feed|index|all\.atom|all)\.xml|feed\.json|rss\.xml|"
    r"manifest\.json|manifest\.webmanifest|browserconfig\.xml|crossdomain\.xml|"
    r"opensearch\.xml|osd\.xml|\.well-known/[\w.-]+"
    r")(?:$|\?)",
    re.IGNORECASE,
)


def org_targets(ctx: ModuleContext) -> tuple[str, list[str]]:
    """(company name, deduped list of domains) an OSINT module should work from:
    the RoE's ``osint.company``, its ``seed_domains``, and any ``scope.in_scope``
    domains (wildcards stripped)."""
    o = ctx.roe.osint
    domains: list[str] = []
    seen: set[str] = set()
    for d in [*o.seed_domains, *(p[2:] if p.startswith("*.") else p
                                 for p in ctx.roe.scope.in_scope.domains)]:
        d = d.strip().lower().strip(".")
        if d and d not in seen:
            seen.add(d)
            domains.append(d)
    return o.company.strip(), domains


def interesting_path(url_or_path: str) -> str | None:
    """Return the matched extension (lower-case) if the path looks like a
    document / dump / config artefact, else None. Standard web plumbing
    (robots.txt, sitemap.xml, feeds, .well-known/*) never counts."""
    s = url_or_path or ""
    if _BORING_FILE.search(s):
        return None
    m = _DOC_EXT.search(s)
    return m.group(1).lower() if m else None


def base_domain(host: str) -> str:
    """Naive registrable-domain guess: last two labels. Good enough for grouping
    OSINT results; the correlation engine does the real parent linking."""
    parts = (host or "").strip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


async def fetch_json(
    ctx: ModuleContext,
    url: str,
    *,
    subject: str,
    source: str,
    timeout: float = 30.0,
    headers: dict[str, str] | None = None,
    ok_statuses: tuple[int, ...] = (200,),
) -> Any | None:
    """GET ``url`` as a third-party OSINT call and parse JSON. Records a
    non-fatal error (never raises) and returns None on any failure."""
    try:
        resp = await ctx.http.request(
            "GET", url, is_target=False, timeout=timeout, headers=headers or {},
            follow_redirects=True,
        )
    except Exception as exc:  # noqa: BLE001 - network/timeout/protocol, all non-fatal
        await ctx.add_error(
            subject_value=subject,
            summary=f"{source} request failed: {type(exc).__name__}",
            raw_data={"source": source, "url": url, "error": str(exc)[:300]},
        )
        return None

    if resp.status_code not in ok_statuses:
        await ctx.add_error(
            subject_value=subject,
            summary=f"{source} returned HTTP {resp.status_code}",
            raw_data={"source": source, "url": url, "status": resp.status_code,
                      "body": resp.text[:300]},
        )
        return None

    try:
        return resp.json()
    except (json.JSONDecodeError, ValueError):
        try:
            return json.loads(resp.text)
        except (json.JSONDecodeError, ValueError):
            await ctx.add_error(
                subject_value=subject,
                summary=f"{source} returned invalid JSON",
                raw_data={"source": source, "url": url},
            )
            return None


async def crtsh_json(ctx: ModuleContext, query: str) -> list | None:
    """Query crt.sh (``?q=<query>&output=json``). ``query`` is a domain,
    ``%.<domain>`` for subdomains, or a free-text org name."""
    from urllib.parse import quote

    url = f"https://crt.sh/?q={quote(query)}&output=json"
    data = await fetch_json(ctx, url, subject=query, source="crt.sh", timeout=90.0)
    if data is None:
        return None
    if not isinstance(data, list):
        await ctx.add_error(
            subject_value=query,
            summary="crt.sh returned an unexpected JSON shape",
            raw_data={"source": "crt.sh", "url": url},
        )
        return None
    return data


def cert_orgs(entry: dict) -> list[str]:
    """Pull the leaf-certificate subject O= (the organisation the cert was
    *issued to*), skipping the issuing CA."""
    orgs: set[str] = set()
    # only the subject - the issuer O= is always a CA
    val = str(entry.get("subject_name") or "")
    for m in re.finditer(r"O\s*=\s*([^,/\n]+)", val):
        org = m.group(1).strip().strip('"')
        if org and org.lower() not in _CA_ORGS and not _CA_NAME.search(org):
            orgs.add(org)
    return sorted(orgs)


# a self-signed / DV cert has no meaningful subject O=; an EV/OV cert names the CA
# in the issuer, which we ignore, but be defensive about CA names anywhere.
_CA_NAME = re.compile(
    r"(certificat\w*|trust services|trust network|"
    r"SSL Corp|GlobalSign|GeoTrust|Comodo|Sectigo|DigiCert|Entrust|"
    r"Starfield Technolog|Let's Encrypt|Actalis|Buypass|IdenTrust|RapidSSL|"
    r"Amazon(?:\s|$)|cPanel)",
    re.IGNORECASE,
)
_CA_ORGS = {
    "let's encrypt", "digicert inc", "sectigo limited", "google trust services",
    "google trust services llc", "amazon", "cloudflare, inc.", "ssl corporation",
    "globalsign nv-sa", "internet security research group", "zerossl",
    "gts ca 1p5", "microsoft corporation", "geotrust", "geotrust inc.",
    "comodo ca limited", "thawte, inc.", "verisign, inc.",
}
