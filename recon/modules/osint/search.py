"""Search-engine dorking (OSINT).

Runs a curated set of dork templates against the target's domain(s) and company
name through the configured search backend (SearXNG or Google CSE - see
``_search.py``). No-ops cleanly when no backend is configured.

Results are mined for: exposed documents / dumps, admin panels, subdomains,
staff (LinkedIn), social + code + collaboration-tool presence, and anything on a
paste / cloud-storage site referencing the target.

Every result is host-and-string validated before it can become a target asset
(see ``_platform_linked`` / ``on_target`` in ``_handle``) - a URL suffix or a
snippet keyword match is never treated as fetched-content verification, only
as a signal that this result is worth recording as evidence.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from recon.models.enums import ModulePhase, SkipReason
from recon.modules.base import ModuleContext, ReconModule
from recon.modules.osint._common import interesting_path, org_targets
from recon.modules.osint._search import run_query, search_backend, verify_operators_honoured
from recon.modules.registry import register

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_PER_QUERY = 8
_MAX_EMIT = 250

# SEO-spam pages echo the dork back in their <title> - a reliable junk signal
_DORK_ECHO = re.compile(r"\b(site|inurl|intitle|filetype|intext)\s*:", re.IGNORECASE)
_LINKEDIN_PROFILE = re.compile(r"^(?:[a-z]{2,3}\.)?linkedin\.com$", re.IGNORECASE)
_FILETYPE_RE = re.compile(r"filetype:([A-Za-z0-9]+)", re.IGNORECASE)
_HOSTNAME_TOKEN_RE = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+"
)


def _linkedin_name(res) -> str | None:
    """A person's name from a genuine linkedin.com/in/<slug> result, or None."""
    parts = urlsplit(res.url)
    host = (parts.hostname or "").lower()
    if not _LINKEDIN_PROFILE.match(host) or "/in/" not in parts.path:
        return None
    title = (res.title or "").strip()
    if _DORK_ECHO.search(title):          # spam echoing the query
        return None
    # "Jane Doe - Senior Engineer at Acme | LinkedIn" -> "Jane Doe"
    name = re.split(r"\s[|–-]\s", title, maxsplit=1)[0].strip()
    if 2 <= len(name) <= 80 and " " in name:
        return name
    slug = parts.path.split("/in/", 1)[1].strip("/").split("/")[0]
    slug = re.sub(r"-[0-9a-f]{6,}$", "", slug)          # trailing id
    pretty = " ".join(w.capitalize() for w in slug.split("-") if not w.isdigit())
    return pretty or None


def _expected_extensions(query: str) -> set[str] | None:
    """The extension set a ``filetype:`` dork actually requested, parsed from
    the query itself - not a separately-tracked table that could drift from
    the query templates below."""
    exts = {m.lower() for m in _FILETYPE_RE.findall(query)}
    return exts or None


# (category, needs_company, template) - {d} = a domain, {co} = quoted company
_DORKS: list[tuple[str, bool, str]] = [
    ("files",      False, 'site:{d} filetype:pdf'),
    ("files",      False, 'site:{d} (filetype:xlsx OR filetype:xls OR filetype:csv)'),
    ("files",      False, 'site:{d} (filetype:doc OR filetype:docx OR filetype:pptx)'),
    ("config",     False, 'site:{d} (filetype:env OR filetype:yml OR filetype:conf OR '
                          'filetype:ini OR filetype:log OR filetype:sql OR filetype:bak OR filetype:txt)'),
    ("exposure",   False, 'site:{d} intitle:"index of"'),
    ("panels",     False, 'site:{d} inurl:(login OR admin OR portal OR dashboard OR signin OR "wp-admin")'),
    ("subdomains", False, 'site:{d} -inurl:www'),
    ("creds",      False, 'site:{d} intext:(password OR passwd OR "api_key" OR "secret")'),
    ("code",       False, '"{d}" (site:github.com OR site:gitlab.com OR site:bitbucket.org)'),
    ("paste",      False, '"{d}" (site:pastebin.com OR site:gist.github.com OR site:paste.ee OR '
                          'site:justpaste.it OR site:controlc.com OR site:rentry.co)'),
    ("people",     True,  '{co} site:linkedin.com/in'),
    ("social",     True,  '{co} (site:twitter.com OR site:x.com OR site:facebook.com OR site:instagram.com)'),
    ("cloud",      True,  '{co} (site:s3.amazonaws.com OR site:storage.googleapis.com OR '
                          'site:blob.core.windows.net)'),
    ("collab",     True,  '{co} (site:trello.com OR site:atlassian.net OR site:notion.site)'),
]

# Dork categories that legitimately target a host other than the domain
# itself. Each maps to the *actual* platform hosts for that category and
# which string (the company name, or a target domain) must genuinely appear
# in the hit - a keyword match alone is not enough, since that's exactly what
# let an unrelated host through (e.g. a career-aggregator page mentioning the
# target's name passing as a "social" asset).
_PASTE_HOSTS = {"pastebin.com", "gist.github.com", "paste.ee",
                "justpaste.it", "controlc.com", "rentry.co"}
_CLOUD_HOSTS = {"s3.amazonaws.com", "storage.googleapis.com", "blob.core.windows.net"}
_CODE_HOSTS = {"github.com", "gitlab.com", "bitbucket.org"}
_SOCIAL_HOSTS = {"twitter.com", "x.com", "facebook.com", "instagram.com"}
_COLLAB_HOSTS = {"trello.com", "atlassian.net", "notion.site"}
_PEOPLE_HOSTS = {"linkedin.com"}

_OFF_DOMAIN_CATS: dict[str, tuple[set[str], str]] = {
    "paste": (_PASTE_HOSTS, "domain"),
    "cloud": (_CLOUD_HOSTS, "company"),
    "code": (_CODE_HOSTS, "domain"),
    "people": (_PEOPLE_HOSTS, "company"),
    "social": (_SOCIAL_HOSTS, "company"),
    "collab": (_COLLAB_HOSTS, "company"),
}


def _host_in(host: str, allowlist: set[str]) -> bool:
    return any(host == h or host.endswith("." + h) for h in allowlist)


def _company_mentioned(text: str, company: str) -> bool:
    """Whether `company` genuinely appears in `text`, tolerant of an engine
    dropping punctuation/spacing from a multi-word name."""
    if not company:
        return False
    blob = text.lower()
    if re.search(r"\b" + re.escape(company.lower()) + r"\b", blob):
        return True
    compact_needle = re.sub(r"\W+", "", company.lower())
    compact_blob = re.sub(r"\W+", "", blob)
    return bool(compact_needle) and compact_needle in compact_blob


def _domain_mentioned(text: str, domain: str) -> bool:
    """Whether `domain` appears in `text` as a complete hostname token - not
    as a substring of a longer one. A regex word-boundary (`\\b`) is not a
    hostname boundary: a hyphen or another dot is a non-word character, so
    `\\bexample\\.com\\b` still matches inside "not-example.com" (hyphen before)
    and "example.com.evil.invalid" (dot after). Instead, extract whole
    hostname-shaped tokens and require an exact match or a genuine
    subdomain relationship, the same check used for a real ``Host:``."""
    if not domain:
        return False
    domain = domain.lower()
    for token in _HOSTNAME_TOKEN_RE.findall(text.lower()):
        token = token.rstrip(".")
        if token == domain or token.endswith("." + domain):
            return True
    return False


def _platform_linked(cat: str, host: str, blob: str, company: str, domains: list[str]) -> bool:
    """For an off-domain dork category (paste/cloud/code/people/social/collab):
    true only if the host is genuinely on that category's expected platform
    *and* the target string actually appears there. Categories not in the
    table (the on-domain ``site:{d}`` dorks) are never platform-linked - they
    rely on ``on_target`` instead."""
    spec = _OFF_DOMAIN_CATS.get(cat)
    if not spec:
        return False
    hosts, needle_kind = spec
    if not _host_in(host, hosts):
        return False
    if needle_kind == "company":
        return _company_mentioned(blob, company)
    return any(_domain_mentioned(blob, d) for d in domains)


def _classify_hit(
    cat: str, query: str, res, host: str, domains: list[str], blob: str
) -> list[tuple[str, str, dict, str]] | None:
    """What a target-linked hit should become, or None if it doesn't qualify
    for its category (wrong filetype, not a real LinkedIn profile, ...).
    Pure - no evidence is written here, so the caller can dedup on the
    outcome instead of racing ahead of it with a premature ``seen.add``."""
    if cat == "subdomains":
        if host and host not in domains and not host.startswith("www."):
            return [("subdomain", host, {"source": "dork", "example_url": res.url},
                      f"{host} - indexed by a search engine")]
        return None

    if cat == "people":
        name = _linkedin_name(res)
        if not name:                       # not a real linkedin.com/in/ profile
            return None
        interest = _derive_interest(cat)
        raw = {"source": f"dork/{cat}", "query": query, "title": res.title,
               "snippet": res.snippet[:400], "engine": res.engine, "interest": interest}
        return [
            ("person", name, raw, f"{name} - LinkedIn ({res.url})"),
            ("social", res.url, raw, f"LinkedIn profile: {res.url}"),
        ]

    if cat in ("social", "code", "collab"):
        interest = _derive_interest(cat)
        raw = {"source": f"dork/{cat}", "query": query, "title": res.title,
               "snippet": res.snippet[:400], "engine": res.engine, "interest": interest}
        return [("social", res.url, raw, f"{cat}: {res.title or res.url}")]

    if cat in ("paste", "cloud"):
        interest = _derive_interest(cat)
        raw = {"source": f"dork/{cat}", "query": query, "title": res.title,
               "snippet": res.snippet[:400], "engine": res.engine, "interest": interest}
        return [("document", res.url, raw, f"[{cat}] {res.title or res.url}")]

    # files / config dorks constrain filetype: - a URL extension is an
    # inferred file type, not fetched-content verification, so require it to
    # actually match one of the extensions *this query* requested (parsed
    # from the query text, not just "looks like some document").
    ext = interesting_path(res.url)
    if cat in ("files", "config"):
        expected = _expected_extensions(query)
        if ext and expected and ext in expected:
            interest = _derive_interest(cat)
            raw = {"source": f"dork/{cat}", "query": query, "title": res.title,
                   "snippet": res.snippet[:400], "engine": res.engine, "interest": interest}
            return [("document", res.url, raw, f"[{cat}] {res.title or res.url}")]
        # a filetype: dork hit whose URL doesn't carry the requested
        # extension is just an indexed page - not worth surfacing.
        return None

    if ext:
        interest = _derive_interest(cat)
        raw = {"source": f"dork/{cat}", "query": query, "title": res.title,
               "snippet": res.snippet[:400], "engine": res.engine, "interest": interest}
        return [("document", res.url, raw, f"[{cat}] {res.title or res.url}")]

    # panels / exposure / creds / anything else on-target -> url finding.
    interest = _derive_interest(cat)
    raw = {"source": f"dork/{cat}", "query": query, "title": res.title,
           "snippet": res.snippet[:400], "engine": res.engine, "interest": interest}
    return [("url", res.url, raw, f"[{cat}] {res.title or res.url}")]


def _derive_interest(cat: str) -> str:
    """Interest from the validated result, not the dork that produced it -
    and never from a snippet keyword or phrase. Natural language about
    security topics defeats any keyword heuristic: "no data was leaked",
    a breach-prevention guide, and "Password: required when signing in"
    all use the same vocabulary as a genuine leak - a fourth keyword pass
    would not close that mechanism, so this module never emits high_value
    at all. An indexed .env or a paste/cloud host mentioning the target is a
    candidate worth surfacing, not proven exposure - that requires fetching
    the artifact and inspecting real content, which is deferred enrichment,
    not something a SERP snippet can establish. Everything here tops out at
    notable."""
    if cat in ("config", "exposure", "panels", "files", "collab", "paste", "cloud"):
        return "notable"
    return "informational"


@register
class SearchDorkModule(ReconModule):
    name = "search"
    phase = ModulePhase.OSINT
    depends_on = ()
    description = "Search-engine dorking (SearXNG / Google CSE): files, panels, staff, leaks"
    max_runtime_seconds = 15 * 60

    async def run(self, ctx: ModuleContext) -> None:
        backend = search_backend()
        if not backend:
            await ctx.progress(
                "search: no backend configured - set RECON_SEARCH_BACKEND + "
                "RECON_SEARXNG_URL (or the Google CSE key/id)"
            )
            # Not a clean empty result: the module never ran because it has no
            # backend. Record it as an explicit skipped/not-configured state so
            # the report does not read zero search hits as a clean search
            # (P1 assessment, tuning item 2).
            await ctx.mark_no_input(SkipReason.NOT_CONFIGURED)
            return

        company, domains = org_targets(ctx)
        if not company and not domains:
            await ctx.progress("search: no company name or domains in the RoE")
            return
        co = f'"{company}"' if company else ""

        operators_honoured = await verify_operators_honoured(
            ctx, domains[0] if domains else "", backend=backend
        )
        if operators_honoured is False:
            await ctx.progress(
                f"search ({backend}): site: probe returned off-domain hosts - "
                "this backend does not appear to honour search operators; "
                "every hit will still be host-verified before being trusted"
            )

        queries: list[tuple[str, str]] = []
        for cat, needs_co, tmpl in _DORKS:
            if needs_co and not company:
                continue
            if "{d}" in tmpl:
                for d in domains:
                    queries.append((cat, tmpl.format(d=d, co=co)))
            else:
                queries.append((cat, tmpl.format(d="", co=co)))

        await ctx.progress(
            f"search ({backend}): {len(queries)} dork(s)", current=0, total=len(queries)
        )
        emitted = 0
        # Dedup for *accepted* evidence only - deliberately not shared with
        # rejection. A URL rejected under one query (e.g. seen off-domain
        # under a "files" dork) must not suppress the same URL being
        # legitimately accepted later (e.g. as a validated "paste" hit).
        seen: set[str] = set()
        for i, (cat, q) in enumerate(queries, start=1):
            ctx.check_alive()
            if emitted >= _MAX_EMIT:
                break
            for res in await run_query(ctx, q, backend=backend, limit=_PER_QUERY):
                emitted += await self._handle(ctx, cat, q, res, domains, seen, company)
            await ctx.progress(
                f"search: {i}/{len(queries)} dorks, {emitted} finding(s)",
                current=i, total=len(queries),
            )
        await ctx.progress(f"search done: {emitted} finding(s) from {len(queries)} dork(s)")

    async def _handle(
        self, ctx: ModuleContext, cat: str, query: str, res, domains: list[str],
        seen: set[str], company: str = "",
    ) -> int:
        if _DORK_ECHO.search(res.title or ""):     # SEO spam echoing the query
            return 0
        host = (urlsplit(res.url).hostname or "").lower().strip(".")
        blob = f"{res.title} {res.snippet}"
        n = 0

        # Every derived entity - including an extracted email - shares this
        # one gate: on-domain host, or a genuinely on-platform host for an
        # off-domain category that also carries the target string. A hit
        # that fails it is unverifiable noise from the backend ignoring its
        # site:/filetype: operators - record it as evidence-only, never
        # promote it (or anything scraped from it) to a target asset. An
        # @target-domain email string is not, on its own, corroboration that
        # an unrelated/rejected page is genuinely associated with the target.
        on_target = any(host == d or host.endswith("." + d) for d in domains)
        target_linked = on_target or _platform_linked(cat, host, blob, company, domains)

        if not target_linked:
            await ctx.add_evidence(
                subject_type="unverified_search_hit", subject_value=res.url,
                raw_data={"source": f"dork/{cat}", "query": query, "host": host,
                          "title": res.title, "snippet": res.snippet[:400],
                          "engine": res.engine},
                summary=f"unverified search hit ({cat}): {res.url} - host not linked to target",
            )
            return n + 1

        # emails in the snippet - confirmed public data by the email's own
        # domain match, now that the containing page has passed the gate.
        for em in set(_EMAIL_RE.findall(res.snippet)):
            emdom = em.lower().rsplit("@", 1)[-1]
            if any(emdom == d or emdom.endswith("." + d) for d in domains):
                await ctx.add_evidence(
                    subject_type="email", subject_value=em.lower(),
                    raw_data={"source": f"dork/{cat}", "seen_on": res.url},
                    summary=f"{em} - in a search result snippet ({res.url})",
                )
                n += 1

        # Classify *before* touching `seen`: a URL that this category
        # doesn't actually qualify (wrong filetype, not a real LinkedIn
        # profile) must not get marked seen and block a different, later
        # query from legitimately accepting the same URL under a category
        # where it does qualify.
        items = _classify_hit(cat, query, res, host, domains, blob)
        if not items:
            return n
        if res.url in seen:
            return n
        seen.add(res.url)
        for subject_type, subject_value, raw_data, summary in items:
            await ctx.add_evidence(
                subject_type=subject_type, subject_value=subject_value,
                raw_data=raw_data, summary=summary,
            )
        return n + len(items)
