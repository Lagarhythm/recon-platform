"""Search-engine dorking (OSINT).

Runs a curated set of dork templates against the target's domain(s) and company
name through the configured search backend (SearXNG or Google CSE - see
``_search.py``). No-ops cleanly when no backend is configured.

Results are mined for: exposed documents / dumps, admin panels, subdomains,
staff (LinkedIn), social + code + collaboration-tool presence, and anything on a
paste / cloud-storage site referencing the target.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from recon.models.enums import ModulePhase
from recon.modules.base import ModuleContext, ReconModule
from recon.modules.osint._common import interesting_path, org_targets
from recon.modules.osint._search import run_query, search_backend
from recon.modules.registry import register

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_PER_QUERY = 8
_MAX_EMIT = 250

# SEO-spam pages echo the dork back in their <title> - a reliable junk signal
_DORK_ECHO = re.compile(r"\b(site|inurl|intitle|filetype|intext)\s*:", re.IGNORECASE)
_LINKEDIN_PROFILE = re.compile(r"^(?:[a-z]{2,3}\.)?linkedin\.com$", re.IGNORECASE)


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

_HIGH_INTEREST = {"config", "creds", "paste", "cloud"}
_NOTABLE = {"exposure", "panels", "files", "collab"}


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
            return

        company, domains = org_targets(ctx)
        if not company and not domains:
            await ctx.progress("search: no company name or domains in the RoE")
            return
        co = f'"{company}"' if company else ""

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
        seen: set[str] = set()
        for i, (cat, q) in enumerate(queries, start=1):
            ctx.check_alive()
            if emitted >= _MAX_EMIT:
                break
            for res in await run_query(ctx, q, limit=_PER_QUERY):
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
        if res.url in seen:
            return 0
        seen.add(res.url)
        if _DORK_ECHO.search(res.title or ""):     # SEO spam echoing the query
            return 0
        host = (urlsplit(res.url).hostname or "").lower().strip(".")
        interest = ("high_value" if cat in _HIGH_INTEREST
                    else "notable" if cat in _NOTABLE else "informational")
        raw = {"source": f"dork/{cat}", "query": query, "title": res.title,
               "snippet": res.snippet[:400], "engine": res.engine, "interest": interest}
        n = 0

        # company-name dorks (people / social / cloud / collab) are noisy - the
        # engine ignores quotes and returns anything sharing a word. Keep a hit
        # only if the company name actually appears in the title/snippet.
        if cat in ("people", "social", "cloud", "collab") and company:
            blob = f"{res.title} {res.snippet}".lower()
            compact = re.sub(r"\W+", "", company.lower())
            if company.lower() not in blob and compact not in re.sub(r"\W+", "", blob):
                return 0

        # emails in the snippet - confirmed public data
        for em in set(_EMAIL_RE.findall(res.snippet)):
            if any(em.lower().endswith(d) for d in domains):
                await ctx.add_evidence(
                    subject_type="email", subject_value=em.lower(),
                    raw_data={"source": f"dork/{cat}", "seen_on": res.url},
                    summary=f"{em} - in a search result snippet ({res.url})",
                )
                n += 1

        on_target = any(host == d or host.endswith("." + d) for d in domains)

        if (cat == "subdomains" and on_target and host
                and host not in domains and not host.startswith("www.")):
            await ctx.add_evidence(
                subject_type="subdomain", subject_value=host,
                raw_data={"source": "dork", "example_url": res.url},
                summary=f"{host} - indexed by a search engine",
            )
            return n + 1

        if cat in ("people",):
            name = _linkedin_name(res)
            if not name:                       # not a real linkedin.com/in/ profile
                return n
            await ctx.add_evidence(
                subject_type="person", subject_value=name,
                raw_data=raw, summary=f"{name} - LinkedIn ({res.url})",
            )
            await ctx.add_evidence(
                subject_type="social", subject_value=res.url, raw_data=raw,
                summary=f"LinkedIn profile: {res.url}",
            )
            return n + 2

        if cat in ("social", "code", "collab"):
            await ctx.add_evidence(
                subject_type="social", subject_value=res.url, raw_data=raw,
                summary=f"{cat}: {res.title or res.url}",
            )
            return n + 1

        # paste / cloud dorks are site-scoped (pastebin.com, s3, ...) - the hit
        # itself is the signal. files / config dorks just constrain filetype:,
        # which the search backends honour loosely, so only trust a result that
        # actually resolves to a document / dump / config artefact.
        if cat in ("paste", "cloud") or interesting_path(res.url):
            await ctx.add_evidence(
                subject_type="document", subject_value=res.url, raw_data=raw,
                summary=f"[{cat}] {res.title or res.url}",
            )
            return n + 1

        # a files / config dork hit that isn't actually a file is just an
        # indexed page - not worth surfacing.
        if cat in ("files", "config"):
            return n

        # panels / exposure / creds / anything else on-target -> url finding
        if on_target or cat in ("creds", "panels", "exposure"):
            await ctx.add_evidence(
                subject_type="url", subject_value=res.url, raw_data=raw,
                summary=f"[{cat}] {res.title or res.url}",
            )
            return n + 1
        return n
