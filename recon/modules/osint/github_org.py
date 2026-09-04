"""GitHub organisation / account OSINT.

Resolves the target's GitHub presence (explicit ``osint.github_org``, else a
domain- or name-anchored search), then enumerates public repos (tech stack,
topics, activity) and, for a real Organisation, public members. Read-only,
public data only.

A hit is only accepted if the account's public profile **corroborates the
target** - a seed domain appears in its blog / email / bio, or (name search
only) the compacted account name matches the company almost exactly. A shared
word is never enough: a fuzzy name match happily picks an unrelated look-alike
org whose name merely contains the company name as a substring.

The GitHub account may be a User rather than an Organisation (a small project
often publishes under a personal-style account); both are handled.

Unauthenticated the GitHub API allows 60 requests/hour; set
``RECON_OSINT_GITHUB_TOKEN`` to raise that to 5000/hour.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from recon.config import get_settings
from recon.models.enums import ModulePhase
from recon.modules.base import ModuleContext, ReconModule
from recon.modules.osint._common import fetch_json, org_targets
from recon.modules.registry import register

_API = "https://api.github.com"


def _compact(s: str) -> str:
    return re.sub(r"\W+", "", (s or "").lower())


def _host(url: str) -> str:
    v = (url or "").strip()
    if v and "://" not in v:
        v = "//" + v
    try:
        h = (urlsplit(v).hostname or "").lower()
    except ValueError:
        return ""
    return h[4:] if h.startswith("www.") else h


@register
class GitHubOrgModule(ReconModule):
    name = "github_org"
    phase = ModulePhase.OSINT
    depends_on = ()
    description = "GitHub org/account: public repos (tech, topics, activity) + public members"
    max_runtime_seconds = 6 * 60

    async def run(self, ctx: ModuleContext) -> None:
        company, domains = org_targets(ctx)
        token = get_settings().osint_github_token.strip()
        self._headers = {"Accept": "application/vnd.github+json"}
        if token:
            self._headers["Authorization"] = f"Bearer {token}"

        login = ctx.roe.osint.github_org
        info: dict | None = None
        if login:
            info = await self._profile(ctx, login)
            if not isinstance(info, dict) or info.get("message"):
                await ctx.add_error(
                    subject_value=login,
                    summary=f"GitHub account {login!r} (from osint.github_org) not found",
                    raw_data={"source": "GitHub", "response": str(info)[:200]},
                )
                return
        else:
            info = await self._find_account(ctx, company, domains)

        if not info:
            await ctx.progress(
                "github_org: no corroborated account - set osint.github_org in the "
                "RoE if you know the slug (name search alone is too fuzzy to trust)"
            )
            return

        login = info.get("login")
        is_org = str(info.get("type", "")).lower() == "organization"
        kind = "org" if is_org else "user"
        await ctx.progress(f"github: {kind} {login}")

        await ctx.add_evidence(
            subject_type="organization",
            subject_value=info.get("name") or login,
            raw_data={"source": "GitHub", "login": login, "account_type": kind,
                      "blog": info.get("blog"), "email": info.get("email"),
                      "location": info.get("location"), "bio": info.get("bio"),
                      "public_repos": info.get("public_repos")},
            summary=f"GitHub {kind} github.com/{login}"
                    + (f" - {info.get('name')}" if info.get("name") else ""),
        )
        await ctx.add_evidence(
            subject_type="social", subject_value=f"https://github.com/{login}",
            raw_data={"source": "GitHub", "kind": f"github_{kind}"},
            summary=f"GitHub {kind} profile: {login}",
        )
        if info.get("email"):
            await ctx.add_evidence(
                subject_type="email", subject_value=str(info["email"]).lower(),
                raw_data={"source": "GitHub profile", "account": login},
                summary=f"{info['email']} (GitHub {kind} {login})",
            )

        await self._repos(ctx, login)
        if is_org:
            await self._members(ctx, login, info.get("name") or login)

    # --- resolution --------------------------------------------------

    async def _find_account(
        self, ctx: ModuleContext, company: str, domains: list[str]
    ) -> dict | None:
        """Return the profile dict of a corroborated GitHub account, or None."""
        seen: set[str] = set()
        candidates: list[str] = []

        # 1. domain-anchored searches - most precise
        for d in domains:
            for q in (f'"{d}"', f'"{d}" in:email', f'{d} in:blog'):
                for login in await self._search_logins(ctx, q, limit=5):
                    if login not in seen:
                        seen.add(login)
                        candidates.append(login)
        # 2. company-name search
        if company:
            for login in await self._search_logins(ctx, company, limit=8):
                if login not in seen:
                    seen.add(login)
                    candidates.append(login)

        # pass A: accept the first candidate whose profile references a seed domain
        name_fallback: dict | None = None
        for login in candidates:
            info = await self._profile(ctx, login)
            if not isinstance(info, dict) or info.get("message"):
                continue
            if self._domain_corroborated(info, domains):
                return info
            if (name_fallback is None and company
                    and self._name_matches(info, login, company)):
                name_fallback = info
        # pass B: fall back to a tight name match ONLY when the RoE gave no seed
        # domains to corroborate against. If it did and none matched, trust
        # nothing - tell the operator to set osint.github_org.
        return name_fallback if not domains else None

    async def _search_logins(self, ctx: ModuleContext, q: str, *, limit: int) -> list[str]:
        data = await fetch_json(
            ctx, f"{_API}/search/users?q={q.replace(' ', '+')}&per_page={limit}",
            subject=q, source="GitHub search", headers=self._headers, timeout=20.0,
        )
        items = (data or {}).get("items") if isinstance(data, dict) else None
        return [i.get("login") for i in (items or []) if i.get("login")]

    async def _profile(self, ctx: ModuleContext, login: str) -> dict | None:
        # /users/<login> returns both User and Organization accounts (with a
        # "type" field), and carries blog/email/bio/name for the match check.
        return await fetch_json(
            ctx, f"{_API}/users/{login}", subject=login, source="GitHub account",
            headers=self._headers, timeout=15.0,
        )

    @staticmethod
    def _domain_corroborated(info: dict, domains: list[str]) -> bool:
        if not domains:
            return False
        blob = " ".join(str(info.get(k) or "").lower() for k in
                        ("email", "name", "bio", "twitter_username", "company"))
        if any(d in blob for d in domains):
            return True
        bh = _host(str(info.get("blog") or ""))
        return bool(bh) and any(bh == d or bh.endswith("." + d) for d in domains)

    @staticmethod
    def _name_matches(info: dict, login: str, company: str) -> bool:
        """A tight name match: the compacted company name equals the compacted
        login or account name, or one is a prefix of the other. NOT a loose
        substring (that lets 'acme' match 'notacmeatall')."""
        want = _compact(company)
        if len(want) < 5:
            return False
        for have in (_compact(login), _compact(str(info.get("name") or ""))):
            if len(have) < 5:
                continue
            if want == have or have.startswith(want) or want.startswith(have):
                return True
        return False

    # --- enumeration -----------------------------------------------

    async def _repos(self, ctx: ModuleContext, login: str) -> None:
        data = await fetch_json(
            ctx, f"{_API}/users/{login}/repos?per_page=100&sort=pushed",
            subject=login, source="GitHub repos", headers=self._headers, timeout=25.0,
        )
        if not isinstance(data, list):
            return
        langs: dict[str, int] = {}
        topics: set[str] = set()
        for r in data:
            if not isinstance(r, dict):
                continue
            await ctx.add_evidence(
                subject_type="repository",
                subject_value=r.get("html_url") or f"https://github.com/{login}/{r.get('name')}",
                raw_data={"source": "GitHub", "name": r.get("full_name"),
                          "description": r.get("description"), "language": r.get("language"),
                          "topics": r.get("topics") or [], "fork": r.get("fork"),
                          "homepage": r.get("homepage"), "pushed_at": r.get("pushed_at"),
                          "archived": r.get("archived")},
                summary=f"{r.get('full_name')} ({r.get('language') or '?'})"
                        + (f" - {r.get('description')}" if r.get("description") else ""),
                relationships=[{"type": "owns", "target_type": "organization",
                                "target_value": login}],
            )
            if r.get("language"):
                langs[r["language"]] = langs.get(r["language"], 0) + 1
            topics.update(r.get("topics") or [])
        if langs:
            top = ", ".join(f"{k} ({v})" for k, v in
                            sorted(langs.items(), key=lambda kv: -kv[1]))
            await ctx.add_evidence(
                subject_type="tech_stack", subject_value=login,
                raw_data={"source": "GitHub repo languages", "languages": langs,
                          "topics": sorted(topics)[:30]},
                summary=f"{login} repo languages: {top}",
            )

    async def _members(self, ctx: ModuleContext, org: str, org_name: str) -> None:
        data = await fetch_json(
            ctx, f"{_API}/orgs/{org}/members?per_page=100",
            subject=org, source="GitHub members", headers=self._headers, timeout=20.0,
        )
        if not isinstance(data, list):
            return
        for m in data:
            if not isinstance(m, dict) or not m.get("login"):
                continue
            await ctx.add_evidence(
                subject_type="person", subject_value=m["login"],
                raw_data={"source": "GitHub public member", "org": org,
                          "profile": m.get("html_url")},
                summary=f"{m['login']} - public member of GitHub org {org}",
                relationships=[{"type": "employed_by", "target_type": "organization",
                                "target_value": org_name}],
            )
