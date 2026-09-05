"""OSINT-phase modules - all HTTP faked, no real network."""

from __future__ import annotations

import json

import httpx
import pytest

from recon.config import get_settings
from recon.modules.osint.ct_org import CTOrgModule
from recon.modules.osint.github_org import GitHubOrgModule
from recon.modules.osint.rdap import RDAPModule
from recon.modules.osint.search import SearchDorkModule
from recon.modules.osint.wayback import WaybackModule
from tests.harness import FakeHTTP, evidence_for, module_harness


def _json(obj) -> httpx.Response:
    return httpx.Response(200, json=obj)


async def _run(engagement_id, module_name, module_cls, routes, **osint):
    http = FakeHTTP(routes)
    async with module_harness(engagement_id, module_name, http=http) as ctx:
        ctx.roe.osint.enabled = True
        for k, v in osint.items():
            setattr(ctx.roe.osint, k, v)
        await module_cls().run(ctx)
    return http


# --------------------------------------------------------------------------- #
# ct_org
# --------------------------------------------------------------------------- #
_CRTSH_DOMAIN = [
    {"name_value": "example.com\nwww.example.com\napi.example.com",
     "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
     "subject_name": "CN=example.com"},
]
_CRTSH_ORG = [
    {"name_value": "portal.example-labs.net",
     "issuer_name": "C=US, O=DigiCert Inc",
     "subject_name": "O=Example Corp, CN=portal.example-labs.net"},
]


@pytest.mark.asyncio
async def test_ct_org_finds_subdomains_and_owned_domains(engagement_id):
    routes = {
        "q=%25.example.com": _json(_CRTSH_DOMAIN),
        "q=Example%20Corp": _json(_CRTSH_ORG),
    }
    await _run(engagement_id, "ct_org", CTOrgModule, routes,
               company="Example Corp", seed_domains=["example.com"])

    subs = {e.subject_value for e in await evidence_for(engagement_id, subject_type="subdomain")}
    assert {"www.example.com", "api.example.com"} <= subs
    domains = {e.subject_value for e in await evidence_for(engagement_id, subject_type="domain")}
    assert "example-labs.net" in domains            # discovered via the org search
    orgs = {e.subject_value for e in await evidence_for(engagement_id, subject_type="organization")}
    assert "Example Corp" in orgs


@pytest.mark.asyncio
async def test_ct_org_noops_without_company_or_domains(engagement_id):
    async with module_harness(engagement_id, "ct_org", http=FakeHTTP({})) as ctx:
        ctx.roe.scope.in_scope.domains = []
        ctx.roe.osint.company = ""
        ctx.roe.osint.seed_domains = []
        await CTOrgModule().run(ctx)
    assert await evidence_for(engagement_id) == []


# --------------------------------------------------------------------------- #
# rdap
# --------------------------------------------------------------------------- #
_RDAP_DOMAIN = {
    "ldhName": "example.com",
    "status": ["client transfer prohibited"],
    "entities": [
        {"roles": ["registrant"],
         "vcardArray": ["vcard", [["version", {}, "text", "4.0"],
                                  ["org", {}, "text", "Example Holdings LLC"]]]},
        {"roles": ["registrar"],
         "vcardArray": ["vcard", [["fn", {}, "text", "MarkMonitor Inc."]]]},
    ],
    "events": [{"eventAction": "registration", "eventDate": "1997-09-15T04:00:00Z"},
               {"eventAction": "expiration", "eventDate": "2031-09-14T04:00:00Z"}],
    "nameservers": [{"ldhName": "ns1.example.net"}, {"ldhName": "ns2.example.net"}],
}
_RDAP_IP = {
    "name": "EXAMPLE-NET-1",
    "cidr0_cidrs": [{"v4prefix": "93.184.216.0", "length": 24}],
    "entities": [{"roles": ["registrant"],
                  "vcardArray": ["vcard", [["fn", {}, "text", "Edgecast Inc."]]]}],
}


@pytest.mark.asyncio
async def test_rdap_domain_and_reverse_ip(engagement_id, monkeypatch):
    async def fake_resolve(self, name, rtype, raise_on_no_answer=False):  # noqa: ANN001
        class _RR(list):
            pass
        class _A:
            rrset = _RR()
        if rtype == "A":
            rd = type("rd", (), {"to_text": lambda s: "93.184.216.34"})()
            a = _A(); a.rrset = _RR([rd]); return a
        return _A()
    monkeypatch.setattr("dns.asyncresolver.Resolver.resolve", fake_resolve)

    routes = {
        "rdap.org/domain/example.com": _json(_RDAP_DOMAIN),
        "rdap.org/ip/93.184.216.34": _json(_RDAP_IP),
    }
    await _run(engagement_id, "rdap", RDAPModule, routes, seed_domains=["example.com"])

    orgs = {e.subject_value for e in await evidence_for(engagement_id, subject_type="organization")}
    assert "Example Holdings LLC" in orgs          # registrant
    assert "Edgecast Inc." in orgs                 # hosting netblock owner
    nets = {e.subject_value for e in await evidence_for(engagement_id, subject_type="netblock")}
    assert "93.184.216.0/24" in nets
    dom_ev = await evidence_for(engagement_id, subject_type="domain")
    assert any(e.raw_data.get("registrar") == "MarkMonitor Inc." for e in dom_ev)


# --------------------------------------------------------------------------- #
# github_org
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_github_org_repos_members_tech(engagement_id):
    routes = {
        "api.github.com/users/examplecorp/repos": _json([
            {"full_name": "examplecorp/web", "html_url": "https://github.com/examplecorp/web",
             "language": "TypeScript", "description": "the site", "topics": ["frontend"],
             "fork": False},
            {"full_name": "examplecorp/api", "html_url": "https://github.com/examplecorp/api",
             "language": "Go", "description": None, "topics": [], "fork": False},
        ]),
        "api.github.com/orgs/examplecorp/members": _json([
            {"login": "alice", "html_url": "https://github.com/alice"},
            {"login": "bob", "html_url": "https://github.com/bob"},
        ]),
        "api.github.com/users/examplecorp": _json(
            {"login": "examplecorp", "type": "Organization", "name": "Example Corp",
             "blog": "https://example.com", "email": "oss@example.com", "public_repos": 2}),
    }
    await _run(engagement_id, "github_org", GitHubOrgModule, routes,
               github_org="examplecorp")

    repos = {e.subject_value for e in await evidence_for(engagement_id, subject_type="repository")}
    assert "https://github.com/examplecorp/web" in repos
    people = {e.subject_value for e in await evidence_for(engagement_id, subject_type="person")}
    assert {"alice", "bob"} <= people
    stack = await evidence_for(engagement_id, subject_type="tech_stack")
    assert stack and set(stack[0].raw_data["languages"]) == {"Go", "TypeScript"}
    emails = {e.subject_value for e in await evidence_for(engagement_id, subject_type="email")}
    assert "oss@example.com" in emails


@pytest.mark.asyncio
async def test_github_org_rejects_fuzzy_name_match(engagement_id):
    # searching a common company name hits unrelated accounts whose *display
    # name* also contains it - with a seed domain given and none corroborating,
    # trust none of them.
    routes = {
        "search/users": _json({"items": [{"login": "orbit3ai"},
                                         {"login": "acme-orbit-community"}]}),
        "api.github.com/users/orbit3ai": _json(
            {"login": "orbit3ai", "type": "Organization", "name": "Orbit3.ai",
             "blog": "https://orbit3.ai"}),
        "api.github.com/users/acme-orbit-community": _json(
            {"login": "acme-orbit-community", "type": "Organization",
             "name": "Orbit AI", "blog": "https://orbit-ai.onrender.com",
             "email": "orbit@acme-college.example"}),
    }
    await _run(engagement_id, "github_org", GitHubOrgModule, routes,
               company="Orbit AI", seed_domains=["orbitai.example"])
    assert await evidence_for(engagement_id, subject_type="repository") == []
    assert await evidence_for(engagement_id, subject_type="person") == []
    assert await evidence_for(engagement_id, subject_type="organization") == []


@pytest.mark.asyncio
async def test_github_org_accepts_user_account_by_blog_domain(engagement_id):
    # a project's GitHub presence can be a *User* account whose blog is the seed
    # domain - that corroboration is enough to accept it.
    routes = {
        "search/users": _json({"items": [{"login": "OrbitAI"}]}),
        "api.github.com/users/OrbitAI/repos": _json([
            {"full_name": "OrbitAI/site", "html_url": "https://github.com/OrbitAI/site",
             "language": "HTML", "description": None, "topics": [], "fork": False},
        ]),
        "api.github.com/users/OrbitAI": _json(
            {"login": "OrbitAI", "type": "User", "name": "Orbit AI",
             "blog": "https://orbitai.example", "public_repos": 1}),
    }
    await _run(engagement_id, "github_org", GitHubOrgModule, routes,
               company="Orbit AI", seed_domains=["orbitai.example"])
    repos = {e.subject_value for e in await evidence_for(engagement_id, subject_type="repository")}
    assert "https://github.com/OrbitAI/site" in repos
    # a User has no /orgs/<x>/members - must not fabricate people
    assert await evidence_for(engagement_id, subject_type="person") == []


# --------------------------------------------------------------------------- #
# wayback
# --------------------------------------------------------------------------- #
_CDX = [
    ["original", "timestamp", "statuscode", "mimetype"],
    ["http://example.com/", "20180101000000", "200", "text/html"],
    ["http://old.example.com/", "20150101000000", "200", "text/html"],
    ["http://example.com/files/budget-2017.pdf", "20170101000000", "200", "application/pdf"],
    ["http://example.com/admin/login", "20160101000000", "200", "text/html"],
]


@pytest.mark.asyncio
async def test_wayback_subdomains_docs_and_paths(engagement_id):
    routes = {"web.archive.org/cdx/search/cdx": _json(_CDX)}
    await _run(engagement_id, "wayback", WaybackModule, routes, seed_domains=["example.com"])

    subs = {e.subject_value for e in await evidence_for(engagement_id, subject_type="subdomain")}
    assert "old.example.com" in subs
    docs = {e.subject_value for e in await evidence_for(engagement_id, subject_type="document")}
    assert "http://example.com/files/budget-2017.pdf" in docs
    urls = {e.subject_value for e in await evidence_for(engagement_id, subject_type="url")}
    assert "http://example.com/admin/login" in urls


# --------------------------------------------------------------------------- #
# search (dorking)
# --------------------------------------------------------------------------- #
def _searx(results) -> httpx.Response:
    return httpx.Response(200, json={"query": "x", "results": results})


@pytest.mark.asyncio
async def test_search_noops_without_a_backend(engagement_id, monkeypatch):
    monkeypatch.setattr("recon.modules.osint.search.search_backend", lambda: None)
    async with module_harness(engagement_id, "search", http=FakeHTTP({})) as ctx:
        ctx.roe.osint.company = "Acme"
        await SearchDorkModule().run(ctx)
    assert await evidence_for(engagement_id) == []


@pytest.mark.asyncio
async def test_search_dorks_produce_documents_people_subdomains(engagement_id, monkeypatch):
    monkeypatch.setattr("recon.modules.osint.search.search_backend", lambda: "searxng")
    # _searxng() builds its URL from get_settings().searxng_url, independent of
    # the search_backend() patch above - needs a real value or every request
    # is a malformed relative URL that never reaches the fake route.
    monkeypatch.setenv("RECON_SEARXNG_URL", "http://127.0.0.1:8888")
    get_settings.cache_clear()

    def route(method, url):
        if "filetype%3Apdf" in url or "filetype:pdf" in url:
            return _searx([{"url": "https://example.com/reports/q3.pdf", "title": "Q3 report",
                            "content": "", "engine": "google"}])
        if "linkedin.com" in url:
            return _searx([
                {"url": "https://linkedin.com/in/jane-doe",
                 "title": "Jane Doe - Acme Corp", "content": "Acme Corp", "engine": "bing"},
                # SEO spam that echoes the dork back - must be dropped, not made a person
                {"url": "https://spam.example.net/x",
                 "title": 'Lorem ipsum "Acme Corp" site:linkedin.com/in dolor',
                 "content": "Acme Corp", "engine": "bing"},
            ])
        if "-inurl%3Awww" in url or "-inurl:www" in url:
            return _searx([{"url": "https://vpn.example.com/", "title": "VPN",
                            "content": "contact ops@example.com", "engine": "google"}])
        return _searx([])

    http = FakeHTTP({"127.0.0.1:8888": route})
    async with module_harness(engagement_id, "search", http=http) as ctx:
        ctx.roe.osint.company = "Acme Corp"
        ctx.roe.osint.seed_domains = ["example.com"]
        await SearchDorkModule().run(ctx)
    get_settings.cache_clear()

    docs = {e.subject_value for e in await evidence_for(engagement_id, subject_type="document")}
    assert "https://example.com/reports/q3.pdf" in docs
    people = {e.subject_value for e in await evidence_for(engagement_id, subject_type="person")}
    assert people == {"Jane Doe"}          # the spam result was rejected
    subs = {e.subject_value for e in await evidence_for(engagement_id, subject_type="subdomain")}
    assert "vpn.example.com" in subs
    emails = {e.subject_value for e in await evidence_for(engagement_id, subject_type="email")}
    assert "ops@example.com" in emails      # scraped from a result snippet


@pytest.mark.asyncio
async def test_search_falls_back_to_google_cse_when_searxng_empty(engagement_id, monkeypatch):
    from recon.modules.osint import _search

    monkeypatch.setattr("recon.modules.osint.search.search_backend", lambda: "searxng")
    monkeypatch.setenv("RECON_GOOGLE_CSE_KEY", "k")
    monkeypatch.setenv("RECON_GOOGLE_CSE_ID", "cx")
    get_settings.cache_clear()

    def route(method, url):
        if "googleapis.com/customsearch" in url:
            return httpx.Response(200, json={"items": [
                {"link": "https://example.com/leak.sql", "title": "dump", "snippet": ""}]})
        return _searx([])                     # SearXNG returns nothing for everything

    http = FakeHTTP({"127.0.0.1:8888": route, "googleapis.com": route})
    async with module_harness(engagement_id, "search", http=http) as ctx:
        ctx.roe.osint.seed_domains = ["example.com"]
        await SearchDorkModule().run(ctx)
    get_settings.cache_clear()

    docs = {e.subject_value for e in await evidence_for(engagement_id, subject_type="document")}
    assert "https://example.com/leak.sql" in docs   # came from the CSE fallback


def _search_ctx(engagement_id, monkeypatch, routes):
    monkeypatch.setattr("recon.modules.osint.search.search_backend", lambda: "searxng")
    monkeypatch.setenv("RECON_SEARXNG_URL", "http://127.0.0.1:8888")
    get_settings.cache_clear()
    return module_harness(engagement_id, "search", http=FakeHTTP(routes))


@pytest.mark.asyncio
async def test_search_gates_off_target_hits_to_unverified_evidence(engagement_id, monkeypatch):
    """The 'Christopher Earl' failure mode: a backend that ignores site:/
    filetype: operators and returns unrelated hosts for every dork category
    (creds/panels/exposure via the on_target-or-category bypass, paste/cloud
    via the no-check-at-all path). None of it should become a url/document
    asset - all of it should land as low-confidence 'unverified_search_hit'
    evidence instead."""
    off_target = [
        {"url": "https://bls.gov/report.pdf", "title": "BLS report",
         "content": "labor stats", "engine": "bing"},   # would-be creds/panels/exposure hit
    ]

    def route(method, url):
        return _searx(off_target)

    async with _search_ctx(engagement_id, monkeypatch, {"127.0.0.1:8888": route}) as ctx:
        ctx.roe.osint.seed_domains = ["example.com"]
        await SearchDorkModule().run(ctx)
    get_settings.cache_clear()

    assert await evidence_for(engagement_id, subject_type="document") == []
    assert await evidence_for(engagement_id, subject_type="url") == []
    unverified = await evidence_for(engagement_id, subject_type="unverified_search_hit")
    assert any(e.subject_value == "https://bls.gov/report.pdf" for e in unverified)


@pytest.mark.asyncio
async def test_search_paste_cloud_require_allowlisted_host(engagement_id, monkeypatch):
    """A 'paste' dork hit on a host that isn't a known paste site (the search
    engine ignored site:pastebin.com etc.) must not become a document asset
    even though the domain string happens to appear in the snippet."""
    def route(method, url):
        if "pastebin.com" in url or "gist.github.com" in url:
            return _searx([
                {"url": "https://not-a-paste-site.example.net/x", "title": "example.com leak",
                 "content": "example.com credentials", "engine": "bing"},
                {"url": "https://pastebin.com/abc123", "title": "example.com dump",
                 "content": "example.com passwords", "engine": "bing"},
            ])
        return _searx([])

    async with _search_ctx(engagement_id, monkeypatch, {"127.0.0.1:8888": route}) as ctx:
        ctx.roe.osint.seed_domains = ["example.com"]
        await SearchDorkModule().run(ctx)
    get_settings.cache_clear()

    docs = {e.subject_value for e in await evidence_for(engagement_id, subject_type="document")}
    assert docs == {"https://pastebin.com/abc123"}
    unverified = {e.subject_value for e in
                  await evidence_for(engagement_id, subject_type="unverified_search_hit")}
    assert "https://not-a-paste-site.example.net/x" in unverified


@pytest.mark.asyncio
async def test_search_email_domain_boundary_not_suffix_match(engagement_id, monkeypatch):
    """contact@notexample.com must not be captured as an email belonging to
    target domain example.com just because the string ends with it."""
    def route(method, url):
        if "-inurl%3Awww" in url or "-inurl:www" in url:
            return _searx([{"url": "https://example.com/contact", "title": "Contact",
                            "content": "reach us at contact@notexample.com or "
                                       "ops@example.com", "engine": "bing"}])
        return _searx([])

    async with _search_ctx(engagement_id, monkeypatch, {"127.0.0.1:8888": route}) as ctx:
        ctx.roe.osint.seed_domains = ["example.com"]
        await SearchDorkModule().run(ctx)
    get_settings.cache_clear()

    emails = {e.subject_value for e in await evidence_for(engagement_id, subject_type="email")}
    assert emails == {"ops@example.com"}
    assert "contact@notexample.com" not in emails


@pytest.mark.asyncio
async def test_search_code_dork_requires_domain_string_in_hit(engagement_id, monkeypatch):
    """'code' dorks quote the domain, not the company - an unrelated GitHub
    result that doesn't actually mention the domain must not become a social
    asset just because the host is github.com."""
    def route(method, url):
        if "github.com" in url:
            return _searx([
                {"url": "https://github.com/someorg/unrelated-repo",
                 "title": "unrelated-repo", "content": "nothing to do with us", "engine": "bing"},
                {"url": "https://github.com/example-com/infra",
                 "title": "infra - example.com tooling", "content": "example.com internal tools",
                 "engine": "bing"},
            ])
        return _searx([])

    async with _search_ctx(engagement_id, monkeypatch, {"127.0.0.1:8888": route}) as ctx:
        ctx.roe.osint.seed_domains = ["example.com"]
        await SearchDorkModule().run(ctx)
    get_settings.cache_clear()

    social = {e.subject_value for e in await evidence_for(engagement_id, subject_type="social")}
    assert social == {"https://github.com/example-com/infra"}


@pytest.mark.asyncio
async def test_search_off_platform_host_not_promoted_despite_target_mention(
    engagement_id, monkeypatch
):
    """A career-aggregator-style page on a host that is NOT the category's
    real platform (not linkedin/twitter/trello/...) must not become a social
    asset just because it mentions the company - this was the exact "Zippia"
    failure mode from the Christopher Earl scan, reproduced here for the
    people/social/collab categories with a synthetic off-platform host."""
    def route(method, url):
        if ("twitter.com" in url or "trello.com" in url or "linkedin.com" in url):
            return _searx([{"url": "https://unrelated.invalid/article",
                            "title": "Example Company profile", "content": "Example Company",
                            "engine": "bing"}])
        return _searx([])

    async with _search_ctx(engagement_id, monkeypatch, {"127.0.0.1:8888": route}) as ctx:
        ctx.roe.osint.company = "Example Company"
        ctx.roe.osint.seed_domains = ["example.com"]
        await SearchDorkModule().run(ctx)
    get_settings.cache_clear()

    assert await evidence_for(engagement_id, subject_type="social") == []
    assert await evidence_for(engagement_id, subject_type="person") == []
    unverified = {e.subject_value for e in
                  await evidence_for(engagement_id, subject_type="unverified_search_hit")}
    assert "https://unrelated.invalid/article" in unverified


@pytest.mark.asyncio
async def test_search_domain_lookalike_text_not_target_linked(engagement_id, monkeypatch):
    """A paste-site hit whose title only contains "notexample.com" (a lookalike
    substring of target domain "example.com") must not be treated as
    mentioning the target - text matching needs the same label boundary as
    host matching."""
    def route(method, url):
        if "pastebin.com" in url:
            return _searx([{"url": "https://pastebin.com/xyz",
                            "title": "notexample.com information", "content": "",
                            "engine": "bing"}])
        return _searx([])

    async with _search_ctx(engagement_id, monkeypatch, {"127.0.0.1:8888": route}) as ctx:
        ctx.roe.osint.seed_domains = ["example.com"]
        await SearchDorkModule().run(ctx)
    get_settings.cache_clear()

    assert await evidence_for(engagement_id, subject_type="document") == []
    unverified = {e.subject_value for e in
                  await evidence_for(engagement_id, subject_type="unverified_search_hit")}
    assert "https://pastebin.com/xyz" in unverified


@pytest.mark.asyncio
@pytest.mark.parametrize("lookalike", ["not-example.com", "example.com.evil.invalid"])
async def test_search_domain_lookalike_hostname_variants_not_target_linked(
    engagement_id, monkeypatch, lookalike
):
    """A regex \\b word-boundary is not a hostname boundary: a hyphen before
    (not-example.com) or another domain after (example.com.evil.invalid) are
    both non-word characters that satisfy \\b without the text actually
    mentioning the target domain as a complete hostname token."""
    def route(method, url):
        if "pastebin.com" in url:
            return _searx([{"url": "https://pastebin.com/xyz",
                            "title": f"{lookalike} release notes", "content": "",
                            "engine": "bing"}])
        return _searx([])

    async with _search_ctx(engagement_id, monkeypatch, {"127.0.0.1:8888": route}) as ctx:
        ctx.roe.osint.seed_domains = ["example.com"]
        await SearchDorkModule().run(ctx)
    get_settings.cache_clear()

    assert await evidence_for(engagement_id, subject_type="document") == []
    unverified = {e.subject_value for e in
                  await evidence_for(engagement_id, subject_type="unverified_search_hit")}
    assert "https://pastebin.com/xyz" in unverified


@pytest.mark.asyncio
async def test_search_paste_cloud_content_never_high_value(engagement_id, monkeypatch):
    """Being on a genuine paste/cloud host that mentions the target is not,
    by itself, exposure evidence. Nor is any snippet keyword: a keyword
    heuristic can't tell a real leak from "no data was leaked or
    compromised" - so the search module never emits high_value for
    paste/cloud at all, from any content. A genuine leak is a candidate
    worth surfacing (notable), not proven exposure until someone fetches and
    inspects the actual artifact."""
    def route(method, url):
        if "pastebin.com" in url:
            return _searx([
                {"url": "https://pastebin.com/release-notes",
                 "title": "example.com release notes",
                 "content": "Public documentation", "engine": "bing"},
                {"url": "https://pastebin.com/status",
                 "title": "example.com security update",
                 "content": "No data was leaked or compromised", "engine": "bing"},
            ])
        if "s3.amazonaws.com" in url:
            return _searx([{"url": "https://bucket.s3.amazonaws.com/readme",
                            "title": "Example Company public documentation",
                            "content": "Public documentation", "engine": "bing"}])
        return _searx([])

    async with _search_ctx(engagement_id, monkeypatch, {"127.0.0.1:8888": route}) as ctx:
        ctx.roe.osint.company = "Example Company"
        ctx.roe.osint.seed_domains = ["example.com"]
        await SearchDorkModule().run(ctx)
    get_settings.cache_clear()

    docs = {e.subject_value: e.raw_data.get("interest")
            for e in await evidence_for(engagement_id, subject_type="document")}
    assert docs.get("https://pastebin.com/release-notes") == "notable"
    assert docs.get("https://pastebin.com/status") == "notable"
    assert docs.get("https://bucket.s3.amazonaws.com/readme") == "notable"


@pytest.mark.asyncio
async def test_search_creds_content_never_high_value(engagement_id, monkeypatch):
    """Neither "how to reset your password" nor a real-looking
    "password=hunter2" snippet earns high_value from a "creds" dork - a SERP
    snippet can't establish exposure either way, so this category always
    tops out at informational (it isn't in the notable set either, since an
    on-target hit satisfying a loose intext: query isn't inherently
    noteworthy the way a directory listing or admin panel is)."""
    def route(method, url):
        if "intext%3A" in url or "intext:" in url:
            return _searx([
                {"url": "https://example.com/help", "title": "Account help",
                 "content": "How to reset your password", "engine": "bing"},
                {"url": "https://example.com/leaked-creds", "title": "Backup config",
                 "content": "password=hunter2 api_key=sk-live-abc123", "engine": "bing"},
            ])
        return _searx([])

    async with _search_ctx(engagement_id, monkeypatch, {"127.0.0.1:8888": route}) as ctx:
        ctx.roe.osint.seed_domains = ["example.com"]
        await SearchDorkModule().run(ctx)
    get_settings.cache_clear()

    urls = {e.subject_value: e.raw_data.get("interest")
            for e in await evidence_for(engagement_id, subject_type="url")}
    assert urls.get("https://example.com/help") == "informational"
    assert urls.get("https://example.com/leaked-creds") == "informational"


@pytest.mark.asyncio
async def test_search_config_extension_is_notable_not_high_value(engagement_id, monkeypatch):
    """An indexed .env file is a candidate worth surfacing, not proven
    exposure - config-by-extension caps at notable, same as every other
    category, since nobody has fetched and inspected its actual content."""
    def route(method, url):
        if "filetype%3Aenv" in url or "filetype:env" in url:
            return _searx([{"url": "https://example.com/.env", "title": ".env",
                            "content": "", "engine": "bing"}])
        return _searx([])

    async with _search_ctx(engagement_id, monkeypatch, {"127.0.0.1:8888": route}) as ctx:
        ctx.roe.osint.seed_domains = ["example.com"]
        await SearchDorkModule().run(ctx)
    get_settings.cache_clear()

    docs = {e.subject_value: e.raw_data.get("interest")
            for e in await evidence_for(engagement_id, subject_type="document")}
    assert docs.get("https://example.com/.env") == "notable"


@pytest.mark.asyncio
async def test_search_never_emits_high_value_interest(engagement_id, monkeypatch):
    """Structural invariant: the search module never stamps high_value on
    anything, for any category or content - a SERP title/snippet can't
    establish real exposure, only fetching and inspecting the actual
    artifact can (deferred enrichment, ticketed separately). Covers every
    category that used to reach high_value under the old category- or
    keyword-based rules."""
    def route(method, url):
        if "filetype%3Aenv" in url or "filetype:env" in url:
            return _searx([{"url": "https://example.com/leak.env", "title": ".env",
                            "content": "DB_PASSWORD=hunter2 SECRET_KEY=abc123", "engine": "bing"}])
        if "intext%3A" in url or "intext:" in url:
            return _searx([{"url": "https://example.com/admin/creds", "title": "creds",
                            "content": "password=hunter2 api_key=sk-live-abc123", "engine": "bing"}])
        if "pastebin.com" in url:
            return _searx([{"url": "https://pastebin.com/leak", "title": "example.com breach",
                            "content": "database dump leaked, confidential, compromised",
                            "engine": "bing"}])
        return _searx([])

    async with _search_ctx(engagement_id, monkeypatch, {"127.0.0.1:8888": route}) as ctx:
        ctx.roe.osint.seed_domains = ["example.com"]
        await SearchDorkModule().run(ctx)
    get_settings.cache_clear()

    all_evidence = await evidence_for(engagement_id)
    assert all_evidence  # sanity: the fixture actually produced evidence
    assert all(e.raw_data.get("interest") != "high_value" for e in all_evidence)


@pytest.mark.asyncio
async def test_search_rejected_page_does_not_promote_its_email(engagement_id, monkeypatch):
    """An off-target/unverifiable page must not have its scraped email
    promoted either - an @target-domain email string appearing on an
    unrelated, rejected page is not corroboration of a real association."""
    def route(method, url):
        if "filetype%3Apdf" in url or "filetype:pdf" in url:
            return _searx([{"url": "https://unrelated.invalid/page", "title": "Unrelated",
                            "content": "ops@example.com", "engine": "bing"}])
        return _searx([])

    async with _search_ctx(engagement_id, monkeypatch, {"127.0.0.1:8888": route}) as ctx:
        ctx.roe.osint.seed_domains = ["example.com"]
        await SearchDorkModule().run(ctx)
    get_settings.cache_clear()

    assert await evidence_for(engagement_id, subject_type="email") == []
    unverified = {e.subject_value for e in
                  await evidence_for(engagement_id, subject_type="unverified_search_hit")}
    assert "https://unrelated.invalid/page" in unverified


@pytest.mark.asyncio
async def test_search_filetype_dork_rejects_wrong_extension(engagement_id, monkeypatch):
    """A .csv result returned for a filetype:pdf query must not become a
    document - the requested extension has to actually match."""
    def route(method, url):
        if "filetype%3Apdf" in url or "filetype:pdf" in url:
            return _searx([{"url": "https://example.com/manual.csv", "title": "Manual",
                            "content": "", "engine": "bing"}])
        return _searx([])

    async with _search_ctx(engagement_id, monkeypatch, {"127.0.0.1:8888": route}) as ctx:
        ctx.roe.osint.seed_domains = ["example.com"]
        await SearchDorkModule().run(ctx)
    get_settings.cache_clear()

    assert await evidence_for(engagement_id, subject_type="document") == []


@pytest.mark.asyncio
async def test_search_rejection_under_one_category_does_not_suppress_other(
    engagement_id, monkeypatch
):
    """The same URL, off-target under a 'files' query (wrong host) and then
    genuinely target-linked under a 'paste' query, must still be accepted the
    second time - a rejection must not poison the per-run dedup set."""
    def route(method, url):
        if "filetype%3Apdf" in url or "filetype:pdf" in url:
            return _searx([{"url": "https://pastebin.com/shared", "title": "example.com data",
                            "content": "", "engine": "bing"}])
        if "pastebin.com" in url:
            return _searx([{"url": "https://pastebin.com/shared", "title": "example.com data",
                            "content": "", "engine": "bing"}])
        return _searx([])

    async with _search_ctx(engagement_id, monkeypatch, {"127.0.0.1:8888": route}) as ctx:
        ctx.roe.osint.seed_domains = ["example.com"]
        await SearchDorkModule().run(ctx)
    get_settings.cache_clear()

    docs = {e.subject_value for e in await evidence_for(engagement_id, subject_type="document")}
    assert "https://pastebin.com/shared" in docs


# --------------------------------------------------------------------------- #
# domain-boundary regressions (suffix-match vs. label-match)
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_wayback_domain_boundary_not_suffix_match(engagement_id):
    """host.endswith(domain) (no dot) would wrongly match notexample.com for
    target domain example.com - must require a real label boundary."""
    cdx = [
        ["original", "timestamp", "statuscode", "mimetype"],
        ["http://notexample.com/", "20180101000000", "200", "text/html"],
        ["http://sub.example.com/", "20180101000000", "200", "text/html"],
    ]
    routes = {"web.archive.org/cdx/search/cdx": _json(cdx)}
    await _run(engagement_id, "wayback", WaybackModule, routes, seed_domains=["example.com"])

    subs = {e.subject_value for e in await evidence_for(engagement_id, subject_type="subdomain")}
    assert "sub.example.com" in subs
    assert "notexample.com" not in subs
    assert await evidence_for(engagement_id, subject_type="url") == []
    assert await evidence_for(engagement_id, subject_type="document") == []


@pytest.mark.asyncio
async def test_ct_org_domain_boundary_not_suffix_match(engagement_id):
    """name.endswith(domain) (no dot) would wrongly match evilexample.com for
    target domain example.com - must require a real label boundary."""
    routes = {
        "q=%25.example.com": _json([
            {"name_value": "evilexample.com\nsub.example.com",
             "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
             "subject_name": "CN=example.com"},
        ]),
    }
    await _run(engagement_id, "ct_org", CTOrgModule, routes, seed_domains=["example.com"])

    subs = {e.subject_value for e in await evidence_for(engagement_id, subject_type="subdomain")}
    assert "sub.example.com" in subs
    assert "evilexample.com" not in subs
