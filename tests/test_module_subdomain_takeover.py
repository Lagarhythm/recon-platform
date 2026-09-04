"""subdomain_takeover - resolver + HTTP mocked, no real network/DNS."""

from __future__ import annotations

import httpx
import pytest

from recon.modules.passive import subdomain_takeover
from recon.modules.passive.subdomain_takeover import (
    SubdomainTakeoverModule,
    _load_providers,
    _match_provider,
)
from recon.core.roe import TakeoverEngine
from recon.modules.registry import MODULES, load_builtin_modules, resolve_order
from tests.harness import FakeHTTP, evidence_for, module_harness


class _Rdata:
    def __init__(self, t): self._t = t
    def to_text(self): return self._t


class _RRset(list):
    ttl = 60


class _Answer:
    def __init__(self, recs): self.rrset = _RRset(_Rdata(r) for r in recs) if recs else None


class _FakeResolver:
    lifetime = timeout = 0.0

    def __init__(self, table: dict[tuple[str, str], list[str]]):
        self._table = table
        self.queried: list[str] = []

    async def resolve(self, name, rtype, raise_on_no_answer=False):
        self.queried.append(str(name).rstrip("."))
        return _Answer(self._table.get((str(name).rstrip("."), rtype), []))


def _sub(v):
    return {"subject_type": "subdomain", "subject_value": v, "raw_data": {}}


async def _run(engagement_id, table, prior, http_routes=None, *, engine="native"):
    http = FakeHTTP(http_routes or {}, default_status=404)
    fake_resolver = _FakeResolver(table)
    async with module_harness(engagement_id, "subdomain_takeover", http=http,
                              prior_evidence=prior) as ctx:
        ctx.roe.recon.takeover.engine = TakeoverEngine(engine)
        with __import__("unittest.mock", fromlist=["mock"]).patch(
            "dns.asyncresolver.Resolver", lambda *a, **k: fake_resolver
        ):
            await SubdomainTakeoverModule().run(ctx)
    return http, fake_resolver


# --------------------------------------------------------------------------
def test_resolves_in_passive_phase():
    load_builtin_modules()
    order = [m.name for m in resolve_order(["subdomain_takeover"])]
    assert order[-1] == "subdomain_takeover"
    assert order.index("dns") < order.index("subdomain_takeover")
    assert order.index("passive_subdomains") < order.index("subdomain_takeover")
    assert MODULES["subdomain_takeover"].phase.value == "passive"


def test_fingerprint_set_loads_and_matches():
    providers = _load_providers()
    assert len(providers) >= 20
    names = {p["provider"] for p in providers}
    assert len(names) == len(providers)  # unique provider names
    assert _match_provider("foo.github.io", providers)["provider"] == "GitHub Pages"
    assert _match_provider("random.example.com", providers) is None


@pytest.mark.asyncio
async def test_dangling_cname_to_unclaimed_target_is_high_value_takeover(engagement_id):
    table = {
        ("orphan.example.com", "CNAME"): ["orphan.github.io"],
        # orphan.github.io has no A/AAAA -> dangling, regardless of fingerprints
    }
    await _run(engagement_id, table, [_sub("orphan.example.com")])
    findings = await evidence_for(engagement_id, subject_type="takeover")
    assert len(findings) == 1
    f = findings[0]
    assert f.subject_value == "orphan.example.com"
    assert f.raw_data["provider"] == "GitHub Pages"
    assert f.raw_data["interest"] == "high_value"
    assert f.raw_data["relationships"][0] == {
        "type": "takeover_candidate", "target_type": "organization",
        "target_value": "GitHub Pages",
    }


@pytest.mark.asyncio
async def test_nxdomain_provider_with_resolving_target_is_not_flagged(engagement_id):
    # Azure Cloud Services expects the target itself to be gone when unclaimed;
    # here it still resolves, so this is NOT a candidate.
    table = {
        ("app.example.com", "CNAME"): ["app.cloudapp.net"],
        ("app.cloudapp.net", "A"): ["203.0.113.5"],
    }
    await _run(engagement_id, table, [_sub("app.example.com")])
    assert await evidence_for(engagement_id, subject_type="takeover") == []


@pytest.mark.asyncio
async def test_body_fingerprint_match_on_a_resolving_target(engagement_id):
    table = {
        ("blog.example.com", "CNAME"): ["blog.ghost.io"],
        ("blog.ghost.io", "A"): ["203.0.113.9"],  # resolves - need the body match
    }
    routes = {
        "blog.example.com": httpx.Response(
            200, text="Oops. The thing you were looking for is no longer here."
        ),
    }
    await _run(engagement_id, table, [_sub("blog.example.com")], routes)
    findings = await evidence_for(engagement_id, subject_type="takeover")
    assert len(findings) == 1 and findings[0].raw_data["provider"] == "Ghost(Pro)"


@pytest.mark.asyncio
async def test_resolving_target_with_no_fingerprint_match_is_not_flagged(engagement_id):
    table = {
        ("www.example.com", "CNAME"): ["www.ghost.io"],
        ("www.ghost.io", "A"): ["203.0.113.9"],
    }
    routes = {"www.example.com": httpx.Response(200, text="<html>Welcome to our real blog!</html>")}
    await _run(engagement_id, table, [_sub("www.example.com")], routes)
    assert await evidence_for(engagement_id, subject_type="takeover") == []


@pytest.mark.asyncio
async def test_no_cname_is_skipped_silently(engagement_id):
    await _run(engagement_id, {}, [_sub("plain.example.com")])
    assert await evidence_for(engagement_id, subject_type="takeover") == []
    assert [e for e in await evidence_for(engagement_id) if e.is_error] == []


@pytest.mark.asyncio
async def test_cname_to_non_provider_is_ignored(engagement_id):
    table = {("api.example.com", "CNAME"): ["api.some-other-vendor.net"]}
    await _run(engagement_id, table, [_sub("api.example.com")])
    assert await evidence_for(engagement_id, subject_type="takeover") == []


@pytest.mark.asyncio
async def test_excluded_host_is_never_checked(engagement_id):
    # mail.example.com is EXAMPLE_ROE's excluded host
    table = {("mail.example.com", "CNAME"): ["mail.github.io"]}
    _, resolver = await _run(engagement_id, table, [_sub("mail.example.com")])
    assert resolver.queried == []            # scoped_targets dropped it before any query
    assert await evidence_for(engagement_id, subject_type="takeover") == []


@pytest.mark.asyncio
async def test_non_native_engine_still_runs_native_check(engagement_id):
    table = {("orphan.example.com", "CNAME"): ["orphan.github.io"]}
    await _run(engagement_id, table, [_sub("orphan.example.com")], engine="nuclei")
    assert len(await evidence_for(engagement_id, subject_type="takeover")) == 1


@pytest.mark.asyncio
async def test_missing_fingerprint_file_is_a_clean_error(engagement_id, monkeypatch):
    monkeypatch.setattr(subdomain_takeover, "_load_providers", lambda: [])
    await _run(engagement_id, {}, [_sub("orphan.example.com")])
    errs = [e for e in await evidence_for(engagement_id) if e.is_error]
    assert errs and "fingerprint" in errs[0].summary
