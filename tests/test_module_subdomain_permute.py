"""subdomain_permute - resolver mocked, no real DNS."""

from __future__ import annotations

import pytest

from recon.modules.passive import subdomain_permute
from recon.modules.passive.subdomain_permute import SubdomainPermuteModule, permutations
from recon.modules.registry import MODULES, load_builtin_modules, resolve_order
from tests.harness import evidence_for, module_harness


class _Rdata:
    def __init__(self, t): self._t = t
    def to_text(self): return self._t


class _RRset(list):
    ttl = 60


class _Answer:
    def __init__(self, recs): self.rrset = _RRset(_Rdata(r) for r in recs) if recs else None


class _FakeResolver:
    lifetime = timeout = 0.0

    def __init__(self, table=None, default=None):
        self._table = table or {}
        self._default = default

    async def resolve(self, name, rtype, raise_on_no_answer=False):
        key = (str(name).rstrip("."), rtype)
        if key in self._table:
            return _Answer(self._table[key])
        if self._default is not None and rtype == "A":
            return _Answer(self._default)
        return _Answer(None)   # no records - not an error


def _sub(v):
    return {"subject_type": "subdomain", "subject_value": v, "raw_data": {}}


@pytest.fixture(autouse=True)
def _small_wordlist(monkeypatch):
    """Keep the candidate count tiny - the real per-run RateLimiter throttles
    every lookup to 10/s, so the full ~90-word list would run for minutes."""
    monkeypatch.setattr(subdomain_permute, "_WORDS", ("dev", "staging", "api"))


# --------------------------------------------------------------------------
def test_permutations_shapes():
    p = permutations("api.example.com", "example.com", ("dev", "staging"))
    assert "dev.api.example.com" in p
    assert "api-dev.example.com" in p
    assert "dev-api.example.com" in p
    assert "api1.example.com" in p          # number-bump on a digit-less label
    assert "api.example.com" not in p       # never yields the input


def test_permutations_number_bump():
    p = permutations("api2.example.com", "example.com", ("x",))
    assert "api1.example.com" in p and "api3.example.com" in p


def test_resolves_in_passive_phase_after_passive_subdomains():
    load_builtin_modules()
    order = [m.name for m in resolve_order(["subdomain_permute"])]
    assert order[-1] == "subdomain_permute"
    assert order.index("passive_subdomains") < order.index("subdomain_permute")
    assert MODULES["subdomain_permute"].phase.value == "passive"


@pytest.mark.asyncio
async def test_resolving_permutation_emits_subdomain_and_alias_edge(engagement_id, monkeypatch):
    table = {("dev.api.example.com", "A"): ["203.0.113.7"]}
    monkeypatch.setattr("dns.asyncresolver.Resolver", lambda *a, **k: _FakeResolver(table))

    async with module_harness(engagement_id, "subdomain_permute",
                              prior_evidence=[_sub("api.example.com")]) as ctx:
        await SubdomainPermuteModule().run(ctx)

    subs = [e for e in await evidence_for(engagement_id, subject_type="subdomain")
            if e.raw_data.get("method") == "permutation"]
    assert any(e.subject_value == "dev.api.example.com" for e in subs)
    hit = next(e for e in subs if e.subject_value == "dev.api.example.com")
    assert hit.raw_data["base"] == "api.example.com"
    assert hit.raw_data["relationships"][0] == {
        "type": "alias_of", "target_type": "subdomain", "target_value": "api.example.com",
    }
    # a dns_record row too
    assert any(e.subject_value == "dev.api.example.com"
               for e in await evidence_for(engagement_id, subject_type="dns_record"))


@pytest.mark.asyncio
async def test_wildcard_only_hits_are_filtered(engagement_id, monkeypatch):
    # every name resolves to the same address -> wildcard zone
    monkeypatch.setattr("dns.asyncresolver.Resolver",
                        lambda *a, **k: _FakeResolver(default=["203.0.113.99"]))
    async with module_harness(engagement_id, "subdomain_permute",
                              prior_evidence=[_sub("api.example.com")]) as ctx:
        await SubdomainPermuteModule().run(ctx)

    perms = [e for e in await evidence_for(engagement_id, subject_type="subdomain")
             if e.raw_data.get("method") == "permutation"]
    assert perms == []          # all collide with the wildcard target -> dropped


@pytest.mark.asyncio
async def test_no_bases_no_work(engagement_id, monkeypatch):
    monkeypatch.setattr("dns.asyncresolver.Resolver", lambda *a, **k: _FakeResolver())
    async with module_harness(engagement_id, "subdomain_permute") as ctx:
        await SubdomainPermuteModule().run(ctx)  # only the apex is known
    assert await evidence_for(engagement_id, subject_type="subdomain") == []


@pytest.mark.asyncio
async def test_max_candidates_cap_is_honored(engagement_id, monkeypatch):
    monkeypatch.setattr("dns.asyncresolver.Resolver", lambda *a, **k: _FakeResolver())
    resolved: list[str] = []

    async def _spy(resolver, fqdn, limiter=None, record_types=None):
        resolved.append(fqdn)
        return []

    monkeypatch.setattr(subdomain_permute, "resolve_records", _spy)
    async with module_harness(engagement_id, "subdomain_permute",
                              prior_evidence=[_sub("api.example.com")]) as ctx:
        ctx.roe.recon.permutation.max_candidates = 5
        await SubdomainPermuteModule().run(ctx)

    # wildcard probes have a 12-hex first label; the rest are the real candidates
    def _is_probe(fqdn: str) -> bool:
        head = fqdn.split(".", 1)[0]
        return len(head) == 12 and all(c in "0123456789abcdef" for c in head)

    candidates = [c for c in resolved if not _is_probe(c)]
    assert 0 < len(candidates) <= 5
