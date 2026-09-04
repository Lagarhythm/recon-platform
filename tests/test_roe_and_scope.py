"""Unit tests for RoE parsing and the Scope Manager."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from recon.core.roe import RoEError, load_roe
from recon.core.scope import ScopeManager, extract_host
from recon.models.enums import ScopeStatus, WindowStatus
from tests.conftest import EXAMPLE_ROE


def _mgr(roe_yaml: str = EXAMPLE_ROE) -> ScopeManager:
    config, _ = load_roe(roe_yaml)
    return ScopeManager(config)


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("https://api.example.com:8443/admin", "api.example.com"),
        ("api.example.com:8080", "api.example.com"),
        ("API.Example.com", "api.example.com"),
        ("http://user:pass@host.example.com/x", "host.example.com"),
        ("[2001:db8::1]:443", "2001:db8::1"),
        ("203.0.113.5", "203.0.113.5"),
    ],
)
def test_extract_host(raw, expected):
    assert extract_host(raw) == expected


def test_scope_in_scope_apex_and_wildcard():
    m = _mgr()
    assert m.classify("example.com").status is ScopeStatus.IN_SCOPE
    assert m.classify("api.example.com").status is ScopeStatus.IN_SCOPE
    assert m.classify("deep.nested.example.com").status is ScopeStatus.IN_SCOPE


def test_scope_excluded_wins_over_in_scope():
    m = _mgr()
    # mail.example.com matches *.example.com but is explicitly excluded
    assert m.classify("mail.example.com").status is ScopeStatus.EXCLUDED


def test_scope_cidr_membership():
    m = _mgr()
    assert m.classify("203.0.113.10").status is ScopeStatus.IN_SCOPE
    assert m.classify("203.0.113.130").status is ScopeStatus.EXCLUDED  # excluded /28
    assert m.classify("198.51.100.1").status is ScopeStatus.FLAGGED


def test_scope_suffix_confusion_is_flagged():
    m = _mgr()
    assert m.classify("evilexample.com").status is ScopeStatus.FLAGGED
    assert m.classify("example.com.attacker.net").status is ScopeStatus.FLAGGED


def test_scope_resolved_ips_considered():
    m = _mgr()
    d = m.classify("unknown-host.tld", resolved_ips=["203.0.113.130"])
    assert d.status is ScopeStatus.EXCLUDED


def test_window_status():
    m = _mgr()
    assert m.check_window(datetime(2027, 1, 1, tzinfo=timezone.utc)) is WindowStatus.WITHIN
    assert m.check_window(datetime(2020, 1, 1, tzinfo=timezone.utc)) is WindowStatus.BEFORE
    assert m.check_window(datetime(2031, 1, 1, tzinfo=timezone.utc)) is WindowStatus.AFTER


def test_roe_rejects_bad_cidr():
    bad = EXAMPLE_ROE.replace("203.0.113.0/24", "203.0.113.0/33")
    with pytest.raises(RoEError):
        load_roe(bad)


def test_roe_rejects_empty_in_scope():
    bad = """
engagement: {name: x, client: y}
scope:
  in_scope: {domains: [], cidrs: [], hosts: []}
  excluded: {}
"""
    with pytest.raises(RoEError):
        load_roe(bad)


def test_roe_rejects_no_scope_and_no_osint():
    with pytest.raises(RoEError):
        load_roe("engagement: {name: x, client: y}")


def test_osint_only_roe_is_valid_without_scope():
    cfg, _ = load_roe(
        "engagement: {name: x, client: y}\n"
        "osint: {enabled: true, company: 'Acme Co', seed_domains: ['acme.com']}\n"
    )
    assert cfg.osint.enabled and cfg.osint.company == "Acme Co"
    assert cfg.scope.is_empty


def test_osint_enabled_needs_a_pivot():
    with pytest.raises(RoEError):
        load_roe(
            "engagement: {name: x, client: y}\n"
            "scope: {in_scope: {domains: ['acme.com']}}\n"
            "osint: {enabled: true}\n"
        )


def test_osint_seed_domains_not_in_scope_is_advised():
    from recon.core.scope import lint_roe
    cfg, _ = load_roe(
        "engagement: {name: x, client: y}\n"
        "osint: {enabled: true, seed_domains: ['acme.com']}\n"
    )
    assert any("pivot points only" in w for w in lint_roe(cfg))


def test_roe_rejects_inverted_window():
    bad = EXAMPLE_ROE.replace(
        '"2030-01-01T00:00:00Z"', '"2025-01-01T00:00:00Z"'
    )
    with pytest.raises(RoEError):
        load_roe(bad)


def test_roe_canonical_hash_is_format_insensitive():
    _, h1 = load_roe(EXAMPLE_ROE)
    reformatted = "# header comment\n" + EXAMPLE_ROE + "\n\n# trailing comment\n"
    _, h2 = load_roe(reformatted)
    assert h1 == h2
