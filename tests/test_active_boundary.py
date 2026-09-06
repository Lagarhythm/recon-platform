"""Architecture test: how active modules are allowed to select network targets.

This is a *down payment* on the P0-1 revised target contract
(``PLANS/RECON_P0_P01_REVISED_TARGET_CONTRACT.md`` invariants 1 and 4). It only
pins what is structurally true today:

* ``port_scan`` was migrated in P0-2 to select targets through
  ``ctx.resolve_targets`` (the same-run materialised view) and must not read the
  correlated Asset graph directly for targets again - that would reintroduce the
  P0-2 defect.
* every other active module still selects targets through the legacy
  ``known_assets`` / ``known_values`` readers. Their migration onto
  ``resolve_targets`` and, later, the permit-only executor boundary is G2/G3 and
  is gated on Security's review - not done here.

The ledger below is exhaustive over active modules, so adding a new active
module (or migrating an existing one) fails this test until the ledger is
updated. The permit boundary for ``run_command`` / raw sockets is deliberately
NOT asserted here - ``port_scan`` legitimately shells out to nmap today; that
becomes a permit consumer in G2.
"""

from __future__ import annotations

import inspect
import sys

from recon.models.enums import ModulePhase
from recon.modules.registry import MODULES, load_builtin_modules

load_builtin_modules()

# Active modules that select network targets via the P0-2 same-run view. A
# module here MUST call ``ctx.resolve_targets`` and MUST NOT call
# ``ctx.known_assets`` / ``ctx.known_asset_rows``.
_ROUTES_THROUGH_RESOLVE_TARGETS = {"port_scan"}

# Active modules still selecting targets through the legacy Asset/Evidence
# readers. Migration onto resolve_targets + the permit boundary is G2 (gated on
# Security's P0-1 review). Listed explicitly so the set can only shrink, visibly.
_LEGACY_TARGET_READERS_PENDING_G2 = {
    "dir_fuzz",
    "dns_axfr",
    "exposure_checks",
    "subdomain_brute",
    "scan_diff",
}

# Active modules that do not select network targets at all (pure correlation).
_NON_TARGET_ACTIVE = {"cve_correlate"}

_LEGACY_READERS = ("known_assets", "known_asset_rows", "known_values")


def _active_module_names() -> set[str]:
    return {n for n, m in MODULES.items() if m.phase is ModulePhase.ACTIVE}


def _module_source(name: str) -> str:
    cls = type(MODULES[name])
    return inspect.getsource(sys.modules[cls.__module__])


def test_every_active_module_is_catalogued() -> None:
    catalogued = (
        _ROUTES_THROUGH_RESOLVE_TARGETS
        | _LEGACY_TARGET_READERS_PENDING_G2
        | _NON_TARGET_ACTIVE
    )
    assert _active_module_names() == catalogued, (
        "an active module is not catalogued in tests/test_active_boundary.py - "
        "classify it as resolve_targets-routed, legacy-reader (G2-pending), or "
        "non-target-selecting"
    )


def test_resolve_targets_modules_do_not_read_the_asset_graph_for_targets() -> None:
    for name in _ROUTES_THROUGH_RESOLVE_TARGETS:
        src = _module_source(name)
        assert "resolve_targets" in src, (
            f"{name} is listed as resolve_targets-routed but does not call "
            f"ctx.resolve_targets"
        )
        for reader in ("known_assets", "known_asset_rows"):
            assert reader not in src, (
                f"{name} routes through resolve_targets but still calls "
                f"ctx.{reader} - P0-2 regression (targets must come from the "
                f"same-run view, not the correlated Asset graph)"
            )


def test_legacy_pending_modules_still_use_a_legacy_reader() -> None:
    # Keeps the G2-pending ledger honest: once a module is migrated it must move
    # to _ROUTES_THROUGH_RESOLVE_TARGETS, not linger here.
    for name in _LEGACY_TARGET_READERS_PENDING_G2:
        src = _module_source(name)
        assert any(r in src for r in _LEGACY_READERS), (
            f"{name} no longer uses a legacy target reader - move it from "
            f"_LEGACY_TARGET_READERS_PENDING_G2 to _ROUTES_THROUGH_RESOLVE_TARGETS"
        )
