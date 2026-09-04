"""Scan diff / CTEM delta (active, PRD v2.1 Section 11.10).

The 2026 ASM/CTEM core loop: on a re-run, compute what is new, changed, or
gone vs. the last completed run's ``AssetSnapshot``. Builds a stable
signature set from what the engagement's evidence/graph already know (not a
fresh scan of its own), set-diffs it against the prior baseline, writes a
``ScanDelta`` row, and emits the deltas as ``delta`` evidence so they surface
in reports and the analyst payload same as any other finding.

Signature categories (Section 8.3):
  - ``subdomain:<host>``               - subdomain/apex existence
  - ``service:<host>:<port>[:product[/version]]`` - open port + service/version
  - ``finding:<subject_type>:<value>`` - finding identity (from the
    correlated graph - the only practical source, since new finding
    ``subject_type``s are introduced by modules this one can't enumerate)

There's no explicit "port closed" signature: a service signature that
existed in the base snapshot and is absent from the current one already
surfaces as ``removed``, which *is* the closed-port transition.

Ordering note: this reads Evidence/Asset state that already exists in the DB
at the point it runs, not a live re-scan. ``depends_on`` covers the two
always-registered active modules (``port_scan``, ``dir_fuzz``) so it runs
after them within this run; ``dns_axfr``/``subdomain_brute`` are optionally
registered (conditional import) and deliberately left out of ``depends_on``
to avoid a KeyError in the registry's phase-ranking check if either isn't
installed - their evidence, if any, is still picked up (engagement-wide, not
scoped to this run) whenever they've run in any prior scan.
"""

from __future__ import annotations

from typing import Any

from recon.models.enums import ModulePhase
from recon.modules.base import ModuleContext, ReconModule
from recon.modules.registry import register


def _service_signature(raw: dict[str, Any], host: str, port: Any) -> str:
    sig = f"service:{host}:{port}"
    product = raw.get("product")
    version = raw.get("version")
    name = raw.get("name")
    if product and version:
        return f"{sig}:{product}/{version}"
    if product:
        return f"{sig}:{product}"
    if name:
        return f"{sig}:{name}"
    return sig


def _service_key(sig: str) -> str | None:
    """The ``service:<host>:<port>`` prefix, stripped of product/version -
    the stable identity used to pair an added/removed pair into "changed"."""
    parts = sig.split(":")
    if len(parts) >= 3 and parts[0] == "service":
        return ":".join(parts[:3])
    return None


def _pair_changes(
    added: list[str], removed: list[str]
) -> tuple[list[dict[str, str]], set[str], set[str]]:
    """Pull matching (same host:port, different product/version) add+remove
    pairs out as "changed" entries. Only services have a natural was/now pair
    - subdomain existence and finding identity are pure presence/absence."""
    added_by_key: dict[str, list[str]] = {}
    for s in added:
        key = _service_key(s)
        if key:
            added_by_key.setdefault(key, []).append(s)
    removed_by_key: dict[str, list[str]] = {}
    for s in removed:
        key = _service_key(s)
        if key:
            removed_by_key.setdefault(key, []).append(s)

    changed: list[dict[str, str]] = []
    consumed_added: set[str] = set()
    consumed_removed: set[str] = set()
    for key in added_by_key.keys() & removed_by_key.keys():
        # Only pair an unambiguous 1:1 change on the same host:port - two
        # simultaneous adds/removes for one port shouldn't happen (one
        # service row per host:port), so don't guess if it does.
        if len(added_by_key[key]) == 1 and len(removed_by_key[key]) == 1:
            now, was = added_by_key[key][0], removed_by_key[key][0]
            changed.append({"signature": key, "was": was, "now": now})
            consumed_added.add(now)
            consumed_removed.add(was)
    return changed, consumed_added, consumed_removed


@register
class ScanDiffModule(ReconModule):
    name = "scan_diff"
    phase = ModulePhase.ACTIVE
    depends_on = ("port_scan", "dir_fuzz")
    description = "CTEM delta: diff the current graph against the last completed run's baseline"
    max_runtime_seconds = 10 * 60

    async def run(self, ctx: ModuleContext) -> None:
        signature_set, summary, finding_interest = await self._build_signature_set(ctx)

        base = await ctx.latest_asset_snapshot()
        if base is None:
            await ctx.write_asset_snapshot(signature_set=signature_set, summary=summary)
            await ctx.progress(
                "scan_diff: first completed run for this engagement - "
                "baseline written, nothing to diff yet"
            )
            return

        old = set(base.signature_set or [])
        cur = set(signature_set)
        added = sorted(cur - old)
        removed = sorted(old - cur)
        changed, consumed_added, consumed_removed = _pair_changes(added, removed)
        added = [s for s in added if s not in consumed_added]
        removed = [s for s in removed if s not in consumed_removed]

        await ctx.write_scan_delta(
            base_snapshot_id=base.id, added=added, removed=removed, changed=changed
        )
        await ctx.write_asset_snapshot(signature_set=signature_set, summary=summary)

        for sig in added:
            await self._emit(ctx, "added", sig, interest=finding_interest.get(sig))
        for sig in removed:
            await self._emit(ctx, "removed", sig, interest=finding_interest.get(sig))
        for c in changed:
            await self._emit(
                ctx, "changed", c["signature"],
                was=c["was"], now=c["now"], interest=finding_interest.get(c["now"]),
            )

        await ctx.progress(
            f"scan_diff: {len(added)} added, {len(removed)} removed, "
            f"{len(changed)} changed vs snapshot {base.id}"
        )

    async def _emit(
        self,
        ctx: ModuleContext,
        kind: str,
        signature: str,
        *,
        interest: str | None = None,
        was: str | None = None,
        now: str | None = None,
    ) -> None:
        raw: dict[str, Any] = {"delta": kind}
        if was is not None:
            raw["was"] = was
        if now is not None:
            raw["now"] = now
        if interest:
            raw["interest"] = interest
        await ctx.add_evidence(
            subject_type="delta",
            subject_value=signature,
            raw_data=raw,
            summary=f"{kind}: {signature}" + (f" (was {was})" if was else ""),
        )

    async def _build_signature_set(
        self, ctx: ModuleContext
    ) -> tuple[list[str], dict[str, int], dict[str, str]]:
        sigs: set[str] = set()
        counts: dict[str, int] = {}

        hosts = ctx.scoped_targets(await ctx.known_values("subdomain", "domain"))
        for h in hosts:
            sigs.add(f"subdomain:{h}")
        counts["subdomain"] = len(hosts)

        service_evs = await ctx.known_evidence("service")
        n_services = 0
        for ev in service_evs:
            raw = ev.raw_data or {}
            host = raw.get("host") or ev.subject_value.rsplit(":", 1)[0]
            if ctx.scope.classify(host).status.value == "excluded":
                continue
            port = raw.get("port")
            sigs.add(_service_signature(raw, host, port))
            n_services += 1
        counts["service"] = n_services

        finding_interest: dict[str, str] = {}
        finding_assets = await ctx.known_asset_rows("finding")
        for a in finding_assets:
            sig = f"finding:{a.value}"
            sigs.add(sig)
            finding_interest[sig] = a.interest_level.value
        counts["finding"] = len(finding_assets)

        return sorted(sigs), counts, finding_interest
