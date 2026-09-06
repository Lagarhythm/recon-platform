"""Port / Service Scanner (active).

**Out of scope for the P0-1 G2 active surface.**

A port scan is a subprocess ``nmap`` sweep. Authorising one from the D0
``dns_connect_bind_v1`` liveness profile let a single TCP/443 connect
acknowledgement turn into up to 1,000 service probes the operator never
acknowledged (Security G2 re-review, S2). Port scanning returns in its own
separately-checkpointed, separately-approved method profile (Task 0P) with its
own permit resolver.

Until then this module is registered only so a run that reaches the active phase
records an explicit ``SKIPPED / unverified_targets`` for it rather than a silent
gap. It never resolves a target, mints a permit, or execs a binary.
"""

from __future__ import annotations

from recon.models.enums import ModulePhase, SkipReason
from recon.modules._targets import is_safe_target as _is_safe_target
from recon.modules.base import ModuleContext, ReconModule
from recon.modules.registry import register

# ``_is_safe_target`` stays importable from this module for the adversarial
# regression suite; the shared safe-form helper lives in ``recon.modules._targets``.
__all__ = ["PortScanModule", "_is_safe_target"]


@register
class PortScanModule(ReconModule):
    name = "port_scan"
    phase = ModulePhase.ACTIVE
    depends_on = ("dns",)
    description = "nmap: TCP port + service/version detection (deferred: not in the G2 active surface)"
    requires_binary = "nmap"

    async def run(self, ctx: ModuleContext) -> None:
        await ctx.progress(
            "port scanning is not part of the active-scan surface for this "
            "release; it returns in its own separately-approved method profile"
        )
        await ctx.mark_no_input(SkipReason.UNVERIFIED_TARGETS)
