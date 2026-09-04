"""Orchestrator - the engine's internal API.

Everything the dashboard can do, it does by calling into this package. No
business logic lives in the web layer. A future CLI (Roadmap, Section 11) is
just another client of these same services - it must not require engine
changes.
"""

from recon.orchestrator.auth import AuthService
from recon.orchestrator.engagements import EngagementService
from recon.orchestrator.killswitch import KillSwitch, kill_switch

__all__ = ["AuthService", "EngagementService", "KillSwitch", "kill_switch"]
