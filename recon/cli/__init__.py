"""The ``recon`` operator CLI (PRD Section 12).

A thin client over ``recon.orchestrator`` - the same services the dashboard
calls. Two transports:

* **in-process** (default): imports the orchestrator, opens its own DB session,
  no server required - ideal for a VPS or CI box;
* **REST** (``--server URL`` + ``RECON_API_TOKEN``): talks to a running
  dashboard over ``/api/v1`` with a bearer token.

No business logic lives here. When a command needs something the orchestrator
does not expose, the fix is a new orchestrator method (which the dashboard
could also call), never a CLI-only code path.
"""
