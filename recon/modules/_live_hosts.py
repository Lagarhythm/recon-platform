"""Shared 'did probe_http find this host live over HTTP' helper.

``probe_http`` (passive) emits one ``liveness`` attribute per host it checks
(``raw_data={"host": ..., "live": bool}``). Downstream modules (``crawler``,
``js_analyzer``, ``dir_fuzz``) use it to seed from the *confirmed-live* set and
skip hosts ``probe_http`` found dead, instead of each speculatively probing
every discovered name on both schemes.

**Fallback:** if ``probe_http`` did not run this scan there are no ``liveness``
rows, both helpers return an empty set, and callers keep their original
"try every discovered host" behaviour.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from recon.modules.base import ModuleContext


def _host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower().strip(".")
    except ValueError:
        return ""


async def _liveness(ctx: ModuleContext) -> dict[str, bool]:
    out: dict[str, bool] = {}
    for ev in await ctx.known_evidence("liveness"):
        raw = ev.raw_data or {}
        if raw.get("source") != "probe_http":
            continue
        host = str(raw.get("host") or ev.subject_value or "").lower().strip(".")
        if host:
            out[host] = out.get(host, False) or bool(raw.get("live"))
    return out


async def probed_hosts(ctx: ModuleContext) -> set[str]:
    """Every host ``probe_http`` assessed this scan - live *and* confirmed-dead.

    ``crawler`` / ``dir_fuzz`` use this to skip speculative scheme guesses: a
    live host is already seeded from its real ``url`` evidence, a dead one is
    dead. Empty => ``probe_http`` did not run.
    """
    return set(await _liveness(ctx))


async def live_hosts(ctx: ModuleContext) -> set[str]:
    """Hosts ``probe_http`` confirmed answer HTTP(S). ``js_analyzer`` uses this
    to drop ``.js`` URLs that point at a host that is no longer up."""
    return {h for h, live in (await _liveness(ctx)).items() if live}
