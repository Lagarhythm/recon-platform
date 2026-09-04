"""Certificate Transparency subdomain enumeration (passive).

Queries the public crt.sh Certificate Transparency log aggregator for every
in-scope apex domain and turns the ``name_value`` fields of the returned cert
entries into ``subdomain`` evidence. This is a third-party OSINT source - no
traffic touches the target.

# TODO(phase3): wordlist brute-force belongs in an active module
"""

from __future__ import annotations

import json

from recon.models.enums import ModulePhase
from recon.modules.base import ModuleContext, ReconModule
from recon.modules.registry import register
from recon.net.http_client import ReconRequestError

_CRTSH_URL = "https://crt.sh/?q=%25.{domain}&output=json"


def _apex_domains(patterns: list[str]) -> set[str]:
    out: set[str] = set()
    for p in patterns:
        p = p.strip().lower().strip(".")
        if p.startswith("*."):
            p = p[2:]
        if p:
            out.add(p)
    return out


def _normalise(name: str) -> str:
    name = name.strip().lower().strip()
    if name.startswith("*."):
        name = name[2:]
    return name.strip().strip(".").strip()


def _iter_names(name_value: str):
    for chunk in (name_value or "").split("\n"):
        norm = _normalise(chunk)
        if norm:
            yield norm


@register
class CTSubdomainsModule(ReconModule):
    name = "ct_subdomains"
    phase = ModulePhase.PASSIVE
    depends_on = ()
    description = "Enumerate subdomains from crt.sh Certificate Transparency logs"

    async def run(self, ctx: ModuleContext) -> None:
        apexes: set[str] = _apex_domains(ctx.roe.scope.in_scope.domains)
        for v in await ctx.known_values("domain"):
            apexes.add(_normalise(v))
        apexes.discard("")

        if not apexes:
            await ctx.progress("no in-scope apex domains for CT lookup")
            return

        total = len(apexes)
        await ctx.progress(
            f"querying crt.sh for {total} apex domain(s)", current=0, total=total
        )

        # discovered name -> {"cert_ids": set[str], "parents": set[str]}
        discovered: dict[str, dict] = {}

        for done, apex in enumerate(sorted(apexes), start=1):
            ctx.check_alive()
            entries = await self._fetch(ctx, apex)
            if entries is None:
                continue
            for entry in entries:
                ctx.check_alive()
                if not isinstance(entry, dict):
                    continue
                cert_id = entry.get("id")
                for name in _iter_names(str(entry.get("name_value", ""))):
                    rec = discovered.setdefault(
                        name, {"cert_ids": set(), "parents": set()}
                    )
                    if cert_id is not None:
                        rec["cert_ids"].add(str(cert_id))
                    rec["parents"].add(apex)
            await ctx.progress(
                f"crt.sh: {apex} -> {len(discovered)} name(s) so far",
                current=done, total=total,
            )

        await ctx.progress(
            f"emitting {len(discovered)} discovered name(s)", count=len(discovered)
        )

        for name in sorted(discovered):
            ctx.check_alive()
            rec = discovered[name]
            cert_ids = sorted(rec["cert_ids"])
            parent = self._match_apex(name, apexes)
            if parent is not None:
                # the apex itself shows up in its own CT logs - it's a domain,
                # not a subdomain of itself
                await ctx.add_evidence(
                    subject_type="domain" if name == parent else "subdomain",
                    subject_value=name,
                    raw_data={
                        "parent": parent,
                        "source": "crt.sh",
                        "cert_ids": cert_ids,
                    },
                    summary=f"{name} seen in CT logs",
                )
            else:
                await ctx.add_evidence(
                    subject_type="subdomain",
                    subject_value=name,
                    raw_data={
                        "source": "crt.sh",
                        "note": "outside in-scope apex",
                        "cert_ids": cert_ids,
                    },
                    summary=f"{name} seen in CT logs",
                )

    @staticmethod
    def _match_apex(name: str, apexes: set[str]) -> str | None:
        for apex in apexes:
            if name == apex or name.endswith("." + apex):
                return apex
        return None

    async def _fetch(self, ctx: ModuleContext, apex: str) -> list | None:
        url = _CRTSH_URL.format(domain=apex)
        try:
            # crt.sh is frequently slow; give it far longer than the default.
            resp = await ctx.http.request(
                "GET", url, is_target=False, timeout=90.0
            )
        except ReconRequestError as exc:
            await ctx.add_error(
                subject_value=apex,
                summary=f"crt.sh request failed: {type(exc).__name__}",
                raw_data={"source": "crt.sh", "url": url, "error": str(exc)},
            )
            return None
        except Exception as exc:  # noqa: BLE001 - timeouts / transport errors
            await ctx.add_error(
                subject_value=apex,
                summary=f"crt.sh request error: {type(exc).__name__}",
                raw_data={"source": "crt.sh", "url": url, "error": str(exc)},
            )
            return None

        if resp.status_code != 200:
            await ctx.add_error(
                subject_value=apex,
                summary=f"crt.sh returned HTTP {resp.status_code} for {apex}",
                raw_data={"source": "crt.sh", "url": url, "status": resp.status_code},
            )
            return None

        try:
            data = resp.json()
        except (json.JSONDecodeError, ValueError):
            try:
                data = json.loads(resp.text)
            except (json.JSONDecodeError, ValueError):
                await ctx.add_error(
                    subject_value=apex,
                    summary=f"crt.sh returned invalid JSON for {apex}",
                    raw_data={"source": "crt.sh", "url": url},
                )
                return None

        if not isinstance(data, list):
            await ctx.add_error(
                subject_value=apex,
                summary=f"crt.sh returned unexpected JSON shape for {apex}",
                raw_data={"source": "crt.sh", "url": url},
            )
            return None
        return data
