"""Certificate Transparency, organisation-first (OSINT).

Two passes over the public crt.sh log aggregator:

  * per seed / in-scope domain - the same subdomain enumeration ``ct_subdomains``
    does, plus the certificate Subject ``O=`` organisation;
  * per company name - certs whose Subject ``O=`` matches the company, which
    surfaces *other* domains the organisation owns.

No traffic touches the target.
"""

from __future__ import annotations

from recon.models.enums import ModulePhase
from recon.modules.base import ModuleContext, ReconModule
from recon.modules.osint._common import base_domain, cert_orgs, crtsh_json, org_targets
from recon.modules.registry import register


def _iter_names(name_value: str):
    for chunk in (name_value or "").split("\n"):
        n = chunk.strip().lower().strip(".")
        if n.startswith("*."):
            n = n[2:]
        if n and " " not in n:
            yield n


@register
class CTOrgModule(ReconModule):
    name = "ct_org"
    phase = ModulePhase.OSINT
    depends_on = ()
    description = "crt.sh by domain AND by organisation name - domains + owner org"
    max_runtime_seconds = 12 * 60

    async def run(self, ctx: ModuleContext) -> None:
        company, domains = org_targets(ctx)
        if not company and not domains:
            await ctx.progress("ct_org: no company name or seed domains in the RoE")
            return

        seen_names: set[str] = set()
        seen_orgs: set[str] = set()

        # --- pass 1: per domain -------------------------------------------
        for i, domain in enumerate(sorted(domains), start=1):
            ctx.check_alive()
            await ctx.progress(
                f"crt.sh: {domain}", current=i - 1, total=len(domains) + (1 if company else 0)
            )
            entries = await crtsh_json(ctx, f"%.{domain}")
            for entry in entries or []:
                if not isinstance(entry, dict):
                    continue
                for org in cert_orgs(entry):
                    await self._emit_org(ctx, org, seen_orgs, via=domain, source="crt.sh cert")
                for name in _iter_names(str(entry.get("name_value", ""))):
                    if name in seen_names or not name.endswith(domain):
                        continue
                    seen_names.add(name)
                    stype = "subdomain" if name != domain and name.count(".") >= 2 else "domain"
                    await ctx.add_evidence(
                        subject_type=stype,
                        subject_value=name,
                        raw_data={"source": "crt.sh", "pivot": domain},
                        summary=f"{name} in CT logs for {domain}",
                    )

        # --- pass 2: per company name ----------------------------------
        if company:
            ctx.check_alive()
            await ctx.progress(
                f"crt.sh org search: {company!r}",
                current=len(domains), total=len(domains) + 1,
            )
            entries = await crtsh_json(ctx, company)
            hit_domains: dict[str, set[str]] = {}
            for entry in entries or []:
                if not isinstance(entry, dict):
                    continue
                orgs = [o for o in cert_orgs(entry)
                        if company.lower() in o.lower() or o.lower() in company.lower()]
                if not orgs:
                    continue
                for org in orgs:
                    await self._emit_org(ctx, org, seen_orgs, via=company,
                                         source="crt.sh org search")
                for name in _iter_names(str(entry.get("name_value", ""))):
                    hit_domains.setdefault(base_domain(name), set()).update(orgs)

            for dom, orgs in sorted(hit_domains.items()):
                if not dom or dom in domains:
                    continue
                await ctx.add_evidence(
                    subject_type="domain",
                    subject_value=dom,
                    raw_data={"source": "crt.sh org search", "matched_orgs": sorted(orgs),
                              "interest": "notable"},
                    summary=f"{dom} - cert issued to org matching {company!r}",
                    relationships=[{"type": "owns", "target_type": "organization",
                                    "target_value": next(iter(orgs))}],
                )

        await ctx.progress(
            f"ct_org done: {len(seen_names)} name(s), {len(seen_orgs)} org(s)"
        )

    async def _emit_org(
        self, ctx: ModuleContext, org: str, seen: set[str], *, via: str, source: str
    ) -> None:
        key = org.strip().lower()
        if not key or key in seen:
            return
        seen.add(key)
        await ctx.add_evidence(
            subject_type="organization",
            subject_value=org.strip(),
            raw_data={"source": source, "seen_via": via},
            summary=f"organisation {org!r} (from {source})",
        )
