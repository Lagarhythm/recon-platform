"""Email security posture (passive, PRD v2.1 §11.6).

SPF / DMARC / DKIM / MTA-STS / TLS-RPT per in-scope apex domain. Cheap,
high-signal, purely passive - everything here is a TXT lookup or a policy file
GET a normal client could make. DNSSEC absence is already emitted by ``dns``;
this module covers the rest of the email-auth posture.

Positive, healthy posture is recorded as an attribute on the domain asset (no
finding noise for a domain doing everything right). A missing control is
``add_negative`` - which lights up the already-wired ``_NEGATIVE_INTEREST``
entries in ``correlation/engine.py`` (``spf``/``dmarc`` -> ``NOTABLE``,
``mta_sts``/``tls_rpt`` -> ``INFORMATIONAL``). A *present but weak* policy
(``+all``, ``p=none``, too many SPF lookups, no aggregate reports) is its own
finding, distinct from plain absence.
"""

from __future__ import annotations

import re

import dns.asyncresolver
import dns.exception
import dns.resolver

from recon.models.enums import ModulePhase
from recon.modules.base import ModuleContext, ReconModule
from recon.modules.registry import register

# RFC 7208 S4.6.4: SPF hard-fails a lookup past 10 of these mechanisms. This is
# a top-level count only - a nested `include:` can hide further lookups this
# native check does not recursively resolve, so it can undercount; still a
# useful red flag when the top-level record alone already exceeds it.
_SPF_LOOKUP_MECHS = ("include", "a", "mx", "ptr", "exists", "redirect")
_DKIM_SELECTORS = (
    "google", "default", "k1", "selector1", "selector2", "s1", "s2", "dkim", "mail",
)
_DMARC_TAG_RE = re.compile(r"\b([a-z]+)\s*=\s*([^;]+)", re.IGNORECASE)


def _base_domains(patterns: list[str]) -> list[str]:
    out: set[str] = set()
    for p in patterns:
        out.add(p[2:] if p.startswith("*.") else p)
    return sorted(out)


async def _txt_strings(resolver, name: str) -> list[str]:
    """Every TXT record on ``name``, each multi-string segment concatenated
    (SPF/DMARC records are routinely split across 255-byte chunks)."""
    try:
        answer = await resolver.resolve(name, "TXT", raise_on_no_answer=False)
    except dns.exception.DNSException:
        return []
    if not answer.rrset:
        return []
    out = []
    for rdata in answer.rrset:
        strings = getattr(rdata, "strings", None)
        out.append(b"".join(strings).decode("utf-8", errors="replace") if strings
                   else rdata.to_text().strip('"'))
    return out


def _parse_spf(record: str) -> dict:
    tokens = record.split()[1:]  # drop "v=spf1"
    lookups = sum(1 for t in tokens if t.lstrip("+-~?").split(":", 1)[0].split("/", 1)[0]
                 in _SPF_LOOKUP_MECHS)
    all_qual = None
    for t in tokens:
        if t.lstrip("+-~?") == "all":
            all_qual = t[0] if t[0] in "+-~?" else "+"
            break
    return {"record": record, "lookup_mechanisms": lookups, "all_qualifier": all_qual}


def _parse_dmarc(record: str) -> dict:
    tags = {m.group(1).lower(): m.group(2).strip() for m in _DMARC_TAG_RE.finditer(record)}
    return {
        "record": record,
        "policy": tags.get("p"),
        "subdomain_policy": tags.get("sp"),
        "pct": int(tags["pct"]) if tags.get("pct", "").isdigit() else 100,
        "rua": bool(tags.get("rua")),
        "ruf": bool(tags.get("ruf")),
    }


@register
class EmailSecurityModule(ReconModule):
    name = "email_security"
    phase = ModulePhase.PASSIVE
    depends_on = ("dns",)
    description = "SPF/DMARC/DKIM/MTA-STS/TLS-RPT posture per in-scope apex domain"
    max_runtime_seconds = 10 * 60

    async def run(self, ctx: ModuleContext) -> None:
        apexes = _base_domains(ctx.roe.scope.in_scope.domains)
        if not apexes:
            await ctx.progress("email_security: no in-scope apex domains")
            return

        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = 6.0
        resolver.timeout = 3.0

        await ctx.progress(f"email_security: {len(apexes)} domain(s)", count=len(apexes))
        for i, domain in enumerate(apexes, start=1):
            ctx.check_alive()
            await ctx.progress(f"email_security: {domain}", current=i, total=len(apexes))
            await self._spf(ctx, resolver, domain)
            await self._dmarc(ctx, resolver, domain)
            await self._dkim(ctx, resolver, domain)
            await self._mta_sts(ctx, resolver, domain)
            await self._tls_rpt(ctx, resolver, domain)

    # --- SPF --------------------------------------------------------
    async def _spf(self, ctx: ModuleContext, resolver, domain: str) -> None:
        records = [t for t in await _txt_strings(resolver, domain)
                  if t.lower().startswith("v=spf1")]
        if not records:
            await ctx.add_negative(
                subject_type="spf", subject_value=domain,
                summary=f"{domain}: no SPF record",
            )
            return
        parsed = _parse_spf(records[0])
        await ctx.add_evidence(
            subject_type="spf", subject_value=domain,
            raw_data={"host": domain, **parsed},
            summary=f"{domain}: SPF present (all={parsed['all_qualifier'] or 'missing'}, "
                    f"{parsed['lookup_mechanisms']} lookup mechanism(s))",
        )
        reasons = []
        if parsed["all_qualifier"] == "+":
            reasons.append("+all allows any sender")
        if parsed["lookup_mechanisms"] > 10:
            reasons.append(f"{parsed['lookup_mechanisms']} DNS-lookup mechanisms (RFC 7208 limit 10)")
        if reasons:
            await ctx.add_evidence(
                subject_type="spf_weak", subject_value=domain,
                raw_data={"host": domain, "reasons": reasons, **parsed},
                summary=f"{domain}: weak SPF - {'; '.join(reasons)}",
            )

    # --- DMARC ------------------------------------------------------
    async def _dmarc(self, ctx: ModuleContext, resolver, domain: str) -> None:
        name = f"_dmarc.{domain}"
        records = [t for t in await _txt_strings(resolver, name)
                  if t.lower().startswith("v=dmarc1")]
        if not records:
            await ctx.add_negative(
                subject_type="dmarc", subject_value=domain,
                summary=f"{domain}: no DMARC record",
            )
            return
        parsed = _parse_dmarc(records[0])
        await ctx.add_evidence(
            subject_type="dmarc", subject_value=domain,
            raw_data={"host": domain, **parsed},
            summary=f"{domain}: DMARC present (p={parsed['policy'] or 'none set'}, "
                    f"pct={parsed['pct']})",
        )
        reasons = []
        if parsed["policy"] == "none":
            reasons.append("p=none - monitoring only, no enforcement")
        if parsed["pct"] < 100:
            reasons.append(f"pct={parsed['pct']} - only a fraction of mail is enforced")
        if not parsed["rua"]:
            reasons.append("no rua= - failures are not being reported to the domain owner")
        if reasons:
            await ctx.add_evidence(
                subject_type="dmarc_weak", subject_value=domain,
                raw_data={"host": domain, "reasons": reasons, **parsed},
                summary=f"{domain}: weak DMARC - {'; '.join(reasons)}",
            )

    # --- DKIM (best-effort: common selectors only) ------------------
    async def _dkim(self, ctx: ModuleContext, resolver, domain: str) -> None:
        found = []
        for selector in _DKIM_SELECTORS:
            ctx.check_alive()
            name = f"{selector}._domainkey.{domain}"
            records = [t for t in await _txt_strings(resolver, name) if "p=" in t.lower()]
            if records:
                found.append(selector)
                await ctx.add_evidence(
                    subject_type="dkim", subject_value=f"{selector}._domainkey.{domain}",
                    raw_data={"host": domain, "selector": selector, "record": records[0]},
                    summary=f"{domain}: DKIM selector '{selector}' found",
                )
        # No negative here: only ~9 common selectors are probed, so "none of
        # these answered" does not mean DKIM is unconfigured - it commonly
        # means a custom selector. Flagging it would be a false absence.
        if not found:
            await ctx.progress(f"{domain}: no DKIM record under the common selectors probed")

    # --- MTA-STS ------------------------------------------------------
    async def _mta_sts(self, ctx: ModuleContext, resolver, domain: str) -> None:
        records = [t for t in await _txt_strings(resolver, f"_mta-sts.{domain}")
                  if t.lower().startswith("v=stsv1")]
        if not records:
            await ctx.add_negative(
                subject_type="mta_sts", subject_value=domain,
                summary=f"{domain}: no MTA-STS record",
            )
            return
        policy = await self._fetch_mta_sts_policy(ctx, domain)
        await ctx.add_evidence(
            subject_type="mta_sts", subject_value=domain,
            raw_data={"host": domain, "record": records[0], **(policy or {})},
            summary=f"{domain}: MTA-STS present"
                    + (f" (mode={policy['mode']})" if policy else " (policy file unreachable)"),
        )

    async def _fetch_mta_sts_policy(self, ctx: ModuleContext, domain: str) -> dict | None:
        url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
        try:
            resp = await ctx.http.get(url, timeout=10.0)
        except Exception:  # noqa: BLE001 - non-fatal, the policy file is optional
            return None
        if resp.status_code != 200:
            return None
        tags = dict(
            line.split(":", 1) for line in resp.text.splitlines()
            if ":" in line and not line.strip().startswith("#")
        )
        mx = [v.strip() for k, v in tags.items() if k.strip().lower() == "mx"]
        mode = tags.get("mode", "").strip() or None
        return {"mode": mode, "mx": mx} if mode else None

    # --- TLS-RPT ------------------------------------------------------
    async def _tls_rpt(self, ctx: ModuleContext, resolver, domain: str) -> None:
        records = [t for t in await _txt_strings(resolver, f"_smtp._tls.{domain}")
                  if t.lower().startswith("v=tlsrptv1")]
        if not records:
            await ctx.add_negative(
                subject_type="tls_rpt", subject_value=domain,
                summary=f"{domain}: no TLS-RPT record",
            )
            return
        await ctx.add_evidence(
            subject_type="tls_rpt", subject_value=domain,
            raw_data={"host": domain, "record": records[0]},
            summary=f"{domain}: TLS-RPT present",
        )
