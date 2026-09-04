"""LLM Analyst service.

Sends the correlated Asset Graph (client-redacted) to the configured remote
endpoint and stores a prioritised assessment. Hard constraints:

  * only runs when ``engagement.llm_analysis_enabled`` is True (per-engagement,
    default off - recon data leaving the host is an opt-in);
  * the payload goes through the same redaction as the client PDF;
  * the LLM's reply is analysis only - it is parsed for text, never executed.
"""

from __future__ import annotations

import json
import re

from sqlalchemy.ext.asyncio import AsyncSession

from recon.llm.client import LLMClient, LLMError
from recon.models.analysis import Analysis
from recon.models.engagement import Engagement
from recon.reporting.collect import build_report_data
from recon.reporting.redaction import RedactionMode, redact_report

_SYSTEM = (
    "You are a senior penetration-testing analyst reviewing correlated "
    "reconnaissance for an AUTHORIZED engagement. You are given a compact JSON "
    "view of the attack surface: open services, hosts, findings (each with the "
    "evidence lines that produced it), notable URLs, and missing security "
    "controls. It may also carry an `osint` block (organisations, people, "
    "emails, repos, netblocks, documents) when the engagement did company OSINT."
    "\n\n"
    "Respond with a SINGLE JSON object, keys in this order:\n"
    '  "summary": a thorough assessment, 2-4 paragraphs. Cover what this target '
    "is, the overall security picture, the most significant exposures, and call "
    "out any finding that is probably a FALSE POSITIVE (e.g. a secret pattern "
    "that matched inside a minified library or a UI placeholder string), with "
    "your reasoning. If an `osint` block is present the target is an "
    "organisation - give a full org profile: what it is, who runs it, its "
    "domain / netblock / repo / people footprint, and what that footprint "
    "implies. Be specific and use the actual values from the data - do not pad "
    "with generic advice.\n"
    '  "priorities": ordered list of strings, most important first - the '
    "specific hosts/services/findings an operator should look at first and why. "
    "Give each one a sentence or two of rationale. Group by host where it helps. "
    "Name the actual values from the data. Aim for 5-12 entries when the data "
    "supports it. Frame each as what to examine, confirm, or map - not an attack "
    "to run (no 'test default credentials', no 'attempt bypass').\n"
    '  "next_steps": list of strings - concrete additional RECON actions only '
    "(enumerate X, fingerprint Y, verify whether Z). Include a 'verify' step for "
    "anything you flagged as a likely false positive. NEVER exploitation.\n\n"
    "Rules: do not invent assets or services not present in the data. Do not "
    "suggest exploitation, credential use, or DoS. Prefer specifics over "
    "generalities. Respond with JSON only, no prose outside the object."
)

_MAX_EVID_PER_FINDING = 4
_MAX_NOTABLE_URLS = 60
_MAX_CHARS = 90_000


def _evidence_lines(asset: dict) -> list[str]:
    out: list[str] = []
    for e in asset.get("evidence", []):
        s = (e.get("summary") or "").strip()
        if s and s not in out:
            out.append(s)
        if len(out) >= _MAX_EVID_PER_FINDING:
            break
    return out


def _compact(redacted: dict) -> dict:
    """A lean view of the Asset Graph for the analyst - the full redacted report
    is mostly per-URL evidence blobs that blow the model's context for no gain.
    """
    assets = redacted.get("assets", [])
    by_type: dict[str, list[dict]] = {}
    for a in assets:
        by_type.setdefault(a.get("type", "?"), []).append(a)

    def interest_rank(a: dict) -> int:
        return {"high_value": 0, "notable": 1}.get(a.get("interest"), 2)

    services = []
    for a in by_type.get("service", []):
        rd = next((e.get("raw_data") or {} for e in a.get("evidence", [])), {})
        confirmed = bool(rd.get("product") or rd.get("banner") or rd.get("version"))
        services.append({
            "value": a["value"],
            "service": rd.get("name"),
            # nmap falls back to a port-number guess when it gets no banner
            "id_confidence": "confirmed" if confirmed else "guessed-from-port-number",
            "evidence": _evidence_lines(a),
        })
    hosts = [
        a["value"]
        for t in ("domain", "subdomain", "ip")
        for a in by_type.get(t, [])
    ]
    # js_file / dnssec findings are inventory, not attack surface - a running
    # count in the summary is enough; the per-item lines just bury the signal.
    _NOISE = ("js_file:", "dnssec:")
    noisy = [f for f in redacted.get("findings", []) if f["value"].startswith(_NOISE)]
    findings = [
        {
            "value": a["value"],
            "interest": a.get("interest"),
            "evidence": _evidence_lines(a),
        }
        for a in sorted(redacted.get("findings", []), key=interest_rank)
        if not a["value"].startswith(_NOISE)
    ]
    notable_urls = [
        a["value"]
        for a in sorted(by_type.get("url", []), key=interest_rank)
        if a.get("interest") in ("high_value", "notable")
    ][:_MAX_NOTABLE_URLS]

    summary = dict(redacted["summary"])
    if noisy:
        summary["inventory_only_findings"] = {
            "js_files": sum(1 for f in noisy if f["value"].startswith("js_file:")),
            "hosts_without_dnssec": sum(1 for f in noisy if f["value"].startswith("dnssec:")),
        }

    def _vals(t: str) -> list[dict]:
        return [{"value": a["value"], "evidence": _evidence_lines(a)}
                for a in by_type.get(t, [])]

    osint = {}
    for key, atype in (("organizations", "organization"), ("people", "person"),
                       ("emails", "email"), ("repositories", "repository"),
                       ("netblocks", "netblock"), ("documents", "document"),
                       ("social", "social")):
        rows = _vals(atype)
        if rows:
            osint[key] = rows[:40]
    fmt = [f for f in redacted.get("findings", []) if f["value"].startswith("email_format:")]
    if fmt:
        osint["email_formats"] = [f["value"].split(":", 1)[1] for f in fmt]

    out = {
        "engagement": redacted["engagement"]["name"],
        "summary": summary,
        "services": services,
        "hosts": sorted(set(hosts)),
        "findings": findings,
        "notable_urls": notable_urls,
        "missing_controls": [n["summary"] for n in redacted.get("negative_findings", [])],
        "relationships": redacted.get("relationships", []),
    }
    if osint:
        out["osint"] = osint
    return out


class AnalystError(RuntimeError):
    pass


class AnalystService:
    def __init__(self, client: LLMClient | None = None) -> None:
        self._client = client or LLMClient()

    async def run(
        self, session: AsyncSession, engagement: Engagement, *, scan_run_id: str | None = None
    ) -> Analysis:
        if not engagement.llm_analysis_enabled:
            raise AnalystError(
                "remote LLM analysis is disabled for this engagement - enable it "
                "on the engagement page first (recon data will leave this host)"
            )

        data = await build_report_data(session, engagement)
        redacted = redact_report(data, RedactionMode.CLIENT)
        payload = _compact(redacted)
        user = json.dumps(payload, default=str)
        if len(user) > _MAX_CHARS:
            # last-ditch trim: drop notable_urls, then missing_controls
            payload["notable_urls"] = payload["notable_urls"][:15]
            payload["missing_controls"] = payload["missing_controls"][:20]
            user = json.dumps(payload, default=str)[:_MAX_CHARS]

        analysis = Analysis(
            engagement_id=engagement.id,
            scan_run_id=scan_run_id,
            model=self._client.model,
            asset_count=redacted["summary"]["asset_count"],
        )
        try:
            result = await self._client.chat(_SYSTEM, user, json_mode=True)
        except LLMError as exc:
            analysis.error = str(exc)
            session.add(analysis)
            await session.flush()
            raise AnalystError(str(exc)) from exc

        analysis.raw_response = result.content
        analysis.usage = result.usage
        analysis.model = result.model
        parsed = _parse(result.content)
        analysis.summary = parsed["summary"]
        analysis.priorities = parsed["priorities"]
        analysis.next_steps = _drop_exploitation(parsed["next_steps"])
        session.add(analysis)
        await session.flush()
        return analysis


# The prompt forbids exploitation advice, but not every model honours it. This
# is a coarse belt-and-suspenders filter over "next steps" - the tool is
# authorised RECON only and must not surface credential-attack / exploit steps.
_EXPLOIT_RE = re.compile(
    r"\b(default|weak|common|guess\w*)\s+(cred|password|login)"
    r"|\bbrute[\s-]?forc|\bpassword spray|\bcredential stuff"
    r"|\bexploit|\bpayload|\breverse shell|\bsqli\b|\bsql injection"
    r"|\bxss\b|\brce\b|\bmetasploit|\bhydra\b|\bsqlmap"
    r"|\battempt(?:ing)?\s+to\s+(?:log|authenticat|access\b.*\bcredential)",
    re.IGNORECASE,
)


def _drop_exploitation(steps: list[str]) -> list[str]:
    kept = [s for s in steps if not _EXPLOIT_RE.search(s)]
    if len(kept) != len(steps):
        kept.append(
            "[note: the model suggested one or more steps that crossed into "
            "exploitation / credential testing - dropped; this tool is recon only]"
        )
    return kept


def _parse(content: str | None) -> dict:
    if not content or not str(content).strip():
        return {"summary": "(model returned no content)", "priorities": [], "next_steps": []}
    text = str(content).strip()
    # reasoning models ("qwen3", ...) prepend a <think>...</think> block
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()
    if text.startswith("```"):
        text = text.split("```", 2)[1]
        text = text[4:] if text.lower().startswith("json") else text
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        # not clean JSON - try to lift the outermost {...} out of surrounding prose
        start, end = text.find("{"), text.rfind("}")
        if 0 <= start < end:
            try:
                obj = json.loads(text[start:end + 1])
            except json.JSONDecodeError:
                return {"summary": text[:4000], "priorities": [], "next_steps": []}
        else:
            return {"summary": text[:4000], "priorities": [], "next_steps": []}
    return {
        "summary": str(obj.get("summary", "")).strip(),
        "priorities": [str(x) for x in obj.get("priorities", []) if str(x).strip()],
        "next_steps": [str(x) for x in obj.get("next_steps", []) if str(x).strip()],
    }
