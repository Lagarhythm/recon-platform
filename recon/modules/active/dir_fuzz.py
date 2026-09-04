"""Directory / File Fuzzer (active) - wraps ffuf.

Runs against in-scope HTTP(S) roots discovered by the passive phase. Uses
ffuf's auto-calibration plus a second-pass response-similarity filter
(size / word-count / line-count clustering) to suppress soft-404 noise ffuf's
own calibration misses. ffuf's ``-rate`` is pinned to the RoE request rate.
"""

from __future__ import annotations

import json
import re
import tempfile
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

_HOST_RE = re.compile(r"^(?![-.])[A-Za-z0-9_.:\[\]-]{1,255}(?<![-.])$")


def _safe_root(url: str) -> bool:
    parts = urlsplit(url)
    return (
        parts.scheme in ("http", "https")
        and bool(parts.hostname)
        and bool(_HOST_RE.match(parts.netloc))
        and "\n" not in url
        and "\r" not in url
    )

from recon.config import get_settings
from recon.models.enums import ModulePhase, ScopeStatus
from recon.modules.base import ModuleContext, ReconModule
from recon.modules.registry import register
from recon.net.external import find_binary, run_command

_MODULE_TIMEOUT = 40 * 60
# a response-signature shared by more than this many hits is treated as a
# catch-all / soft-404 and its members are dropped
_SOFT404_CLUSTER = 12


@register
class DirFuzzModule(ReconModule):
    name = "dir_fuzz"
    phase = ModulePhase.ACTIVE
    depends_on = ("http_analyzer",)
    description = "ffuf: content discovery on in-scope web roots with soft-404 filtering"
    requires_binary = "ffuf"

    async def run(self, ctx: ModuleContext) -> None:
        ffuf = find_binary("ffuf")
        if not ffuf:
            await ctx.add_error(
                subject_value="ffuf",
                summary="ffuf not found on PATH - dir_fuzz skipped",
                raw_data={"module": "dir_fuzz"},
            )
            return

        wordlist = get_settings().fuzz_wordlist
        if not Path(wordlist).is_file():
            await ctx.add_error(
                subject_value=str(wordlist),
                summary=f"fuzz wordlist not found: {wordlist}",
                raw_data={},
            )
            return

        roots = await self._roots(ctx)
        if not roots:
            await ctx.progress("no in-scope web roots to fuzz")
            return

        rate = max(1, int(round(ctx.roe.rate_limits.max_requests_per_second)))
        ordered = sorted(roots)
        total = len(ordered)
        for i, root in enumerate(ordered, start=1):
            ctx.check_alive()
            await ctx.progress(
                f"fuzzing root {i}/{total}: {root}", current=i - 1, total=total
            )
            await self._fuzz_root(ctx, ffuf, str(wordlist), root, rate)
        await ctx.progress(
            f"dir_fuzz done: {total} root(s)", current=total, total=total
        )

    async def _roots(self, ctx: ModuleContext) -> set[str]:
        oos = ctx.allow_out_of_scope
        roots: set[str] = set()
        for url in await ctx.known_assets("url", in_scope_only=not oos):
            parts = urlsplit(url)
            if parts.scheme in ("http", "https") and parts.netloc:
                roots.add(f"{parts.scheme}://{parts.netloc}/")
        # Only guess https:// for a host we have no confirmed root for - fuzzing
        # a full wordlist against a dead scheme is ~40 min of connection errors.
        covered = {urlsplit(r).netloc for r in roots}
        for host in await ctx.known_assets("subdomain", "domain", in_scope_only=not oos):
            if host not in covered:
                roots.add(f"https://{host}/")
        return {
            r for r in roots
            if _safe_root(r) and ctx.scope.classify(r).status is not ScopeStatus.EXCLUDED
        }

    async def _fuzz_root(
        self, ctx: ModuleContext, ffuf: str, wordlist: str, root: str, rate: int
    ) -> None:
        with tempfile.NamedTemporaryFile(
            "w+", suffix=".json", delete=False, encoding="utf-8"
        ) as tf:
            out_path = tf.name
        argv = [
            ffuf,
            "-w", wordlist,
            "-u", root.rstrip("/") + "/FUZZ",
            "-mc", "200,204,301,302,307,401,403,405,500",
            "-ac",                         # auto-calibrate
            "-rate", str(rate),
            "-t", str(max(1, min(rate, ctx.roe.rate_limits.max_concurrent_connections))),
            "-timeout", "10",
            "-of", "json",
            "-o", out_path,
            "-s",                          # silent
        ]
        await ctx.progress(f"ffuf {root} (rate {rate})")
        await ctx.audit_action(
            target=f"ffuf:{root}FUZZ",
            request_detail={"argv": argv},
            in_scope_status=(
                ScopeStatus.IN_SCOPE if not ctx.allow_out_of_scope else ScopeStatus.FLAGGED
            ),
            override_used=ctx.allow_out_of_scope,
        )

        result = await run_command(argv, timeout=_MODULE_TIMEOUT)
        try:
            data = json.loads(Path(out_path).read_text(encoding="utf-8") or "{}")
        except (json.JSONDecodeError, OSError):
            data = {}
        finally:
            Path(out_path).unlink(missing_ok=True)

        if result.timed_out:
            await ctx.add_error(
                subject_value=root, summary="ffuf timed out", raw_data={"root": root}
            )
        results = data.get("results") or []
        if not results:
            if result.returncode != 0:
                await ctx.add_error(
                    subject_value=root,
                    summary=f"ffuf exited {result.returncode}",
                    raw_data={"stderr": result.stderr[:1500]},
                )
            return

        kept = self._filter_soft_404(results)
        for r in kept:
            ctx.check_alive()
            url = r.get("url") or f"{root.rstrip('/')}/{r.get('input', {}).get('FUZZ', '')}"
            status = r.get("status")
            interest = "notable" if status in (200, 401, 403) else "informational"
            await ctx.add_evidence(
                subject_type="url",
                subject_value=url,
                raw_data={
                    "status": status,
                    "length": r.get("length"),
                    "words": r.get("words"),
                    "lines": r.get("lines"),
                    "content_type": r.get("content-type"),
                    "redirectlocation": r.get("redirectlocation"),
                    "source": "ffuf",
                    "interest": interest,
                },
                summary=f"ffuf: {url} -> {status} ({r.get('length')}b)",
            )
        await ctx.progress(
            f"ffuf {root}: {len(results)} raw, {len(kept)} after soft-404 filter"
        )

    @staticmethod
    def _filter_soft_404(results: list[dict]) -> list[dict]:
        """Drop hits whose (status, length, words, lines) signature is shared by
        a large cluster - the hallmark of a catch-all handler."""
        sig = Counter(
            (r.get("status"), r.get("length"), r.get("words"), r.get("lines"))
            for r in results
        )
        return [
            r for r in results
            if sig[(r.get("status"), r.get("length"), r.get("words"), r.get("lines"))]
            <= _SOFT404_CLUSTER
        ]
