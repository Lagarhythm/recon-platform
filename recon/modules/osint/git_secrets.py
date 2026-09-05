"""Git-history secret scanning (osint, PRD v2.1 §11.7 / N7).

Clones the public repos ``github_org`` already discovered and scans their
**full git history** for committed secrets - credentials that were committed
and later deleted or amended, which ``js_analyzer``'s crawl-time regex can
never see (it only reads what is served now, not what history remembers).

Native path only: shell ``git`` (ubiquitous) clones each repo into a temp dir
under ``data/artifacts/`` and walks every blob in every commit, applying a
vendored detect-secrets-style ruleset (AWS/GCP/Azure keys, JWTs, private keys,
Slack/GitHub/GitLab/Stripe tokens, generic high-entropy ``KEY=value``).

Findings are **unverified by default** (like ``js_analyzer``). ``trufflehog``
live verification is an opt-in accelerator behind ``recon.git_secrets.verify:
true`` (PRD decision B, default off) - its read-only probes go to third-party
providers, never the client target. The native path runs regardless.

Hard guardrail: a discovered secret is **flagged only** - never used to
authenticate against any target (Non-Goal 1.1).
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import math
import os
import re
import shutil
import signal
import tempfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from recon.config import get_settings
from recon.core.roe import CloneDepth
from recon.models.enums import ModulePhase
from recon.models.evidence import Evidence
from recon.modules.base import ModuleContext, ReconModule
from recon.modules.registry import register
from recon.net.external import find_binary

#: base remote used to build clone URLs from a ``full_name`` (``org/repo``).
#: A module constant so tests can point it at a local ``file://`` fixture.
_GITHUB_BASE = "https://github.com"

#: a single blob larger than this is almost always a binary / vendor bundle;
#: scanning it is pure CPU/memory burn and never yields a clean text secret.
_MAX_BLOB_BYTES = 10 * 1024 * 1024

_CLONE_TIMEOUT = 300.0
_WALK_TIMEOUT = 120.0
_CAT_TIMEOUT = 180.0

# --- secret ruleset (vendored, detect-secrets-style) --------------------
_RULES: tuple[tuple[str, re.Pattern[str], int], ...] = (
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), 0),
    ("gcp_api_key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), 0),
    ("slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"), 0),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), 0),
    ("github_fine_grained", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b"), 0),
    ("gitlab_token", re.compile(r"\bglpat-[A-Za-z0-9\-_]{20,}\b"), 0),
    ("stripe_secret_key", re.compile(r"\b(?:sk|rk)_live_[0-9a-zA-Z]{16,}\b"), 0),
    ("npm_token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"), 0),
    ("sendgrid_token", re.compile(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b"), 0),
    ("twilio_api_key", re.compile(r"\bSK[0-9a-fA-F]{32}\b"), 0),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), 0),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED |PGP |)PRIVATE KEY(?: BLOCK)?-----"), 0),
    ("azure_storage_key", re.compile(r"(?i)AccountKey\s*=\s*['\"]([A-Za-z0-9+/=]{86,88})['\"]"), 1),
    (
        "aws_secret_key",
        re.compile(
            r"(?i)(?:aws[_-]?secret[_-]?access[_-]?key|secret[_-]?access[_-]?key|aws[_-]?secret)"
            r"[\"']?\s*[:=]\s*['\"]([A-Za-z0-9/+=]{40})['\"]"
        ),
        1,
    ),
)

_GENERIC_SECRET_RE = re.compile(
    r"""(?i)\b(?:api[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|"""
    r"""secret[_-]?key|token|password|passwd|pwd|secret|bearer)\b"""
    r"""\s*[:=]\s*['"]([^'"\s]{20,120})['"]"""
)

_PLACEHOLDER_HINTS = (
    "your", "example", "changeme", "placeholder", "xxxx", "test",
    "dummy", "sample", "redacted", "process.env", "import.meta", "${", "<%", "{{",
)

_FIXTURE_PATH = re.compile(
    r"(?:^|/)(?:tests?|testdata|fixtures|__tests__)(?:/|$)|"
    r"(?:^|/)[^/]+_test\.[^/]+$|(?:^|/)[^/]+\.spec\.[^/]+$|"
    r"(?:^|/)conftest\.py$",
    re.IGNORECASE,
)
_SELF_REPOS = {"lagarhythm/recon-platform"}
_EXCLUDED_PATH_POLICIES = ["tests/**", "testdata/**", "fixtures/**", "__tests__/**", "*_test.*", "*.spec.*", "conftest.py"]


def _mask(secret: str) -> str:
    if len(secret) <= 8:
        return "..."
    return f"{secret[:4]}...{secret[-4:]}"


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in Counter(value).values())


def _matched_specific(value: str) -> bool:
    for _, pattern, _group in _RULES:
        if pattern.search(value):
            return True
    return False


def _looks_binary(content: bytes) -> bool:
    return b"\x00" in content[:8000]


def _normalize_kind(name: str) -> str:
    out = re.sub(r"[^a-z0-9]+", "_", (name or "").lower()).strip("_")
    return out or "generic_secret"


def _clone_url(full_name: str) -> str:
    return f"{_GITHUB_BASE.rstrip('/')}/{full_name}"


def _repo_full_name(ev: Evidence) -> str:
    raw = ev.raw_data or {}
    name = (raw.get("name") or "").strip()
    if name:
        return name
    val = (ev.subject_value or "").strip()
    try:
        return urlsplit(val).path.strip("/")
    except ValueError:
        return ""


def _dir_size(path: Path) -> int:
    total = 0
    for root, _dirs, files in os.walk(path):
        for f in files:
            try:
                total += (Path(root) / f).stat().st_size
            except OSError:
                continue
    return total


def _tail(data: bytes, limit: int = 2000) -> str:
    text = data.decode("utf-8", "replace")
    return text[-limit:] if len(text) > limit else text


def _is_fixture_path(path: str) -> bool:
    return bool(_FIXTURE_PATH.search(path.replace("\\", "/")))


def _scan_text(text: str, repo: str, commit: str, path: str) -> list[dict]:
    """Run the ruleset over one blob's decoded text. Returns findings with the
    match already redacted - the raw secret never leaves this function."""
    if _is_fixture_path(path):
        return []
    findings: list[dict] = []
    seen: set[str] = set()

    for kind, pattern, group in _RULES:
        for m in pattern.finditer(text):
            secret = m.group(group) if group else m.group(0)
            if not secret or secret in seen:
                continue
            seen.add(secret)
            findings.append({
                "kind": kind,
                "match_redacted": _mask(secret),
                "repo": repo, "commit": commit, "path": path,
            })

    for m in _GENERIC_SECRET_RE.finditer(text):
        value = m.group(1)
        if value in seen:
            continue
        low = value.lower()
        if any(h in low for h in _PLACEHOLDER_HINTS):
            continue
        if value.startswith(("http://", "https://", "/")):
            continue
        if _matched_specific(value):
            continue
        if _entropy(value) <= 3.5:
            continue
        seen.add(value)
        findings.append({
            "kind": "generic_secret",
            "match_redacted": _mask(value),
            "repo": repo, "commit": commit, "path": path,
        })
    return findings


def _parse_log(text: str) -> list[tuple[str, list[str]]]:
    """Parse ``git log --format=%H --name-only`` output into ordered
    (commit_sha, [changed paths]) pairs, oldest first (``--reverse``)."""
    commits: list[tuple[str, list[str]]] = []
    current: str | None = None
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if re.fullmatch(r"[0-9a-f]{40}", line):
            current = line
            commits.append((current, []))
        elif current is not None:
            commits[-1][1].append(line)
    return commits


def _parse_batch_check(data: bytes) -> list[tuple[str, int] | None]:
    """Parse ``cat-file --batch-check`` output: one (type, size) per input rev
    in order; None for missing/non-blob objects."""
    out: list[tuple[str, int] | None] = []
    for line in data.decode("utf-8", "replace").splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[1] == "blob":
            try:
                out.append((parts[1], int(parts[2])))
            except ValueError:
                out.append(None)
        else:
            out.append(None)
    return out


def _parse_cat_file(data: bytes) -> list[tuple[str, bytes] | None]:
    """Parse ``cat-file --batch`` output: one (sha, content) per input rev in
    order; None for missing objects. Byte-exact: the header line carries the
    object size, so content of any byte layout survives."""
    out: list[tuple[str, bytes] | None] = []
    i, n = 0, len(data)
    while i < n:
        nl = data.find(b"\n", i)
        if nl == -1:
            break
        header = data[i:nl].decode("utf-8", "replace")
        i = nl + 1
        parts = header.split()
        if len(parts) != 3 or parts[1] != "blob":
            out.append(None)  # "<rev> missing" or unexpected
            continue
        try:
            size = int(parts[2])
        except ValueError:
            out.append(None)
            continue
        content = data[i:i + size]
        i += size
        if i < n and data[i:i + 1] == b"\n":
            i += 1
        out.append((parts[0], content))
    return out


def _parse_trufflehog(line: str) -> dict | None:
    """One JSONL line from ``trufflehog --json`` -> a normalized finding, or
    None if the line is not a finding. ``Redacted`` is trufflehog's own masked
    value; the raw secret is never taken from ``Raw``."""
    try:
        obj = json.loads(line)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(obj, dict):
        return None
    redacted = obj.get("Redacted")
    if not redacted:
        raw = obj.get("Raw")
        if not raw:
            return None
        # Never take the raw secret from ``Raw`` verbatim - mask it first so the
        # hard guardrail (no raw secret ever stored) holds even when trufflehog
        # omits its own ``Redacted`` field.
        redacted = _mask(str(raw))
    src = (obj.get("SourceMetadata") or {}).get("Data") or {}
    gh = src.get("Github") or src.get("GitHub") or {}
    return {
        "kind": _normalize_kind(str(obj.get("DetectorName") or "generic_secret")),
        "match_redacted": str(redacted),
        "verified": bool(obj.get("Verified")),
        "commit": str(gh.get("commit") or ""),
        "path": str(gh.get("file") or ""),
    }


@dataclass
class _GitResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    timed_out: bool = False


async def _run_git(argv: list[str], *, stdin_bytes: bytes | None = None,
                   timeout: float = 300.0) -> _GitResult:
    """Run a git subprocess as an argv list (never a shell), time-boxed and
    byte-safe, killing the whole process tree on timeout."""
    kwargs: dict = {}
    if os.name == "posix":
        kwargs["start_new_session"] = True
    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        **kwargs,
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(input=stdin_bytes), timeout=timeout)
    except TimeoutError:
        _kill_tree(proc)
        with contextlib.suppress(Exception):
            await proc.wait()
        return _GitResult(-1, b"", b"", timed_out=True)
    return _GitResult(proc.returncode if proc.returncode is not None else -1, out or b"", err or b"")


def _kill_tree(proc: asyncio.subprocess.Process) -> None:
    if proc.returncode is not None:
        return
    if os.name == "posix":
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            return
        except (ProcessLookupError, PermissionError, OSError):
            pass
    with contextlib.suppress(ProcessLookupError):
        proc.kill()


@register
class GitSecretsModule(ReconModule):
    name = "git_secrets"
    phase = ModulePhase.OSINT
    depends_on = ("github_org",)
    description = "Scan github_org-discovered public repos' full git history for committed secrets"
    max_runtime_seconds = 30 * 60

    async def run(self, ctx: ModuleContext) -> None:
        repos = await self._collect_repos(ctx)
        if not repos:
            await ctx.progress("git_secrets: no github_org-discovered repos to scan")
            return

        git = find_binary("git")
        if not git:
            await ctx.add_error(
                subject_value="git",
                summary="git not found on PATH - git_secrets skipped",
                raw_data={"module": "git_secrets"},
            )
            return

        verify = ctx.roe.recon.git_secrets.verify
        await ctx.progress(f"git_secrets: {len(repos)} repo(s)", count=len(repos))
        for i, repo in enumerate(repos, start=1):
            ctx.check_alive()
            await self._scan_repo(ctx, git, repo, verify=verify)
            await ctx.progress(
                f"git_secrets: scanned {i}/{len(repos)} repo(s)",
                current=i, total=len(repos),
            )

    # --- inputs ------------------------------------------------------
    async def _collect_repos(self, ctx: ModuleContext) -> list[dict]:
        repos: list[dict] = []
        seen: set[str] = set()
        excluded_repositories: list[str] = []
        for ev in await ctx.known_evidence("repository"):
            name = _repo_full_name(ev)
            if not name or name in seen:
                continue
            seen.add(name)
            if name.lower() in _SELF_REPOS:
                excluded_repositories.append(name)
                continue
            repos.append({"name": name})
        await ctx.set_coverage_metadata({
            "excluded_repositories": sorted(excluded_repositories),
            "excluded_path_policies": _EXCLUDED_PATH_POLICIES,
        })
        return repos

    # --- per-repo ----------------------------------------------------
    async def _scan_repo(self, ctx: ModuleContext, git: str, repo: dict, *, verify: bool) -> None:
        name = repo["name"]
        url = _clone_url(name)
        depth = ctx.roe.recon.git_secrets.clone_depth
        max_bytes = ctx.roe.recon.git_secrets.max_repo_bytes

        base = get_settings().artifacts_dir
        base.mkdir(parents=True, exist_ok=True)
        dest = Path(tempfile.mkdtemp(prefix="git-secrets-", dir=str(base)))
        try:
            argv = [git, "clone", "--mirror", "--quiet", url, str(dest)]
            if depth is CloneDepth.SHALLOW:
                argv.insert(2, "--depth")
                argv.insert(3, "1")
            # third-party (GitHub) clone - audited as n/a, never a target hit
            await ctx.audit_action(
                target=f"git:{name}",
                request_detail={"argv": argv},
            )
            res = await _run_git(argv, timeout=_CLONE_TIMEOUT)
            await ctx.add_artifact(
                data=(res.stdout + res.stderr) or b"(no clone output)",
                kind="git_clone_log",
                content_type="text/plain",
            )
            if res.timed_out or res.returncode != 0:
                await ctx.add_error(
                    subject_value=name,
                    summary=f"clone failed for {name} (rc={res.returncode}): {_tail(res.stderr, 300)}",
                    raw_data={"repo": name, "url": url},
                )
                return

            if _dir_size(dest) > max_bytes:
                await ctx.progress(
                    f"git_secrets: skip {name} - clone exceeds {max_bytes} byte size cap"
                )
                return

            await self._walk_history(ctx, git, dest, name)

            if verify:
                await self._trufflehog(ctx, dest, name)
        finally:
            shutil.rmtree(dest, ignore_errors=True)

    # --- history walk -----------------------------------------------
    async def _walk_history(self, ctx: ModuleContext, git: str, repo_dir: Path, repo: str) -> None:
        res = await _run_git(
            [git, "-C", str(repo_dir), "log", "--all", "--reverse",
             "--format=%H", "--name-only", "--no-renames"],
            timeout=_WALK_TIMEOUT,
        )
        if res.timed_out or res.returncode != 0:
            await ctx.add_error(
                subject_value=repo,
                summary=f"git log failed for {repo} (rc={res.returncode})",
                raw_data={"repo": repo, "stderr": _tail(res.stderr, 300)},
            )
            return

        commits = _parse_log(res.stdout.decode("utf-8", "replace"))
        total = len(commits)
        seen_blobs: set[str] = set()
        for i, (commit, paths) in enumerate(commits, start=1):
            ctx.check_alive()
            if not paths:
                await ctx.progress(
                    f"git_secrets: {repo} {i}/{total}", current=i, total=total,
                )
                continue
            for path, sha, content in await self._read_blobs(git, repo_dir, commit, paths):
                if sha in seen_blobs:
                    continue
                seen_blobs.add(sha)
                if _looks_binary(content):
                    continue
                text = content.decode("utf-8", "replace")
                for f in _scan_text(text, repo, commit, path):
                    await self._emit_secret(
                        ctx, repo, commit, path, f["kind"], f["match_redacted"], verified=False,
                    )
            await ctx.progress(
                f"git_secrets: {repo} {i}/{total}", current=i, total=total,
            )

    async def _read_blobs(
        self, git: str, repo_dir: Path, commit: str, paths: list[str]
    ) -> list[tuple[str, str, bytes]]:
        """Read the blob content at ``commit:path`` for each path, skipping
        blobs over ``_MAX_BLOB_BYTES``. Returns (path, sha, content)."""
        revs = [f"{commit}:{p}" for p in paths]
        check = await _run_git(
            [git, "-C", str(repo_dir), "cat-file",
             "--batch-check=%(objectname) %(objecttype) %(objectsize)"],
            stdin_bytes=("\n".join(revs) + "\n").encode("utf-8"),
            timeout=_CAT_TIMEOUT,
        )
        entries = _parse_batch_check(check.stdout)
        keep = [r for r, e in zip(revs, entries)
                if e is not None and 0 < e[1] <= _MAX_BLOB_BYTES]
        if not keep:
            return []

        read = await _run_git(
            [git, "-C", str(repo_dir), "cat-file", "--batch"],
            stdin_bytes=("\n".join(keep) + "\n").encode("utf-8"),
            timeout=_CAT_TIMEOUT,
        )
        parsed = _parse_cat_file(read.stdout)
        out: list[tuple[str, str, bytes]] = []
        for rev, entry in zip(keep, parsed):
            if entry is None:
                continue
            sha, content = entry
            path = rev.split(":", 1)[1]
            out.append((path, sha, content))
        return out

    # --- trufflehog accelerator (opt-in) ----------------------------
    async def _trufflehog(self, ctx: ModuleContext, repo_dir: Path, repo: str) -> None:
        th = find_binary("trufflehog")
        if not th:
            await ctx.progress(
                f"git_secrets: verify=true but trufflehog not on PATH - "
                f"keeping native (unverified) findings for {repo}"
            )
            return
        res = await _run_git(
            [th, "git", f"file://{repo_dir}", "--json", "--no-update"],
            timeout=_CAT_TIMEOUT,
        )
        if res.timed_out or res.returncode != 0:
            await ctx.add_error(
                subject_value=repo,
                summary=f"trufflehog verification failed for {repo} (rc={res.returncode})",
                raw_data={"repo": repo, "stderr": _tail(res.stderr, 300)},
            )
            return
        for line in res.stdout.decode("utf-8", "replace").splitlines():
            f = _parse_trufflehog(line)
            if f:
                await self._emit_secret(
                    ctx, repo, f["commit"], f["path"], f["kind"],
                    f["match_redacted"], verified=f["verified"],
                )

    # --- evidence ---------------------------------------------------
    async def _emit_secret(
        self, ctx: ModuleContext, repo: str, commit: str, path: str,
        kind: str, match_redacted: str, *, verified: bool,
    ) -> None:
        await ctx.add_evidence(
            subject_type="secret",
            subject_value=f"{kind}:{repo}:{path}:{commit[:12]}",
            raw_data={
                "repo": repo,
                "commit": commit,
                "path": path,
                "kind": kind,
                "match_redacted": match_redacted,
                "verified": verified,
                "interest": "high_value",
            },
            summary=(
                f"Possible {kind} in {repo} @ {path} ({commit[:12]})"
                + (" [verified]" if verified else "")
            ),
        )
