"""git_secrets - git clone + history walk exercised against a local file://
fixture; ruleset + parsers unit-tested with no network."""

from __future__ import annotations

import json
import shutil
import subprocess

import pytest

from recon.core.roe import CloneDepth
from recon.modules.osint import git_secrets
from recon.modules.osint.git_secrets import (
    GitSecretsModule,
    _mask,
    _parse_batch_check,
    _parse_cat_file,
    _parse_log,
    _parse_trufflehog,
    _scan_text,
)
from recon.modules.registry import MODULES, load_builtin_modules, resolve_order
from tests.harness import evidence_for, module_harness

GIT: str = shutil.which("git") or "git"


def _git(*args, cwd):
    return subprocess.run(
        [GIT, *args], cwd=cwd, capture_output=True, text=True, check=False
    )

def _make_repo(tmp_path):
    if not shutil.which("git"):
        pytest.skip("git binary not available")
    repo = tmp_path / "org" / "target-repo"
    repo.mkdir(parents=True)
    _git("init", "-q", cwd=repo)
    _git("config", "user.email", "t@t", cwd=repo)
    _git("config", "user.name", "t", cwd=repo)
    (repo / "a.txt").write_text("hello\n")
    _git("add", ".", cwd=repo)
    _git("commit", "-qm", "first", cwd=repo)
    (repo / "b.txt").write_text(
        "AKIAIOSFODNN7EXAMPLE\n"
        'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n'
        'api_key = "superlonghighlyentropicvalueabcdefghijklmnop"\n'
    )
    _git("add", ".", cwd=repo)
    _git("commit", "-qm", "add secrets", cwd=repo)
    (repo / "b.txt").write_text("clean\n")
    _git("commit", "-qam", "remove secrets", cwd=repo)
    return repo


async def _run_module(engagement_id, repo_name, tmp_path, monkeypatch, mutate=None):
    from recon.config import get_settings

    monkeypatch.setattr(git_secrets, "_GITHUB_BASE", f"file://{tmp_path}")
    monkeypatch.setattr(get_settings(), "artifacts_dir", tmp_path / "artifacts")
    prior = [{
        "subject_type": "repository",
        "subject_value": f"https://github.com/{repo_name}",
        "raw_data": {"name": repo_name},
    }]
    async with module_harness(engagement_id, "git_secrets", prior_evidence=prior) as ctx:
        if mutate:
            mutate(ctx)
        await GitSecretsModule().run(ctx)


# --------------------------------------------------------------------------
def test_resolves_in_osint_phase_after_github_org():
    load_builtin_modules()
    order = [m.name for m in resolve_order(["git_secrets"])]
    assert MODULES["git_secrets"].phase.value == "osint"
    assert order.index("github_org") < order.index("git_secrets")
    assert order[-1] == "git_secrets"


# --- pure helpers -------------------------------------------------------
def test_scan_text_flags_specific_and_generic_but_never_leaks_raw():
    text = (
        "AKIAIOSFODNN7EXAMPLE\n"
        'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n'
        'api_key = "superlonghighlyentropicvalueabcdefghijklmnop"\n'
    )
    fs = _scan_text(text, "org/repo", "c" * 40, "b.txt")
    kinds = {f["kind"] for f in fs}
    assert {"aws_access_key", "aws_secret_key", "generic_secret"} <= kinds
    joined = " ".join(f["match_redacted"] for f in fs)
    assert "AKIAIOSFODNN7EXAMPLE" not in joined
    assert "wJalrXUtnFEMI/K7MDENG" not in joined
    for f in fs:
        assert f["repo"] == "org/repo" and f["commit"] == "c" * 40 and f["path"] == "b.txt"


def test_scan_text_skips_placeholders_and_low_entropy():
    text = 'api_key = "your_api_key_here_xxxxxxxx"\npassword = "aaaa"\n'
    assert _scan_text(text, "r", "c" * 40, "p") == []


def test_scan_text_skips_fixture_paths():
    text = 'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n'
    assert _scan_text(text, "org/repo", "c" * 40, "tests/fixture.py") == []
    assert _scan_text(text, "org/repo", "c" * 40, "conftest.py") == []


def test_parse_log_oldest_first():
    text = (
        "ae8dcc8da8277a64bc43c87784be23596ceee6a8\n\na.txt\n"
        "e81796ea24b5bd5f096408209f5973d3e67739b3\n\nb.txt\n"
        "d387e8c06621395cc6a454b6182e79d4c9b43bf5\n\nb.txt\n"
    )
    assert _parse_log(text) == [
        ("ae8dcc8da8277a64bc43c87784be23596ceee6a8", ["a.txt"]),
        ("e81796ea24b5bd5f096408209f5973d3e67739b3", ["b.txt"]),
        ("d387e8c06621395cc6a454b6182e79d4c9b43bf5", ["b.txt"]),
    ]


def test_parse_cat_file_byte_exact():
    content1 = b"AKIAIOSFODNN7EXAMPLE\nsecret=xxxxxxxxxxxxxxxxxxxxxxxx\n"
    content2 = b"\x00\x01\x02binary\x00tail"
    data = (
        b"deadbeef blob " + str(len(content1)).encode() + b"\n" + content1 + b"\n"
        b"cafebabe blob " + str(len(content2)).encode() + b"\n" + content2 + b"\n"
    )
    assert _parse_cat_file(data) == [
        ("deadbeef", content1),
        ("cafebabe", content2),
    ]


def test_parse_cat_file_missing():
    assert _parse_cat_file(b"HEAD~1:nope.txt missing\n") == [None]


def test_parse_batch_check_types():
    data = b"abc blob 100\nxyz missing\npqr tree 50\n"
    assert _parse_batch_check(data) == [("blob", 100), None, None]


def test_parse_trufflehog_normalizes_and_gates_on_redacted():
    line = json.dumps({
        "DetectorName": "AWS", "Verified": True, "Redacted": "AKIA...MPLE",
        "SourceMetadata": {"Data": {"Github": {"commit": "abc", "file": "x.txt"}}},
    })
    f = _parse_trufflehog(line)
    assert f == {
        "kind": "aws", "match_redacted": "AKIA...MPLE", "verified": True,
        "commit": "abc", "path": "x.txt",
    }
    assert _parse_trufflehog("not json") is None
    assert _parse_trufflehog(json.dumps({"DetectorName": "AWS"})) is None


def test_parse_trufflehog_masks_raw_when_redacted_absent():
    # trufflehog sometimes omits ``Redacted``; the raw secret must still never
    # leak - the parser masks ``Raw`` itself instead of storing it verbatim.
    raw_secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    line = json.dumps({
        "DetectorName": "AWS", "Verified": False, "Raw": raw_secret,
        "SourceMetadata": {"Data": {"Github": {"commit": "abc", "file": "x.txt"}}},
    })
    f = _parse_trufflehog(line)
    assert f is not None
    assert raw_secret not in f["match_redacted"]
    assert f["match_redacted"] == _mask(raw_secret)


# --- integration (real git) --------------------------------------------
@pytest.mark.asyncio
async def test_full_history_finds_secret_deleted_in_later_commit(engagement_id, tmp_path, monkeypatch):
    _make_repo(tmp_path)
    await _run_module(engagement_id, "org/target-repo", tmp_path, monkeypatch)

    secrets = await evidence_for(engagement_id, subject_type="secret")
    assert secrets, "expected at least one secret finding"
    kinds = {e.raw_data["kind"] for e in secrets}
    assert "aws_access_key" in kinds

    aws = next(e for e in secrets if e.raw_data["kind"] == "aws_access_key")
    assert aws.raw_data["verified"] is False
    assert aws.raw_data["repo"] == "org/target-repo"
    assert aws.raw_data["path"] == "b.txt"
    assert aws.raw_data["commit"] and len(aws.raw_data["commit"]) == 40
    assert aws.raw_data["match_redacted"] != "AKIAIOSFODNN7EXAMPLE"

    # the raw secret must never be persisted anywhere
    blob = json.dumps(
        [{"v": e.subject_value, "r": e.raw_data, "s": e.summary} for e in secrets]
    )
    assert "AKIAIOSFODNN7EXAMPLE" not in blob
    assert "wJalrXUtnFEMI/K7MDENG" not in blob


@pytest.mark.asyncio
async def test_shallow_clone_does_not_see_history_secret(engagement_id, tmp_path, monkeypatch):
    _make_repo(tmp_path)
    await _run_module(
        engagement_id, "org/target-repo", tmp_path, monkeypatch,
        mutate=lambda ctx: setattr(ctx.roe.recon.git_secrets, "clone_depth", CloneDepth.SHALLOW),
    )
    secrets = await evidence_for(engagement_id, subject_type="secret")
    assert secrets == []  # HEAD is clean; the secret lives only in history


@pytest.mark.asyncio
async def test_clone_failure_is_non_fatal(engagement_id, tmp_path, monkeypatch):
    await _run_module(engagement_id, "org/does-not-exist", tmp_path, monkeypatch)
    errs = [e for e in await evidence_for(engagement_id) if e.is_error]
    assert any("clone failed" in (e.summary or "") for e in errs)
    assert await evidence_for(engagement_id, subject_type="secret") == []


@pytest.mark.asyncio
async def test_no_repos_is_a_noop(engagement_id, tmp_path, monkeypatch):
    from recon.config import get_settings

    monkeypatch.setattr(get_settings(), "artifacts_dir", tmp_path / "artifacts")
    async with module_harness(engagement_id, "git_secrets") as ctx:
        await GitSecretsModule().run(ctx)
    assert await evidence_for(engagement_id) == []


@pytest.mark.asyncio
async def test_own_recon_platform_repo_is_not_history_scanned(engagement_id, tmp_path, monkeypatch):
    await _run_module(engagement_id, "Lagarhythm/recon-platform", tmp_path, monkeypatch)
    assert await evidence_for(engagement_id, subject_type="secret") == []


@pytest.mark.asyncio
async def test_size_cap_skips_oversized_repo(engagement_id, tmp_path, monkeypatch):
    _make_repo(tmp_path)
    monkeypatch.setattr(git_secrets, "_dir_size", lambda _p: 10**12)
    await _run_module(engagement_id, "org/target-repo", tmp_path, monkeypatch)
    assert await evidence_for(engagement_id, subject_type="secret") == []


@pytest.mark.asyncio
async def test_verify_true_runs_trufflehog_and_marks_verified(engagement_id, tmp_path, monkeypatch):
    _make_repo(tmp_path)
    real_find = git_secrets.find_binary
    real_run = git_secrets._run_git

    def fake_find(name):
        if name == "trufflehog":
            return "/usr/bin/trufflehog"
        return real_find(name)

    async def fake_run(argv, **kw):
        if argv and argv[0] == "/usr/bin/trufflehog":
            line = json.dumps({
                "DetectorName": "AWS", "Verified": True, "Redacted": "AKIA...MPLE",
                "SourceMetadata": {"Data": {"Github": {"commit": "d" * 40, "file": "b.txt"}}},
            })
            return git_secrets._GitResult(0, (line + "\n").encode(), b"")
        return await real_run(argv, **kw)

    monkeypatch.setattr(git_secrets, "find_binary", fake_find)
    monkeypatch.setattr(git_secrets, "_run_git", fake_run)
    await _run_module(
        engagement_id, "org/target-repo", tmp_path, monkeypatch,
        mutate=lambda ctx: setattr(ctx.roe.recon.git_secrets, "verify", True),
    )
    verified = [
        e for e in await evidence_for(engagement_id, subject_type="secret")
        if e.raw_data.get("verified")
    ]
    assert verified, "expected a trufflehog-verified finding"
    assert verified[0].raw_data["kind"] == "aws"
    assert verified[0].raw_data["match_redacted"] == "AKIA...MPLE"
