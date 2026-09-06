"""Migration-level enforcement tests for the active-scan authorization boundary
(d4e2a1c7b930 / G0 blockers B1 + B2).

These run the real alembic migration against a fresh SQLite file and exercise
every FK / CHECK with ``PRAGMA foreign_keys = ON`` set - the migration skeleton
is NOT treated as evidence on its own (Security round-2 explicit ask). The
positive path (a coherent snapshot -> manifest -> entry -> audit chain) is
inserted first so every negative case is a single mutated field away from a
valid row.
"""

from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).parents[1]
_PRIOR_HEAD = "c1a7e5d2f9b0"
_HEAD = "d4e2a1c7b930"


def _alembic(db_path: Path, target: str, direction: str = "upgrade") -> None:
    env = os.environ.copy()
    env["RECON_DATABASE_URL"] = f"sqlite+aiosqlite:///{db_path}"
    env["RECON_DATA_DIR"] = str(db_path.parent / "data")
    env.setdefault("RECON_SECRET_KEY", "migration-test-secret")
    subprocess.run(
        [sys.executable, "-m", "alembic", direction, target],
        check=True,
        cwd=str(_ROOT),
        env=env,
    )


def _connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def _insert(conn: sqlite3.Connection, table: str, **cols) -> None:
    placeholders = ", ".join("?" for _ in cols)
    conn.execute(
        f"INSERT INTO {table} ({', '.join(cols)}) VALUES ({placeholders})",
        tuple(cols.values()),
    )


_TS = "2026-09-06 00:00:00"


def _seed(conn: sqlite3.Connection) -> None:
    """A coherent baseline: two engagements/runs/snapshots ("a" and "b"), one
    authorized CIDR + one authorized hostname per snapshot, a manifest + entry on
    snapshot a, plus a retention artifact. Everything here is valid; tests mutate
    one field to prove the boundary rejects it."""
    _insert(conn, "user", id="u1", username="op", password_hash="x", created_at=_TS)
    for eng in ("eng_a", "eng_b"):
        _insert(
            conn,
            "engagement",
            id=eng,
            name=eng,
            client_name="c",
            roe_config_yaml="{}",
            roe_config="{}",
            roe_config_hash="h",
            status="active",
            llm_analysis_enabled=0,
            created_at=_TS,
        )
    for run, eng in (("run_a", "eng_a"), ("run_b", "eng_b")):
        _insert(
            conn,
            "scan_run",
            id=run,
            engagement_id=eng,
            roe_config_snapshot="{}",
            roe_config_hash="h",
            modules_requested="[]",
            modules_completed="[]",
            status="running",
            allow_out_of_scope=0,
            active_confirmed=1,
            created_at=_TS,
        )
    _insert(
        conn,
        "scan_module_run",
        id="smr_a",
        scan_run_id="run_a",
        engagement_id="eng_a",
        module_name="host_discovery",
        phase="active",
        status="running",
        order_index=0,
        evidence_count=0,
        error_count=0,
        coverage_metadata="{}",
    )
    _insert(
        conn,
        "evidence",
        id="ev_a",
        engagement_id="eng_a",
        source_module="host_discovery",
        subject_type="live_host",
        subject_value="10.0.0.5",
        polarity="present",
        is_error=0,
        raw_data="{}",
        discovered_at=_TS,
    )
    for snap, run, eng in (("snap_a", "run_a", "eng_a"), ("snap_b", "run_b", "eng_b")):
        _insert(
            conn,
            "authorization_snapshot",
            id=snap,
            scan_run_id=run,
            engagement_id=eng,
            roe_config_hash="h",
            scope_policy_hash="sp",
            authorized_by_user_id="u1",
            authorized_at=_TS,
            checkpoint_ack_hash="ack",
            checkpoint_payload="{}",
            flow="interactive",
            policy_version="p1",
            created_at=_TS,
        )
    for cid, snap in (("c_a", "snap_a"), ("c_b", "snap_b")):
        _insert(
            conn,
            "authorized_cidr",
            id=cid,
            snapshot_id=snap,
            cidr="10.0.0.0/24",
            ip_version=4,
            address_count=256,
            source="roe_cidr",
            created_at=_TS,
        )
    for tid, snap in (("t_a", "snap_a"), ("t_b", "snap_b")):
        _insert(
            conn,
            "authorized_target",
            id=tid,
            snapshot_id=snap,
            target_type="hostname",
            value="host.example.com",
            source="roe_host",
            created_at=_TS,
        )
    _insert(
        conn,
        "candidate_manifest",
        id="m_a",
        scan_run_id="run_a",
        scan_module_run_id="smr_a",
        authorization_snapshot_id="snap_a",
        manifest_hash="mh",
        total_addresses=1,
        probeable_addresses=1,
        excluded_addresses=0,
        policy_version="p1",
        method_profile_id="cidr_syn_v1",
        created_at=_TS,
    )
    _insert(
        conn,
        "candidate_manifest_entry",
        id="e_a",
        manifest_id="m_a",
        authorization_snapshot_id="snap_a",
        candidate_ip="10.0.0.5",
        authorized_cidr_id="c_a",
        parent_authorized_cidr="10.0.0.0/24",
        excluded=0,
        created_at=_TS,
    )
    _insert(
        conn,
        "retention_artifact",
        id="ra1",
        kind="audit_retention_bundle",
        sha256="deadbeef",
        byte_size=10,
        stored_path="deadbeef",
        created_at=_TS,
    )
    conn.commit()


def _cidr_audit(conn, **overrides):
    """Insert a valid CIDR-path AddressAudit unless a field is overridden."""
    row = {
        "id": "aa_cidr",
        "manifest_id": "m_a",
        "manifest_entry_id": "e_a",
        "scan_run_id": "run_a",
        "engagement_id": "eng_a",
        "candidate_ip": "10.0.0.5",
        "authorization_snapshot_id": "snap_a",
        "authorized_cidr_id": "c_a",
        "parent_authorized_cidr": "10.0.0.0/24",
        "method_profile_id": "cidr_syn_v1",
        "outcome": "no_response",
        "idempotency_key": "mh:10.0.0.5",
        "created_at": _TS,
    }
    row.update(overrides)
    _insert(conn, "address_audit", **row)


def _d0_audit(conn, **overrides):
    """Insert a valid D0-path (hostname) AddressAudit unless a field is overridden."""
    row = {
        "id": "aa_d0",
        "scan_run_id": "run_a",
        "engagement_id": "eng_a",
        "candidate_ip": "10.0.0.9",
        "authorization_snapshot_id": "snap_a",
        "authorized_target_id": "t_a",
        "source_hostname": "host.example.com",
        "method_profile_id": "dns_connect_bind_v1",
        "outcome": "live",
        "idempotency_key": "snap_a:t_a:10.0.0.9",
        "created_at": _TS,
    }
    row.update(overrides)
    _insert(conn, "address_audit", **row)


@pytest.fixture()
def db(tmp_path):
    path = tmp_path / "authz.db"
    _alembic(path, _HEAD)
    return path


# --------------------------------------------------------------------------- #
# structure
# --------------------------------------------------------------------------- #
def test_authz_boundary_upgrades_and_downgrades(tmp_path):
    path = tmp_path / "authz.db"
    _alembic(path, _PRIOR_HEAD)
    _alembic(path, _HEAD)
    with _connect(path) as conn:
        names = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        assert {
            "authorization_snapshot", "authorized_cidr", "authorized_target",
            "authorization_amendment", "retention_artifact", "liveness_attestation",
            "candidate_manifest", "candidate_manifest_entry", "address_audit",
            "audit_retention_export",
        } <= names
        ev_cols = {r[1] for r in conn.execute("PRAGMA table_info(evidence)")}
        assert "liveness_attestation_id" in ev_cols
        aa_cols = {r[1] for r in conn.execute("PRAGMA table_info(address_audit)")}
        assert "manifest_entry_id" in aa_cols

    _alembic(path, _PRIOR_HEAD, direction="downgrade")
    with _connect(path) as conn:
        names = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        assert "authorization_snapshot" not in names
        assert "address_audit" not in names
        ev_cols = {r[1] for r in conn.execute("PRAGMA table_info(evidence)")}
        assert "liveness_attestation_id" not in ev_cols


def test_authz_boundary_keeps_single_head():
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    script = ScriptDirectory.from_config(Config(str(_ROOT / "alembic.ini")))
    assert script.get_heads() == [_HEAD]


def test_seed_graph_is_valid(db):
    """The baseline the negative cases mutate must itself insert cleanly."""
    with _connect(db) as conn:
        _seed(conn)
        _cidr_audit(conn)
        _d0_audit(conn)
        conn.commit()
        assert conn.execute("SELECT COUNT(*) FROM address_audit").fetchone()[0] == 2


# --------------------------------------------------------------------------- #
# B2 - audit evidence survives deletion (RESTRICT everywhere)
# --------------------------------------------------------------------------- #
def test_engagement_delete_blocked_by_retained_address_audit(db):
    with _connect(db) as conn:
        _seed(conn)
        _cidr_audit(conn)
        conn.commit()
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("DELETE FROM engagement WHERE id = 'eng_a'")


def test_scan_run_delete_blocked_by_retained_snapshot(db):
    with _connect(db) as conn:
        _seed(conn)
        conn.commit()
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("DELETE FROM scan_run WHERE id = 'run_a'")


def test_snapshot_delete_blocked_by_attestation(db):
    with _connect(db) as conn:
        _seed(conn)
        _insert(
            conn, "liveness_attestation",
            id="la1", scan_run_id="run_a", engagement_id="eng_a", evidence_id="ev_a",
            content_hash="ch", method_profile_id="dns_connect_bind_v1", observed_at=_TS,
            observed_ip="10.0.0.9", emitting_module="dns",
            authorization_snapshot_id="snap_a", authorized_target_id="t_a",
            source_hostname="host.example.com", outcome="live", created_at=_TS,
        )
        conn.commit()
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("DELETE FROM authorization_snapshot WHERE id = 'snap_a'")


def test_manifest_entry_delete_blocked_by_retained_audit(db):
    with _connect(db) as conn:
        _seed(conn)
        _cidr_audit(conn)
        conn.commit()
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("DELETE FROM candidate_manifest_entry WHERE id = 'e_a'")


# --------------------------------------------------------------------------- #
# B1 - exactly-one authorization reference
# --------------------------------------------------------------------------- #
def test_address_audit_rejects_both_authz_refs_null(db):
    with _connect(db) as conn:
        _seed(conn)
        with pytest.raises(sqlite3.IntegrityError):
            _cidr_audit(conn, authorized_cidr_id=None, parent_authorized_cidr=None,
                        manifest_id=None, manifest_entry_id=None)


def test_address_audit_rejects_both_authz_refs_set(db):
    with _connect(db) as conn:
        _seed(conn)
        with pytest.raises(sqlite3.IntegrityError):
            _cidr_audit(conn, authorized_target_id="t_a", source_hostname="host.example.com")


def test_liveness_rejects_both_authz_refs_null(db):
    with _connect(db) as conn:
        _seed(conn)
        with pytest.raises(sqlite3.IntegrityError):
            _insert(
                conn, "liveness_attestation",
                id="la_bad", scan_run_id="run_a", engagement_id="eng_a",
                evidence_id="ev_a", content_hash="ch",
                method_profile_id="dns_connect_bind_v1", observed_at=_TS,
                observed_ip="10.0.0.9", emitting_module="dns",
                authorization_snapshot_id="snap_a", outcome="live", created_at=_TS,
            )


# --------------------------------------------------------------------------- #
# B1 - value composite FKs (denormalised value == referenced canonical value)
# --------------------------------------------------------------------------- #
def test_address_audit_rejects_forged_parent_cidr(db):
    with _connect(db) as conn:
        _seed(conn)
        with pytest.raises(sqlite3.IntegrityError):
            _cidr_audit(conn, parent_authorized_cidr="172.16.0.0/24")


def test_liveness_rejects_forged_source_hostname(db):
    with _connect(db) as conn:
        _seed(conn)
        with pytest.raises(sqlite3.IntegrityError):
            _insert(
                conn, "liveness_attestation",
                id="la_bad", scan_run_id="run_a", engagement_id="eng_a",
                evidence_id="ev_a", content_hash="ch",
                method_profile_id="dns_connect_bind_v1", observed_at=_TS,
                observed_ip="10.0.0.9", emitting_module="dns",
                authorization_snapshot_id="snap_a", authorized_target_id="t_a",
                source_hostname="evil.example.com", outcome="live", created_at=_TS,
            )


# --------------------------------------------------------------------------- #
# B1 round 2 - snapshot ownership + run/engagement binding
# --------------------------------------------------------------------------- #
def test_address_audit_rejects_cidr_id_from_other_snapshot(db):
    with _connect(db) as conn:
        _seed(conn)
        # c_b belongs to snap_b; this row names snap_a.
        with pytest.raises(sqlite3.IntegrityError):
            _cidr_audit(conn, authorized_cidr_id="c_b")


def test_address_audit_rejects_snapshot_from_other_run(db):
    with _connect(db) as conn:
        _seed(conn)
        # snap_b belongs to run_b; this row is on run_a.
        with pytest.raises(sqlite3.IntegrityError):
            _cidr_audit(conn, authorization_snapshot_id="snap_b")


def test_address_audit_rejects_snapshot_from_other_engagement(db):
    with _connect(db) as conn:
        _seed(conn)
        with pytest.raises(sqlite3.IntegrityError):
            _cidr_audit(conn, engagement_id="eng_b")


# --------------------------------------------------------------------------- #
# B1 round 3 - manifest -> run chain header FKs
# --------------------------------------------------------------------------- #
def test_manifest_rejects_snapshot_from_other_run(db):
    with _connect(db) as conn:
        _seed(conn)
        with pytest.raises(sqlite3.IntegrityError):
            _insert(
                conn, "candidate_manifest",
                id="m_bad", scan_run_id="run_a", scan_module_run_id="smr_a",
                authorization_snapshot_id="snap_b",  # snap_b is run_b's
                manifest_hash="mh2", total_addresses=1, probeable_addresses=1,
                excluded_addresses=0, policy_version="p1",
                method_profile_id="cidr_syn_v1", created_at=_TS,
            )


def test_manifest_entry_rejects_snapshot_diff_from_its_manifest(db):
    with _connect(db) as conn:
        _seed(conn)
        with pytest.raises(sqlite3.IntegrityError):
            _insert(
                conn, "candidate_manifest_entry",
                id="e_bad", manifest_id="m_a",
                authorization_snapshot_id="snap_b",  # m_a is snap_a's
                candidate_ip="10.0.0.6", authorized_cidr_id="c_b",
                parent_authorized_cidr="10.0.0.0/24", excluded=0, created_at=_TS,
            )


def test_cidr_audit_rejects_manifest_snapshot_diff_from_audit_snapshot(db):
    with _connect(db) as conn:
        _seed(conn)
        # a second manifest legitimately owned by snap_b/run_b
        _insert(
            conn, "scan_module_run", id="smr_b", scan_run_id="run_b",
            engagement_id="eng_b", module_name="host_discovery", phase="active",
            status="running", order_index=0, evidence_count=0, error_count=0,
            coverage_metadata="{}",
        )
        _insert(
            conn, "candidate_manifest", id="m_b", scan_run_id="run_b",
            scan_module_run_id="smr_b", authorization_snapshot_id="snap_b",
            manifest_hash="mhb", total_addresses=1, probeable_addresses=1,
            excluded_addresses=0, policy_version="p1",
            method_profile_id="cidr_syn_v1", created_at=_TS,
        )
        _insert(
            conn, "candidate_manifest_entry", id="e_b", manifest_id="m_b",
            authorization_snapshot_id="snap_b", candidate_ip="10.0.0.5",
            authorized_cidr_id="c_b", parent_authorized_cidr="10.0.0.0/24",
            excluded=0, created_at=_TS,
        )
        conn.commit()
        # audit row claims snap_a/run_a but points at m_b/e_b (snap_b/run_b)
        with pytest.raises(sqlite3.IntegrityError):
            _cidr_audit(conn, manifest_id="m_b", manifest_entry_id="e_b")


# --------------------------------------------------------------------------- #
# B1 round 2 - manifest-entry pins on the audit row
# --------------------------------------------------------------------------- #
def test_cidr_audit_rejects_entry_with_wrong_ip(db):
    with _connect(db) as conn:
        _seed(conn)
        with pytest.raises(sqlite3.IntegrityError):
            _cidr_audit(conn, candidate_ip="10.0.0.99")  # e_a is for 10.0.0.5


def test_cidr_audit_requires_manifest_entry_id(db):
    with _connect(db) as conn:
        _seed(conn)
        with pytest.raises(sqlite3.IntegrityError):
            _cidr_audit(conn, manifest_entry_id=None)


# --------------------------------------------------------------------------- #
# B2 round 2 - retention bundle survival FK
# --------------------------------------------------------------------------- #
def _export(conn, **overrides):
    row = {
        "id": "ex1", "engagement_id": "eng_a", "exported_by_user_id": "u1",
        "exported_at": _TS, "reason": "retention", "bundle_artifact_id": "ra1",
        "bundle_artifact_sha256": "deadbeef", "snapshot_count": 1, "manifest_count": 1,
        "address_audit_count": 1, "attestation_count": 0, "manifest_hashes": "[]",
        "created_at": _TS,
    }
    row.update(overrides)
    _insert(conn, "audit_retention_export", **row)


def test_retention_export_valid_insert(db):
    with _connect(db) as conn:
        _seed(conn)
        _export(conn)
        conn.commit()
        assert conn.execute(
            "SELECT bundle_artifact_sha256 FROM audit_retention_export"
        ).fetchone() == ("deadbeef",)


def test_retention_export_rejects_sha_mismatch(db):
    with _connect(db) as conn:
        _seed(conn)
        with pytest.raises(sqlite3.IntegrityError):
            _export(conn, bundle_artifact_sha256="0000")


def test_retention_artifact_delete_blocked_by_export(db):
    with _connect(db) as conn:
        _seed(conn)
        _export(conn)
        conn.commit()
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("DELETE FROM retention_artifact WHERE id = 'ra1'")


def test_audit_retention_export_has_no_engagement_fk(db):
    """The export row and its bundle outlive the engagement (no FK to purge)."""
    with _connect(db) as conn:
        _seed(conn)
        _export(conn)
        conn.commit()
        # remove every forensic row for eng_a children-first, then the engagement
        conn.execute("DELETE FROM candidate_manifest_entry WHERE manifest_id = 'm_a'")
        conn.execute("DELETE FROM candidate_manifest WHERE id = 'm_a'")
        conn.execute("DELETE FROM authorized_cidr WHERE snapshot_id = 'snap_a'")
        conn.execute("DELETE FROM authorized_target WHERE snapshot_id = 'snap_a'")
        conn.execute("DELETE FROM authorization_snapshot WHERE id = 'snap_a'")
        conn.execute("DELETE FROM scan_module_run WHERE id = 'smr_a'")
        conn.execute("DELETE FROM evidence WHERE id = 'ev_a'")
        conn.execute("DELETE FROM scan_run WHERE id = 'run_a'")
        conn.execute("DELETE FROM engagement WHERE id = 'eng_a'")
        conn.commit()
        row = conn.execute(
            "SELECT engagement_id, bundle_artifact_sha256 FROM audit_retention_export"
        ).fetchone()
        assert row == ("eng_a", "deadbeef")


# --------------------------------------------------------------------------- #
# NULL / MATCH SIMPLE behaviour (Security round-2 explicit ask)
# --------------------------------------------------------------------------- #
def test_valid_cidr_and_d0_audits_both_insert(db):
    """The unused authorization branch is all-NULL, so MATCH SIMPLE skips its
    composite FKs - both shapes insert cleanly with foreign_keys = ON."""
    with _connect(db) as conn:
        _seed(conn)
        _cidr_audit(conn)
        _d0_audit(conn)
        conn.commit()
        outcomes = {r[0] for r in conn.execute("SELECT outcome FROM address_audit")}
        assert outcomes == {"no_response", "live"}


def test_d0_audit_rejects_target_id_from_other_snapshot(db):
    with _connect(db) as conn:
        _seed(conn)
        with pytest.raises(sqlite3.IntegrityError):
            _d0_audit(conn, authorized_target_id="t_b")  # t_b is snap_b's
