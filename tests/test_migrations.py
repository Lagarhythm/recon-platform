"""Alembic head integrity and upgrade coverage for report metadata."""

from __future__ import annotations

import os
import sqlite3
import subprocess
import sys


def _alembic(db_path, target: str) -> None:
    env = os.environ.copy()
    env["RECON_DATABASE_URL"] = f"sqlite+aiosqlite:///{db_path}"
    env["RECON_DATA_DIR"] = str(db_path.parent / "data")
    env.setdefault("RECON_SECRET_KEY", "migration-test-secret")
    subprocess.run([sys.executable, "-m", "alembic", "upgrade", target],
                   check=True, cwd=str(__import__("pathlib").Path(__file__).parents[1]), env=env)


def test_coverage_metadata_migration_has_one_head_and_upgrades_existing_rows(tmp_path):
    fresh_db = tmp_path / "fresh.db"
    _alembic(fresh_db, "head")
    db_path = tmp_path / "migration.db"
    _alembic(db_path, "f09415133468")
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "INSERT INTO scan_module_run (id, scan_run_id, engagement_id, module_name, phase, status, order_index, evidence_count, error_count) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("module-run", "scan-run", "engagement", "git_secrets", "osint", "completed", 0, 0, 0),
        )
        conn.commit()
    _alembic(db_path, "head")
    with sqlite3.connect(db_path) as conn:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(scan_module_run)")}
        assert "coverage_metadata" in columns
        assert conn.execute("SELECT coverage_metadata FROM scan_module_run WHERE id = 'module-run'").fetchone() == ("{}",)
