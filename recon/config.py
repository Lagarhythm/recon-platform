"""Application configuration.

All settings are overridable via ``RECON_``-prefixed environment variables or a
local ``.env`` file. The LLM block is defined here in Phase 1 but not consumed
until Phase 4 - it must remain a pure config concern so the endpoint can be
swapped without code changes (NFR: LLM connectivity).
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

_PROJECT_ROOT = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="RECON_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- Web / server -----------------------------------------------------
    host: str = "127.0.0.1"
    port: int = 8000
    debug: bool = False

    # Signing key for CSRF tokens and cookie integrity. Auto-generated per
    # install if left unset; set explicitly to keep sessions valid across
    # restarts on a long-lived deployment.
    secret_key: str = Field(default="")

    # --- Data / storage -------------------------------------------------
    data_dir: Path = _PROJECT_ROOT / "data"
    database_url: str = ""  # derived from data_dir if empty

    # --- Artifacts (Wave 0) -------------------------------------------
    # Content-addressed blobs live under `artifacts_dir/<engagement_id>/`,
    # referenced by `Artifact` rows. Per-engagement soft cap triggers a warning
    # (PRD Section 9: artifact storage bounds).
    artifacts_dir: Path = _PROJECT_ROOT / "data" / "artifacts"
    artifact_soft_cap_bytes: int = 2 * 1024 * 1024 * 1024  # 2 GiB per engagement

    # --- Auth / sessions ----------------------------------------------
    session_idle_timeout_minutes: int = 60
    session_cookie_name: str = "recon_session"
    session_cookie_secure: bool = False  # set True behind HTTPS

    # --- LLM Analyst (Phase 4; unused in Phase 1) --------------------
    llm_base_url: str = "http://localhost:8080/v1"
    llm_api_key: str = ""
    llm_model: str = "local-model"
    llm_timeout_seconds: int = 120
    # Upper bound on the analyst's reply. Left unset (0) the remote server's
    # default applies, which some OpenAI-compatible backends cap surprisingly low
    # (a few hundred tokens) - hence a generous explicit default here.
    llm_max_tokens: int = 3000

    # --- OSINT phase ------------------------------------------------
    # Optional GitHub token - raises the API rate limit from 60/hr to 5000/hr.
    osint_github_token: str = ""
    # Search / dorking backend (v2 search module):
    #   off | searxng | google_cse
    search_backend: str = "off"
    searxng_url: str = ""                 # e.g. http://127.0.0.1:8888
    google_cse_key: str = ""
    google_cse_id: str = ""

    # --- Active recon -----------------------------------------------
    # Wordlist for the Directory/File Fuzzer. Defaults to a small bundled list;
    # point at SecLists etc. for real engagements.
    fuzz_wordlist: Path = _PROJECT_ROOT / "recon" / "data" / "wordlists" / "common.txt"
    fuzz_max_paths: int = 4000

    @property
    def resolved_database_url(self) -> str:
        if self.database_url:
            return self.database_url
        return f"sqlite+aiosqlite:///{(self.data_dir / 'recon.db').as_posix()}"

    @property
    def sync_database_url(self) -> str:
        """Blocking driver URL - used by Alembic migrations."""
        return self.resolved_database_url.replace("+aiosqlite", "")

    def ensure_dirs(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        (self.data_dir / "reports").mkdir(exist_ok=True)
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    settings.ensure_dirs()
    if not settings.secret_key:
        key_file = settings.data_dir / ".secret_key"
        if key_file.exists():
            settings.secret_key = key_file.read_text().strip()
        else:
            import secrets

            settings.secret_key = secrets.token_urlsafe(48)
            key_file.write_text(settings.secret_key)
            key_file.chmod(0o600)
    return settings
