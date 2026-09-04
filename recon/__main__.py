"""``recon`` command entrypoint.

Operational:

    recon serve        run the dashboard
    recon init-db      apply database migrations
    recon reset-auth   delete all operator accounts (forces first-run setup again)
    recon version

Operator CLI (PRD Section 12) - thin client over ``recon.orchestrator``,
in-process or ``--server URL``:

    recon engagement create|list|show|archive|purge
    recon scan start|status|checkpoint|resume|cancel|list
    recon report | recon diff | recon analyst
    recon cve refresh|status
    recon token create|list|revoke
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent


def _alembic_config():
    from alembic.config import Config

    cfg = Config(str(_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(_ROOT / "migrations"))
    return cfg


def cmd_init_db(_args: argparse.Namespace) -> int:
    from alembic import command

    command.upgrade(_alembic_config(), "head")
    print("Database is at head revision.")
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    from recon.config import get_settings

    s = get_settings()
    uvicorn.run(
        "recon.main:app",
        host=args.host or s.host,
        port=args.port or s.port,
        reload=args.reload,
    )
    return 0


def cmd_reset_auth(args: argparse.Namespace) -> int:
    import asyncio

    from sqlalchemy import delete

    from recon.db import session_scope
    from recon.models.user import Session, User

    if not args.yes:
        confirm = input("Delete ALL operator accounts and sessions? type 'yes': ")
        if confirm.strip() != "yes":
            print("Aborted.")
            return 1

    async def _run() -> None:
        async with session_scope() as db:
            await db.execute(delete(Session))
            await db.execute(delete(User))

    asyncio.run(_run())
    print("Operator accounts cleared. Restart and visit /setup.")
    return 0


def cmd_version(_args: argparse.Namespace) -> int:
    from recon import __version__

    print(__version__)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="recon")
    sub = parser.add_subparsers(dest="command", required=True)

    p_serve = sub.add_parser("serve", help="run the dashboard")
    p_serve.add_argument("--host")
    p_serve.add_argument("--port", type=int)
    p_serve.add_argument("--reload", action="store_true")
    p_serve.set_defaults(func=cmd_serve)

    sub.add_parser("init-db", help="apply database migrations").set_defaults(func=cmd_init_db)

    p_reset = sub.add_parser("reset-auth", help="delete all operator accounts")
    p_reset.add_argument("--yes", action="store_true", help="skip confirmation")
    p_reset.set_defaults(func=cmd_reset_auth)

    sub.add_parser("version").set_defaults(func=cmd_version)

    from recon.cli.app import register as register_cli

    register_cli(sub)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
