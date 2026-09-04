"""``recon`` CLI command wiring (PRD Section 12).

``recon/__main__.py`` calls :func:`register` to graft these subparsers onto the
existing ``recon`` argument parser, so ``recon engagement list`` and
``recon serve`` share one entrypoint.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path
from typing import Any, Awaitable, Callable

from recon.cli.client import ReconClient, build_client
from recon.cli.output import (
    EXIT_MODULE_FAILURES,
    EXIT_OK,
    EXIT_SCAN_FAILED,
    EXIT_USER_ERROR,
    CliError,
    emit_json,
    print_result,
)

Handler = Callable[[ReconClient, argparse.Namespace], Awaitable[int]]


# ---------------------------------------------------------------------------
# runner
# ---------------------------------------------------------------------------
def _server(args: argparse.Namespace) -> str | None:
    from recon.config import get_settings

    return args.server or get_settings().server_url or None


def _token(args: argparse.Namespace) -> str | None:
    from recon.config import get_settings

    return args.token or get_settings().api_token or None


def _run(handler: Handler) -> Callable[[argparse.Namespace], int]:
    def _entry(args: argparse.Namespace) -> int:
        async def _main() -> int:
            client = build_client(_server(args), _token(args))
            try:
                return await handler(client, args)
            finally:
                await client.aclose()

        try:
            return asyncio.run(_main())
        except CliError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return exc.exit_code
        except KeyboardInterrupt:
            print("interrupted", file=sys.stderr)
            return EXIT_USER_ERROR

    return _entry


def _out(args: argparse.Namespace, data: Any, columns: list[str] | None = None) -> None:
    print_result(data, as_json=args.json, table_columns=columns)


# ---------------------------------------------------------------------------
# engagement
# ---------------------------------------------------------------------------
async def _engagement_create(client: ReconClient, args: argparse.Namespace) -> int:
    roe_path = Path(args.roe)
    if not roe_path.is_file():
        raise CliError(f"RoE file not found: {args.roe}")
    result = await client.engagement_create(roe_path.read_text("utf-8"), args.name)
    advisories = result.get("advisories") or []
    if args.json:
        emit_json(result)
    else:
        print_result({k: v for k, v in result.items() if k != "advisories"}, as_json=False)
        for w in advisories:
            print(f"  advisory: {w}", file=sys.stderr)
    return EXIT_OK


async def _engagement_list(client: ReconClient, args: argparse.Namespace) -> int:
    rows = await client.engagement_list(include_archived=not args.active_only)
    _out(args, rows, ["id", "name", "client", "status", "roe_hash", "created_at"])
    return EXIT_OK


async def _engagement_show(client: ReconClient, args: argparse.Namespace) -> int:
    _out(args, await client.engagement_show(args.id))
    return EXIT_OK


async def _engagement_archive(client: ReconClient, args: argparse.Namespace) -> int:
    _out(args, await client.engagement_set_status(args.id, "archived"))
    return EXIT_OK


async def _engagement_purge(client: ReconClient, args: argparse.Namespace) -> int:
    show = await client.engagement_show(args.id)
    if args.older_than is not None:
        created = show.get("created_at") or ""
        from datetime import datetime, timezone

        try:
            age_days = (datetime.now(timezone.utc) - datetime.fromisoformat(created)).days
        except ValueError:
            age_days = 0
        if age_days < args.older_than:
            raise CliError(
                f"engagement is {age_days}d old, younger than --older-than {args.older_than}d; "
                "refusing to purge."
            )
    if args.export_first:
        blob = await client.report(args.id, "json", redacted=False)
        Path(args.export_first).write_bytes(blob)
        print(f"exported to {args.export_first}", file=sys.stderr)
    elif not args.yes:
        confirm = input(
            f"Permanently delete engagement '{show.get('name')}' and ALL its data? type the name: "
        )
        if confirm.strip() != show.get("name"):
            raise CliError("purge aborted: typed name did not match")
    _out(args, await client.engagement_purge(args.id, show.get("name")))
    return EXIT_OK


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------
async def _select_modules(client: ReconClient, args: argparse.Namespace) -> list[str]:
    if args.modules:
        return [m.strip() for m in args.modules.split(",") if m.strip()]
    mods = await client.available_modules()
    if args.all:
        return [m["name"] for m in mods]
    if args.all_passive:
        return [m["name"] for m in mods if m["phase"] in ("osint", "passive")]
    raise CliError("select modules: --modules a,b,c | --all-passive | --all")


def _scan_exit_code(status: dict) -> int:
    st = status.get("status")
    if st == "failed":
        return EXIT_SCAN_FAILED
    mods = status.get("modules") or []
    if st in ("completed", "awaiting_checkpoint", "paused") and any(
        m.get("status") == "failed" for m in mods
    ):
        return EXIT_MODULE_FAILURES
    return EXIT_OK


async def _stream(client: ReconClient, run_id: str) -> None:
    async for event in client.scan_stream(run_id):
        etype = event.get("type", "?")
        detail = " ".join(
            f"{k}={v}" for k, v in event.items() if k != "type"
        )
        print(f"  [{etype}] {detail}".rstrip(), file=sys.stderr)


async def _drive(client: ReconClient, run_id: str, wait: bool) -> dict:
    """After a launch/resume: stream events (``--wait``) or block until the run
    stops (in-process has no daemon; REST returns at once). Then fetch status."""
    if wait:
        await _stream(client, run_id)
    else:
        await client.scan_join(run_id)
    return await client.scan_status(run_id)


async def _scan_start(client: ReconClient, args: argparse.Namespace) -> int:
    modules = await _select_modules(client, args)
    status = await client.scan_start(
        args.engagement, modules,
        allow_out_of_scope=args.allow_out_of_scope,
        yes_active=args.yes_active,
    )
    status = await _drive(client, status["id"], args.wait)
    _out(args, status)
    return _scan_exit_code(status)


async def _scan_status(client: ReconClient, args: argparse.Namespace) -> int:
    status = await client.scan_status(args.run)
    if args.wait and status.get("status") == "running":
        await _stream(client, args.run)
        status = await client.scan_status(args.run)
    _out(args, status)
    return _scan_exit_code(status)


async def _scan_checkpoint(client: ReconClient, args: argparse.Namespace) -> int:
    if not args.approve:
        raise CliError("pass --approve to sign off the passive->active checkpoint")
    await client.scan_checkpoint(args.run)
    status = await _drive(client, args.run, args.wait)
    _out(args, status)
    return _scan_exit_code(status)


async def _scan_resume(client: ReconClient, args: argparse.Namespace) -> int:
    await client.scan_resume(args.run)
    status = await _drive(client, args.run, args.wait)
    _out(args, status)
    return _scan_exit_code(status)


async def _scan_cancel(client: ReconClient, args: argparse.Namespace) -> int:
    _out(args, await client.scan_cancel(args.run))
    return EXIT_OK


async def _scan_list(client: ReconClient, args: argparse.Namespace) -> int:
    rows = await client.scan_list(args.engagement)
    _out(args, rows, ["id", "status", "phase", "started_at", "completed_at"])
    return EXIT_OK


# ---------------------------------------------------------------------------
# report / diff / analyst / cve
# ---------------------------------------------------------------------------
async def _report(client: ReconClient, args: argparse.Namespace) -> int:
    blob = await client.report(args.engagement, args.format, redacted=args.redacted)
    if args.out in (None, "-"):
        sys.stdout.buffer.write(blob)
        if not blob.endswith(b"\n"):
            sys.stdout.buffer.write(b"\n")
    else:
        Path(args.out).write_bytes(blob)
        print(f"wrote {args.out} ({len(blob)} bytes)", file=sys.stderr)
    return EXIT_OK


async def _diff(client: ReconClient, args: argparse.Namespace) -> int:
    _out(args, await client.diff(args.engagement, args.since))
    return EXIT_OK


async def _analyst(client: ReconClient, args: argparse.Namespace) -> int:
    _out(args, await client.analyst_run(args.engagement))
    return EXIT_OK


async def _cve_status(client: ReconClient, args: argparse.Namespace) -> int:
    _out(args, await client.cve_status())
    return EXIT_OK


async def _cve_refresh(client: ReconClient, args: argparse.Namespace) -> int:
    _out(args, await client.cve_refresh(args.source))
    return EXIT_OK


# ---------------------------------------------------------------------------
# token
# ---------------------------------------------------------------------------
async def _token_create(client: ReconClient, args: argparse.Namespace) -> int:
    _out(args, await client.token_create(args.name))
    return EXIT_OK


async def _token_list(client: ReconClient, args: argparse.Namespace) -> int:
    rows = await client.token_list()
    _out(args, rows, ["id", "name", "created_at", "last_used", "revoked"])
    return EXIT_OK


async def _token_revoke(client: ReconClient, args: argparse.Namespace) -> int:
    _out(args, await client.token_revoke(args.id))
    return EXIT_OK


# ---------------------------------------------------------------------------
# registration
# ---------------------------------------------------------------------------
def register(sub: argparse._SubParsersAction) -> None:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--json", action="store_true", help="machine-readable JSON output")
    common.add_argument(
        "--server", metavar="URL",
        help="talk REST to a running dashboard instead of in-process (RECON_SERVER_URL)",
    )
    common.add_argument(
        "--token", metavar="TOKEN",
        help="API token for --server mode (RECON_API_TOKEN)",
    )

    def add(name: str, handler: Handler, help_: str) -> argparse.ArgumentParser:
        p = sub.add_parser(name, parents=[common], help=help_)
        p.set_defaults(func=_run(handler))
        return p

    # -- engagement --------------------------------------------------
    p_eng = sub.add_parser("engagement", help="engagement lifecycle")
    eng_sub = p_eng.add_subparsers(dest="engagement_cmd", required=True)

    def eng(name: str, handler: Handler, help_: str) -> argparse.ArgumentParser:
        p = eng_sub.add_parser(name, parents=[common], help=help_)
        p.set_defaults(func=_run(handler))
        return p

    pe = eng("create", _engagement_create, "create an engagement from an RoE file")
    pe.add_argument("--roe", required=True, metavar="PATH", help="RoE YAML file")
    pe.add_argument("--name", help="override the engagement display name")

    pe = eng("list", _engagement_list, "list engagements")
    pe.add_argument("--active-only", action="store_true", help="hide archived engagements")

    pe = eng("show", _engagement_show, "show one engagement with asset/run stats")
    pe.add_argument("id")

    pe = eng("archive", _engagement_archive, "archive an engagement")
    pe.add_argument("id")

    pe = eng("purge", _engagement_purge, "permanently delete an engagement and its data")
    pe.add_argument("id")
    pe.add_argument("--older-than", type=int, metavar="DAYS",
                    help="only purge if the engagement is at least this many days old")
    pe.add_argument("--export-first", metavar="PATH",
                    help="write a JSON export to PATH before deleting (satisfies the gate)")
    pe.add_argument("--yes", action="store_true", help="skip the typed-name confirmation")

    # -- scan --------------------------------------------------------
    p_scan = sub.add_parser("scan", help="scan control")
    scan_sub = p_scan.add_subparsers(dest="scan_cmd", required=True)

    def scan(name: str, handler: Handler, help_: str) -> argparse.ArgumentParser:
        p = scan_sub.add_parser(name, parents=[common], help=help_)
        p.set_defaults(func=_run(handler))
        return p

    ps = scan("start", _scan_start, "start a scan")
    ps.add_argument("--engagement", required=True)
    ps.add_argument("--modules", help="comma-separated module names")
    ps.add_argument("--all-passive", dest="all_passive", action="store_true",
                    help="every osint + passive module")
    ps.add_argument("--all", action="store_true", help="every module")
    ps.add_argument("--allow-out-of-scope", dest="allow_out_of_scope", action="store_true")
    ps.add_argument("--wait", action="store_true", help="stream progress until it stops")
    ps.add_argument("--yes-active", dest="yes_active", action="store_true",
                    help="pre-authorise the passive->active checkpoint (still audited)")

    ps = scan("status", _scan_status, "show a run's phase + per-module table")
    ps.add_argument("--run", required=True)
    ps.add_argument("--wait", action="store_true", help="stream until the run stops")

    ps = scan("checkpoint", _scan_checkpoint, "sign off the passive->active checkpoint")
    ps.add_argument("--run", required=True)
    ps.add_argument("--approve", action="store_true", required=False)
    ps.add_argument("--wait", action="store_true")

    ps = scan("resume", _scan_resume, "resume a paused run")
    ps.add_argument("--run", required=True)
    ps.add_argument("--wait", action="store_true")

    ps = scan("cancel", _scan_cancel, "request cancellation of a running scan")
    ps.add_argument("--run", required=True)

    ps = scan("list", _scan_list, "list an engagement's scan runs")
    ps.add_argument("--engagement", required=True)

    # -- report / diff / analyst -----------------------------------
    pr = add("report", _report, "generate a report (html|pdf|json|csv)")
    pr.add_argument("--engagement", required=True)
    pr.add_argument("--format", default="html", choices=["html", "pdf", "json", "csv"])
    pr.add_argument("--redacted", action="store_true", help="client-safe redaction pass")
    pr.add_argument("--out", metavar="FILE", help="output file, or - for stdout (default)")

    pd = add("diff", _diff, "diff the asset graph against a prior snapshot")
    pd.add_argument("--engagement", required=True)
    pd.add_argument("--since", metavar="RUN_ID", help="base the diff on this run's snapshot")

    pa = add("analyst", _analyst, "run the LLM analyst (needs llm.analysis_enabled)")
    pa.add_argument("--engagement", required=True)

    # -- cve -------------------------------------------------------
    p_cve = sub.add_parser("cve", help="local CVE index (Wave 2)")
    cve_sub = p_cve.add_subparsers(dest="cve_cmd", required=True)
    pc = cve_sub.add_parser("status", parents=[common], help="CVE index status")
    pc.set_defaults(func=_run(_cve_status))
    pc = cve_sub.add_parser("refresh", parents=[common], help="refresh the CVE index")
    pc.add_argument("--source", choices=["local", "nvd_api"])
    pc.set_defaults(func=_run(_cve_refresh))

    # -- token ----------------------------------------------------
    p_tok = sub.add_parser("token", help="API tokens for CLI / REST auth")
    tok_sub = p_tok.add_subparsers(dest="token_cmd", required=True)
    pt = tok_sub.add_parser("create", parents=[common], help="mint an API token")
    pt.add_argument("--name", required=True, help="label, e.g. 'laptop-cli'")
    pt.set_defaults(func=_run(_token_create))
    pt = tok_sub.add_parser("list", parents=[common], help="list API tokens")
    pt.set_defaults(func=_run(_token_list))
    pt = tok_sub.add_parser("revoke", parents=[common], help="revoke an API token")
    pt.add_argument("id")
    pt.set_defaults(func=_run(_token_revoke))
