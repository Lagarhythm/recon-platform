"""Safe execution of external recon binaries (nmap, ffuf).

Commands are always run as an argv list via ``create_subprocess_exec`` - never
through a shell - so there is no command-injection surface. Every invocation is
time-boxed and the process tree is killed on timeout.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import signal
from dataclasses import dataclass


class BinaryNotFound(RuntimeError):
    pass


class CommandTimeout(RuntimeError):
    pass


@dataclass
class CommandResult:
    argv: list[str]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False


def find_binary(name: str) -> str | None:
    return shutil.which(name)


def require_binary(name: str) -> str:
    path = shutil.which(name)
    if not path:
        raise BinaryNotFound(
            f"required binary {name!r} not found on PATH - install it or "
            f"deselect the module that needs it"
        )
    return path


async def run_command(
    argv: list[str],
    *,
    timeout: float = 300.0,
    stdin: bytes | None = None,
    max_output_bytes: int = 32 * 1024 * 1024,
) -> CommandResult:
    if not argv:
        raise ValueError("empty argv")
    # On POSIX, put the child in its own session so a timeout kills the whole
    # process tree, not just the direct child.
    kwargs: dict = {}
    if os.name == "posix":
        kwargs["start_new_session"] = True
    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdin=asyncio.subprocess.PIPE if stdin is not None else None,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        **kwargs,
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(input=stdin), timeout=timeout)
    except asyncio.TimeoutError:
        _kill_tree(proc)
        with _suppress():
            await proc.wait()
        return CommandResult(argv, -1, "", "", timed_out=True)
    return CommandResult(
        argv=argv,
        returncode=proc.returncode if proc.returncode is not None else -1,
        stdout=out[:max_output_bytes].decode("utf-8", errors="replace"),
        stderr=err[:max_output_bytes].decode("utf-8", errors="replace"),
    )


def _kill_tree(proc: asyncio.subprocess.Process) -> None:
    if proc.returncode is not None:
        return
    if os.name == "posix":
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            return
        except (ProcessLookupError, PermissionError, OSError):
            pass
    with _suppress():
        proc.kill()


class _suppress:
    def __enter__(self):  # noqa: ANN204
        return self

    def __exit__(self, *exc):  # noqa: ANN002
        return True
