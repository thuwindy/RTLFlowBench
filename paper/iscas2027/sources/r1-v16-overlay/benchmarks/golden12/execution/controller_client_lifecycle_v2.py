#!/usr/bin/env python3
"""Opt-in Linux EDA supervisor; preserves the original controller RPC schema.

A separate supervisor observes the invoking shim with a pidfd. If its caller is
killed, it kills only its own tool process group and settles the admitted EDA
activity. Whole-capsule termination may still require conservative host closure.
This is a new runtime identity; historical clients are unchanged.
"""

from __future__ import annotations

import importlib.util
import os
import secrets
import select
import shlex
import signal
import subprocess
import sys
from pathlib import Path

BASE_PATH = Path(
    os.environ.get(
        "RTLFLOWBENCH_BASE_CONTROLLER_CLIENT",
        str(Path(__file__).with_name("controller_client.py")),
    )
).resolve(strict=True)
if BASE_PATH == Path(__file__).resolve():
    raise ValueError("lifecycle client cannot delegate to itself")
_spec = importlib.util.spec_from_file_location("_lifecycle_base_client", BASE_PATH)
base = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = base
_spec.loader.exec_module(base)


TOOLS = base.TOOLS | {"verilator", "native_sim"}


def __getattr__(name):
    return getattr(base, name)


def _parent_exited(fd: int) -> bool:
    return bool(select.select([fd], [], [], 0)[0])


def _kill_tool_group(process: subprocess.Popen) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait()


def _supervise(parent_pid: int, tool: str, arguments: list[str]) -> int:
    if tool not in TOOLS or not hasattr(os, "pidfd_open"):
        raise RuntimeError("Linux pidfd lifecycle support is required")
    # Compare the actual parent before opening its pidfd to reject a detached or
    # reused numeric PID; the pidfd then remains bound to that exact process.
    if os.getppid() != parent_pid:
        return 125
    try:
        parent_fd = os.pidfd_open(parent_pid, 0)
    except ProcessLookupError:
        return 125
    child = None
    admitted = False
    outcome = "failed"
    socket_path = os.environ["RTLFLOWBENCH_CONTROLLER_SOCKET"]
    session_id = os.environ["RTLFLOWBENCH_CONTROLLER_SESSION"]
    invocation = f"{tool}.{os.getpid()}.{secrets.token_hex(8)}"
    try:
        if _parent_exited(parent_fd):
            return 125
        base._rpc(
            socket_path,
            {
                "schema_version": base.PROTOCOL_VERSION,
                "session_id": session_id,
                "operation": "eda_start",
                "invocation_id": invocation,
                "tool": tool,
            },
        )
        admitted = True
        if _parent_exited(parent_fd):
            return 125
        if tool == "native_sim":
            if not arguments:
                raise ValueError("native simulator executable required")
            executable = Path(arguments[0])
            if not executable.is_absolute() or executable.is_symlink() or not executable.is_file():
                raise ValueError("native simulator must be an absolute regular executable")
            with executable.open("rb") as stream:
                if stream.read(4) != b"\x7fELF":
                    raise ValueError("native simulator must be ELF")
            command = arguments
        else:
            command = [os.environ[f"RTLFLOWBENCH_REAL_{tool.upper()}"], *arguments]
        child = subprocess.Popen(command, start_new_session=True)
        while child.poll() is None:
            if select.select([parent_fd], [], [], 0.05)[0]:
                _kill_tool_group(child)
                return 125
        code = child.returncode
        outcome = "completed" if code == 0 else "failed"
        return code
    finally:
        try:
            if child is not None:
                # Also remove descendants left by an already-exited direct tool.
                _kill_tool_group(child)
        finally:
            os.close(parent_fd)
            if admitted:
                base._rpc(
                    socket_path,
                    {
                        "schema_version": base.PROTOCOL_VERSION,
                        "session_id": session_id,
                        "operation": "eda_finish",
                        "invocation_id": invocation,
                        "outcome": outcome,
                    },
                )


def _run_eda_shim(tool: str) -> int:
    # The supervisor is outside the caller's process group so a public runner
    # killing its timed-out group cannot prevent cleanup and RPC settlement.
    process = subprocess.Popen(
        [
            sys.executable,
            str(Path(__file__).resolve()),
            "--eda-supervise",
            str(os.getpid()),
            tool,
            *sys.argv[1:],
        ],
        start_new_session=True,
    )
    return process.wait()


def _install_shims(shim_root: Path, *, socket_path: str, session_id: str) -> None:
    if shim_root.exists() or shim_root.is_symlink():
        raise FileExistsError("refusing to overwrite EDA shim root")
    shim_root.mkdir(parents=True, mode=0o700)
    for tool in sorted(TOOLS):
        wrapper = shim_root / tool
        wrapper.write_text(
            "#!/bin/sh\n"
            f"RTLFLOWBENCH_CONTROLLER_SOCKET={shlex.quote(socket_path)} "
            f"RTLFLOWBENCH_CONTROLLER_SESSION={shlex.quote(session_id)} "
            f"RTLFLOWBENCH_REAL_{tool.upper()}=/usr/bin/{tool} "
            f"RTLFLOWBENCH_EDA_TOOL={shlex.quote(tool)} exec "
            f"{shlex.quote(sys.executable)} "
            f'{shlex.quote(str(Path(__file__).resolve()))} "$@"\n'
        )
        wrapper.chmod(0o700)


def main() -> int:
    if sys.argv[1:2] == ["--eda-supervise"]:
        return _supervise(int(sys.argv[2]), sys.argv[3], sys.argv[4:])
    tool = os.environ.get("RTLFLOWBENCH_EDA_TOOL") or Path(sys.argv[0]).name
    if tool in TOOLS:
        return _run_eda_shim(tool)
    # Keep the original wrapped-provider policy; this module only changes the
    # explicitly installed EDA shims, not model/budget/feedback permissions.
    base._install_shims = _install_shims
    return base.main()


if __name__ == "__main__":
    raise SystemExit(main())
