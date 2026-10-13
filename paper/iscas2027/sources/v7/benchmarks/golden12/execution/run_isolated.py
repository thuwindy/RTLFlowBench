#!/usr/bin/env python3
"""Run one offline workflow command in a narrow bubblewrap sandbox."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import time
from typing import Any

from jsonschema import Draft202012Validator


RUNNER_ID = "rtlflowbench.bwrap_strace_isolated_runner.v1"
EDA_TOOLS = {
    "compile_or_lint": {
        "iverilog",
        "slang",
        "surelog",
        "verible-verilog-lint",
        "verilator",
        "verilator_bin",
        "vlog",
    },
    "simulation": {
        "simv",
        "vcs",
        "vvp",
        "vsim",
        "xrun",
    },
    "formal": {
        "abc",
        "boolector",
        "sby",
        "yosys-smtbmc",
        "z3",
    },
    "synthesis": {
        "dc_shell",
        "genus",
        "nextpnr",
        "openroad",
        "quartus_sh",
        "vivado",
        "yosys",
    },
}
EXEC_RE = re.compile(
    r"^(?P<timestamp>[0-9]+(?:\.[0-9]+)?) "
    r"execve\(\"(?P<path>(?:\\.|[^\"])*)\".*\) = 0$"
)
CHILD_RE = re.compile(
    r"^(?P<timestamp>[0-9]+(?:\.[0-9]+)?) "
    r"(?:clone|clone3|fork|vfork)\(.*\) = (?P<pid>[0-9]+)$"
)
NETWORK_RE = re.compile(
    r"^(?P<timestamp>[0-9]+(?:\.[0-9]+)?) "
    r"(?:socket|connect|sendto|sendmsg)\("
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _load(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"not a regular JSON file: {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected one JSON object: {path}")
    return value


def _validate_read_only_tree(root: Path, label: str) -> Path:
    root = root.expanduser()
    if root.is_symlink():
        raise ValueError(f"{label} root is a symlink")
    root = root.resolve()
    if not root.is_dir():
        raise ValueError(f"{label} root is not a directory")
    for path in root.rglob("*"):
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode):
            raise ValueError(
                f"{label} contains symlink: {path.relative_to(root)}"
            )
        if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
            raise ValueError(
                f"{label} contains special file: {path.relative_to(root)}"
            )
    return root


def _prepare_empty_directory(path: Path, label: str) -> Path:
    path = path.expanduser()
    if path.is_symlink():
        raise ValueError(f"{label} is a symlink")
    path = path.resolve()
    if path.exists():
        if not path.is_dir() or any(path.iterdir()):
            raise ValueError(f"{label} must be an empty directory")
    else:
        path.mkdir(parents=True)
    return path


def _decode_trace_string(value: str) -> str:
    try:
        decoded = ast.literal_eval(f'"{value}"')
    except (SyntaxError, ValueError):
        return value
    return decoded if isinstance(decoded, str) else value


def parse_trace_files(
    trace_files: list[Path],
) -> dict[str, Any]:
    execs: list[tuple[float, int, str]] = []
    children: dict[int, set[int]] = {}
    network_events: list[tuple[float, int]] = []
    for path in sorted(trace_files):
        try:
            pid = int(path.suffix[1:])
        except ValueError as exc:
            raise ValueError(f"invalid strace file suffix: {path}") from exc
        for raw_line in path.read_text(
            encoding="utf-8",
            errors="replace",
        ).splitlines():
            line = raw_line.strip()
            exec_match = EXEC_RE.match(line)
            if exec_match:
                execs.append(
                    (
                        float(exec_match.group("timestamp")),
                        pid,
                        _decode_trace_string(
                            exec_match.group("path")
                        ),
                    )
                )
                continue
            child_match = CHILD_RE.match(line)
            if child_match:
                children.setdefault(pid, set()).add(
                    int(child_match.group("pid"))
                )
                continue
            network_match = NETWORK_RE.match(line)
            if network_match:
                network_events.append(
                    (
                        float(network_match.group("timestamp")),
                        pid,
                    )
                )

    ordered_execs = sorted(execs)
    supervisor_index = next(
        (
            index
            for index, item in enumerate(ordered_execs)
            if Path(item[2]).name == "bwrap"
        ),
        None,
    )
    workflow_execs = [
        item
        for index, item in enumerate(ordered_execs)
        if index != supervisor_index
    ]
    workflow_pids = {item[1] for item in workflow_execs}
    pending = list(workflow_pids)
    while pending:
        parent = pending.pop()
        for child in children.get(parent, set()):
            if child not in workflow_pids:
                workflow_pids.add(child)
                pending.append(child)
    first_workflow_exec = {
        pid: min(
            timestamp
            for timestamp, exec_pid, _ in workflow_execs
            if exec_pid == pid
        )
        for pid in {item[1] for item in workflow_execs}
    }
    network_attempt_count = sum(
        pid in workflow_pids
        and (
            pid not in first_workflow_exec
            or timestamp >= first_workflow_exec[pid]
        )
        for timestamp, pid in network_events
    )
    commands = [
        executable for _, _, executable in sorted(workflow_execs)
    ]
    eda_calls = {
        category: sum(
            Path(command).name in tools for command in commands
        )
        for category, tools in EDA_TOOLS.items()
    }
    return {
        "process_count": len(commands),
        "observed_commands": commands,
        "eda_calls": eda_calls,
        "network_attempt_count": network_attempt_count,
        "supervisor_exec_count": (
            1 if supervisor_index is not None else 0
        ),
        "trace_file_count": len(trace_files),
    }


def run_isolated(
    *,
    command_path: Path,
    command_schema_path: Path,
    receipt_schema_path: Path,
    task_root: Path,
    repository_root: Path,
    workflow_root: Path,
    artifact_root: Path,
    output_root: Path,
) -> dict[str, Any]:
    command_path = command_path.expanduser().resolve()
    command_schema_path = command_schema_path.expanduser().resolve()
    receipt_schema_path = receipt_schema_path.expanduser().resolve()
    task_root = _validate_read_only_tree(task_root, "task")
    repository_root = _validate_read_only_tree(
        repository_root,
        "repository",
    )
    workflow_root = _validate_read_only_tree(
        workflow_root,
        "workflow",
    )
    artifact_root = _prepare_empty_directory(
        artifact_root,
        "artifact root",
    )
    output_root = output_root.expanduser().resolve()
    if output_root.exists():
        raise FileExistsError(
            f"refusing to overwrite output root: {output_root}"
        )
    output_root.mkdir(parents=True)
    monitor_root = output_root / "monitor"
    monitor_root.mkdir()

    command_schema = _load(command_schema_path)
    receipt_schema = _load(receipt_schema_path)
    command = _load(command_path)
    Draft202012Validator.check_schema(command_schema)
    Draft202012Validator.check_schema(receipt_schema)
    Draft202012Validator(command_schema).validate(command)
    if command["environment"] != {}:
        raise ValueError(
            "isolated command environment must remain empty"
        )

    bwrap = shutil.which("bwrap")
    strace = shutil.which("strace")
    if bwrap is None or strace is None:
        raise RuntimeError("bubblewrap and strace are both required")
    bwrap_path = Path(bwrap).resolve()
    strace_path = Path(strace).resolve()
    python_path = Path("/usr/bin/python3").resolve()
    if (
        command["runtime_profile"] != "python3_stdlib"
        or not python_path.is_file()
        or python_path.parent != Path("/usr/bin")
        or not Path("/usr/lib").is_dir()
        or not Path("/usr/lib64").is_dir()
    ):
        raise RuntimeError(
            "python3_stdlib runtime profile is unavailable"
        )
    trace_prefix = monitor_root / "exec"
    bwrap_argv = [
        str(bwrap_path),
        "--die-with-parent",
        "--new-session",
        "--unshare-all",
        "--dir",
        "/usr",
        "--dir",
        "/usr/bin",
        "--ro-bind",
        str(python_path),
        str(python_path),
        "--symlink",
        python_path.name,
        "/usr/bin/python3",
        "--ro-bind",
        "/usr/lib",
        "/usr/lib",
        "--ro-bind",
        "/usr/lib64",
        "/usr/lib64",
        "--symlink",
        "usr/bin",
        "/bin",
        "--symlink",
        "usr/lib",
        "/lib",
        "--symlink",
        "usr/lib64",
        "/lib64",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
        "--dir",
        "/task",
        "--ro-bind",
        str(task_root),
        "/task",
        "--dir",
        "/repository",
        "--ro-bind",
        str(repository_root),
        "/repository",
        "--dir",
        "/workflow",
        "--ro-bind",
        str(workflow_root),
        "/workflow",
        "--dir",
        "/artifacts",
        "--bind",
        str(artifact_root),
        "/artifacts",
        "--clearenv",
        "--setenv",
        "PATH",
        "/usr/bin:/bin",
        "--setenv",
        "LANG",
        "C.UTF-8",
        "--setenv",
        "LC_ALL",
        "C.UTF-8",
        "--setenv",
        "HOME",
        "/tmp",
        "--chdir",
        "/task",
        *command["argv"],
    ]
    invocation = [
        str(strace_path),
        "-ff",
        "-qq",
        "-ttt",
        "-s",
        "4096",
        "-e",
        "trace=process,network",
        "-o",
        str(trace_prefix),
        *bwrap_argv,
    ]
    _write(
        output_root / "invocation.json",
        {
            "runner_id": RUNNER_ID,
            "argv": invocation,
            "timeout_seconds": command["timeout_seconds"],
            "task_mount": "/task",
            "repository_mount": "/repository",
            "workflow_mount": "/workflow",
            "artifact_mount": "/artifacts",
        },
    )

    timed_out = False
    started = time.monotonic()
    with (
        (output_root / "stdout.log").open("wb") as stdout,
        (output_root / "stderr.log").open("wb") as stderr,
    ):
        process = subprocess.Popen(
            invocation,
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr,
            start_new_session=True,
            env={
                "PATH": os.environ.get("PATH", ""),
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
            },
        )
        try:
            returncode = process.wait(
                timeout=command["timeout_seconds"]
            )
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=2)
            returncode = None
    wall_time_seconds = round(time.monotonic() - started, 6)

    trace_files = sorted(monitor_root.glob("exec.*"))
    if not trace_files:
        raise RuntimeError(
            "strace did not produce process-monitor evidence"
        )
    observed = parse_trace_files(trace_files)
    if timed_out:
        workflow_status = "timeout"
    elif observed["process_count"] == 0 and returncode != 0:
        workflow_status = "infra_error"
    else:
        workflow_status = "completed"
    receipt = {
        "schema_version": "rtlflowbench.g12_execution_receipt.v1",
        "task_id": command["task_id"],
        "provenance": "isolated_runner_process_monitor",
        "runner_id": RUNNER_ID,
        "runner_sha256": _sha256(Path(__file__).resolve()),
        "runtime_profile": command["runtime_profile"],
        "isolation_backend": "bubblewrap_unshare_all",
        "isolation_backend_sha256": _sha256(bwrap_path),
        "monitor_backend": "strace_process_network",
        "monitor_backend_sha256": _sha256(strace_path),
        "monitoring_complete": True,
        "network_isolation_enforced": True,
        "network_access_observed": False,
        "network_attempt_count": observed["network_attempt_count"],
        "workflow_status": workflow_status,
        "workflow_exit_code": (
            returncode if workflow_status == "completed" else None
        ),
        "wall_time_seconds": wall_time_seconds,
        "process_count": observed["process_count"],
        "eda_calls": observed["eda_calls"],
        "observed_commands": observed["observed_commands"],
    }
    Draft202012Validator(receipt_schema).validate(receipt)
    _write(output_root / "execution_receipt.json", receipt)
    _write(
        output_root / "monitor_summary.json",
        {
            **observed,
            "bwrap_sha256": _sha256(bwrap_path),
            "strace_sha256": _sha256(strace_path),
            "command_sha256": _sha256(command_path),
            "command_schema_sha256": _sha256(command_schema_path),
            "receipt_schema_sha256": _sha256(receipt_schema_path),
            "artifact_files": sorted(
                path.relative_to(artifact_root).as_posix()
                for path in artifact_root.rglob("*")
                if path.is_file()
            ),
        },
    )
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--command", type=Path, required=True)
    parser.add_argument("--command-schema", type=Path, required=True)
    parser.add_argument("--receipt-schema", type=Path, required=True)
    parser.add_argument("--task-root", type=Path, required=True)
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--workflow-root", type=Path, required=True)
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = run_isolated(
            command_path=args.command,
            command_schema_path=args.command_schema,
            receipt_schema_path=args.receipt_schema,
            task_root=args.task_root,
            repository_root=args.repository_root,
            workflow_root=args.workflow_root,
            artifact_root=args.artifact_root,
            output_root=args.output_root,
        )
    except Exception as exc:
        print(
            json.dumps(
                {
                    "status": "fail",
                    "error": f"{type(exc).__name__}: {exc}",
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["workflow_status"] == "completed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
