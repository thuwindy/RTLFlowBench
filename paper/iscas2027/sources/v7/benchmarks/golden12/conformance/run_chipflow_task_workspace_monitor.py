#!/usr/bin/env python3
"""Run the G01 public visible suite under an external process/network monitor.

The native ChipFlow model-provider control plane stays outside this boundary.
Only the command that consumes generated task-workspace RTL is placed in an
offline bubblewrap namespace and traced by the host.  The resulting compact
receipt is consumed by the neutral ChipFlow attempt finalizer.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import signal
import shlex
import subprocess
import time
from typing import Any


TASK_ID = "G01-common-fifo-spec"
SUITE_ID = "g01-visible-directed-v1-development"
MONITOR_ID = "rtlflowbench.bwrap_strace_task_workspace_monitor.v1"
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
    r'execve\("(?P<path>(?:\\.|[^"])*)".*\) = 0$'
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


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _write_new_json(path: Path, value: Any) -> None:
    if path.exists() or path.is_symlink():
        raise FileExistsError(f"refusing to overwrite output: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    if temporary.exists() or temporary.is_symlink():
        raise FileExistsError(
            f"temporary monitor output already exists: {temporary}"
        )
    temporary.write_bytes(_canonical_json(value))
    os.replace(temporary, path)


def _tree_digest(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    total_bytes = 0
    for candidate in sorted(path.rglob("*")):
        if candidate.is_symlink():
            raise ValueError(
                f"previous monitor output contains a symlink: {candidate}"
            )
        if not candidate.is_file():
            continue
        relative = candidate.relative_to(path).as_posix()
        raw = candidate.read_bytes()
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(raw).digest())
        total_bytes += len(raw)
    return digest.hexdigest(), total_bytes


def _archive_previous_attempt_outputs(
    *,
    run_root: Path,
    output_root: Path,
    monitor_root: Path,
    receipt_output: Path,
) -> str | None:
    """Preserve one completed prior monitor attempt before a Debug rerun."""

    run_root = run_root.expanduser().resolve(strict=True)
    raw_eda_path = run_root / "raw_eda_results.json"
    candidates = {
        "visible_output": output_root.expanduser().resolve(),
        "monitor_output": monitor_root.expanduser().resolve(),
        "monitor_receipt": receipt_output.expanduser().resolve(),
        "raw_eda_results": raw_eda_path.resolve(),
    }
    present = {
        label: path.exists() or path.is_symlink()
        for label, path in candidates.items()
    }
    if not any(present.values()):
        return None
    if not all(present.values()):
        raise FileExistsError(
            "previous task-workspace monitor attempt is incomplete; "
            f"refusing retry archive: {present}"
        )

    manifest_entries: list[dict[str, Any]] = []
    for label, path in candidates.items():
        if path.is_symlink() or not path.is_relative_to(run_root):
            raise ValueError(
                f"previous {label} is unsafe or escaped the run root"
            )
        if label in {"visible_output", "monitor_output"}:
            if not path.is_dir():
                raise ValueError(
                    f"previous {label} must be a directory"
                )
            digest, size_bytes = _tree_digest(path)
            kind = "directory"
        else:
            if not path.is_file():
                raise ValueError(
                    f"previous {label} must be a regular file"
                )
            digest = _sha256(path)
            size_bytes = path.stat().st_size
            kind = "file"
        manifest_entries.append(
            {
                "label": label,
                "original_path": path.relative_to(
                    run_root
                ).as_posix(),
                "kind": kind,
                "sha256": digest,
                "size_bytes": size_bytes,
            }
        )

    archive_key = hashlib.sha256(
        _canonical_json(manifest_entries)
    ).hexdigest()[:24]
    archive_root = (
        run_root
        / "verification/task_workspace_attempt_history"
        / archive_key
    )
    if archive_root.exists() or archive_root.is_symlink():
        raise FileExistsError(
            f"previous monitor archive already exists: {archive_root}"
        )
    archive_root.mkdir(parents=True)
    for entry in manifest_entries:
        source = run_root / entry["original_path"]
        target = archive_root / entry["label"]
        os.replace(source, target)
        entry["archived_path"] = target.relative_to(
            run_root
        ).as_posix()
    _write_new_json(
        archive_root / "archive_manifest.json",
        {
            "schema_version": (
                "rtlflowbench.task_workspace_attempt_archive.v1"
            ),
            "archive_key": archive_key,
            "artifacts": manifest_entries,
            "reason": (
                "Preserved completed prior task-workspace evidence "
                "before an evidence-bound Debug rerun."
            ),
        },
    )
    return archive_root.relative_to(run_root).as_posix()


def _decode_trace_string(value: str) -> str:
    try:
        decoded = ast.literal_eval(f'"{value}"')
    except (SyntaxError, ValueError):
        return value
    return decoded if isinstance(decoded, str) else value


def parse_trace_files(trace_files: list[Path]) -> dict[str, Any]:
    """Summarize only processes descended from the sandboxed visible suite."""

    execs: list[tuple[float, int, str]] = []
    children: dict[int, set[int]] = {}
    network_events: list[tuple[float, int]] = []
    for path in sorted(trace_files):
        try:
            pid = int(path.suffix[1:])
        except ValueError as exc:
            raise ValueError(
                f"invalid strace file suffix: {path.name}"
            ) from exc
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
        executable for _, _, executable in workflow_execs
    ]
    command_names = [Path(command).name for command in commands]
    eda_calls = {
        category: sum(
            command_name in tools
            for command_name in command_names
        )
        for category, tools in EDA_TOOLS.items()
    }
    known_eda_names = set().union(*EDA_TOOLS.values())
    generated_verilator_simulations = sum(
        PurePosixPath(command).is_relative_to(PurePosixPath("/output"))
        and PurePosixPath(command).parent.suffix == ".obj"
        and Path(command).name not in known_eda_names
        for command in commands
    )
    eda_calls["simulation"] += generated_verilator_simulations
    # `verilator` is a Perl launcher that normally execs `verilator_bin`
    # more than once, including a capability probe. The public runner records
    # the launcher as one logical EDA call. When that launcher is present,
    # observed `verilator_bin` execs are implementation details rather than
    # additional workflow calls. A direct `verilator_bin` invocation remains
    # countable when no launcher was observed.
    if "verilator" in command_names:
        eda_calls["compile_or_lint"] -= command_names.count(
            "verilator_bin"
        )
    return {
        "process_count": len(commands),
        "observed_commands": commands,
        "eda_calls": eda_calls,
        "network_attempt_count": network_attempt_count,
        "trace_file_count": len(trace_files),
        "supervisor_exec_count": (
            1 if supervisor_index is not None else 0
        ),
    }


def _safe_directory_below(
    run_root: Path,
    candidate: Path,
    *,
    label: str,
    must_exist: bool,
) -> Path:
    if candidate.is_symlink():
        raise ValueError(f"{label} must not be a symlink")
    resolved = candidate.expanduser().resolve()
    if not resolved.is_relative_to(run_root):
        raise ValueError(f"{label} escaped the ChipFlow run root")
    if must_exist and not resolved.is_dir():
        raise ValueError(f"{label} is not a directory")
    current = run_root
    for part in resolved.relative_to(run_root).parts:
        current = current / part
        if current.is_symlink():
            raise ValueError(f"{label} contains a symlink component")
    return resolved


def _preflight(
    *,
    run_root: Path,
    workspace: Path,
    visible_root: Path,
    output_root: Path,
    monitor_root: Path,
    receipt_output: Path,
) -> tuple[Path, Path, Path, Path, Path, Path, Path]:
    if run_root.is_symlink():
        raise ValueError("ChipFlow run root must not be a symlink")
    run_root = run_root.expanduser().resolve(strict=True)
    if not run_root.is_dir():
        raise ValueError("ChipFlow run root is not a directory")
    workspace = _safe_directory_below(
        run_root,
        workspace,
        label="task workspace",
        must_exist=True,
    )
    visible_root = _safe_directory_below(
        run_root,
        visible_root,
        label="public visible runner root",
        must_exist=True,
    )
    required_public = (
        "runner.py",
        "verdict.py",
        "g01_visible_tb.sv",
        "g01_invalid_parameter_probe.sv",
    )
    for name in required_public:
        source = visible_root / name
        if source.is_symlink() or not source.is_file():
            raise ValueError(
                f"public visible runner asset is missing: {name}"
            )
    rtl = workspace / "rtl/golden12_fifo.sv"
    if rtl.is_symlink() or not rtl.is_file():
        raise ValueError(
            "generated task workspace lacks rtl/golden12_fifo.sv"
        )
    output_root = _safe_directory_below(
        run_root,
        output_root,
        label="visible output root",
        must_exist=False,
    )
    monitor_root = _safe_directory_below(
        run_root,
        monitor_root,
        label="monitor output root",
        must_exist=False,
    )
    receipt_output = receipt_output.expanduser().resolve()
    if not receipt_output.is_relative_to(run_root):
        raise ValueError("monitor receipt escaped the ChipFlow run root")
    if (
        output_root.exists()
        or monitor_root.exists()
        or receipt_output.exists()
        or receipt_output.is_symlink()
    ):
        raise FileExistsError(
            "visible, monitor, and receipt outputs must be new"
        )
    bwrap = shutil.which("bwrap")
    strace = shutil.which("strace")
    if bwrap is None or strace is None:
        raise RuntimeError("bubblewrap and strace are both required")
    return (
        run_root,
        workspace,
        visible_root,
        output_root,
        monitor_root,
        Path(bwrap).resolve(),
        Path(strace).resolve(),
    )


def build_bwrap_argv(
    *,
    bwrap: Path,
    workspace: Path,
    visible_root: Path,
    output_root: Path,
    command_timeout_seconds: int,
) -> list[str]:
    """Build the fixed, offline G01 public-visible invocation."""

    return [
        str(bwrap),
        "--die-with-parent",
        "--new-session",
        "--unshare-all",
        "--ro-bind",
        "/usr",
        "/usr",
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
        "/visible",
        "--ro-bind",
        str(visible_root),
        "/visible",
        "--dir",
        "/submission",
        "--ro-bind",
        str(workspace),
        "/submission",
        "--dir",
        "/output",
        "--bind",
        str(output_root),
        "/output",
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
        "/submission",
        "/usr/bin/python3",
        "/visible/runner.py",
        "--submission-root",
        "/submission",
        "--output-dir",
        "/output",
        "--iverilog",
        "/usr/bin/iverilog",
        "--vvp",
        "/usr/bin/vvp",
        "--command-timeout-seconds",
        str(command_timeout_seconds),
    ]


def _terminate_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=2)


def _raw_eda_results(
    visible_result: dict[str, Any],
) -> dict[str, Any]:
    """Project the public runner's real child processes into usage evidence."""

    results: list[dict[str, Any]] = []

    def add_process(process: Any) -> None:
        if not isinstance(process, dict):
            return
        argv = process.get("argv")
        if (
            not isinstance(argv, list)
            or not argv
            or not all(isinstance(item, str) for item in argv)
        ):
            raise ValueError(
                "visible runner process evidence has invalid argv"
            )
        process_status = process.get("process_status")
        exit_code = process.get("exit_code")
        if process_status == "timeout":
            status = "timeout"
        elif process_status == "infra_error":
            status = "infra_error"
        elif exit_code == 0:
            status = "pass"
        else:
            status = "fail"
        duration = process.get("wall_time_seconds")
        results.append(
            {
                "command": shlex.join(argv),
                "cwd": str(process.get("cwd") or "/submission"),
                "exit_code": (
                    exit_code if isinstance(exit_code, int) else None
                ),
                "duration_sec": (
                    float(duration)
                    if isinstance(duration, (int, float))
                    else 0.0
                ),
                "status": status,
            }
        )

    checks = visible_result.get("checks")
    if not isinstance(checks, list):
        raise ValueError("visible result has no checks list")
    for check in checks:
        if not isinstance(check, dict):
            raise ValueError("visible result check is not an object")
        process = check.get("process")
        add_process(process)
        if isinstance(process, dict):
            add_process(process.get("simulation"))
    return {
        "schema_version": "chipflow.native_verify.v1",
        "modified": {
            "status": (
                "pass"
                if visible_result.get("verdict") == "pass"
                and visible_result.get("pass") is True
                else "fail"
            ),
            "results": results,
        },
    }


def run_monitored_visible_suite(
    *,
    chipflow_run_id: str,
    run_root: Path,
    workspace: Path,
    visible_root: Path,
    output_root: Path,
    monitor_root: Path,
    receipt_output: Path,
    timeout_seconds: int,
    command_timeout_seconds: int,
) -> dict[str, Any]:
    if not chipflow_run_id.strip():
        raise ValueError("chipflow_run_id must be non-empty")
    if timeout_seconds < 1 or timeout_seconds > 900:
        raise ValueError("monitor timeout_seconds must be in [1, 900]")
    if (
        command_timeout_seconds < 1
        or command_timeout_seconds > 300
    ):
        raise ValueError(
            "command_timeout_seconds must be in [1, 300]"
        )
    prior_attempt_archive = _archive_previous_attempt_outputs(
        run_root=run_root,
        output_root=output_root,
        monitor_root=monitor_root,
        receipt_output=receipt_output,
    )
    (
        run_root,
        workspace,
        visible_root,
        output_root,
        monitor_root,
        bwrap,
        strace,
    ) = _preflight(
        run_root=run_root,
        workspace=workspace,
        visible_root=visible_root,
        output_root=output_root,
        monitor_root=monitor_root,
        receipt_output=receipt_output,
    )
    receipt_output = receipt_output.expanduser().resolve()
    output_root.mkdir(parents=True)
    monitor_root.mkdir(parents=True)
    trace_prefix = monitor_root / "exec"
    bwrap_argv = build_bwrap_argv(
        bwrap=bwrap,
        workspace=workspace,
        visible_root=visible_root,
        output_root=output_root,
        command_timeout_seconds=command_timeout_seconds,
    )
    invocation = [
        str(strace),
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
    _write_new_json(
        monitor_root / "invocation.json",
        {
            "monitor_id": MONITOR_ID,
            "argv": invocation,
            "timeout_seconds": timeout_seconds,
            "workspace_mount": "/submission",
            "public_visible_mount": "/visible",
            "output_mount": "/output",
        },
    )
    stdout_path = monitor_root / "stdout.log"
    stderr_path = monitor_root / "stderr.log"
    timed_out = False
    started = time.monotonic()
    with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
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
            returncode = process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
            _terminate_group(process)
            returncode = None
    trace_files = sorted(monitor_root.glob("exec.*"))
    if not trace_files:
        raise RuntimeError(
            "strace did not produce task-workspace monitor evidence"
        )
    observed = parse_trace_files(trace_files)
    visible_result_path = output_root / "result.json"
    visible_result: dict[str, Any] | None = None
    if visible_result_path.is_file() and not visible_result_path.is_symlink():
        value = json.loads(
            visible_result_path.read_text(encoding="utf-8")
        )
        if isinstance(value, dict):
            visible_result = value
    if visible_result is not None:
        _write_new_json(
            run_root / "raw_eda_results.json",
            _raw_eda_results(visible_result),
        )
    visible_pass = bool(
        not timed_out
        and returncode == 0
        and visible_result is not None
        and visible_result.get("task_id") == TASK_ID
        and visible_result.get("suite_id") == SUITE_ID
        and visible_result.get("verdict") == "pass"
        and visible_result.get("pass") is True
    )
    monitor_pass = (
        observed["network_attempt_count"] == 0
        and observed["supervisor_exec_count"] == 1
        and observed["process_count"] > 0
    )
    receipt = {
        "schema_version": (
            "rtlflowbench.chipflow_task_workspace_monitor.v1"
        ),
        "chipflow_run_id": chipflow_run_id,
        "monitoring_complete": True,
        "network_isolation_enforced": True,
        "network_access_observed": (
            observed["network_attempt_count"] > 0
        ),
        "network_attempt_count": observed[
            "network_attempt_count"
        ],
        "monitor_backend": MONITOR_ID,
        "eda_calls": observed["eda_calls"],
        "observed_commands": observed["observed_commands"],
    }
    _write_new_json(receipt_output, receipt)
    _write_new_json(
        monitor_root / "monitor_summary.json",
        {
            **observed,
            "monitor_id": MONITOR_ID,
            "monitor_source_sha256": _sha256(
                Path(__file__).resolve()
            ),
            "bwrap_sha256": _sha256(bwrap),
            "strace_sha256": _sha256(strace),
            "timed_out": timed_out,
            "workflow_exit_code": returncode,
            "wall_time_seconds": round(
                time.monotonic() - started,
                6,
            ),
            "visible_result_path": str(
                visible_result_path.relative_to(run_root)
            ),
            "visible_result_sha256": (
                _sha256(visible_result_path)
                if visible_result is not None
                else None
            ),
            "visible_pass": visible_pass,
            "monitor_pass": monitor_pass,
            "prior_attempt_archive": prior_attempt_archive,
        },
    )
    if visible_result is not None:
        print(
            json.dumps(
                visible_result,
                indent=2,
                sort_keys=True,
            )
        )
    if visible_pass and monitor_pass:
        print(
            "CHIPFLOW_G01_VISIBLE_MONITORED_PASS "
            f"task={TASK_ID}"
        )
    return {
        "status": (
            "pass" if visible_pass and monitor_pass else "fail"
        ),
        "visible_pass": visible_pass,
        "monitor_pass": monitor_pass,
        "receipt": receipt,
        "monitor_summary_path": str(
            (monitor_root / "monitor_summary.json").relative_to(
                run_root
            )
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--chipflow-run-id", required=True)
    parser.add_argument("--run-root", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--visible-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--monitor-root", type=Path, required=True)
    parser.add_argument("--receipt-output", type=Path, required=True)
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=300,
    )
    parser.add_argument(
        "--command-timeout-seconds",
        type=int,
        default=30,
    )
    args = parser.parse_args()
    try:
        result = run_monitored_visible_suite(
            chipflow_run_id=args.chipflow_run_id,
            run_root=args.run_root,
            workspace=args.workspace,
            visible_root=args.visible_root,
            output_root=args.output_root,
            monitor_root=args.monitor_root,
            receipt_output=args.receipt_output,
            timeout_seconds=args.timeout_seconds,
            command_timeout_seconds=args.command_timeout_seconds,
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
    return 0 if result["status"] == "pass" else 2


if __name__ == "__main__":
    raise SystemExit(main())
