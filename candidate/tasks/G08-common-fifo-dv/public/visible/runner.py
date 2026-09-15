#!/usr/bin/env python3
"""Public deterministic visible runner for G08."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import shutil
import subprocess
import sys
import threading
import time
from typing import Any

sys.dont_write_bytecode = True

_VERDICT_PATH = Path(__file__).resolve().parent / "verdict.py"
_VERDICT_SPEC = importlib.util.spec_from_file_location(
    "rtlflowbench_g08_visible_verdict",
    _VERDICT_PATH,
)
if _VERDICT_SPEC is None or _VERDICT_SPEC.loader is None:
    raise ImportError(f"could not load verdict helper: {_VERDICT_PATH}")
_VERDICT_MODULE = importlib.util.module_from_spec(_VERDICT_SPEC)
sys.modules[_VERDICT_SPEC.name] = _VERDICT_MODULE
_VERDICT_SPEC.loader.exec_module(_VERDICT_MODULE)
VisibleVerdict = _VERDICT_MODULE.VisibleVerdict
classify_compile = _VERDICT_MODULE.classify_compile
classify_correct_simulation = _VERDICT_MODULE.classify_correct_simulation
classify_negative_simulation = _VERDICT_MODULE.classify_negative_simulation


TASK_ID = "G08-common-fifo-dv"
REQUIRED_FILES = (
    Path("verification/g08_fifo_tb.sv"),
    Path("verification/g08_fifo_properties.sv"),
)
DUT = Path("src/fifo_v3.sv")
NOTICE = Path("LICENSE")
MAX_SUBMISSION_BYTES = 131_072
MAX_PROCESS_OUTPUT_BYTES = 1_048_576
EXPECTED_REPOSITORY_SHA256 = {
    DUT: "0b33c4ca3d81eb0af72772aa8f064d655974627841e4ba5aca5634cbb46147ce",
    NOTICE: "6527a46225891b976fa94f634f6ee0cd22e1c7129d6f11c5c98c997627625fc7",
}
VISIBLE_ROOT = Path(__file__).resolve().parent
PROPERTY_BIND = VISIBLE_ROOT / "g08_property_bind.sv"


def _systemverilog_code_only(source: str) -> str:
    """Remove comments and string contents for conservative token checks."""

    output: list[str] = []
    index = 0
    state = "code"
    while index < len(source):
        current = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if state == "code":
            if current == "/" and following == "/":
                output.extend("  ")
                index += 2
                state = "line_comment"
                continue
            if current == "/" and following == "*":
                output.extend("  ")
                index += 2
                state = "block_comment"
                continue
            if current == '"':
                output.append(" ")
                index += 1
                state = "string"
                continue
            output.append(current)
            index += 1
            continue
        if state == "line_comment":
            output.append("\n" if current == "\n" else " ")
            index += 1
            if current == "\n":
                state = "code"
            continue
        if state == "block_comment":
            if current == "*" and following == "/":
                output.extend("  ")
                index += 2
                state = "code"
            else:
                output.append("\n" if current == "\n" else " ")
                index += 1
            continue
        if current == "\\" and following:
            output.extend("  ")
            index += 2
        elif current == '"':
            output.append(" ")
            index += 1
            state = "code"
        else:
            output.append("\n" if current == "\n" else " ")
            index += 1
    return "".join(output)


def _classify_property_language(
    properties_path: Path,
) -> tuple[VisibleVerdict, str]:
    """Enforce the public assumption-free, Yosys-portable source subset."""

    try:
        code = _systemverilog_code_only(
            properties_path.read_text(encoding="utf-8")
        )
    except (OSError, UnicodeError) as exc:
        return (
            VisibleVerdict.INVALID_SUBMISSION,
            f"property source is not readable UTF-8: {type(exc).__name__}",
        )
    forbidden = (
        (r"\bassume\b", "submitted assumptions"),
        (r"\b(?:property|endproperty)\b", "named property declarations"),
        (r"\b(?:sequence|endsequence)\b", "named sequence declarations"),
        (r"\b(?:s_eventually|eventually)\b", "eventuality operators"),
        (r"\#\#", "concurrent sequence delays"),
        (r"\|->|\|=>", "concurrent implication operators"),
    )
    violations = [
        label for pattern, label in forbidden if re.search(pattern, code)
    ]
    for match in re.finditer(r"\b(assert|cover)\b", code):
        statement = match.group(1)
        index = match.end()
        while index < len(code) and code[index].isspace():
            index += 1
        if index >= len(code) or code[index] != "(":
            continue
        depth = 0
        while index < len(code):
            if code[index] == "(":
                depth += 1
            elif code[index] == ")":
                depth -= 1
                if depth == 0:
                    index += 1
                    break
            index += 1
        while index < len(code) and code[index].isspace():
            index += 1
        if depth != 0 or index >= len(code) or code[index] != ";":
            violations.append(f"non-bare immediate {statement} statement")
    if violations:
        return (
            VisibleVerdict.INVALID_SUBMISSION,
            "property source violates the public immediate-assertion "
            "profile: " + ", ".join(violations),
        )
    return (
        VisibleVerdict.PASS,
        "property source uses the public assumption-free immediate-assertion profile",
    )


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except (OSError, ProcessLookupError):
        process.terminate()
    try:
        process.wait(timeout=1)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (OSError, ProcessLookupError):
        process.kill()
    process.wait(timeout=2)


def _capture_stream(
    stream: Any,
    *,
    label: str,
    path: Path,
    state: dict[str, int],
    lock: threading.Lock,
    output_limited: threading.Event,
) -> None:
    observed_key = f"{label}_observed"
    captured_key = f"{label}_captured"
    with path.open("wb") as output:
        while True:
            chunk = stream.read(65_536)
            if not chunk:
                break
            with lock:
                state[observed_key] += len(chunk)
                remaining = max(
                    0,
                    MAX_PROCESS_OUTPUT_BYTES - state["captured_total"],
                )
                captured = chunk[:remaining]
                state[captured_key] += len(captured)
                state["captured_total"] += len(captured)
                if len(captured) != len(chunk):
                    output_limited.set()
            if captured:
                output.write(captured)


def _execute(
    argv: list[str],
    *,
    cwd: Path,
    timeout: int,
    stdout_path: Path,
    stderr_path: Path,
) -> dict[str, Any]:
    started = time.monotonic()
    state = {
        "captured_total": 0,
        "stdout_observed": 0,
        "stdout_captured": 0,
        "stderr_observed": 0,
        "stderr_captured": 0,
    }
    lock = threading.Lock()
    output_limited = threading.Event()
    process: subprocess.Popen[bytes] | None = None
    threads: list[threading.Thread] = []
    try:
        # Never expose the caller's real home directory to a compiler.  Some
        # Verilator builds invoke ccache through their generated makefile; a
        # cleared HOME makes that tool fail before compilation, while a host
        # HOME would make the supposedly isolated gate environment-dependent.
        # Keep one writable, output-scoped tool home and disable cache reuse.
        tool_home = stdout_path.parent / ".tool-home"
        tool_home.mkdir(parents=True, exist_ok=True)
        process = subprocess.Popen(
            argv,
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            env={
                "PATH": os.environ.get("PATH", ""),
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "HOME": str(tool_home),
                "CCACHE_DISABLE": "1",
            },
        )
        assert process.stdout is not None
        assert process.stderr is not None
        for label, stream, path in (
            ("stdout", process.stdout, stdout_path),
            ("stderr", process.stderr, stderr_path),
        ):
            thread = threading.Thread(
                target=_capture_stream,
                kwargs={
                    "stream": stream,
                    "label": label,
                    "path": path,
                    "state": state,
                    "lock": lock,
                    "output_limited": output_limited,
                },
                daemon=True,
            )
            thread.start()
            threads.append(thread)

        deadline = started + timeout
        status = "completed"
        while True:
            if output_limited.is_set():
                status = "output_limit"
                _terminate_process_group(process)
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                status = "timeout"
                _terminate_process_group(process)
                break
            try:
                process.wait(timeout=min(0.05, remaining))
                break
            except subprocess.TimeoutExpired:
                continue
        for thread in threads:
            thread.join(timeout=3)
        if any(thread.is_alive() for thread in threads):
            status = "infra_error"
            _terminate_process_group(process)
        elif output_limited.is_set():
            status = "output_limit"
        exit_code = (
            process.returncode if status == "completed" else None
        )
    except OSError as exc:
        if process is not None:
            _terminate_process_group(process)
        stdout_path.write_bytes(b"")
        stderr_path.write_text(
            f"{type(exc).__name__}: {exc}\n",
            encoding="utf-8",
        )
        status, exit_code = "infra_error", None
    stdout = stdout_path.read_text(
        encoding="utf-8",
        errors="replace",
    )
    stderr = stderr_path.read_text(
        encoding="utf-8",
        errors="replace",
    )
    return {
        "argv": list(argv),
        "cwd": str(cwd),
        "timeout_seconds": timeout,
        "process_status": status,
        "exit_code": exit_code,
        "wall_time_seconds": round(time.monotonic() - started, 6),
        "output_limit_bytes": MAX_PROCESS_OUTPUT_BYTES,
        "captured_output_bytes": state["captured_total"],
        "stdout_bytes_observed": state["stdout_observed"],
        "stderr_bytes_observed": state["stderr_observed"],
        "stdout_truncated": (
            state["stdout_observed"] > state["stdout_captured"]
        ),
        "stderr_truncated": (
            state["stderr_observed"] > state["stderr_captured"]
        ),
        "stdout_path": stdout_path.name,
        "stderr_path": stderr_path.name,
        "stdout_sha256": _sha256(stdout_path),
        "stderr_sha256": _sha256(stderr_path),
        "_stdout": stdout,
        "_stderr": stderr,
    }


def _classify_compile_process(
    process: dict[str, Any],
) -> tuple[VisibleVerdict, str]:
    """Separate a known compiler-launch environment failure from RTL errors."""

    diagnostic = "\n".join(
        str(process.get(key) or "") for key in ("_stdout", "_stderr")
    )
    if "ccache: error: Could not determine home directory" in diagnostic:
        return (
            VisibleVerdict.INFRA_ERROR,
            "compiler launcher could not resolve its isolated home directory",
        )
    return classify_compile(
        process_status=process["process_status"],
        exit_code=process["exit_code"],
    )


def _preflight(
    repository_root: Path,
    submission_root: Path,
    output_root: Path,
) -> tuple[VisibleVerdict, str, dict[str, Any]]:
    if not repository_root.is_dir() or repository_root.is_symlink():
        return VisibleVerdict.INVALID_SUBMISSION, "repository root invalid", {}
    if not submission_root.is_dir() or submission_root.is_symlink():
        return VisibleVerdict.INVALID_SUBMISSION, "submission root invalid", {}
    if output_root == submission_root or output_root.is_relative_to(
        submission_root
    ):
        return (
            VisibleVerdict.INVALID_SUBMISSION,
            "output must be outside submission",
            {},
        )

    repository_digests: dict[str, str] = {}
    for relative, expected in EXPECTED_REPOSITORY_SHA256.items():
        path = repository_root / relative
        if not path.is_file() or path.is_symlink():
            return (
                VisibleVerdict.INVALID_SUBMISSION,
                f"read-only repository file missing: {relative}",
                {},
            )
        observed = _sha256(path)
        repository_digests[relative.as_posix()] = observed
        if observed != expected:
            return (
                VisibleVerdict.INVALID_SUBMISSION,
                f"read-only repository digest mismatch: {relative}",
                {"repository_sha256": repository_digests},
            )

    observed_files: list[str] = []
    submission_bytes = 0
    submission_digests: dict[str, str] = {}
    for path in sorted(submission_root.rglob("*")):
        if path.is_symlink():
            return (
                VisibleVerdict.SCOPE_VIOLATION,
                f"submission symlink: {path.relative_to(submission_root)}",
                {},
            )
        if path.is_file():
            relative = path.relative_to(submission_root).as_posix()
            observed_files.append(relative)
            submission_bytes += path.stat().st_size
            submission_digests[relative] = _sha256(path)
    expected_files = sorted(path.as_posix() for path in REQUIRED_FILES)
    if observed_files != expected_files:
        return (
            VisibleVerdict.SCOPE_VIOLATION,
            "submission must contain exactly the two required files",
            {
                "observed_files": observed_files,
                "expected_files": expected_files,
            },
        )
    if submission_bytes > MAX_SUBMISSION_BYTES:
        return (
            VisibleVerdict.SCOPE_VIOLATION,
            "submission exceeds byte budget",
            {"submission_bytes": submission_bytes},
        )
    return (
        VisibleVerdict.PASS,
        "repository digests and exact two-file scope validated",
        {
            "observed_files": observed_files,
            "submission_bytes": submission_bytes,
            "submission_sha256": submission_digests,
            "repository_sha256": repository_digests,
        },
    )


def _tb_compile_argv(
    *,
    iverilog: str,
    executable: Path,
    dut_path: Path,
    submission_root: Path,
    data_width: int,
    depth: int,
    fall_through: int,
    seed: int,
) -> list[str]:
    return [
        iverilog,
        "-g2012",
        "-DVERILATOR",
        f"-DG08_DATA_WIDTH={data_width}",
        f"-DG08_DEPTH={depth}",
        f"-DG08_FALL_THROUGH={fall_through}",
        f"-DG08_SEED={seed}",
        "-s",
        "g08_fifo_tb",
        "-o",
        str(executable),
        str(dut_path),
        str(submission_root / REQUIRED_FILES[0]),
    ]


def _tb_verilator_compile_argv(
    *,
    verilator: str,
    executable_name: str,
    object_dir: Path,
    dut_path: Path,
    submission_root: Path,
    data_width: int,
    depth: int,
    fall_through: int,
    seed: int,
) -> list[str]:
    """Compile the submitted TB alone under the property runtime frontend."""

    return [
        verilator,
        "--binary",
        "--timing",
        "--assert",
        "-Wno-fatal",
        "--top-module",
        "g08_fifo_tb",
        f"-DG08_DATA_WIDTH={data_width}",
        f"-DG08_DEPTH={depth}",
        f"-DG08_FALL_THROUGH={fall_through}",
        f"-DG08_SEED={seed}",
        "--Mdir",
        str(object_dir),
        "-o",
        executable_name,
        str(dut_path),
        str(submission_root / REQUIRED_FILES[0]),
    ]


def _property_runtime_verilator_compile_argv(
    *,
    verilator: str,
    executable_name: str,
    object_dir: Path,
    dut_path: Path,
    submission_root: Path,
    data_width: int,
    depth: int,
    fall_through: int,
    seed: int,
) -> list[str]:
    """Compile bound properties with the public coverage frontend enabled."""

    return [
        verilator,
        "--binary",
        "--timing",
        "--assert",
        "--coverage-line",
        "--coverage-toggle",
        "--coverage-user",
        "-Wno-fatal",
        "--top-module",
        "g08_fifo_tb",
        f"-DG08_DATA_WIDTH={data_width}",
        f"-DG08_DEPTH={depth}",
        f"-DG08_FALL_THROUGH={fall_through}",
        f"-DG08_SEED={seed}",
        "--Mdir",
        str(object_dir),
        "-o",
        executable_name,
        str(dut_path),
        str(submission_root / REQUIRED_FILES[0]),
        str(submission_root / REQUIRED_FILES[1]),
        str(PROPERTY_BIND),
    ]


def _record_process_check(
    checks: list[dict[str, Any]],
    *,
    check_id: str,
    stage: str,
    verdict: VisibleVerdict,
    reason: str,
    process: dict[str, Any],
) -> None:
    process.pop("_stdout", None)
    process.pop("_stderr", None)
    checks.append(
        {
            "check_id": check_id,
            "stage": stage,
            "verdict": verdict.value,
            "reason": reason,
            "process": process,
        }
    )


def run(args: argparse.Namespace) -> dict[str, Any]:
    started = time.monotonic()
    repository_root = args.repository_root.expanduser().resolve()
    submission_root = args.submission_root.expanduser().resolve()
    output_root = args.output_dir.expanduser().resolve()
    output_root.mkdir(parents=True, exist_ok=False)
    verdict, reason, scope = _preflight(
        repository_root,
        submission_root,
        output_root,
    )
    checks: list[dict[str, Any]] = [
        {
            "check_id": "scope",
            "stage": "scope",
            "verdict": verdict.value,
            "reason": reason,
        }
    ]
    tools = {
        "iverilog": shutil.which(args.iverilog) or args.iverilog,
        "vvp": shutil.which(args.vvp) or args.vvp,
        "verilator": shutil.which(args.verilator) or args.verilator,
    }

    correct_cases = (
        ("correct_d1_ft0", 1, 1, 0, 5),
        ("correct_d5_ft0", 8, 5, 0, 1),
        ("correct_d4_ft1", 8, 4, 1, 2),
    )
    for case_id, width, depth, fall_through, seed in correct_cases:
        if verdict != VisibleVerdict.PASS:
            break
        executable = output_root / f"{case_id}.vvp"
        process = _execute(
            _tb_compile_argv(
                iverilog=tools["iverilog"],
                executable=executable,
                dut_path=repository_root / DUT,
                submission_root=submission_root,
                data_width=width,
                depth=depth,
                fall_through=fall_through,
                seed=seed,
            ),
            cwd=submission_root,
            timeout=args.command_timeout_seconds,
            stdout_path=output_root / f"{case_id}.compile.stdout.log",
            stderr_path=output_root / f"{case_id}.compile.stderr.log",
        )
        verdict, reason = _classify_compile_process(process)
        _record_process_check(
            checks,
            check_id=f"{case_id}_compile",
            stage="tb_compile",
            verdict=verdict,
            reason=reason,
            process=process,
        )
        if verdict != VisibleVerdict.PASS:
            break
        process = _execute(
            [tools["vvp"], str(executable)],
            cwd=submission_root,
            timeout=args.command_timeout_seconds,
            stdout_path=output_root / f"{case_id}.simulation.stdout.log",
            stderr_path=output_root / f"{case_id}.simulation.stderr.log",
        )
        verdict, reason = classify_correct_simulation(
            process_status=process["process_status"],
            exit_code=process["exit_code"],
            stdout=process["_stdout"],
            stderr=process["_stderr"],
        )
        _record_process_check(
            checks,
            check_id=f"{case_id}_simulation",
            stage="correct_simulation",
            verdict=verdict,
            reason=reason,
            process=process,
        )

    # Property-runtime failures are actionable only after the same TB and
    # exact stimulus cases have passed under the same Verilator frontend
    # without a property module attached.  This separates cross-simulator TB
    # races from property false positives and keeps retry scope evidence-based.
    verilator_tb_cases = (
        ("tb_verilator_d1_ft0", 1, 1, 0, 7),
        ("tb_verilator_d4_ft1", 8, 4, 1, 9),
    )
    for case_id, width, depth, fall_through, seed in verilator_tb_cases:
        if verdict != VisibleVerdict.PASS:
            break
        executable_name = "g08_tb"
        object_dir = output_root / f"{case_id}.obj"
        executable = object_dir / executable_name
        process = _execute(
            _tb_verilator_compile_argv(
                verilator=tools["verilator"],
                executable_name=executable_name,
                object_dir=object_dir,
                dut_path=repository_root / DUT,
                submission_root=submission_root,
                data_width=width,
                depth=depth,
                fall_through=fall_through,
                seed=seed,
            ),
            cwd=submission_root,
            timeout=args.command_timeout_seconds,
            stdout_path=output_root / f"{case_id}.compile.stdout.log",
            stderr_path=output_root / f"{case_id}.compile.stderr.log",
        )
        verdict, reason = _classify_compile_process(process)
        _record_process_check(
            checks,
            check_id=f"{case_id}_compile",
            stage="tb_portability_compile",
            verdict=verdict,
            reason=reason,
            process=process,
        )
        if verdict != VisibleVerdict.PASS:
            break
        process = _execute(
            [str(executable)],
            cwd=submission_root,
            timeout=args.command_timeout_seconds,
            stdout_path=output_root / f"{case_id}.simulation.stdout.log",
            stderr_path=output_root / f"{case_id}.simulation.stderr.log",
        )
        verdict, reason = classify_correct_simulation(
            process_status=process["process_status"],
            exit_code=process["exit_code"],
            stdout=process["_stdout"],
            stderr=process["_stderr"],
        )
        _record_process_check(
            checks,
            check_id=f"{case_id}_simulation",
            stage="tb_portability_simulation",
            verdict=verdict,
            reason=reason,
            process=process,
        )

    negative_cases = (
        ("reset_status_corrupt", "reset_status_corrupt.sv"),
        ("ordering_corrupt", "ordering_corrupt.sv"),
        (
            "full_simultaneous_priority_corrupt",
            "full_simultaneous_priority_corrupt.sv",
        ),
    )
    for case_id, fixture_name in negative_cases:
        if verdict != VisibleVerdict.PASS:
            break
        executable = output_root / f"{case_id}.vvp"
        process = _execute(
            _tb_compile_argv(
                iverilog=tools["iverilog"],
                executable=executable,
                dut_path=VISIBLE_ROOT / "fixtures" / fixture_name,
                submission_root=submission_root,
                data_width=8,
                depth=5,
                fall_through=0,
                seed=3,
            ),
            cwd=submission_root,
            timeout=args.command_timeout_seconds,
            stdout_path=output_root / f"{case_id}.compile.stdout.log",
            stderr_path=output_root / f"{case_id}.compile.stderr.log",
        )
        verdict, reason = _classify_compile_process(process)
        _record_process_check(
            checks,
            check_id=f"{case_id}_compile",
            stage="tb_compile",
            verdict=verdict,
            reason=reason,
            process=process,
        )
        if verdict != VisibleVerdict.PASS:
            break
        process = _execute(
            [tools["vvp"], str(executable)],
            cwd=submission_root,
            timeout=args.command_timeout_seconds,
            stdout_path=output_root / f"{case_id}.simulation.stdout.log",
            stderr_path=output_root / f"{case_id}.simulation.stderr.log",
        )
        verdict, reason = classify_negative_simulation(
            process_status=process["process_status"],
            exit_code=process["exit_code"],
            stdout=process["_stdout"],
            stderr=process["_stderr"],
        )
        _record_process_check(
            checks,
            check_id=f"{case_id}_detection",
            stage="negative_simulation",
            verdict=verdict,
            reason=reason,
            process=process,
        )

    if verdict == VisibleVerdict.PASS:
        verdict, reason = _classify_property_language(
            submission_root / REQUIRED_FILES[1]
        )
        checks.append(
            {
                "check_id": "properties_language",
                "stage": "property_compile",
                "verdict": verdict.value,
                "reason": reason,
            }
        )

    if verdict == VisibleVerdict.PASS:
        process = _execute(
            [
                tools["verilator"],
                "--lint-only",
                "--timing",
                "--assert",
                "-Wno-fatal",
                "--top-module",
                "g08_property_compile_top",
                str(repository_root / DUT),
                str(submission_root / REQUIRED_FILES[1]),
                str(VISIBLE_ROOT / "g08_property_compile_top.sv"),
            ],
            cwd=submission_root,
            timeout=args.command_timeout_seconds,
            stdout_path=output_root / "properties.compile.stdout.log",
            stderr_path=output_root / "properties.compile.stderr.log",
        )
        verdict, reason = _classify_compile_process(process)
        _record_process_check(
            checks,
            check_id="properties_compile",
            stage="property_compile",
            verdict=verdict,
            reason=reason,
            process=process,
        )

    property_runtime_cases = (
        ("properties_runtime_d1_ft0", 1, 1, 0, 7),
        ("properties_runtime_d4_ft1", 8, 4, 1, 9),
    )
    for case_id, width, depth, fall_through, seed in property_runtime_cases:
        if verdict != VisibleVerdict.PASS:
            break
        executable = output_root / f"{case_id}.obj/g08_properties"
        process = _execute(
            _property_runtime_verilator_compile_argv(
                verilator=tools["verilator"],
                executable_name="g08_properties",
                object_dir=output_root / f"{case_id}.obj",
                dut_path=repository_root / DUT,
                submission_root=submission_root,
                data_width=width,
                depth=depth,
                fall_through=fall_through,
                seed=seed,
            ),
            cwd=submission_root,
            timeout=args.command_timeout_seconds,
            stdout_path=output_root / f"{case_id}.compile.stdout.log",
            stderr_path=output_root / f"{case_id}.compile.stderr.log",
        )
        verdict, reason = _classify_compile_process(process)
        _record_process_check(
            checks,
            check_id=f"{case_id}_compile",
            stage="property_compile",
            verdict=verdict,
            reason=reason,
            process=process,
        )
        if verdict != VisibleVerdict.PASS:
            break
        process = _execute(
            [str(executable)],
            cwd=executable.parent,
            timeout=args.command_timeout_seconds,
            stdout_path=output_root / f"{case_id}.simulation.stdout.log",
            stderr_path=output_root / f"{case_id}.simulation.stderr.log",
        )
        verdict, reason = classify_correct_simulation(
            process_status=process["process_status"],
            exit_code=process["exit_code"],
            stdout=process["_stdout"],
            stderr=process["_stderr"],
        )
        _record_process_check(
            checks,
            check_id=f"{case_id}_simulation",
            stage="correct_simulation",
            verdict=verdict,
            reason=reason,
            process=process,
        )

    evidence = []
    for path in sorted(output_root.glob("*.log")):
        evidence.append(
            {
                "path": path.name,
                "bytes": path.stat().st_size,
                "sha256": _sha256(path),
            }
        )
    return {
        "schema_version": "chipflow.golden12.g08_visible_result.v1",
        "task_id": TASK_ID,
        "suite_status": "development_not_frozen",
        "verdict": verdict.value,
        "pass": verdict == VisibleVerdict.PASS,
        "wall_time_seconds": round(time.monotonic() - started, 6),
        "tool_paths": tools,
        "scope_receipt": scope,
        "checks": checks,
        "evidence_manifest": evidence,
        "excluded_claims": [
            "Visible PASS is not hidden F2P/P2P or benchmark PASS.",
            "Public fixtures are not hidden mutants and establish no frozen mutation score.",
            "No coverage, formal proof, environment freeze, scoring freeze, or admission is claimed.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--submission-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--iverilog", default="iverilog")
    parser.add_argument("--vvp", default="vvp")
    parser.add_argument("--verilator", default="verilator")
    parser.add_argument("--command-timeout-seconds", type=int, default=30)
    args = parser.parse_args()
    try:
        result = run(args)
    except Exception as exc:
        result = {
            "schema_version": "chipflow.golden12.g08_visible_result.v1",
            "task_id": TASK_ID,
            "suite_status": "development_not_frozen",
            "verdict": "infra_error",
            "pass": False,
            "wall_time_seconds": None,
            "tool_paths": {},
            "scope_receipt": {},
            "checks": [],
            "evidence_manifest": [],
            "excluded_claims": [
                "Runner raised before evaluation completed."
            ],
            "error": f"{type(exc).__name__}: {exc}",
        }
    result_path = args.output_dir.expanduser().resolve() / "result.json"
    result_path.parent.mkdir(parents=True, exist_ok=True)
    result_path.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    if result["pass"]:
        print("GOLDEN12_G08_VISIBLE_PASS")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["verdict"] == "pass" else 2


if __name__ == "__main__":
    raise SystemExit(main())
