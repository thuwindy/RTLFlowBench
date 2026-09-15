#!/usr/bin/env python3
"""Public deterministic visible runner for G03."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from typing import Any

sys.dont_write_bytecode = True

_VERDICT_PATH = Path(__file__).resolve().parent / "verdict.py"
_VERDICT_SPEC = importlib.util.spec_from_file_location(
    "rtlflowbench_g03_visible_verdict",
    _VERDICT_PATH,
)
if _VERDICT_SPEC is None or _VERDICT_SPEC.loader is None:
    raise ImportError(f"could not load verdict helper: {_VERDICT_PATH}")
_VERDICT_MODULE = importlib.util.module_from_spec(_VERDICT_SPEC)
sys.modules[_VERDICT_SPEC.name] = _VERDICT_MODULE
_VERDICT_SPEC.loader.exec_module(_VERDICT_MODULE)
VisibleVerdict = _VERDICT_MODULE.VisibleVerdict
classify_process = _VERDICT_MODULE.classify_process


TASK_ID = "G03-axis-fifo-backpressure"
REQUIRED_RTL = Path("rtl/golden12_axis_fifo.sv")
DEPENDENCY = Path("rtl/axis_fifo.v")
MAX_SUBMISSION_BYTES = 65_536
INVALID_PARAMETER_CASES = (
    (
        "invalid_parameter_rejection",
        "g03_visible_invalid_parameter_tb",
        "invalid_parameter",
    ),
    (
        "nonintegral_capacity_rejection",
        "g03_visible_nonintegral_capacity_tb",
        "nonintegral_capacity",
    ),
    (
        "nonpower_capacity_rejection",
        "g03_visible_nonpower_capacity_tb",
        "nonpower_capacity",
    ),
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _execute(
    argv: list[str],
    *,
    cwd: Path,
    timeout: int,
    stdout_path: Path,
    stderr_path: Path,
) -> dict[str, Any]:
    started = time.monotonic()
    try:
        completed = subprocess.run(
            argv,
            cwd=cwd,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            env={
                "PATH": os.environ.get("PATH", ""),
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
            },
        )
        stdout, stderr = completed.stdout, completed.stderr
        status, exit_code = "completed", completed.returncode
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode(errors="replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode(errors="replace")
        status, exit_code = "timeout", None
    except OSError as exc:
        stdout, stderr = "", f"{type(exc).__name__}: {exc}\n"
        status, exit_code = "infra_error", None
    stdout_path.write_text(stdout, encoding="utf-8")
    stderr_path.write_text(stderr, encoding="utf-8")
    return {
        "argv": list(argv),
        "cwd": str(cwd),
        "timeout_seconds": timeout,
        "process_status": status,
        "exit_code": exit_code,
        "wall_time_seconds": round(time.monotonic() - started, 6),
        "stdout_path": stdout_path.name,
        "stderr_path": stderr_path.name,
        "stdout_sha256": _sha256(stdout_path),
        "stderr_sha256": _sha256(stderr_path),
        "_stdout": stdout,
    }


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
    dependency = repository_root / DEPENDENCY
    if not dependency.is_file() or dependency.is_symlink():
        return (
            VisibleVerdict.INVALID_SUBMISSION,
            "read-only axis_fifo dependency missing",
            {},
        )
    required = submission_root / REQUIRED_RTL
    if not required.is_file() or required.is_symlink():
        return (
            VisibleVerdict.INVALID_SUBMISSION,
            f"required regular file missing: {REQUIRED_RTL}",
            {},
        )
    observed = []
    for path in sorted(submission_root.rglob("*")):
        if path.is_symlink():
            return (
                VisibleVerdict.SCOPE_VIOLATION,
                f"submission symlink: {path.relative_to(submission_root)}",
                {},
            )
        if path.is_file():
            observed.append(path.relative_to(submission_root).as_posix())
    if observed != [REQUIRED_RTL.as_posix()]:
        return (
            VisibleVerdict.SCOPE_VIOLATION,
            "submission must contain exactly one wrapper file",
            {"observed_files": observed},
        )
    if required.stat().st_size > MAX_SUBMISSION_BYTES:
        return (
            VisibleVerdict.SCOPE_VIOLATION,
            "submission exceeds byte budget",
            {"submission_bytes": required.stat().st_size},
        )
    return (
        VisibleVerdict.PASS,
        "repository dependency and one-file scope validated",
        {
            "observed_files": observed,
            "submission_bytes": required.stat().st_size,
            "submission_sha256": _sha256(required),
            "dependency_sha256": _sha256(dependency),
        },
    )


def _run_parameter_rejection_case(
    *,
    tools: dict[str, str],
    repository_root: Path,
    submission_root: Path,
    output_root: Path,
    testbench_top: str,
    artifact_prefix: str,
    timeout_seconds: int,
) -> tuple[VisibleVerdict, str, dict[str, Any]]:
    executable = output_root / f"{artifact_prefix}.vvp"
    compile_process = _execute(
        [
            tools["iverilog"],
            "-g2012",
            "-s",
            testbench_top,
            "-o",
            str(executable),
            str(repository_root / DEPENDENCY),
            str(submission_root / REQUIRED_RTL),
            str(
                Path(__file__).resolve().parent
                / "g03_invalid_parameter_tb.sv"
            ),
        ],
        cwd=submission_root,
        timeout=timeout_seconds,
        stdout_path=output_root / f"{artifact_prefix}_compile.stdout.log",
        stderr_path=output_root / f"{artifact_prefix}_compile.stderr.log",
    )
    compile_process.pop("_stdout")
    if compile_process["process_status"] == "timeout":
        return (
            VisibleVerdict.TIMEOUT,
            f"{artifact_prefix} compile timed out",
            compile_process,
        )
    if (
        compile_process["process_status"] == "infra_error"
        or compile_process["exit_code"] is None
    ):
        return (
            VisibleVerdict.INFRA_ERROR,
            f"{artifact_prefix} compile could not execute",
            compile_process,
        )
    if compile_process["exit_code"] != 0:
        return (
            VisibleVerdict.PASS,
            "illegal public parameter combination was rejected during elaboration",
            compile_process,
        )

    simulation_process = _execute(
        [tools["vvp"], str(executable)],
        cwd=submission_root,
        timeout=timeout_seconds,
        stdout_path=output_root / f"{artifact_prefix}_simulation.stdout.log",
        stderr_path=output_root / f"{artifact_prefix}_simulation.stderr.log",
    )
    simulation_process.pop("_stdout")
    compile_process["simulation"] = simulation_process
    if simulation_process["process_status"] == "timeout":
        return (
            VisibleVerdict.TIMEOUT,
            f"{artifact_prefix} simulation timed out",
            compile_process,
        )
    if (
        simulation_process["process_status"] == "infra_error"
        or simulation_process["exit_code"] is None
    ):
        return (
            VisibleVerdict.INFRA_ERROR,
            f"{artifact_prefix} simulation could not execute",
            compile_process,
        )
    if simulation_process["exit_code"] != 0:
        return (
            VisibleVerdict.PASS,
            "illegal public parameter combination was rejected at runtime",
            compile_process,
        )
    return (
        VisibleVerdict.FUNCTIONAL_FAIL,
        "illegal public parameter combination was not rejected",
        compile_process,
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
    }
    if verdict == VisibleVerdict.PASS:
        executable = output_root / "visible.vvp"
        process = _execute(
            [
                tools["iverilog"],
                "-g2012",
                "-s",
                "g03_visible_tb",
                "-o",
                str(executable),
                str(repository_root / DEPENDENCY),
                str(submission_root / REQUIRED_RTL),
                str(Path(__file__).resolve().parent / "g03_visible_tb.sv"),
            ],
            cwd=submission_root,
            timeout=args.command_timeout_seconds,
            stdout_path=output_root / "compile.stdout.log",
            stderr_path=output_root / "compile.stderr.log",
        )
        verdict, reason = classify_process(
            stage="compile",
            process_status=process["process_status"],
            exit_code=process["exit_code"],
            stdout=process["_stdout"],
        )
        process.pop("_stdout")
        checks.append(
            {
                "check_id": "compile",
                "stage": "compile",
                "verdict": verdict.value,
                "reason": reason,
                "process": process,
            }
        )
    if (
        verdict == VisibleVerdict.PASS
        and not args.preapproval_contract_only
    ):
        process = _execute(
            [tools["vvp"], str(output_root / "visible.vvp")],
            cwd=submission_root,
            timeout=args.command_timeout_seconds,
            stdout_path=output_root / "simulation.stdout.log",
            stderr_path=output_root / "simulation.stderr.log",
        )
        verdict, reason = classify_process(
            stage="simulation",
            process_status=process["process_status"],
            exit_code=process["exit_code"],
            stdout=process["_stdout"],
        )
        process.pop("_stdout")
        checks.append(
            {
                "check_id": "simulation",
                "stage": "simulation",
                "verdict": verdict.value,
                "reason": reason,
                "process": process,
            }
        )
    for check_id, testbench_top, artifact_prefix in INVALID_PARAMETER_CASES:
        if verdict != VisibleVerdict.PASS:
            break
        verdict, reason, compile_process = _run_parameter_rejection_case(
            tools=tools,
            repository_root=repository_root,
            submission_root=submission_root,
            output_root=output_root,
            testbench_top=testbench_top,
            artifact_prefix=artifact_prefix,
            timeout_seconds=args.command_timeout_seconds,
        )
        checks.append(
            {
                "check_id": check_id,
                "stage": "parameter_rejection",
                "verdict": verdict.value,
                "reason": reason,
                "process": compile_process,
            }
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
        "schema_version": "chipflow.golden12.g03_visible_result.v1",
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
            "No coverage, performance, PPA, environment freeze, or admission is claimed.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--submission-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--iverilog", default="iverilog")
    parser.add_argument("--vvp", default="vvp")
    parser.add_argument("--command-timeout-seconds", type=int, default=30)
    parser.add_argument(
        "--preapproval-contract-only",
        action="store_true",
        help=(
            "Run valid elaboration plus the public invalid-parameter "
            "rejection probe, without the positive protocol simulation."
        ),
    )
    args = parser.parse_args()
    try:
        result = run(args)
    except Exception as exc:
        result = {
            "schema_version": "chipflow.golden12.g03_visible_result.v1",
            "task_id": TASK_ID,
            "suite_status": "development_not_frozen",
            "verdict": "infra_error",
            "pass": False,
            "wall_time_seconds": None,
            "tool_paths": {},
            "scope_receipt": {},
            "checks": [],
            "evidence_manifest": [],
            "excluded_claims": ["Runner raised before evaluation completed."],
            "error": f"{type(exc).__name__}: {exc}",
        }
    result_path = args.output_dir.expanduser().resolve() / "result.json"
    result_path.parent.mkdir(parents=True, exist_ok=True)
    result_path.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["verdict"] == "pass" else 2


if __name__ == "__main__":
    raise SystemExit(main())
