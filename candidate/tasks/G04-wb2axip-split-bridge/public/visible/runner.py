#!/usr/bin/env python3
"""Public deterministic visible runner for G04."""

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
_SPEC = importlib.util.spec_from_file_location("rtlflowbench_g04_visible_verdict", _VERDICT_PATH)
if _SPEC is None or _SPEC.loader is None:
    raise ImportError(f"could not load verdict helper: {_VERDICT_PATH}")
_MODULE = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _MODULE
_SPEC.loader.exec_module(_MODULE)
VisibleVerdict = _MODULE.VisibleVerdict
classify_process = _MODULE.classify_process

TASK_ID = "G04-wb2axip-split-bridge"
REQUIRED_RTL = Path("rtl/golden12_axil_wb_split_bridge.sv")
DEPENDENCIES = {
    Path("rtl/axilrd2wbsp.v"): "7d535bbde1f719f0ef8b754c2dcb49857e9f0999cec4cc995e2e1318951c9239",
    Path("rtl/axilwr2wbsp.v"): "020eb692505d2e7badf3f36e9b881ba100e5737b70419a344c89a663cb92fc61",
}
NOTICE = Path("README.md")
MAX_SUBMISSION_BYTES = 65_536


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _execute(
    argv: list[str], *, cwd: Path, timeout: int, stdout_path: Path, stderr_path: Path
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
            env={"PATH": os.environ.get("PATH", ""), "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
        )
        stdout, stderr = completed.stdout, completed.stderr
        status, exit_code = "completed", completed.returncode
    except subprocess.TimeoutExpired as exc:
        stdout, stderr = exc.stdout or "", exc.stderr or ""
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


def _preflight(repository_root: Path, submission_root: Path, output_root: Path) -> tuple[VisibleVerdict, str, dict[str, Any]]:
    if not repository_root.is_dir() or repository_root.is_symlink():
        return VisibleVerdict.INVALID_SUBMISSION, "repository root invalid", {}
    if not submission_root.is_dir() or submission_root.is_symlink():
        return VisibleVerdict.INVALID_SUBMISSION, "submission root invalid", {}
    if output_root == submission_root or output_root.is_relative_to(submission_root):
        return VisibleVerdict.INVALID_SUBMISSION, "output must be outside submission", {}
    digests: dict[str, str] = {}
    for relative, expected in DEPENDENCIES.items():
        path = repository_root / relative
        if not path.is_file() or path.is_symlink():
            return VisibleVerdict.INVALID_SUBMISSION, f"read-only dependency missing: {relative}", {}
        observed = _sha256(path)
        if observed != expected:
            return VisibleVerdict.INVALID_SUBMISSION, f"read-only dependency digest mismatch: {relative}", {"observed_sha256": observed}
        digests[relative.as_posix()] = observed
    notice = repository_root / NOTICE
    if not notice.is_file() or notice.is_symlink():
        return VisibleVerdict.INVALID_SUBMISSION, "projected license notice missing", {}
    required = submission_root / REQUIRED_RTL
    if not required.is_file() or required.is_symlink():
        return VisibleVerdict.INVALID_SUBMISSION, f"required regular file missing: {REQUIRED_RTL}", {}
    observed_files: list[str] = []
    for path in sorted(submission_root.rglob("*")):
        if path.is_symlink():
            return VisibleVerdict.SCOPE_VIOLATION, f"submission symlink: {path.relative_to(submission_root)}", {}
        if path.is_file():
            observed_files.append(path.relative_to(submission_root).as_posix())
    if observed_files != [REQUIRED_RTL.as_posix()]:
        return VisibleVerdict.SCOPE_VIOLATION, "submission must contain exactly one wrapper file", {"observed_files": observed_files}
    if required.stat().st_size > MAX_SUBMISSION_BYTES:
        return VisibleVerdict.SCOPE_VIOLATION, "submission exceeds byte budget", {"submission_bytes": required.stat().st_size}
    return VisibleVerdict.PASS, "pinned dependencies and one-file scope validated", {
        "observed_files": observed_files,
        "submission_bytes": required.stat().st_size,
        "submission_sha256": _sha256(required),
        "dependency_sha256": digests,
        "notice_sha256": _sha256(notice),
    }


def _classify_invalid_probe(process: dict[str, Any], *, phase: str) -> tuple[VisibleVerdict, str]:
    if process["process_status"] == "timeout":
        return VisibleVerdict.TIMEOUT, f"invalid-parameter {phase} timed out"
    if process["process_status"] == "infra_error" or process["exit_code"] is None:
        return VisibleVerdict.INFRA_ERROR, f"invalid-parameter {phase} could not execute"
    if process["exit_code"] != 0:
        return VisibleVerdict.PASS, f"illegal public parameter combination was rejected during {phase}"
    return VisibleVerdict.FUNCTIONAL_FAIL, f"illegal public parameter combination was not rejected during {phase}"


def run(args: argparse.Namespace) -> dict[str, Any]:
    started = time.monotonic()
    repository_root = args.repository_root.expanduser().resolve()
    submission_root = args.submission_root.expanduser().resolve()
    output_root = args.output_dir.expanduser().resolve()
    output_root.mkdir(parents=True, exist_ok=False)
    verdict, reason, scope = _preflight(repository_root, submission_root, output_root)
    checks: list[dict[str, Any]] = [{"check_id": "scope", "stage": "scope", "verdict": verdict.value, "reason": reason}]
    tool_paths = {"iverilog": shutil.which(args.iverilog) or args.iverilog, "vvp": shutil.which(args.vvp) or args.vvp}
    source_argv = [str(repository_root / path) for path in DEPENDENCIES]
    if verdict == VisibleVerdict.PASS:
        executable = output_root / "visible.vvp"
        process = _execute(
            [tool_paths["iverilog"], "-g2012", "-s", "g04_visible_tb", "-o", str(executable), *source_argv, str(submission_root / REQUIRED_RTL), str(Path(__file__).resolve().parent / "g04_visible_tb.sv")],
            cwd=submission_root, timeout=args.command_timeout_seconds,
            stdout_path=output_root / "compile.stdout.log", stderr_path=output_root / "compile.stderr.log",
        )
        verdict, reason = classify_process(stage="compile", process_status=process["process_status"], exit_code=process["exit_code"], stdout=process["_stdout"])
        process.pop("_stdout")
        checks.append({"check_id": "compile", "stage": "compile", "verdict": verdict.value, "reason": reason, "process": process})
    if verdict == VisibleVerdict.PASS and not args.preapproval_contract_only:
        process = _execute(
            [tool_paths["vvp"], str(output_root / "visible.vvp")], cwd=submission_root,
            timeout=args.command_timeout_seconds, stdout_path=output_root / "simulation.stdout.log", stderr_path=output_root / "simulation.stderr.log",
        )
        verdict, reason = classify_process(stage="simulation", process_status=process["process_status"], exit_code=process["exit_code"], stdout=process["_stdout"])
        process.pop("_stdout")
        checks.append({"check_id": "simulation", "stage": "simulation", "verdict": verdict.value, "reason": reason, "process": process})
    if verdict == VisibleVerdict.PASS:
        invalid_executable = output_root / "invalid_parameter.vvp"
        compile_process = _execute(
            [tool_paths["iverilog"], "-g2012", "-s", "g04_visible_invalid_parameter_tb", "-o", str(invalid_executable), *source_argv, str(submission_root / REQUIRED_RTL), str(Path(__file__).resolve().parent / "g04_invalid_parameter_tb.sv")],
            cwd=submission_root, timeout=args.command_timeout_seconds,
            stdout_path=output_root / "invalid_parameter_compile.stdout.log", stderr_path=output_root / "invalid_parameter_compile.stderr.log",
        )
        compile_process.pop("_stdout")
        if compile_process["process_status"] == "timeout":
            verdict, reason = VisibleVerdict.TIMEOUT, "invalid-parameter compile timed out"
        elif compile_process["process_status"] == "infra_error" or compile_process["exit_code"] is None:
            verdict, reason = VisibleVerdict.INFRA_ERROR, "invalid-parameter compile could not execute"
        elif compile_process["exit_code"] != 0:
            verdict, reason = VisibleVerdict.PASS, "illegal public parameter combination was rejected during elaboration"
        else:
            simulation_process = _execute(
                [tool_paths["vvp"], str(invalid_executable)], cwd=submission_root,
                timeout=args.command_timeout_seconds,
                stdout_path=output_root / "invalid_parameter_simulation.stdout.log",
                stderr_path=output_root / "invalid_parameter_simulation.stderr.log",
            )
            simulation_process.pop("_stdout")
            compile_process["simulation"] = simulation_process
            verdict, reason = _classify_invalid_probe(simulation_process, phase="runtime")
        checks.append({"check_id": "invalid_parameter_rejection", "stage": "parameter_rejection", "verdict": verdict.value, "reason": reason, "process": compile_process})
    evidence = [{"path": path.name, "bytes": path.stat().st_size, "sha256": _sha256(path)} for path in sorted(output_root.glob("*.log"))]
    return {
        "schema_version": "chipflow.golden12.g04_visible_result.v1",
        "task_id": TASK_ID,
        "suite_status": "development_not_frozen",
        "verdict": verdict.value,
        "pass": verdict == VisibleVerdict.PASS,
        "wall_time_seconds": round(time.monotonic() - started, 6),
        "tool_paths": tool_paths,
        "scope_receipt": scope,
        "checks": checks,
        "evidence_manifest": evidence,
        "excluded_claims": [
            "Visible PASS is not hidden F2P/P2P, formal proof, or benchmark PASS.",
            "No coverage, performance, PPA, environment freeze, scoring freeze, or admission is claimed."
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
    parser.add_argument("--preapproval-contract-only", action="store_true")
    args = parser.parse_args()
    try:
        result = run(args)
    except Exception as exc:
        result = {
            "schema_version": "chipflow.golden12.g04_visible_result.v1",
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
    result_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["verdict"] == "pass" else 2


if __name__ == "__main__":
    raise SystemExit(main())
