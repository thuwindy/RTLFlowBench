#!/usr/bin/env python3
"""Fail-closed public visible runner for G05."""

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
_SPEC = importlib.util.spec_from_file_location(
    "rtlflowbench_g05_visible_verdict",
    _VERDICT_PATH,
)
if _SPEC is None or _SPEC.loader is None:
    raise ImportError(f"could not load verdict helper: {_VERDICT_PATH}")
_MODULE = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _MODULE
_SPEC.loader.exec_module(_MODULE)
VisibleVerdict = _MODULE.VisibleVerdict
classify_process = _MODULE.classify_process

TASK_ID = "G05-picorv32-missing-irq"
REQUIRED_RTL = Path("picorv32.v")
MAX_SUBMISSION_BYTES = 131_072


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


def _preflight(
    repository_root: Path,
    submission_root: Path,
    output_root: Path,
) -> tuple[VisibleVerdict, str, dict[str, Any]]:
    baseline = repository_root / REQUIRED_RTL
    submitted = submission_root / REQUIRED_RTL
    if (
        not repository_root.is_dir()
        or repository_root.is_symlink()
        or not submission_root.is_dir()
        or submission_root.is_symlink()
    ):
        return VisibleVerdict.INVALID_SUBMISSION, "input root invalid", {}
    if output_root == submission_root or output_root.is_relative_to(
        submission_root
    ):
        return VisibleVerdict.INVALID_SUBMISSION, "output inside submission", {}
    if not baseline.is_file() or baseline.is_symlink():
        return VisibleVerdict.INVALID_SUBMISSION, "pinned base missing", {}
    if not submitted.is_file() or submitted.is_symlink():
        return VisibleVerdict.INVALID_SUBMISSION, "picorv32.v missing", {}
    observed = [
        path.relative_to(submission_root).as_posix()
        for path in sorted(submission_root.rglob("*"))
        if path.is_file()
    ]
    if any(path.is_symlink() for path in submission_root.rglob("*")):
        return VisibleVerdict.SCOPE_VIOLATION, "submission symlink", {}
    if observed != [REQUIRED_RTL.as_posix()]:
        return VisibleVerdict.SCOPE_VIOLATION, "exactly one file required", {
            "observed_files": observed
        }
    if submitted.stat().st_size > MAX_SUBMISSION_BYTES:
        return VisibleVerdict.SCOPE_VIOLATION, "byte budget exceeded", {}
    notice_end = b"/* verilator lint_off WIDTH */"
    baseline_bytes = baseline.read_bytes()
    submitted_bytes = submitted.read_bytes()
    boundary = baseline_bytes.find(notice_end)
    if boundary < 0 or not submitted_bytes.startswith(
        baseline_bytes[:boundary]
    ):
        return VisibleVerdict.SCOPE_VIOLATION, "ISC notice changed", {}
    return VisibleVerdict.PASS, "scope and notice validated", {
        "observed_files": observed,
        "submission_bytes": submitted.stat().st_size,
        "submission_sha256": _sha256(submitted),
        "baseline_sha256": _sha256(baseline),
    }


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
    checks: list[dict[str, Any]] = [{
        "check_id": "scope_notice",
        "stage": "scope",
        "verdict": verdict.value,
        "reason": reason,
    }]
    tools = {
        "iverilog": shutil.which(args.iverilog) or args.iverilog,
        "vvp": shutil.which(args.vvp) or args.vvp,
    }
    if verdict == VisibleVerdict.PASS:
        process = _execute(
            [
                tools["iverilog"],
                "-g2005-sv",
                "-s",
                "g05_visible_tb",
                "-o",
                str(output_root / "visible.vvp"),
                str(submission_root / REQUIRED_RTL),
                str(Path(__file__).resolve().parent / "g05_visible_tb.v"),
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
        checks.append({
            "check_id": "compile",
            "stage": "compile",
            "verdict": verdict.value,
            "reason": reason,
            "process": process,
        })
    if verdict == VisibleVerdict.PASS:
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
        checks.append({
            "check_id": "external_timer_service_reset_smoke",
            "stage": "simulation",
            "verdict": verdict.value,
            "reason": reason,
            "process": process,
        })
    evidence = [{
        "path": path.name,
        "bytes": path.stat().st_size,
        "sha256": _sha256(path),
    } for path in sorted(output_root.glob("*.log"))]
    return {
        "schema_version": "chipflow.golden12.g05_visible_result.v1",
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
            "Visible smoke PASS is not hidden F2P/P2P or benchmark PASS.",
            "No formal, coverage, performance, PPA, environment freeze, or admission is claimed."
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
    args = parser.parse_args()
    try:
        result = run(args)
    except Exception as exc:
        result = {
            "schema_version": "chipflow.golden12.g05_visible_result.v1",
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
