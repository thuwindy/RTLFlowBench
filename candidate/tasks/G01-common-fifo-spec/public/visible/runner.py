#!/usr/bin/env python3
"""Public, workflow-neutral visible runner for G01.

This development runner validates the one-file submission scope, executes a
deterministic legal-parameter matrix, checks invalid parameter rejection, and
writes raw command logs plus a machine-readable verdict.  It is not the hidden
evaluator and does not make the task benchmark-ready.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True

from verdict import (  # noqa: E402
    VisibleVerdict,
    aggregate_visible_verdict,
    classify_expected_rejection,
    classify_required_success,
)


TASK_ID = "G01-common-fifo-spec"
REQUIRED_RTL = Path("rtl/golden12_fifo.sv")
MAX_SUBMISSION_BYTES = 65_536
LEGAL_CASES = ((1, 2), (8, 3), (16, 4), (32, 5), (7, 7))
INVALID_CASES = ((0, 4), (8, 1))


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _relative_log_path(path: Path, output_root: Path) -> str:
    return str(path.resolve().relative_to(output_root.resolve()))


def _execute(
    *,
    argv: list[str],
    cwd: Path,
    timeout_seconds: int,
    log_root: Path,
    check_id: str,
) -> dict[str, Any]:
    stdout_path = log_root / f"{check_id}.stdout.log"
    stderr_path = log_root / f"{check_id}.stderr.log"
    started = time.monotonic()
    record: dict[str, Any] = {
        "argv": argv,
        "cwd": str(cwd),
        "timeout_seconds": timeout_seconds,
        "stdout_path": _relative_log_path(stdout_path, log_root.parent),
        "stderr_path": _relative_log_path(stderr_path, log_root.parent),
    }
    try:
        completed = subprocess.run(
            argv,
            cwd=cwd,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            env={
                "PATH": os.environ.get("PATH", ""),
                "LANG": os.environ.get("LANG", "C.UTF-8"),
                "LC_ALL": os.environ.get("LC_ALL", "C.UTF-8"),
            },
        )
        stdout = completed.stdout
        stderr = completed.stderr
        record.update(
            {
                "process_status": "completed",
                "exit_code": completed.returncode,
                "wall_time_seconds": round(time.monotonic() - started, 6),
            }
        )
    except subprocess.TimeoutExpired as exc:
        stdout = (
            exc.stdout.decode("utf-8", errors="replace")
            if isinstance(exc.stdout, bytes)
            else (exc.stdout or "")
        )
        stderr = (
            exc.stderr.decode("utf-8", errors="replace")
            if isinstance(exc.stderr, bytes)
            else (exc.stderr or "")
        )
        record.update(
            {
                "process_status": "timeout",
                "exit_code": None,
                "wall_time_seconds": round(time.monotonic() - started, 6),
            }
        )
    except OSError as exc:
        stdout = ""
        stderr = f"{type(exc).__name__}: {exc}\n"
        record.update(
            {
                "process_status": "infra_error",
                "exit_code": None,
                "wall_time_seconds": round(time.monotonic() - started, 6),
            }
        )
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    stdout_path.write_text(stdout, encoding="utf-8")
    stderr_path.write_text(stderr, encoding="utf-8")
    record["stdout_sha256"] = _sha256(stdout_path)
    record["stderr_sha256"] = _sha256(stderr_path)
    record["_stdout"] = stdout
    return record


def _scope_preflight(
    submission_root: Path,
    output_root: Path,
) -> tuple[VisibleVerdict, str, dict[str, Any]]:
    if not submission_root.is_dir():
        return (
            VisibleVerdict.INVALID_SUBMISSION,
            "submission root is not a directory",
            {},
        )
    if output_root == submission_root or output_root.is_relative_to(
        submission_root
    ):
        return (
            VisibleVerdict.INVALID_SUBMISSION,
            "output directory must be outside the submission root",
            {},
        )
    required = submission_root / REQUIRED_RTL
    if not required.is_file() or required.is_symlink():
        return (
            VisibleVerdict.INVALID_SUBMISSION,
            f"required regular file is missing: {REQUIRED_RTL}",
            {},
        )
    observed_files: list[str] = []
    for path in sorted(submission_root.rglob("*")):
        relative = path.relative_to(submission_root)
        if path.is_symlink():
            return (
                VisibleVerdict.SCOPE_VIOLATION,
                f"submission contains a symlink: {relative}",
                {},
            )
        if path.is_file():
            observed_files.append(str(relative))
    if observed_files != [str(REQUIRED_RTL)]:
        return (
            VisibleVerdict.SCOPE_VIOLATION,
            "submission must contain exactly rtl/golden12_fifo.sv",
            {"observed_files": observed_files},
        )
    size = required.stat().st_size
    if size > MAX_SUBMISSION_BYTES:
        return (
            VisibleVerdict.SCOPE_VIOLATION,
            f"submission RTL exceeds {MAX_SUBMISSION_BYTES} bytes",
            {"submission_bytes": size},
        )
    return (
        VisibleVerdict.PASS,
        "one-file scope validated",
        {
            "observed_files": observed_files,
            "submission_bytes": size,
            "rtl_sha256": _sha256(required),
        },
    )


def _record_check(
    checks: list[dict[str, Any]],
    *,
    check_id: str,
    stage: str,
    verdict: VisibleVerdict,
    reason: str,
    process: dict[str, Any] | None = None,
    expected_sentinel: str | None = None,
) -> None:
    check: dict[str, Any] = {
        "check_id": check_id,
        "stage": stage,
        "verdict": verdict.value,
        "reason": reason,
        "expected_sentinel": expected_sentinel,
    }
    if process is not None:
        process = dict(process)
        process.pop("_stdout", None)
        check["process"] = process
    checks.append(check)


def _run(args: argparse.Namespace) -> dict[str, Any]:
    visible_root = Path(__file__).resolve().parent
    submission_root = args.submission_root.expanduser().resolve()
    output_root = args.output_dir.expanduser().resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    log_root = output_root / "raw_logs"
    build_root = output_root / "build"
    checks: list[dict[str, Any]] = []
    started = time.monotonic()

    scope_verdict, scope_reason, scope_receipt = _scope_preflight(
        submission_root,
        output_root,
    )
    _record_check(
        checks,
        check_id="scope",
        stage="scope",
        verdict=scope_verdict,
        reason=scope_reason,
    )
    if scope_verdict != VisibleVerdict.PASS:
        return _result_payload(
            checks=checks,
            scope_receipt=scope_receipt,
            output_root=output_root,
            visible_root=visible_root,
            started=started,
            tool_paths={},
        )

    tool_paths = {
        "iverilog": shutil.which(args.iverilog) or args.iverilog,
        "vvp": shutil.which(args.vvp) or args.vvp,
    }
    rtl = submission_root / REQUIRED_RTL
    legal_tb = visible_root / "g01_visible_tb.sv"
    invalid_tb = visible_root / "g01_invalid_parameter_probe.sv"

    for data_width, depth in LEGAL_CASES:
        case_id = f"w{data_width}_d{depth}"
        case_root = build_root / case_id
        case_root.mkdir(parents=True, exist_ok=True)
        executable = case_root / "visible.vvp"
        compile_id = f"{case_id}_compile"
        compile_process = _execute(
            argv=[
                tool_paths["iverilog"],
                "-g2012",
                "-s",
                "g01_visible_tb",
                "-o",
                str(executable),
                "-P",
                f"g01_visible_tb.DATA_WIDTH={data_width}",
                "-P",
                f"g01_visible_tb.DEPTH={depth}",
                str(rtl),
                str(legal_tb),
            ],
            cwd=submission_root,
            timeout_seconds=args.command_timeout_seconds,
            log_root=log_root,
            check_id=compile_id,
        )
        if compile_process["process_status"] == "timeout":
            compile_verdict = VisibleVerdict.TIMEOUT
            compile_reason = "compile command timed out"
        elif compile_process["process_status"] == "infra_error":
            compile_verdict = VisibleVerdict.INFRA_ERROR
            compile_reason = "compile command could not be executed"
        else:
            compile_verdict, compile_reason = classify_required_success(
                stage="compile",
                exit_code=int(compile_process["exit_code"]),
                stdout=compile_process["_stdout"],
                expected_sentinel=None,
            )
        _record_check(
            checks,
            check_id=compile_id,
            stage="compile",
            verdict=compile_verdict,
            reason=compile_reason,
            process=compile_process,
        )
        if compile_verdict != VisibleVerdict.PASS:
            break

        sentinel = (
            "GOLDEN12_VISIBLE_PASS "
            f"task={TASK_ID} width={data_width} depth={depth}"
        )
        simulation_id = f"{case_id}_simulation"
        simulation_process = _execute(
            argv=[tool_paths["vvp"], str(executable)],
            cwd=submission_root,
            timeout_seconds=args.command_timeout_seconds,
            log_root=log_root,
            check_id=simulation_id,
        )
        if simulation_process["process_status"] == "timeout":
            simulation_verdict = VisibleVerdict.TIMEOUT
            simulation_reason = "simulation command timed out"
        elif simulation_process["process_status"] == "infra_error":
            simulation_verdict = VisibleVerdict.INFRA_ERROR
            simulation_reason = "simulation command could not be executed"
        else:
            simulation_verdict, simulation_reason = (
                classify_required_success(
                    stage="simulation",
                    exit_code=int(simulation_process["exit_code"]),
                    stdout=simulation_process["_stdout"],
                    expected_sentinel=sentinel,
                )
            )
        _record_check(
            checks,
            check_id=simulation_id,
            stage="simulation",
            verdict=simulation_verdict,
            reason=simulation_reason,
            process=simulation_process,
            expected_sentinel=sentinel,
        )
        if simulation_verdict != VisibleVerdict.PASS:
            break

    if aggregate_visible_verdict(checks) == VisibleVerdict.PASS:
        for data_width, depth in INVALID_CASES:
            case_id = f"invalid_w{data_width}_d{depth}"
            case_root = build_root / case_id
            case_root.mkdir(parents=True, exist_ok=True)
            executable = case_root / "invalid.vvp"
            compile_process = _execute(
                argv=[
                    tool_paths["iverilog"],
                    "-g2012",
                    "-s",
                    "g01_invalid_parameter_probe",
                    "-o",
                    str(executable),
                    "-P",
                    f"g01_invalid_parameter_probe.DATA_WIDTH={data_width}",
                    "-P",
                    f"g01_invalid_parameter_probe.DEPTH={depth}",
                    str(rtl),
                    str(invalid_tb),
                ],
                cwd=submission_root,
                timeout_seconds=args.command_timeout_seconds,
                log_root=log_root,
                check_id=f"{case_id}_compile",
            )
            if compile_process["process_status"] == "timeout":
                _record_check(
                    checks,
                    check_id=case_id,
                    stage="invalid_parameter",
                    verdict=VisibleVerdict.TIMEOUT,
                    reason="invalid-parameter compile timed out",
                    process=compile_process,
                )
                break
            if compile_process["process_status"] == "infra_error":
                _record_check(
                    checks,
                    check_id=case_id,
                    stage="invalid_parameter",
                    verdict=VisibleVerdict.INFRA_ERROR,
                    reason="invalid-parameter compile could not be executed",
                    process=compile_process,
                )
                break

            simulation_process: dict[str, Any] | None = None
            if compile_process["exit_code"] == 0:
                simulation_process = _execute(
                    argv=[tool_paths["vvp"], str(executable)],
                    cwd=submission_root,
                    timeout_seconds=args.command_timeout_seconds,
                    log_root=log_root,
                    check_id=f"{case_id}_simulation",
                )
                if simulation_process["process_status"] == "timeout":
                    _record_check(
                        checks,
                        check_id=case_id,
                        stage="invalid_parameter",
                        verdict=VisibleVerdict.TIMEOUT,
                        reason="invalid-parameter simulation timed out",
                        process=simulation_process,
                    )
                    break
                if simulation_process["process_status"] == "infra_error":
                    _record_check(
                        checks,
                        check_id=case_id,
                        stage="invalid_parameter",
                        verdict=VisibleVerdict.INFRA_ERROR,
                        reason=(
                            "invalid-parameter simulation could not be executed"
                        ),
                        process=simulation_process,
                    )
                    break

            accepted_sentinel = (
                "GOLDEN12_INVALID_PARAMETER_ACCEPTED "
                f"width={data_width} depth={depth}"
            )
            rejection_verdict, rejection_reason = (
                classify_expected_rejection(
                    compile_exit_code=int(compile_process["exit_code"]),
                    simulation_exit_code=(
                        None
                        if simulation_process is None
                        else int(simulation_process["exit_code"])
                    ),
                    simulation_stdout=(
                        ""
                        if simulation_process is None
                        else simulation_process["_stdout"]
                    ),
                    accepted_sentinel=accepted_sentinel,
                )
            )
            combined_process = dict(compile_process)
            combined_process.pop("_stdout", None)
            if simulation_process is not None:
                simulation_copy = dict(simulation_process)
                simulation_copy.pop("_stdout", None)
                combined_process["simulation"] = simulation_copy
            _record_check(
                checks,
                check_id=case_id,
                stage="invalid_parameter",
                verdict=rejection_verdict,
                reason=rejection_reason,
                process=combined_process,
                expected_sentinel=accepted_sentinel,
            )
            if rejection_verdict != VisibleVerdict.PASS:
                break

    return _result_payload(
        checks=checks,
        scope_receipt=scope_receipt,
        output_root=output_root,
        visible_root=visible_root,
        started=started,
        tool_paths=tool_paths,
    )


def _result_payload(
    *,
    checks: list[dict[str, Any]],
    scope_receipt: dict[str, Any],
    output_root: Path,
    visible_root: Path,
    started: float,
    tool_paths: dict[str, str],
) -> dict[str, Any]:
    verdict = aggregate_visible_verdict(checks)
    evidence_files = sorted(
        path
        for path in output_root.rglob("*")
        if path.is_file() and path.name != "result.json"
    )
    return {
        "schema_version": "chipflow.golden12.visible_result.v1",
        "task_id": TASK_ID,
        "suite_id": "g01-visible-directed-v1-development",
        "suite_status": "development_not_frozen",
        "verdict": verdict.value,
        "pass": verdict == VisibleVerdict.PASS,
        "wall_time_seconds": round(time.monotonic() - started, 6),
        "tool_paths": tool_paths,
        "scope_receipt": scope_receipt,
        "checks": checks,
        "evidence_manifest": [
            {
                "path": str(path.relative_to(output_root)),
                "bytes": path.stat().st_size,
                "sha256": _sha256(path),
            }
            for path in evidence_files
        ],
        "excluded_claims": [
            "A visible-suite PASS is not a hidden-evaluator PASS.",
            "This development runner does not make G01 benchmark-ready.",
            "No PPA, performance, coverage, or formal result is reported.",
        ],
        "runner_sources": {
            path.name: _sha256(path)
            for path in (
                visible_root / "runner.py",
                visible_root / "verdict.py",
                visible_root / "g01_visible_tb.sv",
                visible_root / "g01_invalid_parameter_probe.sv",
            )
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--submission-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--iverilog", default="iverilog")
    parser.add_argument("--vvp", default="vvp")
    parser.add_argument(
        "--command-timeout-seconds",
        type=int,
        default=30,
        choices=range(1, 301),
        metavar="[1-300]",
    )
    args = parser.parse_args()
    output_root = args.output_dir.expanduser().resolve()
    try:
        result = _run(args)
    except Exception as exc:
        output_root.mkdir(parents=True, exist_ok=True)
        result = {
            "schema_version": "chipflow.golden12.visible_result.v1",
            "task_id": TASK_ID,
            "suite_id": "g01-visible-directed-v1-development",
            "suite_status": "development_not_frozen",
            "verdict": VisibleVerdict.INFRA_ERROR.value,
            "pass": False,
            "wall_time_seconds": None,
            "tool_paths": {},
            "scope_receipt": {},
            "checks": [],
            "evidence_manifest": [],
            "error": f"{type(exc).__name__}: {exc}",
            "excluded_claims": [
                "The runner encountered an infrastructure error.",
                "No PASS or benchmark-ready claim is made.",
            ],
        }
    _write_json(output_root / "result.json", result)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["verdict"] == VisibleVerdict.PASS.value else 2


if __name__ == "__main__":
    raise SystemExit(main())
