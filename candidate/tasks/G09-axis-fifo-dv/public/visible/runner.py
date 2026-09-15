#!/usr/bin/env python3
"""Public G09 correct/mutant differential runner."""

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
import tempfile
import time

sys.dont_write_bytecode = True

TASK_ID = "G09-axis-fifo-dv"
SUBMISSION = Path("verification/test_axis_fifo_backpressure.py")
PASS_SENTINEL = "GOLDEN12_G09_VISIBLE_PASS"
EXPECTED_PROJECTION = {
    "rtl/axis_fifo.v": "6aa530205a5c72ecf298a2e818c1dda683062616c148a29947ba70ca3f84bf01",
    "COPYING": "8ea57f95365e9b16a5b516f422b71269183a1ae53bab5878ae6d69039e58fe77",
}
PUBLIC_MUTATIONS = {
    "valid_suppressed_under_stall": (
        "assign m_axis_tvalid = m_axis_tvalid_pipe;",
        "assign m_axis_tvalid = m_axis_tvalid_pipe && m_axis_tready;",
    ),
    "inverted_frame_termination": (
        "assign m_axis_tlast = m_axis_tlast_pipe;",
        "assign m_axis_tlast = ~m_axis_tlast_pipe;",
    ),
}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_verdict_module():
    path = Path(__file__).with_name("verdict.py")
    spec = importlib.util.spec_from_file_location("g09_visible_verdict", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load visible verdict module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _write_result(path: Path, result: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _base_result(verdict: str, checks: list[dict], correct_passes: int, mutant_kills: int) -> dict:
    return {
        "schema_version": "rtlflowbench.g09_visible_result.v1",
        "task_id": TASK_ID,
        "verdict": verdict,
        "pass": verdict == "pass",
        "checks": checks,
        "metrics": {
            "correct_subject_count": 1,
            "correct_subject_pass_count": correct_passes,
            "public_mutant_count": 2,
            "public_mutant_kill_count": mutant_kills,
        },
        "excluded_claims": [
            "Visible differential success is not hidden mutation calibration or benchmark PASS.",
            "The runner reports no frozen coverage, false-positive, workflow-resource, or scoring metric.",
            "No ChipFlow adapter readiness, PPA, performance, or independent admission is claimed.",
        ],
    }


def _scope_issues(workspace: Path) -> list[str]:
    issues: list[str] = []
    regular_files: list[Path] = []
    for path in sorted(workspace.rglob("*")):
        if path.is_symlink():
            issues.append(f"symlink:{path.relative_to(workspace)}")
        elif path.is_file():
            regular_files.append(path)
    observed = {path.relative_to(workspace) for path in regular_files}
    if observed != {SUBMISSION}:
        issues.append("submission must contain exactly verification/test_axis_fifo_backpressure.py")
    candidate = workspace / SUBMISSION
    if candidate.is_file() and not candidate.is_symlink():
        if candidate.stat().st_size > 131072:
            issues.append("submission byte budget exceeded")
        try:
            text = candidate.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            issues.append("submission is not UTF-8")
        else:
            if PASS_SENTINEL in text:
                issues.append("submission contains runner-owned sentinel")
            if "../private" in text or "/private/" in text:
                issues.append("submission references evaluator-private path")
    return issues


def _projection_issues(projection: Path) -> list[str]:
    issues = []
    for relative, expected in EXPECTED_PROJECTION.items():
        path = projection / relative
        if path.is_symlink() or not path.is_file() or _sha256(path) != expected:
            issues.append(f"projection digest mismatch:{relative}")
    return issues


def _materialize_rtl(source: Path, target: Path, mutation: tuple[str, str] | None) -> None:
    text = source.read_text(encoding="utf-8")
    if mutation is not None:
        old, new = mutation
        if text.count(old) != 1:
            raise ValueError("public mutation anchor count is not one")
        text = text.replace(old, new, 1)
    target.write_text(text, encoding="utf-8")


def _run_subject(*, python: Path, submission: Path, rtl_source: Path, output: Path, check_id: str, subject_kind: str, mutation: tuple[str, str] | None, seed: int, data_width: int, depth_bytes: int, timeout: int, verdict_module) -> dict:
    subject_root = output / "subjects" / check_id
    subject_root.mkdir(parents=True, exist_ok=True)
    rtl = subject_root / "axis_fifo.v"
    _materialize_rtl(rtl_source, rtl, mutation)
    build = subject_root / "sim_build"
    log = subject_root / "process.log"
    env = os.environ.copy()
    env.update({
        "G09_AXIS_FIFO_RTL": str(rtl),
        "G09_BUILD_DIR": str(build),
        "G09_SEED": str(seed),
        "G09_DATA_WIDTH": str(data_width),
        "G09_DEPTH_BYTES": str(depth_bytes),
        "PYTHONDONTWRITEBYTECODE": "1",
        "COCOTB_REDUCED_LOG_FMT": "1",
    })
    started = time.monotonic()
    try:
        completed = subprocess.run(
            [
                str(python),
                "-m",
                "pytest",
                "-q",
                "-o",
                "log_cli=true",
                "--log-cli-level=INFO",
                str(submission),
            ],
            cwd=subject_root,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        status = "completed"
        exit_code = completed.returncode
        combined = completed.stdout + completed.stderr
    except subprocess.TimeoutExpired as exc:
        status = "timeout"
        exit_code = None
        combined = (exc.stdout or "") + (exc.stderr or "")
    log.write_text(combined, encoding="utf-8", errors="replace")
    verdict = verdict_module.classify_process(
        subject_kind=subject_kind,
        process_status=status,
        exit_code=exit_code,
        output=combined,
    ).value
    return {
        "check_id": check_id,
        "subject_kind": subject_kind,
        "verdict": verdict,
        "exit_code": exit_code,
        "log_path": str(log.relative_to(output)),
        "wall_time_seconds": round(time.monotonic() - started, 6),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--repo-projection", type=Path, required=True)
    parser.add_argument("--python", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=120)
    args = parser.parse_args()
    workspace = args.workspace.resolve()
    projection = args.repo_projection.resolve()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    checks: list[dict] = []

    scope_issues = _scope_issues(workspace)
    projection_issues = _projection_issues(projection)
    if not args.python.is_file():
        checks.append({
            "check_id": "python_environment",
            "subject_kind": "environment",
            "verdict": "infra_error",
            "exit_code": None,
            "log_path": None,
        })
        result = _base_result("infra_error", checks, 0, 0)
        _write_result(output / "result.json", result)
        return 3
    if scope_issues or projection_issues:
        verdict = "scope_violation" if scope_issues else "invalid_instance"
        checks.append({
            "check_id": "scope_and_projection", "subject_kind": "scope",
            "verdict": verdict, "exit_code": None, "log_path": None,
        })
        result = _base_result(verdict, checks, 0, 0)
        _write_result(output / "result.json", result)
        return 2

    verdict_module = _load_verdict_module()
    submission = workspace / SUBMISSION
    rtl_source = projection / "rtl/axis_fifo.v"
    # Preserve the virtual-environment launcher symlink.  Resolving it would
    # silently replace the requested environment with the system interpreter.
    python = args.python.absolute()
    correct = _run_subject(
        python=python, submission=submission, rtl_source=rtl_source,
        output=output, check_id="correct_seed_9001", subject_kind="correct",
        mutation=None, seed=9001, data_width=16, depth_bytes=64,
        timeout=args.timeout_seconds,
        verdict_module=verdict_module,
    )
    checks.append({key: correct[key] for key in ("check_id", "subject_kind", "verdict", "exit_code", "log_path")})
    if correct["verdict"] != "pass":
        result = _base_result(correct["verdict"], checks, 0, 0)
        _write_result(output / "result.json", result)
        return 2

    kills = 0
    for index, (mutation_id, mutation) in enumerate(PUBLIC_MUTATIONS.items(), start=1):
        observed = _run_subject(
            python=python, submission=submission, rtl_source=rtl_source,
            output=output, check_id=mutation_id, subject_kind="public_mutant",
            mutation=mutation, seed=9001 + index, data_width=16,
            depth_bytes=64, timeout=args.timeout_seconds,
            verdict_module=verdict_module,
        )
        checks.append({key: observed[key] for key in ("check_id", "subject_kind", "verdict", "exit_code", "log_path")})
        if observed["verdict"] == "pass":
            kills += 1
        else:
            result = _base_result(observed["verdict"], checks, 1, kills)
            _write_result(output / "result.json", result)
            return 2

    result = _base_result("pass", checks, 1, kills)
    _write_result(output / "result.json", result)
    print(PASS_SENTINEL)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
