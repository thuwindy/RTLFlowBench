#!/usr/bin/env python3
"""Run the fail-closed G07 public scope and partial-lint checks."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import signal
import subprocess
import tempfile
import time
from typing import Any


TASK_ID = "G07-ibex-ifetch-error-timing"
PASS_SENTINEL = "GOLDEN12_G07_VISIBLE_PASS"
FAIL_PREFIX = "GOLDEN12_G07_VISIBLE_FAIL"
RESULT_SCHEMA_VERSION = "rtlflowbench.g07_visible_result.v1"
MAX_PROCESS_OUTPUT_BYTES = 1024 * 1024
LINT_PATHS = [
    "rtl/ibex_pkg.sv",
    "rtl/ibex_decoder.sv",
    "rtl/ibex_controller.sv",
    "rtl/ibex_id_stage.sv",
]


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} must contain one JSON object")
    return value


def _safe_relative(value: object) -> tuple[str, Path]:
    if not isinstance(value, str):
        raise ValueError("locked path must be a string")
    pure = PurePosixPath(value)
    if pure.is_absolute() or not pure.parts or ".." in pure.parts:
        raise ValueError(f"unsafe locked path: {value}")
    return value, Path(*pure.parts)


def _enumerate_workspace(workspace: Path) -> tuple[set[str], list[str]]:
    files: set[str] = set()
    issues: list[str] = []
    for path in sorted(workspace.rglob("*")):
        relative = path.relative_to(workspace).as_posix()
        if path.is_symlink():
            issues.append(f"symlink is forbidden: {relative}")
        elif path.is_dir():
            continue
        elif not path.is_file():
            issues.append(f"non-regular entry is forbidden: {relative}")
        else:
            files.add(relative)
    return files, issues


def _preflight(
    workspace: Path,
    repo_lock: dict[str, Any],
    allowed_scope: dict[str, Any],
    budget: dict[str, Any],
) -> tuple[str, str, dict[str, Any]]:
    result: dict[str, Any] = {
        "status": "fail",
        "projected_file_count": None,
        "editable_path": "rtl/ibex_id_stage.sv",
        "editable_bytes": None,
        "editable_sha256": None,
        "issues": [],
    }
    if workspace.is_symlink() or not workspace.is_dir():
        result["issues"] = ["workspace must be a regular directory"]
        return "invalid_submission", result["issues"][0], result
    if repo_lock.get("task_id") != TASK_ID or allowed_scope.get("task_id") != TASK_ID:
        result["issues"] = ["public contracts do not identify G07"]
        return "infra_error", result["issues"][0], result
    raw_entries = repo_lock.get("repository_projection_files")
    if not isinstance(raw_entries, list) or not raw_entries:
        result["issues"] = ["repo.lock projection is absent"]
        return "infra_error", result["issues"][0], result
    entries: dict[str, dict[str, Any]] = {}
    try:
        for raw in raw_entries:
            if not isinstance(raw, dict):
                raise ValueError("projection entry must be an object")
            name, _ = _safe_relative(raw.get("path"))
            if name in entries:
                raise ValueError(f"duplicate projection path: {name}")
            entries[name] = raw
    except ValueError as exc:
        result["issues"] = [str(exc)]
        return "infra_error", str(exc), result

    files, issues = _enumerate_workspace(workspace)
    expected = set(entries)
    issues.extend(
        f"required projection file is missing: {name}"
        for name in sorted(expected - files)
    )
    issues.extend(
        f"file is outside the projection: {name}"
        for name in sorted(files - expected)
    )
    editable_paths = allowed_scope.get("editable_paths")
    read_only_paths = allowed_scope.get("read_only_repository_paths")
    if editable_paths != ["rtl/ibex_id_stage.sv"]:
        issues.append("allowed scope does not expose exactly ibex_id_stage.sv")
    if not isinstance(read_only_paths, list) or set(read_only_paths) != {
        name for name, entry in entries.items() if entry.get("mode") == "read_only"
    }:
        issues.append("read-only scope differs from repo.lock")
    result["projected_file_count"] = len(files)
    for name, entry in entries.items():
        path = workspace / Path(*PurePosixPath(name).parts)
        if name not in files:
            continue
        payload = path.read_bytes()
        digest = _sha256_bytes(payload)
        if entry.get("mode") == "read_only":
            if len(payload) != entry.get("bytes") or digest != entry.get("sha256"):
                issues.append(f"read-only projection file drifted: {name}")
        elif entry.get("mode") == "editable":
            result["editable_bytes"] = len(payload)
            result["editable_sha256"] = digest
        else:
            issues.append(f"invalid projection mode: {name}")
    maximum = budget.get("limits", {}).get("maximum_submission_bytes")
    editable_bytes = result["editable_bytes"]
    if not isinstance(maximum, int) or isinstance(maximum, bool) or maximum < 1:
        issues.append("submission byte budget is invalid")
    elif isinstance(editable_bytes, int) and editable_bytes > maximum:
        result["issues"] = issues + ["editable submission exceeds byte budget"]
        return "invalid_submission", result["issues"][-1], result
    result["issues"] = issues
    if issues:
        return "scope_violation", issues[0], result
    result["status"] = "pass"
    return "pass", "exact projection and editable byte budget verified", result


def _terminate(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
    except ProcessLookupError:
        pass
    process.wait(timeout=5)


def _execute_capped(
    argv: list[str],
    *,
    cwd: Path,
    timeout_seconds: float,
    stdout_path: Path,
    stderr_path: Path,
) -> dict[str, Any]:
    started = time.monotonic()
    status = "completed"
    exit_code: int | None = None
    try:
        with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
            process = subprocess.Popen(
                argv,
                cwd=cwd,
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                start_new_session=True,
            )
            while process.poll() is None:
                elapsed = time.monotonic() - started
                total = stdout_path.stat().st_size + stderr_path.stat().st_size
                if total > MAX_PROCESS_OUTPUT_BYTES:
                    status = "output_limit"
                    _terminate(process)
                    break
                if elapsed > timeout_seconds:
                    status = "timeout"
                    _terminate(process)
                    break
                time.sleep(0.02)
            if status == "completed":
                exit_code = process.wait()
                total = stdout_path.stat().st_size + stderr_path.stat().st_size
                if total > MAX_PROCESS_OUTPUT_BYTES:
                    status = "output_limit"
                    exit_code = None
    except Exception as exc:
        status = "error"
        error_payload = f"{type(exc).__name__}: {exc}\n".encode()
        if not stderr_path.exists():
            stderr_path.write_bytes(error_payload[:MAX_PROCESS_OUTPUT_BYTES])
    for path in (stdout_path, stderr_path):
        if path.exists() and path.stat().st_size > MAX_PROCESS_OUTPUT_BYTES:
            with path.open("r+b") as stream:
                stream.truncate(MAX_PROCESS_OUTPUT_BYTES)
    return {
        "process_status": status,
        "exit_code": exit_code,
        "wall_time_seconds": round(time.monotonic() - started, 6),
    }


def _empty_lint(timeout_seconds: float) -> dict[str, Any]:
    return {
        "status": "not_run",
        "process_status": "not_run",
        "exit_code": None,
        "timeout_seconds": timeout_seconds,
        "warning_count": None,
        "output_limit_bytes": MAX_PROCESS_OUTPUT_BYTES,
        "stdout_sha256": None,
        "stderr_sha256": None,
        "stdout_bytes": None,
        "stderr_bytes": None,
    }


def _artifact(path: Path) -> dict[str, Any]:
    return {
        "name": path.name,
        "sha256": _sha256(path),
        "bytes": path.stat().st_size,
    }


def run_visible(
    *,
    workspace: Path,
    result_path: Path,
    repo_lock_path: Path,
    allowed_scope_path: Path,
    budget_path: Path,
    verilator: str,
    timeout_seconds: float,
) -> tuple[int, dict[str, Any]]:
    started = time.monotonic()
    workspace = workspace.expanduser().resolve()
    result_path = result_path.expanduser().resolve()
    result_path.parent.mkdir(parents=True, exist_ok=True)
    if result_path.exists():
        raise FileExistsError(f"refusing to overwrite result: {result_path}")
    if result_path.is_relative_to(workspace):
        raise ValueError("result path must be outside the workflow workspace")
    stdout_path = result_path.parent / "verilator.stdout.log"
    stderr_path = result_path.parent / "verilator.stderr.log"
    version_stdout = result_path.parent / "verilator-version.stdout.log"
    version_stderr = result_path.parent / "verilator-version.stderr.log"
    raw_paths = [stdout_path, stderr_path, version_stdout, version_stderr]
    if any(path.exists() for path in raw_paths):
        raise FileExistsError("refusing to overwrite visible-runner raw logs")

    scope_result = {
        "status": "not_run",
        "projected_file_count": None,
        "editable_path": "rtl/ibex_id_stage.sv",
        "editable_bytes": None,
        "editable_sha256": None,
        "issues": [],
    }
    tool_result = {
        "status": "not_run",
        "name": "verilator",
        "version": None,
        "executable_sha256": None,
    }
    lint_result = _empty_lint(timeout_seconds)
    raw_artifacts: list[dict[str, Any]] = []
    verdict = "infra_error"
    reason = "visible runner did not reach a gate"
    try:
        lock = _load(repo_lock_path)
        scope = _load(allowed_scope_path)
        budget = _load(budget_path)
        verdict, reason, scope_result = _preflight(workspace, lock, scope, budget)
        if verdict == "pass":
            resolved_tool = Path(verilator).expanduser()
            if not resolved_tool.is_absolute():
                found = shutil.which(verilator)
                if found is None:
                    raise FileNotFoundError("verilator executable was not found")
                resolved_tool = Path(found)
            resolved_tool = resolved_tool.resolve()
            if not resolved_tool.is_file():
                raise FileNotFoundError("verilator executable is not a regular file")
            tool_result["executable_sha256"] = _sha256(resolved_tool)
            version_process = _execute_capped(
                [str(resolved_tool), "--version"],
                cwd=result_path.parent,
                timeout_seconds=min(timeout_seconds, 10.0),
                stdout_path=version_stdout,
                stderr_path=version_stderr,
            )
            raw_artifacts.extend([_artifact(version_stdout), _artifact(version_stderr)])
            version_text = version_stdout.read_text(
                encoding="utf-8", errors="replace"
            ).strip()
            if (
                version_process["process_status"] != "completed"
                or version_process["exit_code"] != 0
            ):
                verdict = "infra_error"
                reason = "verilator version probe failed"
                tool_result["status"] = "fail"
            elif not version_text.startswith("Verilator "):
                verdict = "infra_error"
                reason = "verilator version output is malformed"
                tool_result["status"] = "fail"
            else:
                tool_result["status"] = "pass"
                tool_result["version"] = version_text
                include_dir = Path(__file__).resolve().parent / "include"
                with tempfile.TemporaryDirectory(prefix="g07-visible-") as temporary:
                    argv = [
                        str(resolved_tool),
                        "--lint-only",
                        "--language",
                        "1800-2017",
                        "--top-module",
                        "ibex_id_stage",
                        "-Wno-fatal",
                        "-DSYNTHESIS",
                        "--Mdir",
                        str(Path(temporary) / "obj"),
                        f"-I{include_dir}",
                        *LINT_PATHS,
                    ]
                    process = _execute_capped(
                        argv,
                        cwd=workspace,
                        timeout_seconds=timeout_seconds,
                        stdout_path=stdout_path,
                        stderr_path=stderr_path,
                    )
                raw_artifacts.extend([_artifact(stdout_path), _artifact(stderr_path)])
                stdout_text = stdout_path.read_text(
                    encoding="utf-8", errors="replace"
                )
                stderr_text = stderr_path.read_text(
                    encoding="utf-8", errors="replace"
                )
                lint_result = {
                    "status": "fail",
                    "process_status": process["process_status"],
                    "exit_code": process["exit_code"],
                    "timeout_seconds": timeout_seconds,
                    "warning_count": sum(
                        line.startswith("%Warning")
                        for line in stderr_text.splitlines()
                    ),
                    "output_limit_bytes": MAX_PROCESS_OUTPUT_BYTES,
                    "stdout_sha256": _sha256(stdout_path),
                    "stderr_sha256": _sha256(stderr_path),
                    "stdout_bytes": stdout_path.stat().st_size,
                    "stderr_bytes": stderr_path.stat().st_size,
                }
                has_error = any(
                    line.startswith(("%Error", "%Fatal"))
                    for line in (stdout_text + "\n" + stderr_text).splitlines()
                )
                if process["process_status"] == "timeout":
                    verdict, reason = "timeout", "verilator lint exceeded timeout"
                elif process["process_status"] == "output_limit":
                    verdict, reason = (
                        "infra_error",
                        "verilator output exceeded hard limit",
                    )
                elif process["process_status"] != "completed":
                    verdict, reason = (
                        "infra_error",
                        "verilator process failed to execute",
                    )
                elif process["exit_code"] != 0 or has_error:
                    verdict, reason = (
                        "compile_error",
                        "partial elaboration or lint failed",
                    )
                else:
                    verdict, reason = (
                        "pass",
                        "scope and partial Verilator lint passed",
                    )
                    lint_result["status"] = "pass"
    except (FileNotFoundError, OSError, json.JSONDecodeError, KeyError, ValueError) as exc:
        if verdict == "pass":
            verdict = "infra_error"
        reason = f"{type(exc).__name__}: {exc}"
        if tool_result["status"] == "not_run" and scope_result["status"] == "pass":
            tool_result["status"] = "fail"

    result = {
        "schema_version": RESULT_SCHEMA_VERSION,
        "task_id": TASK_ID,
        "suite_status": "development_not_frozen",
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "verdict": verdict,
        "pass": verdict == "pass",
        "reason": reason,
        "wall_time_seconds": round(time.monotonic() - started, 6),
        "scope": scope_result,
        "tool": tool_result,
        "lint": lint_result,
        "raw_artifacts": raw_artifacts,
        "excluded_claims": [
            "A visible lint pass is not a hidden functional, differential, or formal pass.",
            "Assertion and functional-coverage instrumentation is disabled only for this public lint gate.",
            "The visible runner environment, resource budget, and tool binary are not frozen.",
            "No performance, PPA, score, benchmark readiness, or ChipFlow adapter readiness is claimed.",
        ],
    }
    result_path.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return (0 if verdict == "pass" else 2), result


def main() -> int:
    visible = Path(__file__).resolve().parent
    public = visible.parent
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--result", type=Path, required=True)
    parser.add_argument("--repo-lock", type=Path, default=public / "repo.lock")
    parser.add_argument(
        "--allowed-scope",
        type=Path,
        default=public / "allowed_scope.json",
    )
    parser.add_argument("--budget", type=Path, default=public / "budget.json")
    parser.add_argument("--verilator", default="verilator")
    parser.add_argument("--timeout-seconds", type=float, default=60.0)
    args = parser.parse_args()
    if not (0.05 <= args.timeout_seconds <= 300.0):
        parser.error("timeout must be between 0.05 and 300 seconds")
    try:
        exit_code, result = run_visible(
            workspace=args.workspace,
            result_path=args.result,
            repo_lock_path=args.repo_lock,
            allowed_scope_path=args.allowed_scope,
            budget_path=args.budget,
            verilator=args.verilator,
            timeout_seconds=args.timeout_seconds,
        )
    except Exception as exc:
        print(f"{FAIL_PREFIX} verdict=infra_error")
        print(json.dumps({"error": f"{type(exc).__name__}: {exc}"}, sort_keys=True))
        return 2
    print(
        json.dumps(
            {"result": args.result.name, "verdict": result["verdict"]},
            sort_keys=True,
        )
    )
    if exit_code == 0:
        print(PASS_SENTINEL)
    else:
        print(f"{FAIL_PREFIX} verdict={result['verdict']}")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
