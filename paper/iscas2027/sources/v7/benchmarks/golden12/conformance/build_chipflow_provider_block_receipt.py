#!/usr/bin/env python3
"""Build a content-bound receipt for a pre-DesignSpec provider BLOCK.

The builder is intentionally task-neutral.  It records a workflow
infrastructure observation without manufacturing a submission, evaluator
result, score, or benchmark PASS.  Raw provider logs remain outside the
receipt and are referenced only by relative path and SHA256.
"""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from typing import Any

from jsonschema import Draft202012Validator


SCHEMA_PATH = Path(__file__).with_name(
    "chipflow_provider_block_receipt.schema.json"
)
STABLE_ERROR_CLASS = (
    "model_provider_infra_error: quota_or_billing_unavailable"
)
HTTP_402_PATTERN = re.compile(r"(?:error code|status)\s*:?\s*402", re.I)
ATTEMPT_PATTERN = re.compile(
    r"LLM call failed after\s+(\d+)\s+attempt\(s\)", re.I
)


def _load_object(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"not a regular JSON file: {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain one JSON object")
    return value


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical_sha256(value: Any) -> str:
    payload = json.dumps(
        value,
        separators=(",", ":"),
        sort_keys=True,
        ensure_ascii=False,
    ).encode()
    return hashlib.sha256(payload).hexdigest()


def _parse_datetime(value: str, *, label: str) -> str:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{label} must include a timezone")
    return value


def _safe_file(root: Path, path: Path, *, label: str) -> tuple[str, Path]:
    root = root.expanduser().resolve(strict=True)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("evidence root must be a regular directory")
    path = path.expanduser()
    candidate = path if path.is_absolute() else root / path
    if candidate.is_symlink():
        raise ValueError(f"{label} must not be a symlink")
    resolved = candidate.resolve(strict=True)
    if not resolved.is_file():
        raise ValueError(f"{label} must be a regular file")
    try:
        relative = resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"{label} must stay inside the evidence root") from exc
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError(f"{label} path contains a symlink")
    return relative.as_posix(), resolved


def _safe_directory(root: Path, path: Path, *, label: str) -> Path:
    root = root.expanduser().resolve(strict=True)
    candidate = path if path.is_absolute() else root / path
    if candidate.is_symlink():
        raise ValueError(f"{label} must not be a symlink")
    resolved = candidate.resolve(strict=True)
    if not resolved.is_dir() or not resolved.is_relative_to(root):
        raise ValueError(f"{label} must be a directory inside evidence root")
    return resolved


def _workspace_map(workspace: Path) -> dict[str, dict[str, Any]]:
    observed: dict[str, dict[str, Any]] = {}
    for path in sorted(workspace.rglob("*")):
        if path.is_symlink():
            raise ValueError("workspace projection contains a symlink")
        if path.is_dir():
            continue
        if not path.is_file():
            raise ValueError("workspace projection contains a non-file entry")
        relative = path.relative_to(workspace).as_posix()
        observed[relative] = {
            "bytes": path.stat().st_size,
            "sha256": _sha256(path),
        }
    return observed


def _projection_map(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    entries = manifest.get("entries")
    if not isinstance(entries, list) or not entries:
        raise ValueError("projection manifest entries are missing")
    expected: dict[str, dict[str, Any]] = {}
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            raise ValueError("projection manifest entry is invalid")
        path = entry["path"]
        if path in expected or Path(path).is_absolute() or ".." in Path(path).parts:
            raise ValueError("projection manifest contains an unsafe path")
        expected[path] = {
            "bytes": entry.get("bytes"),
            "sha256": entry.get("sha256"),
        }
    return expected


def _git_output(authority_root: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(authority_root), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout


def _authority_guard(authority_root: Path) -> dict[str, Any]:
    authority_root = authority_root.expanduser().resolve(strict=True)
    if not authority_root.is_dir():
        raise ValueError("authority root must be a directory")
    head = _git_output(authority_root, "rev-parse", "HEAD").strip()
    branch = _git_output(authority_root, "branch", "--show-current").strip()
    lines = _git_output(
        authority_root,
        "status",
        "--porcelain=v1",
    ).splitlines()
    canonical = ("\n".join(sorted(lines)) + ("\n" if lines else "")).encode()
    return {
        "head": head,
        "branch": branch,
        "dirty_entry_count": len(lines),
        "porcelain_sha256": hashlib.sha256(canonical).hexdigest(),
        "mode": "read_only",
        "modified": False,
    }


def _source_lock(source_root: Path, source_files: list[Path]) -> dict[str, Any]:
    source_root = source_root.expanduser().resolve(strict=True)
    components: dict[str, str] = {}
    for relative in source_files:
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError(f"source file must be relative: {relative}")
        candidate = source_root / relative
        if candidate.is_symlink() or not candidate.is_file():
            raise ValueError(f"source file is missing or unsafe: {relative}")
        components[relative.as_posix()] = _sha256(candidate)
    if not components:
        raise ValueError("at least one runtime source file is required")
    return {
        "component_count": len(components),
        "components": components,
        "canonical_sha256": _canonical_sha256(components),
    }


def build_receipt(
    *,
    evidence_root: Path,
    run_root: Path,
    raw_log: Path,
    projection_manifest_path: Path,
    projection_receipt_path: Path,
    source_root: Path,
    source_files: list[Path],
    authority_root: Path,
    root_locator: str,
    observed_at: str,
    exit_code: int,
) -> dict[str, Any]:
    if exit_code == 0:
        raise ValueError("a provider BLOCK receipt requires a non-zero exit code")
    _parse_datetime(observed_at, label="observed_at")
    evidence_root = evidence_root.expanduser().resolve(strict=True)
    run_root = _safe_directory(
        evidence_root,
        run_root,
        label="run root",
    )
    summary_relative, summary_path = _safe_file(
        evidence_root,
        run_root / "orchestration_summary.json",
        label="orchestration summary",
    )
    config_relative, config_path = _safe_file(
        evidence_root,
        run_root / "runtime/config_evidence.json",
        label="runtime config evidence",
    )
    raw_relative, raw_path = _safe_file(
        evidence_root,
        raw_log,
        label="raw command log",
    )
    manifest_relative, manifest_path = _safe_file(
        evidence_root,
        projection_manifest_path,
        label="projection manifest",
    )
    projection_relative, projection_path = _safe_file(
        evidence_root,
        projection_receipt_path,
        label="projection receipt",
    )

    summary = _load_object(summary_path)
    config = _load_object(config_path)
    manifest = _load_object(manifest_path)
    projection = _load_object(projection_path)
    if (
        summary.get("status") != "blocked"
        or summary.get("current_stage") != "BLOCKED"
        or STABLE_ERROR_CLASS not in str(summary.get("blocked_reason") or "")
        or summary.get("artifact_count") != 0
        or summary.get("approval_request") is not None
        or summary.get("judge_decision") is not None
        or summary.get("executor_result") is not None
        or summary.get("verification_result") is not None
        or summary.get("private_evaluator_run") is not False
    ):
        raise ValueError("run is not a pre-DesignSpec provider infrastructure BLOCK")
    task_id = str(summary.get("task_id") or "")
    if config.get("task_id") != task_id:
        raise ValueError("summary and runtime config task IDs do not match")

    log_text = raw_path.read_text(encoding="utf-8", errors="replace")
    attempt_match = ATTEMPT_PATTERN.search(log_text)
    if (
        not HTTP_402_PATTERN.search(log_text)
        or "insufficient balance" not in log_text.lower()
        or attempt_match is None
    ):
        raise ValueError("raw log does not prove the classified provider BLOCK")
    model_dispatch_attempts = int(attempt_match.group(1))
    if model_dispatch_attempts < 1:
        raise ValueError("model dispatch attempt count must be positive")

    runtime_manifest = config.get("runtime_manifest")
    if not isinstance(runtime_manifest, dict):
        raise ValueError("runtime manifest binding is missing")
    runtime_relative = Path(str(runtime_manifest.get("path") or ""))
    runtime_manifest_relative, runtime_manifest_path = _safe_file(
        evidence_root,
        run_root / runtime_relative,
        label="native runtime manifest",
    )
    if _sha256(runtime_manifest_path) != runtime_manifest.get("sha256"):
        raise ValueError("native runtime manifest hash drifted")

    expected = _projection_map(manifest)
    workspace = _safe_directory(
        evidence_root,
        run_root / "workspace",
        label="workspace",
    )
    observed = _workspace_map(workspace)
    if observed != expected:
        raise ValueError("blocked run workspace differs from repository projection")
    if (
        projection.get("task_id") != task_id
        or projection.get("manifest_sha256") != _sha256(manifest_path)
        or projection.get("contains_evaluator_assets") is not False
        or projection.get("workflow_files_writable") is not False
    ):
        raise ValueError("projection receipt is inconsistent with the blocked run")
    config_projection = config.get("repository_projection")
    if (
        not isinstance(config_projection, dict)
        or config_projection.get("manifest_sha256") != _sha256(manifest_path)
        or config_projection.get("contains_evaluator_assets") is not False
    ):
        raise ValueError("runtime config projection binding is inconsistent")

    effective_models = runtime_manifest.get("effective_models")
    if (
        not isinstance(effective_models, list)
        or len(effective_models) != 1
        or not isinstance(effective_models[0], str)
    ):
        raise ValueError("exactly one effective model alias is required")
    started_at = _parse_datetime(
        str(config.get("started_at") or ""),
        label="started_at",
    )
    source_lock = _source_lock(source_root, source_files)
    receipt = {
        "schema_version": "rtlflowbench.chipflow_provider_block_receipt.v1",
        "task_id": task_id,
        "observed_at": observed_at,
        "status": "blocked_model_provider_infra_before_design_spec",
        "attempt": {
            "run_id": config["chipflow_run_id"],
            "started_at": started_at,
            "exit_code": exit_code,
            "terminal_status": "blocked",
            "terminal_stage": "BLOCKED",
            "stable_error_class": STABLE_ERROR_CLASS,
            "provider_http_status": 402,
            "provider_error_code": "insufficient_balance_or_quota",
            "effective_model_alias": effective_models[0],
            "model_dispatch_attempts": model_dispatch_attempts,
        },
        "evidence": {
            "root_locator": root_locator,
            "orchestration_summary": {
                "path": summary_relative,
                "sha256": _sha256(summary_path),
            },
            "runtime_config": {
                "path": config_relative,
                "sha256": _sha256(config_path),
            },
            "native_runtime_manifest": {
                "path": runtime_manifest_relative,
                "sha256": _sha256(runtime_manifest_path),
                "run_manifest_sha256": runtime_manifest.get(
                    "run_manifest_sha256"
                ),
            },
            "raw_command_log": {
                "path": raw_relative,
                "sha256": _sha256(raw_path),
            },
            "projection_manifest": {
                "path": manifest_relative,
                "sha256": _sha256(manifest_path),
            },
            "projection_receipt": {
                "path": projection_relative,
                "sha256": _sha256(projection_path),
            },
        },
        "repository_projection": {
            "archive_sha256": projection.get("archive_sha256"),
            "manifest_sha256": _sha256(manifest_path),
            "projection_digest": projection.get("projection_digest"),
            "projected_file_count": len(expected),
            "projected_paths": sorted(expected),
            "workspace_file_count": len(observed),
            "workspace_mismatch_count": 0,
            "contains_evaluator_assets": False,
            "workflow_files_writable": False,
            "redistribution_review_complete": bool(
                projection.get("redistribution_review_complete", False)
            ),
        },
        "runtime_source_lock": source_lock,
        "safety_observations": {
            "design_spec_produced": False,
            "judge_accept_observed": False,
            "approval_observed": False,
            "safe_executor_run_count": 0,
            "workspace_mutation_count": 0,
            "eda_run_count": 0,
            "private_evaluator_run_count": 0,
            "neutral_export_count": 0,
            "benchmark_pass_claimed": False,
            "score_claimed": False,
            "ppa_claimed": False,
            "task_workspace_network_access_observed": None,
        },
        "resource_usage": {
            "wall_time_seconds": None,
            "input_tokens": None,
            "output_tokens": None,
            "llm_calls": model_dispatch_attempts,
            "eda_calls": {
                "compile_or_lint": 0,
                "simulation": 0,
                "formal": 0,
                "synthesis": 0,
            },
            "human_interventions": 0,
            "missing_measurements": [
                "wall_time_seconds",
                "input_tokens",
                "output_tokens",
            ],
        },
        "readiness_impact": {
            "fresh_current_source_attempt_observed": True,
            "verified_completion_observed": False,
            "provider_healthy_retry_required": True,
            "current_runtime_multirun_complete": False,
            "benchmark_ready": False,
            "chipflow_adapter_ready": False,
        },
        "server_source_authority_guard": _authority_guard(authority_root),
        "excluded_claims": [
            "A provider-infrastructure BLOCK before DesignSpec is not a successful RTL workflow completion.",
            "No Judge ACCEPT, approval, Safe Executor execution, visible verification, neutral export, or private evaluation occurred.",
            "No functional PASS, QoR improvement, PPA, score, benchmark readiness, adapter readiness, or multi-run success rate is claimed.",
            "Missing resource measurements remain null and are not replaced by zero.",
        ],
    }
    Draft202012Validator(_load_object(SCHEMA_PATH)).validate(receipt)
    return receipt


def _write_new(path: Path, value: dict[str, Any]) -> None:
    path = path.expanduser().resolve()
    if path.exists() or path.is_symlink():
        raise FileExistsError(f"refusing to overwrite output: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    if temporary.exists() or temporary.is_symlink():
        raise FileExistsError(f"temporary output already exists: {temporary}")
    temporary.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--run-root", type=Path, required=True)
    parser.add_argument("--raw-log", type=Path, required=True)
    parser.add_argument("--projection-manifest", type=Path, required=True)
    parser.add_argument("--projection-receipt", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument(
        "--source-file",
        type=Path,
        action="append",
        required=True,
    )
    parser.add_argument("--authority-root", type=Path, required=True)
    parser.add_argument("--root-locator", required=True)
    parser.add_argument("--observed-at", required=True)
    parser.add_argument("--exit-code", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        receipt = build_receipt(
            evidence_root=args.evidence_root,
            run_root=args.run_root,
            raw_log=args.raw_log,
            projection_manifest_path=args.projection_manifest,
            projection_receipt_path=args.projection_receipt,
            source_root=args.source_root,
            source_files=args.source_file,
            authority_root=args.authority_root,
            root_locator=args.root_locator,
            observed_at=args.observed_at,
            exit_code=args.exit_code,
        )
        _write_new(args.output, receipt)
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
    print(
        json.dumps(
            {
                "status": "provider_block_receipt_built",
                "task_id": receipt["task_id"],
                "output": str(args.output),
                "receipt_sha256": _sha256(args.output),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
