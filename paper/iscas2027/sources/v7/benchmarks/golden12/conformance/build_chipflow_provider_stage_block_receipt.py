#!/usr/bin/env python3
"""Build a stage-aware receipt for a real ChipFlow provider-infra BLOCK.

This builder is task-neutral and intentionally separate from the historical
pre-DesignSpec v1 receipt.  It binds a run that made partial workflow progress
before a provider quota/billing failure, including any pre-approval machine
gate.  It never copies raw provider responses and never manufactures a
submission, evaluator result, score, or PASS.
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
    "chipflow_provider_stage_block_receipt.schema.json"
)
STABLE_ERROR_CLASS = (
    "model_provider_infra_error: quota_or_billing_unavailable"
)
HTTP_STATUS_PATTERN = re.compile(
    r"(?:error\s+code|status)\s*:?\s*(402|429)",
    re.I,
)
ELAPSED_PATTERN = re.compile(
    r"Elapsed \(wall clock\) time \(h:mm:ss or m:ss\):\s*(\S+)",
)
MAX_RSS_PATTERN = re.compile(
    r"Maximum resident set size \(kbytes\):\s*(\d+)",
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


def _safe_root(path: Path, *, label: str) -> Path:
    if path.is_symlink():
        raise ValueError(f"{label} must not be a symlink")
    resolved = path.expanduser().resolve(strict=True)
    if not resolved.is_dir():
        raise ValueError(f"{label} must be a directory")
    return resolved


def _safe_path(
    root: Path,
    path: Path,
    *,
    label: str,
    require_file: bool,
) -> tuple[str, Path]:
    root = _safe_root(root, label=f"{label} root")
    candidate = path.expanduser() if path.is_absolute() else root / path
    if candidate.is_symlink():
        raise ValueError(f"{label} must not be a symlink")
    resolved = candidate.resolve(strict=True)
    try:
        relative = resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"{label} must stay inside its declared root") from exc
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError(f"{label} path contains a symlink")
    if require_file and not resolved.is_file():
        raise ValueError(f"{label} must be a regular file")
    if not require_file and not resolved.is_dir():
        raise ValueError(f"{label} must be a directory")
    return relative.as_posix(), resolved


def _safe_file(root: Path, path: Path, *, label: str) -> tuple[str, Path]:
    return _safe_path(root, path, label=label, require_file=True)


def _safe_directory(root: Path, path: Path, *, label: str) -> tuple[str, Path]:
    return _safe_path(root, path, label=label, require_file=False)


def _run_file_evidence(run_root: Path, path: Path, *, label: str) -> dict[str, Any]:
    relative, resolved = _safe_file(run_root, path, label=label)
    return {"path": relative, "sha256": _sha256(resolved), "root": "run"}


def _evidence_file_evidence(
    evidence_root: Path,
    path: Path,
    *,
    label: str,
) -> dict[str, Any]:
    relative, resolved = _safe_file(evidence_root, path, label=label)
    return {
        "path": relative,
        "sha256": _sha256(resolved),
        "root": "evidence",
    }


def _tree_map(root: Path) -> dict[str, dict[str, Any]]:
    observed: dict[str, dict[str, Any]] = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError(f"tree contains a symlink: {path}")
        if path.is_dir():
            continue
        if not path.is_file():
            raise ValueError(f"tree contains a non-file entry: {path}")
        relative = path.relative_to(root).as_posix()
        observed[relative] = {
            "bytes": path.stat().st_size,
            "sha256": _sha256(path),
        }
    return observed


def _git_output(authority_root: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(authority_root), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout


def _authority_snapshot(authority_root: Path) -> dict[str, Any]:
    authority_root = _safe_root(authority_root, label="authority root")
    lines = _git_output(
        authority_root,
        "status",
        "--porcelain=v1",
    ).splitlines()
    canonical = ("\n".join(sorted(lines)) + ("\n" if lines else "")).encode()
    return {
        "head": _git_output(authority_root, "rev-parse", "HEAD").strip(),
        "branch": _git_output(
            authority_root,
            "branch",
            "--show-current",
        ).strip(),
        "dirty_entry_count": len(lines),
        "porcelain_sha256": hashlib.sha256(canonical).hexdigest(),
    }


def _source_lock(source_root: Path, source_files: list[Path]) -> dict[str, Any]:
    source_root = _safe_root(source_root, label="source root")
    components: dict[str, str] = {}
    for relative in source_files:
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError(f"source file must be relative: {relative}")
        relative_text, candidate = _safe_file(
            source_root,
            relative,
            label="runtime source file",
        )
        if relative_text in components:
            raise ValueError(f"duplicate runtime source file: {relative_text}")
        components[relative_text] = _sha256(candidate)
    if not components:
        raise ValueError("at least one runtime source file is required")
    return {
        "component_count": len(components),
        "components": components,
        "canonical_sha256": _canonical_sha256(components),
    }


def _public_input_binding(
    run_root: Path,
    config: dict[str, Any],
    context: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    config_manifest = config.get("public_input_manifest")
    context_manifest = context.get("public_input_manifest")
    if (
        not isinstance(config_manifest, list)
        or not config_manifest
        or config_manifest != context_manifest
    ):
        raise ValueError("runtime config and context public manifests differ")
    declared_paths = context.get("public_input_paths")
    manifest_paths = [entry.get("path") for entry in config_manifest if isinstance(entry, dict)]
    if declared_paths != manifest_paths:
        raise ValueError("runtime context public path list differs from manifest")
    observed: dict[str, dict[str, Any]] = {}
    total_bytes = 0
    contains_private_or_hidden = False
    for entry in config_manifest:
        if not isinstance(entry, dict):
            raise ValueError("public input manifest entry is not an object")
        path_value = entry.get("path")
        if not isinstance(path_value, str):
            raise ValueError("public input manifest path is missing")
        relative = Path(path_value)
        if (
            relative.is_absolute()
            or ".." in relative.parts
            or path_value in observed
        ):
            raise ValueError("public input manifest contains an unsafe or duplicate path")
        lowered_parts = {part.lower() for part in relative.parts}
        if lowered_parts.intersection({"private", "hidden"}):
            contains_private_or_hidden = True
        _, candidate = _safe_file(
            run_root,
            relative,
            label="public input",
        )
        expected_size = entry.get("size_bytes")
        expected_hash = entry.get("sha256")
        actual_size = candidate.stat().st_size
        actual_hash = _sha256(candidate)
        if expected_size != actual_size or expected_hash != actual_hash:
            raise ValueError(f"public input hash or size drifted: {path_value}")
        observed[path_value] = {"bytes": actual_size, "sha256": actual_hash}
        total_bytes += actual_size
    if contains_private_or_hidden:
        raise ValueError("public input manifest contains a private or hidden path")

    inputs_relative, inputs_root = _safe_directory(
        run_root,
        Path("inputs"),
        label="run inputs",
    )
    assert inputs_relative == "inputs"
    actual_input_paths = set(_tree_map(inputs_root))
    manifested_inputs = {
        Path(path).relative_to("inputs").as_posix()
        for path in observed
        if Path(path).parts and Path(path).parts[0] == "inputs"
    }
    allowed_runtime_only = {"design_unit_runtime_context.json"}
    unexpected = actual_input_paths - manifested_inputs - allowed_runtime_only
    if unexpected:
        raise ValueError(
            "run inputs contain files outside the public manifest: "
            + ", ".join(sorted(unexpected))
        )
    binding = {
        "manifest_sha256": _canonical_sha256(config_manifest),
        "file_count": len(observed),
        "total_bytes": total_bytes,
        "path_count": len(manifest_paths),
        "mismatch_count": 0,
        "contains_private_or_hidden_path": False,
        "runtime_config_matches_context": True,
    }
    return binding, observed


def _classify_stage(stage: str) -> str:
    if stage.startswith("research-design-"):
        return "design"
    if stage.startswith("research-review-"):
        return "review"
    if stage.startswith("research-judge-"):
        return "judge"
    if stage.startswith("research-patch-plan-"):
        return "patch_plan"
    raise ValueError(f"unsupported provider BLOCK stage: {stage}")


def _collect_dispatches(run_root: Path) -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, int]]:
    paths = sorted(run_root.glob("agents/*/*_dispatch_result.json"))
    if not paths:
        raise ValueError("run contains no persisted dispatch results")
    evidence: list[dict[str, Any]] = []
    blocked: list[dict[str, Any]] = []
    tokens = {
        "input_tokens": 0,
        "output_tokens": 0,
        "total_tokens": 0,
        "token_accounted_dispatches": 0,
    }
    for path in paths:
        relative, safe_path = _safe_file(
            run_root,
            path,
            label="dispatch result",
        )
        payload = _load_object(safe_path)
        stage = payload.get("stage")
        status = payload.get("status")
        if not isinstance(stage, str) or status not in {"completed", "blocked"}:
            raise ValueError("dispatch result has unsupported stage or status")
        records = payload.get("token_usage_records")
        if not isinstance(records, list):
            raise ValueError("dispatch result token usage records are missing")
        if records:
            tokens["token_accounted_dispatches"] += 1
        for record in records:
            if not isinstance(record, dict):
                raise ValueError("token usage record is invalid")
            input_tokens = record.get("input_tokens")
            output_tokens = record.get("output_tokens")
            total_tokens = record.get("total_tokens")
            if (
                not isinstance(input_tokens, int)
                or input_tokens < 0
                or not isinstance(output_tokens, int)
                or output_tokens < 0
                or total_tokens != input_tokens + output_tokens
            ):
                raise ValueError("token usage record is inconsistent")
            tokens["input_tokens"] += input_tokens
            tokens["output_tokens"] += output_tokens
            tokens["total_tokens"] += total_tokens
        raw_response_value = payload.get("raw_response_path")
        if not isinstance(raw_response_value, str):
            raise ValueError("dispatch raw response path is missing")
        raw_response = _run_file_evidence(
            run_root,
            Path(raw_response_value),
            label="raw provider response",
        )
        item = {
            "path": relative,
            "sha256": _sha256(safe_path),
            "root": "run",
            "stage": stage,
            "status": status,
            "token_usage_record_count": len(records),
            "raw_response": raw_response,
        }
        evidence.append(item)
        if status == "blocked":
            if payload.get("error") != STABLE_ERROR_CLASS or records:
                raise ValueError("blocked dispatch lacks the stable provider classification")
            blocked.append(payload)
    if len(blocked) != 1:
        raise ValueError("exactly one persisted provider-blocked dispatch is required")
    return evidence, blocked[0], tokens


def _parse_elapsed(value: str) -> float:
    parts = value.split(":")
    try:
        numbers = [float(part) for part in parts]
    except ValueError as exc:
        raise ValueError("invalid GNU time elapsed value") from exc
    if len(numbers) == 2:
        minutes, seconds = numbers
        return minutes * 60 + seconds
    if len(numbers) == 3:
        hours, minutes, seconds = numbers
        return hours * 3600 + minutes * 60 + seconds
    raise ValueError("invalid GNU time elapsed value")


def _provider_and_time_evidence(
    evidence_root: Path,
    raw_logs: list[Path],
) -> tuple[int, str, list[dict[str, Any]], float | None, int | None]:
    if not raw_logs:
        raise ValueError("at least one raw command log is required")
    files: list[dict[str, Any]] = []
    texts: list[str] = []
    for path in raw_logs:
        relative, safe_path = _safe_file(
            evidence_root,
            path,
            label="raw command log",
        )
        files.append(
            {
                "path": relative,
                "sha256": _sha256(safe_path),
                "root": "evidence",
            }
        )
        texts.append(safe_path.read_text(encoding="utf-8", errors="replace"))
    text = "\n".join(texts)
    statuses = {int(match) for match in HTTP_STATUS_PATTERN.findall(text)}
    if len(statuses) != 1:
        raise ValueError("raw logs must prove exactly one provider HTTP status")
    http_status = statuses.pop()
    lowered = text.lower()
    if http_status == 402:
        if "insufficient" not in lowered and "balance" not in lowered:
            raise ValueError("HTTP 402 log lacks quota/balance evidence")
        provider_error_code = "insufficient_balance_or_quota"
    else:
        if not any(term in lowered for term in ("rate limit", "free-models-per-day", "quota")):
            raise ValueError("HTTP 429 log lacks rate-limit/quota evidence")
        provider_error_code = "rate_limit_or_quota_exhausted"
    elapsed_values = ELAPSED_PATTERN.findall(text)
    rss_values = MAX_RSS_PATTERN.findall(text)
    wall_time = _parse_elapsed(elapsed_values[-1]) if elapsed_values else None
    max_rss = int(rss_values[-1]) if rss_values else None
    return http_status, provider_error_code, files, wall_time, max_rss


def _collect_machine_gates(run_root: Path) -> list[dict[str, Any]]:
    gates: list[dict[str, Any]] = []
    for eda_path in sorted(
        run_root.glob("planning/preapproval_elaboration/*/eda_result.json")
    ):
        gate_root = eda_path.parent
        candidate_path = gate_root / "candidate_plan.json"
        result_path = gate_root / "visible-output/result.json"
        candidate = _load_object(candidate_path)
        eda = _load_object(eda_path)
        result = _load_object(result_path)
        gate_sha256 = gate_root.name
        if (
            not re.fullmatch(r"[0-9a-f]{64}", gate_sha256)
            or candidate.get("gate_sha256") != gate_sha256
            or eda.get("plan_sha256") != gate_sha256
        ):
            raise ValueError("preapproval machine-gate binding is inconsistent")
        eda_status = eda.get("status")
        visible_verdict = result.get("verdict")
        commands = eda.get("results")
        if (
            eda_status not in {"pass", "fail", "infra_error"}
            or visible_verdict
            not in {"pass", "functional_fail", "compile_error", "timeout", "infra_error"}
            or eda.get("workspace_mutated") is not False
            or not isinstance(commands, list)
            or not commands
        ):
            raise ValueError("preapproval machine-gate result is invalid")
        gates.append(
            {
                "gate_sha256": gate_sha256,
                "candidate_plan": _run_file_evidence(
                    run_root,
                    candidate_path,
                    label="preapproval candidate plan",
                ),
                "eda_result": _run_file_evidence(
                    run_root,
                    eda_path,
                    label="preapproval EDA result",
                ),
                "visible_result": _run_file_evidence(
                    run_root,
                    result_path,
                    label="preapproval visible result",
                ),
                "eda_status": eda_status,
                "visible_verdict": visible_verdict,
                "workspace_mutated": False,
                "command_count": len(commands),
            }
        )
    return gates


def build_receipt(
    *,
    evidence_root: Path,
    allowed_runs_root: Path,
    run_root: Path,
    raw_logs: list[Path],
    source_root: Path,
    source_files: list[Path],
    authority_root: Path,
    evidence_root_locator: str,
    run_root_locator: str,
    observed_at: str,
    exit_code: int,
) -> dict[str, Any]:
    if exit_code == 0:
        raise ValueError("a provider BLOCK receipt requires a non-zero exit code")
    _parse_datetime(observed_at, label="observed_at")
    evidence_root = _safe_root(evidence_root, label="evidence root")
    allowed_runs_root = _safe_root(allowed_runs_root, label="allowed runs root")
    _, run_root = _safe_directory(
        allowed_runs_root,
        run_root,
        label="run root",
    )
    authority_before = _authority_snapshot(authority_root)

    summary_path = run_root / "orchestration_summary.json"
    config_path = run_root / "runtime/config_evidence.json"
    context_path = run_root / "inputs/design_unit_runtime_context.json"
    approval_path = run_root / "hitl/approval_decisions.jsonl"
    summary = _load_object(summary_path)
    config = _load_object(config_path)
    context = _load_object(context_path)
    if (
        summary.get("status") != "blocked"
        or summary.get("current_stage") != "BLOCKED"
        or STABLE_ERROR_CLASS not in str(summary.get("blocked_reason") or "")
        or summary.get("approval_request") is not None
        or summary.get("executor_result") is not None
        or summary.get("verification_result") is not None
        or summary.get("private_evaluator_run") is not False
        or summary.get("benchmark_ready") is not False
        or summary.get("chipflow_adapter_ready") is not False
    ):
        raise ValueError("run is not a fail-closed provider infrastructure BLOCK")
    task_id = summary.get("task_id")
    if (
        not isinstance(task_id, str)
        or config.get("task_id") != task_id
        or context.get("design_unit_id") != task_id
    ):
        raise ValueError("summary, config, and context task IDs do not match")

    runtime_manifest = config.get("runtime_manifest")
    if not isinstance(runtime_manifest, dict):
        raise ValueError("runtime manifest binding is missing")
    runtime_manifest_value = runtime_manifest.get("path")
    if not isinstance(runtime_manifest_value, str):
        raise ValueError("runtime manifest path is missing")
    runtime_manifest_path = run_root / runtime_manifest_value
    runtime_payload = _load_object(runtime_manifest_path)
    if (
        _sha256(runtime_manifest_path) != runtime_manifest.get("sha256")
        or runtime_payload.get("run_manifest_sha256")
        != runtime_manifest.get("run_manifest_sha256")
    ):
        raise ValueError("native runtime manifest binding drifted")
    effective_models = runtime_manifest.get("effective_models")
    if (
        not isinstance(effective_models, list)
        or len(effective_models) != 1
        or not isinstance(effective_models[0], str)
    ):
        raise ValueError("exactly one effective model alias is required")

    public_binding, _ = _public_input_binding(run_root, config, context)
    task_payload = _load_object(run_root / "inputs/task.json")
    if task_payload.get("task_id") != task_id:
        raise ValueError("public task ID differs from runtime task ID")
    if task_payload.get("source_mode") != "blank_scaffold":
        raise ValueError("v2 stage BLOCK receipt requires a blank scaffold")
    workspace_value = context.get("workspace_root")
    if not isinstance(workspace_value, str):
        raise ValueError("runtime context workspace root is missing")
    workspace_relative, workspace = _safe_directory(
        run_root,
        Path(workspace_value),
        label="workflow workspace",
    )
    workspace_files = _tree_map(workspace)
    if workspace_files:
        raise ValueError("blank workflow workspace contains terminal files")

    dispatch_evidence, blocked_dispatch, token_usage = _collect_dispatches(run_root)
    failed_stage = str(blocked_dispatch.get("stage") or "")
    workflow_stage = _classify_stage(failed_stage)
    http_status, provider_error_code, raw_log_evidence, wall_time, max_rss = (
        _provider_and_time_evidence(evidence_root, raw_logs)
    )

    approval_relative, approval_safe = _safe_file(
        run_root,
        approval_path,
        label="approval decisions",
    )
    if approval_safe.stat().st_size != 0:
        raise ValueError("provider-blocked run contains an approval decision")

    design_path = run_root / "design/design_spec.json"
    design_spec_produced = design_path.is_file() and not design_path.is_symlink()
    produced_artifacts: list[dict[str, Any]] = []
    if design_spec_produced:
        design_payload = _load_object(design_path)
        if design_payload.get("design_unit_id") != task_id:
            raise ValueError("produced DesignSpec task binding differs")
        produced_artifacts.append(
            _run_file_evidence(run_root, design_path, label="produced DesignSpec")
        )
    if workflow_stage != "design" and not design_spec_produced:
        raise ValueError("post-design provider BLOCK lacks a DesignSpec")

    completed_critics = sum(
        1
        for item in dispatch_evidence
        if item["status"] == "completed"
        and item["stage"].startswith("research-review-chipflow-critic-")
    )
    judge_decision = summary.get("judge_decision")
    judge_accept = judge_decision == "ACCEPT"
    if workflow_stage == "patch_plan" and not judge_accept:
        raise ValueError("PatchPlan-stage BLOCK lacks Judge ACCEPT")

    machine_gates = _collect_machine_gates(run_root)
    candidate_plan_count = len(
        list(run_root.glob("planning/preapproval_elaboration/*/candidate_plan.json"))
    )
    if candidate_plan_count != len(machine_gates):
        raise ValueError("candidate PatchPlan and machine-gate counts differ")

    completed_count = sum(
        item["status"] == "completed" for item in dispatch_evidence
    )
    missing_measurements = ["failed_dispatch_tokens"]
    if wall_time is None:
        missing_measurements.insert(0, "wall_time_seconds")
    if max_rss is None:
        insertion = 1 if wall_time is None else 0
        missing_measurements.insert(insertion, "maximum_resident_set_kib")

    runtime_manifest_evidence = _run_file_evidence(
        run_root,
        runtime_manifest_path,
        label="native runtime manifest",
    )
    runtime_manifest_evidence["run_manifest_sha256"] = runtime_manifest.get(
        "run_manifest_sha256"
    )
    receipt = {
        "schema_version": "rtlflowbench.chipflow_provider_stage_block_receipt.v2",
        "task_id": task_id,
        "observed_at": observed_at,
        "status": "blocked_model_provider_infra_after_partial_workflow",
        "attempt": {
            "run_id": config.get("chipflow_run_id"),
            "started_at": _parse_datetime(
                str(config.get("started_at") or ""),
                label="started_at",
            ),
            "exit_code": exit_code,
            "terminal_status": "blocked",
            "terminal_stage": "BLOCKED",
            "failed_workflow_stage": workflow_stage,
            "failed_dispatch_stage": failed_stage,
            "stable_error_class": STABLE_ERROR_CLASS,
            "provider_http_status": http_status,
            "provider_error_code": provider_error_code,
            "effective_model_alias": effective_models[0],
            "dispatch_result_count": len(dispatch_evidence),
            "completed_dispatch_count": completed_count,
            "blocked_dispatch_count": 1,
        },
        "evidence": {
            "evidence_root_locator": evidence_root_locator,
            "run_root_locator": run_root_locator,
            "orchestration_summary": _run_file_evidence(
                run_root,
                summary_path,
                label="orchestration summary",
            ),
            "runtime_config": _run_file_evidence(
                run_root,
                config_path,
                label="runtime config evidence",
            ),
            "runtime_context": _run_file_evidence(
                run_root,
                context_path,
                label="runtime context",
            ),
            "native_runtime_manifest": runtime_manifest_evidence,
            "approval_decisions": {
                "path": approval_relative,
                "sha256": _sha256(approval_safe),
                "root": "run",
                "bytes": 0,
            },
            "raw_command_logs": raw_log_evidence,
            "dispatch_results": dispatch_evidence,
            "produced_artifacts": produced_artifacts,
            "raw_provider_response_copied": False,
        },
        "public_input_binding": public_binding,
        "workspace_observation": {
            "source_mode": "blank_scaffold",
            "workflow_workspace_path": workspace_relative,
            "terminal_file_count": 0,
            "terminal_tree_sha256": _canonical_sha256(workspace_files),
            "main_workspace_mutation_observed": False,
            "preapproval_sandbox_separate": bool(machine_gates),
            "private_evaluator_exposed": False,
        },
        "workflow_progress": {
            "design_spec_produced": design_spec_produced,
            "completed_critic_count": completed_critics,
            "judge_decision": judge_decision,
            "judge_accept_observed": judge_accept,
            "patch_plan_candidate_count": candidate_plan_count,
            "preapproval_machine_gates": machine_gates,
            "approval_observed": False,
            "safe_executor_run_count": 0,
            "post_executor_verification_run_count": 0,
            "private_evaluator_run_count": 0,
            "neutral_export_count": 0,
            "benchmark_pass_claimed": False,
            "score_claimed": False,
            "ppa_claimed": False,
        },
        "resource_usage": {
            "wall_time_seconds": wall_time,
            "maximum_resident_set_kib": max_rss,
            "input_tokens": token_usage["input_tokens"],
            "output_tokens": token_usage["output_tokens"],
            "total_tokens": token_usage["total_tokens"],
            "llm_dispatches": len(dispatch_evidence),
            "token_accounted_dispatches": token_usage[
                "token_accounted_dispatches"
            ],
            "failed_unaccounted_dispatches": 1,
            "preapproval_machine_gate_runs": len(machine_gates),
            "post_executor_eda_runs": 0,
            "human_interventions": 0,
            "missing_measurements": missing_measurements,
        },
        "runtime_source_lock": _source_lock(source_root, source_files),
        "server_source_authority_guard": {},
        "readiness_impact": {
            "fresh_current_source_attempt_observed": True,
            "verified_completion_observed": False,
            "provider_healthy_retry_required": True,
            "current_runtime_expected_pass_observed": False,
            "current_runtime_multirun_complete": False,
            "benchmark_ready": False,
            "chipflow_adapter_ready": False,
        },
        "excluded_claims": [
            "A provider-infrastructure BLOCK after partial workflow progress is not a successful RTL workflow completion.",
            "A pre-approval machine-gate result is not post-executor verification or hidden-evaluator evidence.",
            "No approval, Safe Executor mutation, final visible PASS, hidden PASS, neutral export, or official score is claimed.",
            "No QoR improvement, PPA, benchmark readiness, adapter readiness, human-level result, or multi-run success rate is claimed.",
            "Tokens for the failed provider dispatch remain unavailable and are not replaced by zero.",
        ],
    }
    authority_after = _authority_snapshot(authority_root)
    if authority_before != authority_after:
        raise ValueError("server source authority changed while building receipt")
    receipt["server_source_authority_guard"] = {
        **authority_before,
        "before_after_equal": True,
        "mode": "read_only",
        "modified": False,
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
    parser.add_argument("--allowed-runs-root", type=Path, required=True)
    parser.add_argument("--run-root", type=Path, required=True)
    parser.add_argument("--raw-log", type=Path, action="append", required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--source-file", type=Path, action="append", required=True)
    parser.add_argument("--authority-root", type=Path, required=True)
    parser.add_argument("--evidence-root-locator", required=True)
    parser.add_argument("--run-root-locator", required=True)
    parser.add_argument("--observed-at", required=True)
    parser.add_argument("--exit-code", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        receipt = build_receipt(
            evidence_root=args.evidence_root,
            allowed_runs_root=args.allowed_runs_root,
            run_root=args.run_root,
            raw_logs=args.raw_log,
            source_root=args.source_root,
            source_files=args.source_file,
            authority_root=args.authority_root,
            evidence_root_locator=args.evidence_root_locator,
            run_root_locator=args.run_root_locator,
            observed_at=args.observed_at,
            exit_code=args.exit_code,
        )
        _write_new(args.output, receipt)
    except Exception as exc:
        print(
            json.dumps(
                {"status": "fail", "error": f"{type(exc).__name__}: {exc}"},
                indent=2,
                sort_keys=True,
            )
        )
        return 2
    print(
        json.dumps(
            {
                "status": "provider_stage_block_receipt_built",
                "task_id": receipt["task_id"],
                "failed_workflow_stage": receipt["attempt"][
                    "failed_workflow_stage"
                ],
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
