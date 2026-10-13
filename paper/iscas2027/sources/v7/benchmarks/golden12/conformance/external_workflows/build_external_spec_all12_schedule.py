#!/usr/bin/env python3
"""Build one external Spec-to-RTL workflow's complete Golden-12 schedule.

Every task and required repeat appears.  Supported public shapes are left
pending for real workflow execution.  Unsupported public shapes become
controller-bound BLOCK attempts via the shared terminal-result builder.  No
provider, EDA tool, or private evaluator is invoked by this control stage.
"""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import tempfile
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[3]
PROFILE = REPO_ROOT / "benchmarks/golden12/evaluation/profile.json"
TASK_SCHEMA = REPO_ROOT / "benchmarks/golden12/schemas/task.schema.json"
SOURCE_PREFLIGHT_SCHEMA = HERE / "source_runtime_preflight.schema.json"
PUBLIC_SPEC_BRIDGE = HERE / "public_spec_submission_bridge.py"
TERMINAL_BUILDER = (
    REPO_ROOT / "benchmarks/golden12/evaluation/build_workflow_terminal_result.py"
)
OUTPUT_SCHEMA = HERE / "external_spec_all12_schedule.schema.json"
CONTROLLER_NAME = "rtlflowbench-external-spec-all12-schedule-controller"
CONTROLLER_VERSION = "1"


def _load(path: Path, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a regular non-symlink file: {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{label} must contain one JSON object")
    return value


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ValueError(f"could not load module: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical_sha256(value: dict[str, Any]) -> str:
    encoded = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _write_new(path: Path, value: dict[str, Any]) -> None:
    if path.exists() or path.is_symlink():
        raise FileExistsError(f"refusing to overwrite output: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _copy_public_workspace(source: Path, destination: Path) -> None:
    if source.is_symlink() or not source.is_dir():
        raise ValueError(f"public task root is not a regular directory: {source}")
    for path in source.rglob("*"):
        if path.is_symlink() or (not path.is_file() and not path.is_dir()):
            raise ValueError(f"public task contains an unsafe entry: {path}")
    shutil.copytree(source, destination, symlinks=False)


def _tree_manifest(root: Path) -> tuple[str, int, int]:
    entries: list[dict[str, Any]] = []
    total_bytes = 0
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError(f"workspace manifest encountered symlink: {path}")
        if path.is_dir():
            continue
        if not path.is_file():
            raise ValueError(f"workspace manifest encountered non-file: {path}")
        relative = path.relative_to(root).as_posix()
        size = path.stat().st_size
        total_bytes += size
        entries.append({"path": relative, "sha256": _sha256(path), "bytes": size})
    payload = json.dumps(
        entries, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest(), len(entries), total_bytes


def _metadata(
    *,
    workflow: Any,
    task_id: str,
    independent_run_index: int,
    config_sha256: str,
) -> dict[str, Any]:
    return {
        "schema_version": "rtlflowbench.submission_metadata.v1",
        "submission_id": (
            f"{workflow.workflow_id}-{task_id.lower()}-no-submission-"
            f"{independent_run_index}"
        ),
        "workflow": {
            "name": workflow.display_name,
            "version": f"source@{workflow.commit[:12]}",
            "adapter_name": "rtlflowbench-public-spec-submission-bridge",
            "adapter_version": "1",
            "model": {"provider": None, "name": None},
            "config_sha256": config_sha256,
        },
        "attempt": {
            "attempt_id": (
                f"{workflow.workflow_id}-{task_id.lower()}-independent-run-"
                f"{independent_run_index}"
            ),
            "attempt_index": 1,
            "repeat_group_id": (
                f"{workflow.workflow_id}-{task_id.lower()}-repeat-group"
            ),
            "seed": independent_run_index,
        },
        "resource_usage": {
            "wall_time_seconds": 0.0,
            # This row is emitted only after the controller records that the
            # workflow process and provider were never started.  Zero is an
            # observed count here, not a replacement for missing provider
            # telemetry.
            "input_tokens": 0,
            "output_tokens": 0,
            "llm_calls": 0,
            "eda_calls": {
                "compile_or_lint": 0,
                "simulation": 0,
                "formal": 0,
                "synthesis": 0,
            },
            "human_interventions": 0,
            "missing_measurements": [],
        },
        "network_access_observed": False,
        "claims": [
            "Controller preflight row only; no workflow submission exists."
        ],
    }


def _validate_task(task: dict[str, Any]) -> None:
    schema = _load(TASK_SCHEMA, "task schema")
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(task)


def _validate_candidate_lock(
    *, repo_root: Path, task_id: str, descriptor_path: Path
) -> tuple[str, str]:
    lock_path = (
        repo_root
        / "benchmarks/golden12/tasks"
        / task_id
        / "private/admission/candidate.lock.json"
    )
    lock = _load(lock_path, f"{task_id} candidate lock")
    if lock.get("task_id") != task_id:
        raise ValueError(f"candidate lock identity mismatch for {task_id}")
    components = lock.get("component_sha256")
    if not isinstance(components, dict):
        raise ValueError(f"candidate lock components are invalid for {task_id}")
    relative = descriptor_path.relative_to(repo_root).as_posix()
    expected = components.get(relative)
    observed = _sha256(descriptor_path)
    if expected != observed:
        raise ValueError(f"candidate lock descriptor digest mismatch for {task_id}")
    return _sha256(lock_path), observed


def _validate_preflights(
    *,
    workflow: Any,
    source_preflight_path: Path,
    adapter_test_receipt_path: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    source_preflight = _load(source_preflight_path, "source preflight receipt")
    schema = _load(SOURCE_PREFLIGHT_SCHEMA, "source preflight schema")
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(
        source_preflight
    )
    if source_preflight["status"] != "source_preflight_pass_environment_blocked":
        raise ValueError("source preflight status is not the reviewed blocked state")
    if source_preflight["workflow"]["workflow_id"] != workflow.workflow_id:
        raise ValueError("source preflight workflow identity drift")
    if source_preflight["workflow"]["commit"] != workflow.commit:
        raise ValueError("source preflight commit drift")
    source = source_preflight["source_binding"]
    if (
        source["archive_sha256"] != workflow.source_archive_sha256
        or source["recreated_archive_sha256"] != workflow.source_archive_sha256
        or source["tracked_manifest_sha256"]
        != workflow.tracked_manifest_sha256
        or source["worktree_clean"] is not True
        or source["submodules_present"] is not False
    ):
        raise ValueError("source preflight content binding drift")
    required_checks = (
        "source_commit_matches",
        "worktree_clean",
        "source_archive_matches",
        "recreated_archive_matches",
        "tracked_manifest_matches",
        "submodule_status_empty",
        "entrypoint_ast_parses",
        "dependency_metadata_parsed",
    )
    if not all(source_preflight["checks"].get(key) is True for key in required_checks):
        raise ValueError("source preflight automatic checks are incomplete")
    readiness = source_preflight["readiness"]
    if (
        readiness["source_preflight_passed"] is not True
        or readiness["environment_reproduced"] is not False
        or readiness["adapter_conformance_passed"] is not False
        or readiness["airtl_run_observed"] is not False
        or readiness["private_evaluator_run"] is not False
        or readiness["rtl_verdict_produced"] is not False
        or readiness["official_attempts_permitted"] is not False
    ):
        raise ValueError("source preflight readiness semantics drift")

    adapter = _load(adapter_test_receipt_path, "adapter test receipt")
    if (
        adapter.get("status") != "pass"
        or adapter.get("returncode") != 0
        or adapter.get("authority_unchanged") is not True
        or adapter.get("airtl_workflow_run_count") != 0
        or adapter.get("hidden_evaluator_run_count") != 0
        or adapter.get("rtl_verdict_count") != 0
        or adapter.get("benchmark_ready") is not False
    ):
        raise ValueError("adapter test receipt does not prove a safe control test")
    return source_preflight, adapter


def build_schedule(
    *,
    repo_root: Path,
    workflow_id: str,
    source_preflight_path: Path,
    adapter_test_receipt_path: Path,
    output_dir: Path,
    observed_at: str,
) -> dict[str, Any]:
    parsed = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("observed_at must include a timezone")
    repo_root = repo_root.expanduser().resolve(strict=True)
    output_dir = output_dir.expanduser().absolute()
    if output_dir.exists() or output_dir.is_symlink():
        raise FileExistsError(f"refusing to overwrite output: {output_dir}")
    bridge = _load_module(
        "rtlflowbench_external_spec_schedule_bridge", PUBLIC_SPEC_BRIDGE
    )
    terminal_builder = _load_module(
        "rtlflowbench_external_spec_schedule_terminal_builder", TERMINAL_BUILDER
    )
    profile = _load(PROFILE, "evaluation profile")
    try:
        workflow = bridge.WORKFLOWS[workflow_id]
    except KeyError as exc:
        raise ValueError(f"unsupported external workflow: {workflow_id}") from exc
    source_preflight_path = source_preflight_path.expanduser().resolve(strict=True)
    adapter_test_receipt_path = adapter_test_receipt_path.expanduser().resolve(
        strict=True
    )
    _validate_preflights(
        workflow=workflow,
        source_preflight_path=source_preflight_path,
        adapter_test_receipt_path=adapter_test_receipt_path,
    )
    config_sha256 = _canonical_sha256(
        {
            "controller": CONTROLLER_NAME,
            "controller_version": CONTROLLER_VERSION,
            "workflow_id": workflow.workflow_id,
            "workflow_commit": workflow.commit,
            "workflow_source_archive_sha256": workflow.source_archive_sha256,
            "workflow_source_manifest_sha256": workflow.tracked_manifest_sha256,
            "source_preflight_sha256": _sha256(source_preflight_path),
            "adapter_test_receipt_sha256": _sha256(adapter_test_receipt_path),
            "bridge_sha256": _sha256(PUBLIC_SPEC_BRIDGE),
            "terminal_builder_sha256": _sha256(TERMINAL_BUILDER),
            "profile_sha256": _sha256(PROFILE),
        }
    )
    output_dir.mkdir(parents=True)
    tasks: list[dict[str, Any]] = []
    terminal_records: list[tuple[str, str, str]] = []
    total_attempts = 0
    pending_attempts = 0
    block_attempts = 0
    with tempfile.TemporaryDirectory(
        prefix=f"rtlflowbench-{workflow.workflow_id}-all12-"
    ) as temp:
        workspace_base = Path(temp)
        for task_profile in profile["tasks"]:
            task_id = task_profile["task_id"]
            public_root = repo_root / "benchmarks/golden12/tasks" / task_id / "public"
            task = _load(public_root / "external_task.json", f"{task_id} task")
            _validate_task(task)
            if task["task_id"] != task_id:
                raise ValueError(f"profile/task identity mismatch for {task_id}")
            candidate_lock_sha256, task_descriptor_sha256 = _validate_candidate_lock(
                repo_root=repo_root,
                task_id=task_id,
                descriptor_path=public_root / "external_task.json",
            )
            classification = bridge.classify_public_task_shape(task)
            minimum = task_profile["minimum_independent_runs"]
            total_attempts += minimum
            task_row = {
                "task_id": task_id,
                "capability_family": task_profile["capability_family"],
                "minimum_independent_runs": minimum,
                "candidate_lock_sha256": candidate_lock_sha256,
                "task_descriptor_sha256": task_descriptor_sha256,
                "public_shape_classification": classification,
                "attempts": [],
            }
            for independent_run_index in range(1, minimum + 1):
                if classification["supported"]:
                    pending_attempts += 1
                    task_row["attempts"].append(
                        {
                            "independent_run_index": independent_run_index,
                            "workflow_attempt_index": 1,
                            "status": "pending_real_workflow_execution",
                            "terminal_result_path": None,
                            "attempt_control_path": None,
                        }
                    )
                    continue
                workspace = (
                    workspace_base
                    / task_id
                    / str(independent_run_index)
                    / "public"
                )
                workspace.parent.mkdir(parents=True)
                _copy_public_workspace(public_root, workspace)
                initial_sha, file_count, total_bytes = _tree_manifest(workspace)
                copied_task = _load(
                    workspace / "external_task.json", "copied public task"
                )
                copied_classification = bridge.classify_public_task_shape(copied_task)
                if copied_classification != classification:
                    raise ValueError(f"public shape classification drift for {task_id}")
                final_sha, final_file_count, final_bytes = _tree_manifest(workspace)
                if (initial_sha, file_count, total_bytes) != (
                    final_sha,
                    final_file_count,
                    final_bytes,
                ):
                    raise ValueError(f"public workspace changed during preflight: {task_id}")
                slug = (
                    f"records/{workflow.workflow_id}/{task_id.lower()}"
                    f"/independent-run-{independent_run_index}"
                )
                workspace_evidence = f"{slug}/workspace-provisioning.json"
                process_evidence = f"{slug}/process-isolation.json"
                terminal_evidence = f"{slug}/terminal-observation.json"
                metadata_relative = f"{slug}/metadata.json"
                _write_new(
                    output_dir / workspace_evidence,
                    {
                        "task_id": task_id,
                        "independent_run_index": independent_run_index,
                        "workflow_attempt_index": 1,
                        "workspace_source": "fresh_public_packet_unpack",
                        "workspace_manifest_sha256": initial_sha,
                        "file_count": file_count,
                        "bytes": total_bytes,
                        "workspace_removed_after_preflight": True,
                    },
                )
                _write_new(
                    output_dir / process_evidence,
                    {
                        "task_id": task_id,
                        "independent_run_index": independent_run_index,
                        "workflow_attempt_index": 1,
                        "controller_process_started": True,
                        "workflow_process_started": False,
                        "provider_call_observed": False,
                    },
                )
                _write_new(
                    output_dir / terminal_evidence,
                    {
                        "task_id": task_id,
                        "independent_run_index": independent_run_index,
                        "workflow_attempt_index": 1,
                        "classification": copied_classification,
                        "hidden_evaluator_run": False,
                        "private_assets_exposed": False,
                    },
                )
                metadata = _metadata(
                    workflow=workflow,
                    task_id=task_id,
                    independent_run_index=independent_run_index,
                    config_sha256=config_sha256,
                )
                _write_new(output_dir / metadata_relative, metadata)
                terminal, control = terminal_builder.build_terminal_documents(
                    run_root=output_dir,
                    task_path=workspace / "external_task.json",
                    metadata_path=output_dir / metadata_relative,
                    terminal_result_id=(
                        f"{workflow.workflow_id}-{task_id.lower()}-terminal-"
                        f"{independent_run_index}"
                    ),
                    run_id=(
                        f"{workflow.workflow_id}-{task_id.lower()}-run-"
                        f"{independent_run_index}"
                    ),
                    reason_code=classification["reason_code"],
                    workflow_process_started=False,
                    provider_call_observed=False,
                    workspace_initial_manifest_sha256=initial_sha,
                    workspace_final_manifest_sha256=final_sha,
                    workspace_evidence_relative=workspace_evidence,
                    process_evidence_relative=process_evidence,
                    terminal_evidence_relative=terminal_evidence,
                    controller_name=CONTROLLER_NAME,
                    controller_version=CONTROLLER_VERSION,
                    controller_config_sha256=config_sha256,
                    observed_at=observed_at,
                )
                terminal_relative = f"{slug}/terminal-result.json"
                control_relative = f"{slug}/attempt-control.json"
                _write_new(output_dir / terminal_relative, terminal)
                _write_new(output_dir / control_relative, control)
                terminal_records.append(
                    (task_id, terminal_relative, control_relative)
                )
                block_attempts += 1
                task_row["attempts"].append(
                    {
                        "independent_run_index": independent_run_index,
                        "workflow_attempt_index": 1,
                        "status": "controller_block_recorded",
                        "terminal_result_path": terminal_relative,
                        "attempt_control_path": control_relative,
                    }
                )
            tasks.append(task_row)
    result = {
        "schema_version": "rtlflowbench.external_spec_all12_schedule.v1",
        "observed_at": observed_at,
        "status": "all12_scheduled_partial_terminal_projection_not_released",
        "workflow": {
            "workflow_id": workflow.workflow_id,
            "name": workflow.display_name,
            "version": f"source@{workflow.commit[:12]}",
            "commit": workflow.commit,
            "source_archive_sha256": workflow.source_archive_sha256,
            "tracked_manifest_sha256": workflow.tracked_manifest_sha256,
            "adapter_name": "rtlflowbench-public-spec-submission-bridge",
            "adapter_version": "1",
            "config_sha256": config_sha256,
        },
        "tasks": tasks,
        "summary": {
            "task_count": len(tasks),
            "scheduled_attempt_count": total_attempts,
            "pending_real_workflow_attempt_count": pending_attempts,
            "controller_block_attempt_count": block_attempts,
            "omitted_attempt_count": 0,
            "airtl_workflow_run_count": 0,
            "hidden_evaluator_run_count": 0,
            "rtl_verdict_count": 0,
        },
        "terminal_records": [
            {
                "task_id": task_id,
                "terminal_result_path": terminal_path,
                "terminal_result_sha256": _sha256(output_dir / terminal_path),
                "attempt_control_path": control_path,
                "attempt_control_sha256": _sha256(output_dir / control_path),
            }
            for task_id, terminal_path, control_path in terminal_records
        ],
        "source_sha256": {
            "benchmarks/golden12/evaluation/profile.json": _sha256(PROFILE),
            "benchmarks/golden12/conformance/external_workflows/source_runtime_preflight.schema.json": _sha256(
                SOURCE_PREFLIGHT_SCHEMA
            ),
            "benchmarks/golden12/conformance/external_workflows/public_spec_submission_bridge.py": _sha256(
                PUBLIC_SPEC_BRIDGE
            ),
            "benchmarks/golden12/evaluation/build_workflow_terminal_result.py": _sha256(
                TERMINAL_BUILDER
            ),
            "benchmarks/golden12/conformance/external_workflows/build_external_spec_all12_schedule.py": _sha256(
                Path(__file__).resolve()
            ),
            "benchmarks/golden12/conformance/external_workflows/external_spec_all12_schedule.schema.json": _sha256(
                OUTPUT_SCHEMA
            ),
        },
        "preflight_evidence": {
            "source_preflight_sha256": _sha256(source_preflight_path),
            "adapter_test_receipt_sha256": _sha256(adapter_test_receipt_path),
            "source_preflight_passed": True,
            "adapter_control_tests_passed": True,
            "environment_reproduced": False,
            "dependency_lock_frozen": False,
        },
        "readiness": {
            "schedule_complete": total_attempts == 40,
            "terminal_projection_complete_for_unsupported_shapes": (
                block_attempts == 34
            ),
            "real_workflow_attempts_complete": False,
            "environment_frozen": False,
            "adapter_ready": False,
            "benchmark_ready": False,
            "publication_permitted": False,
        },
        "excluded_claims": [
            "A controller BLOCK row is not an AIRTL workflow run or RTL verdict.",
            "Six public-shape-supported attempts remain pending real provider execution and evaluation.",
            "No hidden evaluator, PASS, FAIL, score, QoR, PPA, readiness or publication is claimed.",
        ],
    }
    schema = _load(OUTPUT_SCHEMA, "external Spec-to-RTL all-12 schedule schema")
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(
        schema, format_checker=FormatChecker()
    ).validate(result)
    _write_new(output_dir / "external-spec-all12-schedule.json", result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--workflow-id", choices=("verilogcoder", "hdlagent"), required=True)
    parser.add_argument("--source-preflight", type=Path, required=True)
    parser.add_argument("--adapter-test-receipt", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--observed-at", required=True)
    args = parser.parse_args()
    try:
        result = build_schedule(
            repo_root=args.repo_root,
            workflow_id=args.workflow_id,
            source_preflight_path=args.source_preflight,
            adapter_test_receipt_path=args.adapter_test_receipt,
            output_dir=args.output_dir,
            observed_at=args.observed_at,
        )
    except Exception as exc:
        print(
            json.dumps(
                {"status": "invalid_evidence", "error": f"{type(exc).__name__}: {exc}"},
                indent=2,
                sort_keys=True,
            )
        )
        return 2
    print(json.dumps(result["summary"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
