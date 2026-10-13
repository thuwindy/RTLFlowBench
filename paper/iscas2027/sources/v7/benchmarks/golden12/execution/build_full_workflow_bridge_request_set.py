#!/usr/bin/env python3
"""Materialize public-only launch inputs or explicit controller dispositions.

The builder performs no provider, EDA, private-evaluator, or workflow call.  It
projects the same content-bound public workspace into each selected workflow's
native request format.  A workflow whose public capability contract cannot
represent a task receives an explicit preclassified controller disposition;
the task is never omitted or silently reassigned.
"""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import sys
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[2]
SET_SCHEMA = HERE / "full_workflow_bridge_request_set.schema.json"
RESOURCE_REQUEST_SCHEMA = (
    HERE / "full_workflow_resource_measurement_request.schema.json"
)
RESOURCE_REQUEST_SET_SCHEMA = (
    HERE / "full_workflow_resource_measurement_request_set.schema.json"
)
WORKSPACE_SET_SCHEMA = (
    REPO_ROOT / "benchmarks/golden12/admission/"
    "public_trial_workspace_set_receipt.schema.json"
)
WORKSPACE_SET_BUILDER = (
    REPO_ROOT / "benchmarks/golden12/admission/build_public_trial_workspace_set.py"
)
CHIPFLOW_BUILDER = REPO_ROOT / "benchmarks/golden12/chipflow/build_launch_request.py"
VANILLA_BUILDER = (
    REPO_ROOT / "benchmarks/golden12/baselines/vanilla_agent/build_launch_request.py"
)
MAGE_BRIDGE = (
    REPO_ROOT / "benchmarks/golden12/conformance/external_workflows/"
    "mage_submission_bridge.py"
)
PUBLIC_SPEC_BRIDGE = (
    REPO_ROOT / "benchmarks/golden12/conformance/external_workflows/"
    "public_spec_submission_bridge.py"
)
COMMON_MODEL_SCHEMA = (
    REPO_ROOT
    / "benchmarks/golden12/evaluation/common_model_decoding_candidate.schema.json"
)
TASK_IDS = (
    "G01-common-fifo-spec",
    "G02-common-rr-arbiter-spec",
    "G03-axis-fifo-backpressure",
    "G04-wb2axip-split-bridge",
    "G05-picorv32-missing-irq",
    "G06-ibex-debug-csr-exception",
    "G07-ibex-ifetch-error-timing",
    "G08-common-fifo-dv",
    "G09-axis-fifo-dv",
    "G10-serv-area-qor",
    "G11-picorv32-qor",
    "G12-common-cdc-missing-contract",
)
SLOTS = (
    ("chipflow", "chipflow"),
    ("same_model_vanilla_agent", "same_model_vanilla_agent"),
    ("external_airtl_1", "mage"),
    ("external_airtl_2", "verilogcoder"),
    ("external_airtl_3", "hdlagent"),
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
FORBIDDEN_PATH_PARTS = frozenset({"private", "oracle", "evaluator"})


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _sha256(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"expected a regular non-symlink file: {path}")
    return _sha256_bytes(path.read_bytes())


def _require_sha256(path: Path, expected: str, label: str) -> str:
    if SHA256_RE.fullmatch(expected) is None or _sha256(path) != expected:
        raise ValueError(f"{label} differs from its out-of-band SHA256")
    return expected


def _load(path: Path, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a regular non-symlink file")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{label} must contain one JSON object")
    return value


def _validate(schema_path: Path, value: dict[str, Any], label: str) -> None:
    schema = _load(schema_path, f"{label} schema")
    Draft202012Validator.check_schema(schema)
    errors = sorted(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(value),
        key=lambda error: list(error.absolute_path),
    )
    if errors:
        first = errors[0]
        location = "/".join(str(part) for part in first.absolute_path)
        raise ValueError(
            f"{label} schema error at {location or '<root>'}: {first.message}"
        )


def _module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ValueError(f"cannot load current source module: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _safe_relative(value: str, label: str) -> PurePosixPath:
    relative = PurePosixPath(value)
    lowered = {part.lower() for part in relative.parts}
    if (
        relative.is_absolute()
        or not relative.parts
        or any(part in {"", ".", ".."} for part in relative.parts)
        or lowered & FORBIDDEN_PATH_PARTS
    ):
        raise ValueError(f"unsafe {label}: {value}")
    return relative


def _tree_entries(root: Path, label: str) -> list[dict[str, Any]]:
    if root.is_symlink() or not root.is_dir():
        raise ValueError(f"{label} must be a regular directory")
    rows: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        _safe_relative(relative, label)
        if path.is_symlink():
            raise ValueError(f"{label} contains a symlink")
        if path.is_dir():
            continue
        if not path.is_file():
            raise ValueError(f"{label} contains a non-regular entry")
        payload = path.read_bytes()
        rows.append(
            {
                "path": relative,
                "bytes": len(payload),
                "sha256": _sha256_bytes(payload),
            }
        )
    return rows


def _canonical_digest(value: Any) -> str:
    return _sha256_bytes(
        json.dumps(
            value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
    )


def _copy_workspace(source: Path, destination: Path) -> None:
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(f"refusing to reuse bridge request root: {destination}")
    for path in [source, *sorted(source.rglob("*"))]:
        if path.is_symlink():
            raise ValueError("public workspace contains a symlink")
        if not path.is_dir() and not path.is_file():
            raise ValueError("public workspace contains a non-regular entry")
        if path != source:
            _safe_relative(path.relative_to(source).as_posix(), "workspace path")
    shutil.copytree(source, destination, copy_function=shutil.copy2)


def _workspace_rows(
    *,
    workspace_root: Path,
    workspace_set: dict[str, Any],
    workspace_set_builder: Any,
) -> dict[str, dict[str, Any]]:
    children = sorted(path.name for path in workspace_root.iterdir())
    if children != sorted(TASK_IDS):
        raise ValueError("workspace root must contain exactly the twelve tasks")
    rows = workspace_set.get("tasks")
    if not isinstance(rows, list) or [row.get("task_id") for row in rows] != list(
        TASK_IDS
    ):
        raise ValueError("public workspace set task order drift")
    by_task: dict[str, dict[str, Any]] = {}
    for row in rows:
        task_id = row["task_id"]
        root = workspace_root / task_id
        receipt = root / "workspace_receipt.json"
        public_entries = workspace_set_builder._tree_entries(
            root / "public", label="bridge public workspace"
        )
        worktree_entries = workspace_set_builder._tree_entries(
            root / "worktree", label="bridge repository workspace"
        )
        payload_entries = [
            {**item, "path": f"public/{item['path']}"} for item in public_entries
        ] + [{**item, "path": f"worktree/{item['path']}"} for item in worktree_entries]
        if not (
            _sha256(receipt) == row.get("workspace_receipt_sha256")
            and workspace_set_builder._canonical_digest(public_entries)
            == row.get("public_tree_sha256")
            and workspace_set_builder._canonical_digest(payload_entries)
            == row.get("workspace_payload_sha256")
            and len(public_entries) == row.get("public_file_count")
            and len(worktree_entries) == row.get("repository_file_count")
            and row.get("private_file_count") == 0
        ):
            raise ValueError(f"public workspace content drift: {task_id}")
        by_task[task_id] = row
    return by_task


def _prepare_internal(
    *,
    module: Any,
    source_workspace: Path,
    destination: Path,
    workspace_row: dict[str, Any],
    workflow_binding: Path,
    workflow_binding_sha256: str,
    model: str,
    resource_request: dict[str, Any],
) -> str:
    _copy_workspace(source_workspace, destination)
    official = resource_request["official_attempt_binding"]
    module.build_request(
        request_root=destination,
        workspace_receipt_sha256=workspace_row["workspace_receipt_sha256"],
        workflow_binding_path=workflow_binding,
        workflow_binding_sha256=workflow_binding_sha256,
        expected_model=model,
        mode="development",
        attempt_id=resource_request["attempt_id"],
        # This is the retry index inside one freshly provisioned workflow
        # invocation, not the controller-owned independent-run index.  The
        # latter remains bound by official_attempt_binding and the request-set
        # row.  Every currently frozen Golden-12 task permits one workflow
        # attempt per independent run.
        attempt_index=1,
        repeat_group_id=(
            f"resource-calibration-{resource_request['workflow_slot_id']}-"
            f"{resource_request['task_id']}"
        ),
        seed=official["seed"],
        submission_id=f"submission-{resource_request['attempt_id']}",
        maximum_public_text_bytes=1_048_576,
        maximum_repository_text_bytes=4_194_304,
    )
    return (
        "chipflow_native_public_request"
        if resource_request["workflow_slot_id"] == "chipflow"
        else "same_model_vanilla_public_request"
    )


def _external_classification(
    *, workflow_id: str, task: dict[str, Any], mage: Any, public_spec: Any
) -> dict[str, Any]:
    if workflow_id == "mage":
        return mage.classify_public_task_shape(task)
    if workflow_id in {"verilogcoder", "hdlagent"}:
        return public_spec.classify_public_task_shape(task)
    raise ValueError(f"unknown external workflow: {workflow_id}")


def _prepare_external(
    *,
    workflow_id: str,
    public_root: Path,
    destination: Path,
    observed_at: str,
    mage: Any,
    public_spec: Any,
) -> str:
    if workflow_id == "mage":
        profile = mage._profile()
        mage.prepare_request(
            task_public_root=public_root,
            output_dir=destination,
            observed_at=observed_at,
            mode="development",
            upstream_commit=profile["upstream"]["commit"],
            source_manifest_sha256=profile["source_intake"]["manifest_sha256"],
        )
        return "mage_public_spec_request"
    workflow = public_spec.WORKFLOWS[workflow_id]
    public_spec.prepare_request(
        workflow_id=workflow_id,
        task_public_root=public_root,
        output_dir=destination,
        observed_at=observed_at,
        mode="development",
        upstream_commit=workflow.commit,
        source_manifest_sha256=workflow.tracked_manifest_sha256,
    )
    return f"{workflow_id}_public_spec_request"


def build_bridge_request_set(
    *,
    repo_root: Path,
    workspace_root: Path,
    public_workspace_set_path: Path,
    expected_public_workspace_set_sha256: str,
    resource_request_set_path: Path,
    expected_resource_request_set_sha256: str,
    chipflow_binding_path: Path,
    expected_chipflow_binding_sha256: str,
    vanilla_binding_path: Path,
    expected_vanilla_binding_sha256: str,
    common_model_path: Path,
    expected_common_model_sha256: str,
    observed_at: str,
    output_dir: Path,
) -> dict[str, Any]:
    parsed = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("observed_at must include a timezone")
    repo_root = repo_root.expanduser().resolve(strict=True)
    workspace_root = workspace_root.expanduser().resolve(strict=True)
    output_dir = output_dir.expanduser().absolute()
    if output_dir.exists() or output_dir.is_symlink():
        raise FileExistsError(f"refusing to overwrite bridge set: {output_dir}")

    workspace_set_path = public_workspace_set_path.expanduser().resolve(strict=True)
    request_set_path = resource_request_set_path.expanduser().resolve(strict=True)
    chipflow_binding_path = chipflow_binding_path.expanduser().resolve(strict=True)
    vanilla_binding_path = vanilla_binding_path.expanduser().resolve(strict=True)
    common_model_path = common_model_path.expanduser().resolve(strict=True)
    workspace_set_sha = _require_sha256(
        workspace_set_path,
        expected_public_workspace_set_sha256,
        "public workspace set",
    )
    request_set_sha = _require_sha256(
        request_set_path,
        expected_resource_request_set_sha256,
        "resource request set",
    )
    chipflow_binding_sha = _require_sha256(
        chipflow_binding_path,
        expected_chipflow_binding_sha256,
        "ChipFlow binding",
    )
    vanilla_binding_sha = _require_sha256(
        vanilla_binding_path,
        expected_vanilla_binding_sha256,
        "vanilla binding",
    )
    common_model_sha = _require_sha256(
        common_model_path,
        expected_common_model_sha256,
        "common model candidate",
    )

    workspace_set = _load(workspace_set_path, "public workspace set")
    request_set = _load(request_set_path, "resource request set")
    common_model = _load(common_model_path, "common model candidate")
    _validate(WORKSPACE_SET_SCHEMA, workspace_set, "public workspace set")
    _validate(RESOURCE_REQUEST_SET_SCHEMA, request_set, "resource request set")
    _validate(COMMON_MODEL_SCHEMA, common_model, "common model candidate")
    if not (
        workspace_set.get("status")
        == "development_public_trial_workspace_set_materialized_not_admitted"
        and workspace_set.get("summary", {}).get("workspace_count") == 12
        and workspace_set.get("summary", {}).get("private_file_count") == 0
        and workspace_set.get("readiness", {}).get("all_public_workspaces_materialized")
        is True
        and workspace_set.get("readiness", {}).get("official_attempts_permitted")
        is False
    ):
        raise ValueError("public workspace set is stale or unsafe")
    if not (
        request_set.get("status") == "requests_materialized_execution_blocked"
        and request_set.get("input_sha256", {}).get("public_workspace_set")
        == workspace_set_sha
        and request_set.get("summary", {}).get("request_count") == 200
        and request_set.get("summary", {}).get("public_workspace_count") == 12
        and request_set.get("readiness", {}).get("all_public_workspaces_materialized")
        is True
        and request_set.get("readiness", {}).get("controller_envelope_bound") is False
        and request_set.get("readiness", {}).get("common_provider_preflight_passed")
        is False
        and request_set.get("blockers")
        == [
            "controller_aware_measurement_envelope_not_bound",
            "common_provider_preflight_not_passed",
        ]
    ):
        raise ValueError("resource request set is stale or unsafe")
    model = common_model.get("model")
    if (
        not isinstance(model, str)
        or not model
        or common_model.get("scope") != "all_five_airtl_workflow_slots_all_twelve_tasks"
        or common_model.get("release_freeze", {}).get("effective") is not False
    ):
        raise ValueError("common model candidate is not the fail-closed cohort input")
    chipflow_binding = _load(chipflow_binding_path, "ChipFlow binding")
    vanilla_binding = _load(vanilla_binding_path, "vanilla binding")
    for label, binding, name in (
        ("ChipFlow", chipflow_binding, "chipflow-native"),
        ("vanilla", vanilla_binding, "same-model-vanilla-agent"),
    ):
        workflow = binding.get("workflow", {})
        if not (
            binding.get("status") == "development_not_frozen"
            and workflow.get("name") == name
            and workflow.get("model")
            == {"provider": common_model.get("provider"), "name": model}
        ):
            raise ValueError(f"{label} binding differs from the common model")

    workspace_module = _module(
        "rtlflowbench_bridge_workspace_set", WORKSPACE_SET_BUILDER
    )
    chipflow_module = _module("rtlflowbench_bridge_chipflow_request", CHIPFLOW_BUILDER)
    vanilla_module = _module("rtlflowbench_bridge_vanilla_request", VANILLA_BUILDER)
    mage_module = _module("rtlflowbench_bridge_mage", MAGE_BRIDGE)
    public_spec_module = _module("rtlflowbench_bridge_public_spec", PUBLIC_SPEC_BRIDGE)
    workspace_by_task = _workspace_rows(
        workspace_root=workspace_root,
        workspace_set=workspace_set,
        workspace_set_builder=workspace_module,
    )

    request_root = request_set_path.parent
    request_schema = _load(RESOURCE_REQUEST_SCHEMA, "resource request schema")
    Draft202012Validator.check_schema(request_schema)
    index = request_set.get("requests")
    if not isinstance(index, list) or len(index) != 200:
        raise ValueError("resource request index must contain 200 rows")
    output_dir.mkdir(parents=True)
    result_rows: list[dict[str, Any]] = []
    materialized_count = 0
    controller_block_count = 0
    per_slot = {slot: {"materialized": 0, "controller_block": 0} for slot, _ in SLOTS}
    slot_workflows = dict(SLOTS)
    for position, item in enumerate(index):
        relative = _safe_relative(item["request_relative_path"], "request path")
        request_path = (request_root / Path(*relative.parts)).resolve(strict=True)
        if not request_path.is_relative_to(request_root):
            raise ValueError("resource request escapes its set root")
        if _sha256(request_path) != item.get("request_sha256"):
            raise ValueError("resource request differs from its set index")
        resource_request = _load(request_path, "resource request")
        errors = list(
            Draft202012Validator(request_schema).iter_errors(resource_request)
        )
        if errors:
            raise ValueError(f"resource request schema drift at row {position}")
        slot = resource_request["workflow_slot_id"]
        workflow_id = resource_request["workflow_id"]
        task_id = resource_request["task_id"]
        run_index = resource_request["calibration_run_index"]
        workspace_row = workspace_by_task.get(task_id)
        public_input = resource_request["public_input_binding"]
        if not (
            slot_workflows.get(slot) == workflow_id
            and item.get("workflow_slot_id") == slot
            and item.get("workflow_id") == workflow_id
            and item.get("task_id") == task_id
            and item.get("calibration_run_index") == run_index
            and workspace_row is not None
            and public_input.get("workspace_set_receipt_sha256") == workspace_set_sha
            and public_input.get("workspace_receipt_sha256")
            == workspace_row["workspace_receipt_sha256"]
            and public_input.get("workspace_payload_sha256")
            == workspace_row["workspace_payload_sha256"]
            and public_input.get("private_assets_included") is False
            and resource_request.get("blockers")
            == [
                "controller_aware_measurement_envelope_not_bound",
                "common_provider_preflight_not_passed",
            ]
        ):
            raise ValueError(f"resource/public workspace binding drift: {position}")

        destination_relative = PurePosixPath(
            "requests", slot, task_id, f"run-{run_index}"
        )
        destination = output_dir / Path(*destination_relative.parts)
        classification: dict[str, Any]
        bridge_kind: str
        disposition: str
        if slot == "chipflow":
            bridge_kind = _prepare_internal(
                module=chipflow_module,
                source_workspace=workspace_root / task_id,
                destination=destination,
                workspace_row=workspace_row,
                workflow_binding=chipflow_binding_path,
                workflow_binding_sha256=chipflow_binding_sha,
                model=model,
                resource_request=resource_request,
            )
            classification = {
                "supported": True,
                "reason_code": None,
                "reason": None,
            }
            disposition = "launch_request_materialized_not_run"
        elif slot == "same_model_vanilla_agent":
            bridge_kind = _prepare_internal(
                module=vanilla_module,
                source_workspace=workspace_root / task_id,
                destination=destination,
                workspace_row=workspace_row,
                workflow_binding=vanilla_binding_path,
                workflow_binding_sha256=vanilla_binding_sha,
                model=model,
                resource_request=resource_request,
            )
            classification = {
                "supported": True,
                "reason_code": None,
                "reason": None,
            }
            disposition = "launch_request_materialized_not_run"
        else:
            public_root = repo_root / "benchmarks/golden12/tasks" / task_id / "public"
            task = _load(public_root / "external_task.json", "public task")
            classification = _external_classification(
                workflow_id=workflow_id,
                task=task,
                mage=mage_module,
                public_spec=public_spec_module,
            )
            if classification["supported"]:
                bridge_kind = _prepare_external(
                    workflow_id=workflow_id,
                    public_root=public_root,
                    destination=destination,
                    observed_at=observed_at,
                    mage=mage_module,
                    public_spec=public_spec_module,
                )
                disposition = "launch_request_materialized_not_run"
            else:
                bridge_kind = f"{workflow_id}_public_capability_classification"
                disposition = "controller_block_preclassified_not_run"

        if disposition == "launch_request_materialized_not_run":
            manifest = _tree_entries(destination, "bridge request")
            request_relative_root: str | None = destination_relative.as_posix()
            request_file_count: int | None = len(manifest)
            request_payload_sha256: str | None = _canonical_digest(manifest)
            materialized_count += 1
            per_slot[slot]["materialized"] += 1
        else:
            request_relative_root = None
            request_file_count = None
            request_payload_sha256 = None
            controller_block_count += 1
            per_slot[slot]["controller_block"] += 1
        result_rows.append(
            {
                "measurement_id": resource_request["measurement_id"],
                "workflow_slot_id": slot,
                "workflow_id": workflow_id,
                "task_id": task_id,
                "calibration_run_index": run_index,
                "resource_request_sha256": item["request_sha256"],
                "public_workspace_set_sha256": workspace_set_sha,
                "public_workspace_receipt_sha256": workspace_row[
                    "workspace_receipt_sha256"
                ],
                "public_workspace_payload_sha256": workspace_row[
                    "workspace_payload_sha256"
                ],
                "bridge_kind": bridge_kind,
                "support_classification": classification,
                "disposition": disposition,
                "request_relative_root": request_relative_root,
                "request_file_count": request_file_count,
                "request_payload_sha256": request_payload_sha256,
                "provider_calls": 0,
                "eda_calls": 0,
                "private_evaluator_calls": 0,
                "official_semantic_attempt_consumed": False,
            }
        )

    expected_slot_counts = {
        "chipflow": {"materialized": 40, "controller_block": 0},
        "same_model_vanilla_agent": {"materialized": 40, "controller_block": 0},
        "external_airtl_1": {"materialized": 6, "controller_block": 34},
        "external_airtl_2": {"materialized": 6, "controller_block": 34},
        "external_airtl_3": {"materialized": 6, "controller_block": 34},
    }
    if per_slot != expected_slot_counts:
        raise ValueError(f"workflow bridge support matrix drift: {per_slot}")
    result = {
        "schema_version": "rtlflowbench.full_workflow_bridge_request_set.v1",
        "observed_at": observed_at,
        "status": "bridge_inputs_materialized_execution_blocked",
        "scope": "five_workflows_all_twelve_tasks_all_planned_resource_runs",
        "input_sha256": {
            "public_workspace_set": workspace_set_sha,
            "resource_request_set": request_set_sha,
            "chipflow_workflow_binding": chipflow_binding_sha,
            "vanilla_workflow_binding": vanilla_binding_sha,
            "common_model_candidate": common_model_sha,
            "workspace_set_builder": _sha256(WORKSPACE_SET_BUILDER),
            "chipflow_request_builder": _sha256(CHIPFLOW_BUILDER),
            "vanilla_request_builder": _sha256(VANILLA_BUILDER),
            "mage_bridge": _sha256(MAGE_BRIDGE),
            "public_spec_bridge": _sha256(PUBLIC_SPEC_BRIDGE),
            "builder": _sha256(Path(__file__).resolve()),
            "schema": _sha256(SET_SCHEMA),
        },
        "requests": result_rows,
        "summary": {
            "workflow_count": 5,
            "task_count": 12,
            "planned_run_count": 200,
            "launch_request_materialized_count": materialized_count,
            "controller_block_preclassified_count": controller_block_count,
            "public_workspace_count": 12,
            "provider_call_count": 0,
            "eda_call_count": 0,
            "private_evaluator_call_count": 0,
            "official_attempt_count": 0,
            "per_workflow_slot": [
                {
                    "workflow_slot_id": slot,
                    "workflow_id": workflow_id,
                    "launch_request_materialized_count": per_slot[slot]["materialized"],
                    "controller_block_preclassified_count": per_slot[slot][
                        "controller_block"
                    ],
                }
                for slot, workflow_id in SLOTS
            ],
        },
        "readiness": {
            "all_200_inputs_or_fail_closed_dispositions_materialized": True,
            "all_public_workspaces_bound": True,
            "task_solution_knowledge_included": False,
            "private_evaluator_reachable": False,
            "controller_envelope_bound": False,
            "common_provider_preflight_passed": False,
            "resource_campaign_permitted": False,
            "official_attempts_permitted": False,
        },
        "blockers": [
            "controller_aware_measurement_envelope_not_bound",
            "common_provider_preflight_not_passed",
        ],
        "excluded_claims": [
            "Materialized public bridge inputs are not AIRTL workflow runs or benchmark verdicts.",
            "A public capability preclassification is not an observed workflow capability BLOCK result.",
            "No provider, EDA tool, private evaluator, hidden oracle, reference solution, or official attempt is invoked.",
            "The common model and workflow bindings remain development candidates rather than frozen releases.",
            "No PASS, FAIL, score, ranking, QoR, PPA, readiness, or publication result is claimed.",
        ],
    }
    _validate(SET_SCHEMA, result, "bridge request set")
    rendered = json.dumps(result, sort_keys=True)
    if "/home/" in rendered or "/Users/" in rendered:
        raise ValueError("bridge request set exposes a private host path")
    output = output_dir / "bridge-request-set.json"
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--workspace-root", type=Path, required=True)
    parser.add_argument("--public-workspace-set", type=Path, required=True)
    parser.add_argument("--expected-public-workspace-set-sha256", required=True)
    parser.add_argument("--resource-request-set", type=Path, required=True)
    parser.add_argument("--expected-resource-request-set-sha256", required=True)
    parser.add_argument("--chipflow-binding", type=Path, required=True)
    parser.add_argument("--expected-chipflow-binding-sha256", required=True)
    parser.add_argument("--vanilla-binding", type=Path, required=True)
    parser.add_argument("--expected-vanilla-binding-sha256", required=True)
    parser.add_argument("--common-model", type=Path, required=True)
    parser.add_argument("--expected-common-model-sha256", required=True)
    parser.add_argument("--observed-at", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = build_bridge_request_set(
            repo_root=args.repo_root,
            workspace_root=args.workspace_root,
            public_workspace_set_path=args.public_workspace_set,
            expected_public_workspace_set_sha256=(
                args.expected_public_workspace_set_sha256
            ),
            resource_request_set_path=args.resource_request_set,
            expected_resource_request_set_sha256=(
                args.expected_resource_request_set_sha256
            ),
            chipflow_binding_path=args.chipflow_binding,
            expected_chipflow_binding_sha256=(args.expected_chipflow_binding_sha256),
            vanilla_binding_path=args.vanilla_binding,
            expected_vanilla_binding_sha256=(args.expected_vanilla_binding_sha256),
            common_model_path=args.common_model,
            expected_common_model_sha256=args.expected_common_model_sha256,
            observed_at=args.observed_at,
            output_dir=args.output_dir,
        )
    except Exception as exc:
        print(
            json.dumps(
                {
                    "status": "bridge_request_set_build_error",
                    "exception_class": type(exc).__name__,
                    "provider_calls": 0,
                    "eda_calls": 0,
                    "private_evaluator_calls": 0,
                    "official_attempts_started": 0,
                },
                sort_keys=True,
            )
        )
        return 2
    print(
        json.dumps(
            {
                "status": result["status"],
                "planned_run_count": result["summary"]["planned_run_count"],
                "launch_request_materialized_count": result["summary"][
                    "launch_request_materialized_count"
                ],
                "controller_block_preclassified_count": result["summary"][
                    "controller_block_preclassified_count"
                ],
                "provider_calls": 0,
                "eda_calls": 0,
                "private_evaluator_calls": 0,
                "official_attempts_started": 0,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
