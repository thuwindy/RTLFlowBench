#!/usr/bin/env python3
"""Materialize 200 content-bound resource-only workflow launch requests.

The builder loads only public task trees and already-audited control-plane
receipts.  It does not create a trial workspace, start a workflow, call a
provider or EDA tool, mount a private evaluator, or produce a benchmark
result.  Requests remain fail-closed until those separate gates are bound.
"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import datetime
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


HERE = Path(__file__).resolve().parent
REQUEST_SCHEMA = HERE / "full_workflow_resource_measurement_request.schema.json"
SET_SCHEMA = HERE / "full_workflow_resource_measurement_request_set.schema.json"
POLICY_SCHEMA = HERE / "full_workflow_resource_launch_policy_candidate.schema.json"
WORKSPACE_SET_SCHEMA = (
    HERE.parent / "admission/public_trial_workspace_set_receipt.schema.json"
)
WORKSPACE_SOURCE_PATHS = {
    "workspace_set_builder": (
        "benchmarks/golden12/admission/build_public_trial_workspace_set.py"
    ),
    "workspace_materializer": (
        "benchmarks/golden12/admission/prepare_public_trial_workspace.py"
    ),
    "workspace_receipt_schema": (
        "benchmarks/golden12/admission/public_trial_workspace_receipt.schema.json"
    ),
    "public_suite_verifier": (
        "benchmarks/golden12/admission/verify_public_suite_candidate.py"
    ),
}
SLOTS = (
    ("chipflow", "chipflow"),
    ("same_model_vanilla_agent", "same_model_vanilla_agent"),
    ("external_airtl_1", "mage"),
    ("external_airtl_2", "verilogcoder"),
    ("external_airtl_3", "hdlagent"),
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
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
PLACEHOLDER_RE = re.compile(r"\{([A-Z][A-Z0-9_]*)\}")
FORBIDDEN_PUBLIC_PARTS = frozenset({"private", "hidden", "oracle"})


def _load(path: Path, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a regular non-symlink file")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{label} must contain one JSON object")
    return value


def _sha(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"expected regular non-symlink file: {path}")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _require_sha(path: Path, expected: str, label: str) -> str:
    if SHA_RE.fullmatch(expected) is None or _sha(path) != expected:
        raise ValueError(f"{label} differs from its out-of-band trust anchor")
    return expected


def _canonical_sha(value: Any) -> str:
    payload = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _render(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _write_new(path: Path, payload: bytes) -> None:
    if path.exists() or path.is_symlink():
        raise FileExistsError(f"refusing to overwrite: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)


def _validated(schema_path: Path, value: dict[str, Any], label: str) -> None:
    schema = _load(schema_path, f"{label} schema")
    Draft202012Validator.check_schema(schema)
    errors = sorted(
        Draft202012Validator(
            schema, format_checker=FormatChecker()
        ).iter_errors(value),
        key=lambda error: list(error.absolute_path),
    )
    if errors:
        first = errors[0]
        location = "/".join(str(part) for part in first.absolute_path)
        raise ValueError(
            f"{label} schema validation failed at {location or '<root>'}: "
            f"{first.message}"
        )


def _ordered_rows(
    value: dict[str, Any], label: str
) -> list[dict[str, Any]]:
    rows = value.get("workflows")
    if not isinstance(rows, list) or len(rows) != len(SLOTS):
        raise ValueError(f"{label} must contain five workflow rows")
    identities = [
        (row.get("workflow_slot_id"), row.get("workflow_id")) for row in rows
    ]
    if identities != list(SLOTS):
        raise ValueError(f"{label} workflow order or identities drifted")
    return rows


def _public_manifest(public_root: Path) -> tuple[str, int]:
    if public_root.is_symlink() or not public_root.is_dir():
        raise ValueError("public task root must be a regular non-symlink directory")
    entries: list[dict[str, Any]] = []
    for path in sorted(public_root.rglob("*")):
        relative = path.relative_to(public_root)
        if path.is_symlink():
            raise ValueError("public task tree contains a symlink")
        if FORBIDDEN_PUBLIC_PARTS.intersection(
            part.casefold() for part in relative.parts
        ):
            raise ValueError("public task tree contains a private-control path")
        if path.is_dir():
            continue
        if not path.is_file():
            raise ValueError("public task tree contains a non-regular entry")
        entries.append(
            {
                "path": PurePosixPath(*relative.parts).as_posix(),
                "bytes": path.stat().st_size,
                "sha256": _sha(path),
            }
        )
    if not entries:
        raise ValueError("public task tree is empty")
    return _canonical_sha(entries), len(entries)


def _task_inputs(repo_root: Path) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for task_id in TASK_IDS:
        relative_root = Path("benchmarks/golden12/tasks") / task_id / "public"
        public_root = repo_root / relative_root
        manifest_sha, file_count = _public_manifest(public_root)
        external_task_path = public_root / "external_task.json"
        budget_path = public_root / "budget.json"
        repo_lock_path = public_root / "repo.lock"
        external_task = _load(external_task_path, f"{task_id} external task")
        budget = _load(budget_path, f"{task_id} budget")
        if external_task.get("task_id") != task_id or budget.get("task_id") != task_id:
            raise ValueError(f"{task_id} public task identity drift")
        limits = budget.get("limits")
        eda_limits = budget.get("eda_call_limits")
        if not (
            isinstance(limits, dict)
            and isinstance(limits.get("wall_time_seconds"), int)
            and 1 <= limits["wall_time_seconds"] <= 86400
            and limits.get("network_access") is False
            and isinstance(eda_limits, dict)
            and isinstance(eda_limits.get("compile_or_lint"), int)
            and eda_limits["compile_or_lint"] >= 0
        ):
            raise ValueError(f"{task_id} provisional resource budget is malformed")
        result[task_id] = {
            "source_relative_root": PurePosixPath(*relative_root.parts).as_posix(),
            "tree_manifest_sha256": manifest_sha,
            "file_count": file_count,
            "external_task_sha256": _sha(external_task_path),
            "budget_sha256": _sha(budget_path),
            "repo_lock_sha256": _sha(repo_lock_path),
            "wall_time_seconds": limits["wall_time_seconds"],
            "compile_limit": eda_limits["compile_or_lint"],
        }
    return result


def _plan_rows(plan: dict[str, Any]) -> list[dict[str, Any]]:
    summary = plan.get("attempt_summary")
    attempts = plan.get("attempts")
    if not (
        plan.get("status") == "blocked_not_executable_until_all_controller_gates_frozen"
        and plan.get("workflow_slot_ids") == [slot for slot, _ in SLOTS]
        and plan.get("task_ids") == list(TASK_IDS)
        and summary
        == {
            "workflow_count": 5,
            "task_count": 12,
            "attempts_per_workflow": 40,
            "total_attempt_slots": 200,
            "started_attempts": 0,
            "semantic_attempts_consumed": 0,
            "omitted_attempt_slots": 0,
        }
        and isinstance(attempts, list)
        and len(attempts) == 200
    ):
        raise ValueError("primary cohort plan is not the exact unopened schedule")
    seen_ids: set[str] = set()
    counts: Counter[tuple[str, str]] = Counter()
    seeds: dict[tuple[str, int], set[int]] = defaultdict(set)
    for row in attempts:
        required = {
            "attempt_id",
            "workflow_slot_id",
            "task_id",
            "independent_run_index",
            "seed",
            "budget_sha256",
            "execution_status",
            "semantic_attempt_consumed",
            "result_class",
        }
        if not required.issubset(row):
            raise ValueError("primary cohort attempt row is incomplete")
        attempt_id = row["attempt_id"]
        slot = row["workflow_slot_id"]
        task_id = row["task_id"]
        run_index = row["independent_run_index"]
        seed = row["seed"]
        if not (
            isinstance(attempt_id, str)
            and attempt_id not in seen_ids
            and slot in {item[0] for item in SLOTS}
            and task_id in TASK_IDS
            and isinstance(run_index, int)
            and 1 <= run_index <= 5
            and isinstance(seed, int)
            and 0 <= seed <= 0xFFFFFFFF
            and row["execution_status"]
            == "controller_gate_blocked_not_started"
            and row["semantic_attempt_consumed"] is False
            and row["result_class"] is None
        ):
            raise ValueError("primary cohort attempt row was opened or malformed")
        seen_ids.add(attempt_id)
        counts[(slot, task_id)] += 1
        seeds[(task_id, run_index)].add(seed)
    expected_counts = {
        (slot, task_id): 5 if task_id in TASK_IDS[9:11] else 3
        for slot, _ in SLOTS
        for task_id in TASK_IDS
    }
    if dict(counts) != expected_counts:
        raise ValueError("primary cohort per-cell run counts differ from policy")
    if any(len(values) != 1 for values in seeds.values()):
        raise ValueError("same task/run seed differs across workflows")
    return attempts


def _placeholder_values(
    *, placeholders: list[str], policy: dict[str, Any], compile_limit: int,
    workflow_id: str,
) -> dict[str, str]:
    work_mount = policy["measurement_envelope"]["work_mount"]
    if work_mount != "/work":
        raise ValueError("measurement work mount differs from the reviewed path")
    work_root = work_mount if workflow_id == "mage" else f"{work_mount}/attempt"
    all_values = {
        "PUBLIC_BRIDGE_REQUEST_ROOT": policy["measurement_envelope"]["public_input_mount"],
        "WORK_ROOT": work_root,
        "OBSERVED_AT": "runtime_observed_at",
        "FROZEN_MODEL": policy["model"]["name"],
        "TASK_COMPILE_LIMIT": str(compile_limit),
        "MODEL_CONTEXT_WINDOW": str(policy["mage"]["context_window"]),
        "MAX_TOKENS_PER_CALL": str(policy["provider"]["maximum_output_tokens_per_call"]),
        "PROVIDER_MAX_RETRIES": str(policy["provider"]["maximum_retries"]),
        "PROVIDER_TIMEOUT_SECONDS": str(policy["provider"]["timeout_seconds"]),
        "THINKING_MODE": policy["provider"]["thinking_mode"],
        "MAGE_SIM_MAX_RETRY": str(policy["mage"]["sim_max_retry"]),
        "MAGE_RTL_MAX_CANDIDATES": str(policy["mage"]["rtl_max_candidates"]),
        "MAGE_RTL_SELECTED_CANDIDATES": str(policy["mage"]["rtl_selected_candidates"]),
    }
    if len(placeholders) != len(set(placeholders)) or any(
        value not in all_values for value in placeholders
    ):
        raise ValueError("launch contract placeholders are invalid or duplicated")
    return {key: all_values[key] for key in placeholders}


def build_request_set(
    *,
    repo_root: Path,
    workflow_release_candidate_path: Path,
    expected_workflow_release_candidate_sha256: str,
    primary_cohort_plan_path: Path,
    expected_primary_cohort_plan_sha256: str,
    oci_inventory_path: Path,
    expected_oci_inventory_sha256: str,
    launch_contract_intake_path: Path,
    expected_launch_contract_intake_sha256: str,
    observed_transport_probe_path: Path,
    expected_observed_transport_probe_sha256: str,
    common_model_candidate_path: Path,
    expected_common_model_candidate_sha256: str,
    launch_policy_path: Path,
    expected_launch_policy_sha256: str,
    public_workspace_set_path: Path | None = None,
    expected_public_workspace_set_sha256: str | None = None,
    output_root: Path,
    request_set_id: str,
    observed_at: str,
) -> dict[str, Any]:
    parsed = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("observed_at must include a timezone")
    if re.fullmatch(r"[a-z0-9][a-z0-9-]{0,127}", request_set_id) is None:
        raise ValueError("request_set_id is invalid")
    repo_root = repo_root.expanduser().resolve(strict=True)
    if repo_root.is_symlink() or not repo_root.is_dir():
        raise ValueError("repo root must be a regular non-symlink directory")
    if (public_workspace_set_path is None) != (
        expected_public_workspace_set_sha256 is None
    ):
        raise ValueError("public workspace set path and digest must be paired")
    paths = {
        "workflow_release_candidate": workflow_release_candidate_path.expanduser().resolve(strict=True),
        "primary_cohort_execution_plan": primary_cohort_plan_path.expanduser().resolve(strict=True),
        "oci_inventory": oci_inventory_path.expanduser().resolve(strict=True),
        "launch_contract_intake": launch_contract_intake_path.expanduser().resolve(strict=True),
        "observed_transport_probe": observed_transport_probe_path.expanduser().resolve(strict=True),
        "common_model_candidate": common_model_candidate_path.expanduser().resolve(strict=True),
        "launch_policy": launch_policy_path.expanduser().resolve(strict=True),
    }
    expected = {
        "workflow_release_candidate": expected_workflow_release_candidate_sha256,
        "primary_cohort_execution_plan": expected_primary_cohort_plan_sha256,
        "oci_inventory": expected_oci_inventory_sha256,
        "launch_contract_intake": expected_launch_contract_intake_sha256,
        "observed_transport_probe": expected_observed_transport_probe_sha256,
        "common_model_candidate": expected_common_model_candidate_sha256,
        "launch_policy": expected_launch_policy_sha256,
    }
    if public_workspace_set_path is not None:
        paths["public_workspace_set"] = (
            public_workspace_set_path.expanduser().resolve(strict=True)
        )
        assert expected_public_workspace_set_sha256 is not None
        expected["public_workspace_set"] = expected_public_workspace_set_sha256
    input_sha256 = {
        key: _require_sha(paths[key], expected[key], key.replace("_", " "))
        for key in paths
    }
    release = _load(paths["workflow_release_candidate"], "workflow release candidate")
    plan = _load(paths["primary_cohort_execution_plan"], "primary cohort plan")
    inventory = _load(paths["oci_inventory"], "OCI inventory")
    launch = _load(paths["launch_contract_intake"], "launch contract intake")
    transport = _load(paths["observed_transport_probe"], "observed transport probe")
    model = _load(paths["common_model_candidate"], "common model candidate")
    policy = _load(paths["launch_policy"], "resource launch policy")
    workspace_set = (
        _load(paths["public_workspace_set"], "public workspace set")
        if "public_workspace_set" in paths
        else None
    )
    _validated(POLICY_SCHEMA, policy, "resource launch policy")
    if not (
        model.get("status") == "proposed_not_frozen"
        and model.get("scope") == "all_five_airtl_workflow_slots_all_twelve_tasks"
        and model.get("model") == policy["model"]["name"]
        and model.get("decoding", {}).get("maximum_output_tokens")
        == policy["provider"]["maximum_output_tokens_per_call"]
        and policy["model"]["candidate_sha256"]
        == input_sha256["common_model_candidate"]
    ):
        raise ValueError("common model candidate differs from resource launch policy")
    for source in policy["source_evidence"].values():
        source_path = repo_root / source["path"]
        if _sha(source_path) != source["sha256"]:
            raise ValueError("resource launch policy source evidence drifted")

    release_rows = _ordered_rows(release, "workflow release candidate")
    inventory_rows = _ordered_rows(inventory, "OCI inventory")
    launch_rows = _ordered_rows(launch, "launch contract intake")
    if not (
        release.get("status") == "automatic_inputs_assessed_release_pending"
        and release.get("summary", {}).get("attempt_slot_count") == 200
        and inventory.get("workflow_release_candidate_sha256")
        == input_sha256["workflow_release_candidate"]
        and inventory.get("summary", {}).get("unique_digest_match_count") == 5
        and launch.get("status") == "launch_contract_intake_complete"
        and launch.get("decision") == "PASS"
        and launch.get("input_sha256", {}).get("workflow_release_candidate")
        == input_sha256["workflow_release_candidate"]
        and launch.get("input_sha256", {}).get("oci_inventory")
        == input_sha256["oci_inventory"]
        and transport.get("status") == "pass"
        and transport.get("input_sha256", {}).get("oci_inventory")
        == input_sha256["oci_inventory"]
        and transport.get("summary", {}).get("probe_pass_count") == 5
        and transport.get("summary", {}).get("private_evaluator_call_count") == 0
        and transport.get("summary", {}).get("benchmark_result_count") == 0
    ):
        raise ValueError("release, OCI, launch, or transport control binding drifted")

    release_by_slot = {row["workflow_slot_id"]: row for row in release_rows}
    inventory_by_slot = {row["workflow_slot_id"]: row for row in inventory_rows}
    launch_by_slot = {row["workflow_slot_id"]: row for row in launch_rows}
    for slot, workflow_id in SLOTS:
        release_row = release_by_slot[slot]
        inventory_row = inventory_by_slot[slot]
        launch_row = launch_by_slot[slot]
        contract = launch_row.get("launch_contract")
        if not (
            release_row.get("scheduled_attempt_count") == 40
            and release_row.get("source_commit") == launch_row.get("source_commit")
            and release_row.get("source_manifest_sha256")
            == launch_row.get("source_manifest_sha256")
            and release_row.get("runtime_image_digest")
            == inventory_row.get("expected_image_digest")
            == launch_row.get("runtime_image_digest")
            and inventory_row.get("inventory_status")
            == "available_unique_digest_match"
            and inventory_row.get("resolved_image_id")
            == launch_row.get("runtime_image_id")
            and isinstance(contract, dict)
            and contract.get("task_solution_knowledge_included") is False
            and contract.get("hidden_evaluator_reachable") is False
            and contract.get("provider_transport")
            == "host_observed_openai_compatible_unix_socket"
            and contract.get("eda_observation")
            == "path_interposed_iverilog_vvp_yosys_unix_socket_events"
        ):
            raise ValueError(f"workflow launch identity drifted: {slot}")
        placeholders = contract.get("placeholders")
        argv_template = contract.get("argv_template")
        if not isinstance(placeholders, list) or not isinstance(argv_template, list):
            raise ValueError(f"workflow launch contract is incomplete: {slot}")
        observed_placeholders = []
        for argument in argv_template:
            observed_placeholders.extend(PLACEHOLDER_RE.findall(argument))
            if any(task_id in argument for task_id in TASK_IDS):
                raise ValueError("workflow launch contract contains task-specific knowledge")
        ordered_unique_placeholders = list(dict.fromkeys(observed_placeholders))
        if (
            ordered_unique_placeholders != placeholders
            or set(observed_placeholders) != set(placeholders)
        ):
            raise ValueError(f"workflow launch placeholder order drifted: {slot}")
        if workflow_id in {"chipflow", "same_model_vanilla_agent", "mage", "hdlagent"} and "FROZEN_MODEL" not in placeholders:
            raise ValueError(f"model-bound workflow launch omits FROZEN_MODEL: {slot}")

    public_inputs = _task_inputs(repo_root)
    workspace_by_task: dict[str, dict[str, Any]] = {}
    if workspace_set is not None:
        _validated(WORKSPACE_SET_SCHEMA, workspace_set, "public workspace set")
        if (
            workspace_set.get("status")
            != "development_public_trial_workspace_set_materialized_not_admitted"
            or workspace_set.get("summary", {}).get("workspace_count") != 12
            or workspace_set.get("summary", {}).get("private_file_count") != 0
            or workspace_set.get("readiness", {}).get(
                "all_public_workspaces_materialized"
            )
            is not True
            or workspace_set.get("readiness", {}).get(
                "public_private_path_isolation_verified"
            )
            is not True
            or workspace_set.get("readiness", {}).get(
                "official_attempts_permitted"
            )
            is not False
            or any(workspace_set.get("attempt_accounting", {}).values())
        ):
            raise ValueError("public workspace set is incomplete or unsafe")
        for key, relative in WORKSPACE_SOURCE_PATHS.items():
            source = repo_root / relative
            if workspace_set["source_sha256"].get(key) != _sha(source):
                raise ValueError(f"public workspace set source drifted: {key}")
        workspace_by_task = {
            row["task_id"]: row for row in workspace_set.get("tasks", [])
        }
        if set(workspace_by_task) != set(TASK_IDS) or len(
            workspace_set.get("tasks", [])
        ) != 12:
            raise ValueError("public workspace set does not close to twelve tasks")
        for task_id, public in public_inputs.items():
            row = workspace_by_task[task_id]
            if (
                row.get("public_tree_sha256") != public["tree_manifest_sha256"]
                or row.get("public_file_count") != public["file_count"]
                or row.get("private_file_count") != 0
            ):
                raise ValueError(f"public workspace differs from task input: {task_id}")
    attempts = _plan_rows(plan)
    for row in attempts:
        if row["budget_sha256"] != public_inputs[row["task_id"]]["budget_sha256"]:
            raise ValueError("primary cohort attempt budget differs from public task")

    request_schema = _load(REQUEST_SCHEMA, "full workflow request schema")
    set_schema = _load(SET_SCHEMA, "full workflow request set schema")
    Draft202012Validator.check_schema(request_schema)
    Draft202012Validator.check_schema(set_schema)
    output_root = output_root.expanduser().absolute()
    if output_root.exists() or output_root.is_symlink():
        raise FileExistsError(f"refusing to overwrite output root: {output_root}")

    request_payloads: list[tuple[Path, bytes]] = []
    request_index: list[dict[str, Any]] = []
    for attempt in attempts:
        slot = attempt["workflow_slot_id"]
        workflow_id = dict(SLOTS)[slot]
        task_id = attempt["task_id"]
        run_index = attempt["independent_run_index"]
        task_code = task_id[:3].lower()
        workflow_token = workflow_id.replace("_", "-")
        measurement_id = f"resource-{workflow_token}-{task_code}-run-{run_index}"
        resource_attempt_id = (
            f"resource-calibration-{workflow_token}-{task_code}-run-{run_index}"
        )
        public = public_inputs[task_id]
        workspace_row = workspace_by_task.get(task_id)
        release_row = release_by_slot[slot]
        inventory_row = inventory_by_slot[slot]
        contract = launch_by_slot[slot]["launch_contract"]
        placeholders = contract["placeholders"]
        bindings = _placeholder_values(
            placeholders=placeholders,
            policy=policy,
            compile_limit=public["compile_limit"],
            workflow_id=workflow_id,
        )
        static_materialization_sha = _canonical_sha(
            {
                "argv_template": contract["argv_template"],
                "placeholder_bindings": bindings,
            }
        )
        request = {
            "schema_version": "rtlflowbench.full_workflow_resource_measurement_request.v1",
            "measurement_id": measurement_id,
            "measurement_scope": "full_workflow_calibration",
            "workflow_slot_id": slot,
            "workflow_id": workflow_id,
            "task_id": task_id,
            "calibration_run_index": run_index,
            "attempt_id": resource_attempt_id,
            "official_attempt_binding": {
                "attempt_id": attempt["attempt_id"],
                "independent_run_index": run_index,
                "seed": attempt["seed"],
                "budget_sha256": attempt["budget_sha256"],
                "execution_status": attempt["execution_status"],
                "semantic_attempt_consumed": False,
            },
            "source_binding": {
                "commit": release_row["source_commit"],
                "manifest_sha256": release_row["source_manifest_sha256"],
            },
            "runtime_binding": {
                "image_digest": release_row["runtime_image_digest"],
                "image_id": inventory_row["resolved_image_id"],
            },
            "public_input_binding": {
                "source_relative_root": public["source_relative_root"],
                "tree_manifest_sha256": public["tree_manifest_sha256"],
                "file_count": public["file_count"],
                "external_task_sha256": public["external_task_sha256"],
                "budget_sha256": public["budget_sha256"],
                "repo_lock_sha256": public["repo_lock_sha256"],
                "private_assets_included": False,
                "workspace_materialized": workspace_row is not None,
                **(
                    {
                        "workspace_set_receipt_sha256": input_sha256[
                            "public_workspace_set"
                        ],
                        "workspace_receipt_sha256": workspace_row[
                            "workspace_receipt_sha256"
                        ],
                        "workspace_payload_sha256": workspace_row[
                            "workspace_payload_sha256"
                        ],
                    }
                    if workspace_row is not None
                    else {}
                ),
            },
            "launch_contract_binding": {
                "intake_sha256": input_sha256["launch_contract_intake"],
                "contract_version": contract["contract_version"],
                "entrypoint": contract["entrypoint"],
                "entrypoint_sha256": contract["entrypoint_sha256"],
                "container_argv_template": contract["argv_template"],
                "placeholder_bindings": bindings,
                "unresolved_runtime_placeholders": (
                    ["OBSERVED_AT"] if "OBSERVED_AT" in placeholders else []
                ),
                "static_materialization_sha256": static_materialization_sha,
                "task_solution_knowledge_included": False,
                "hidden_evaluator_reachable": False,
            },
            "controller_binding": {
                "observed_transport_probe_sha256": input_sha256["observed_transport_probe"],
                "provider_transport": contract["provider_transport"],
                "eda_observation": contract["eda_observation"],
                "network_policy": "offline",
                "credential_location": "host_controller_only",
                "raw_provider_content_persisted": False,
                "private_evaluator_reachable": False,
            },
            "resource_policy": {
                "launch_policy_sha256": input_sha256["launch_policy"],
                "wall_time_seconds": public["wall_time_seconds"],
                "maximum_provider_calls": policy["provider"][
                    "maximum_calls_per_measurement"
                ],
                "maximum_output_tokens_per_call": policy["provider"][
                    "maximum_output_tokens_per_call"
                ],
                "maximum_input_tokens": policy["provider"][
                    "maximum_input_tokens_per_measurement"
                ],
                "maximum_output_tokens": policy["provider"][
                    "maximum_output_tokens_per_measurement"
                ],
                "maximum_consecutive_identical_requests": policy["provider"][
                    "maximum_consecutive_identical_requests"
                ],
                "maximum_consecutive_identical_errors": policy["provider"][
                    "maximum_consecutive_identical_errors"
                ],
                "sampling_interval_ms": policy["measurement_envelope"]["sampling_interval_ms"],
                "pids_limit": policy["measurement_envelope"]["pids_limit"],
                "memory_limit_bytes": policy["measurement_envelope"][
                    "memory_limit_bytes"
                ],
                "public_input_mount": policy["measurement_envelope"]["public_input_mount"],
                "work_mount": policy["measurement_envelope"]["work_mount"],
            },
            "attempt_accounting": {
                "official_attempts_started": 0,
                "official_semantic_attempts_consumed": 0,
                "resource_calibration_attempts_consumed": 0,
                "benchmark_results_created": 0,
                "private_evaluator_calls": 0,
                "provider_calls": 0,
                "eda_calls": 0,
            },
            "readiness": {
                "request_materialized": True,
                "public_workspace_materialized": workspace_row is not None,
                "controller_envelope_bound": False,
                "common_provider_preflight_passed": False,
                "resource_calibration_execution_eligible": False,
                "official_attempts_permitted": False,
            },
            "blockers": (
                [
                    "controller_aware_measurement_envelope_not_bound",
                    "common_provider_preflight_not_passed",
                ]
                if workspace_row is not None
                else [
                    "public_trial_workspace_not_materialized",
                    "controller_aware_measurement_envelope_not_bound",
                    "common_provider_preflight_not_passed",
                ]
            ),
            "excluded_claims": [
                "This materialized request is not a workflow run, benchmark verdict, score, QoR result, PPA result, or resource sample.",
                (
                    "The isolated public trial workspace is content-bound, but no workflow or controller-aware measurement has been started."
                    if workspace_row is not None
                    else "The public task content is digest-bound but its isolated trial workspace has not yet been materialized for this resource request."
                ),
                "The task-neutral launch contract is bound, but the controller-aware measurement envelope has not yet been attached to this request.",
                "No provider, EDA tool, private evaluator, official attempt, or semantic candidate is invoked or consumed by request materialization.",
            ],
        }
        _validated(REQUEST_SCHEMA, request, "full workflow request")
        relative_path = (
            Path("requests") / slot / task_id / f"run-{run_index}.json"
        )
        payload = _render(request)
        request_payloads.append((relative_path, payload))
        request_index.append(
            {
                "measurement_id": measurement_id,
                "workflow_slot_id": slot,
                "workflow_id": workflow_id,
                "task_id": task_id,
                "calibration_run_index": run_index,
                "request_relative_path": PurePosixPath(*relative_path.parts).as_posix(),
                "request_sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
    if len(request_payloads) != 200 or len({row["measurement_id"] for row in request_index}) != 200:
        raise ValueError("materialized request identities do not close to 200")

    result = {
        "schema_version": "rtlflowbench.full_workflow_resource_measurement_request_set.v1",
        "request_set_id": request_set_id,
        "observed_at": observed_at,
        "status": "requests_materialized_execution_blocked",
        "scope": "five_workflows_all_twelve_tasks_resource_calibration_only",
        "input_sha256": {
            **input_sha256,
            "request_schema": _sha(REQUEST_SCHEMA),
            "set_schema": _sha(SET_SCHEMA),
            "builder": _sha(Path(__file__).resolve()),
        },
        "requests": request_index,
        "summary": {
            "workflow_count": 5,
            "task_count": 12,
            "workflow_task_cell_count": 60,
            "request_count": 200,
            "requests_per_workflow": 40,
            "three_run_cell_count": 50,
            "five_run_cell_count": 10,
            "public_workspace_count": 12 if workspace_set is not None else 0,
            "controller_envelope_count": 0,
            "provider_preflight_pass_count": 0,
        },
        "attempt_accounting": {
            "official_attempts_started": 0,
            "official_semantic_attempts_consumed": 0,
            "resource_calibration_attempts_consumed": 0,
            "benchmark_results_created": 0,
            "private_evaluator_calls": 0,
            "provider_calls": 0,
            "eda_calls": 0,
        },
        "readiness": {
            "all_requests_materialized": True,
            "all_public_workspaces_materialized": workspace_set is not None,
            "controller_envelope_bound": False,
            "common_provider_preflight_passed": False,
            "resource_campaign_permitted": False,
            "host_capacity_policy_derivation_permitted": False,
            "official_attempts_permitted": False,
        },
        "blockers": (
            [
                "controller_aware_measurement_envelope_not_bound",
                "common_provider_preflight_not_passed",
            ]
            if workspace_set is not None
            else [
                "public_trial_workspaces_missing_0_of_12",
                "controller_aware_measurement_envelope_not_bound",
                "common_provider_preflight_not_passed",
            ]
        ),
        "excluded_claims": [
            "Materializing 200 content-bound resource requests does not start a workflow, provider call, EDA invocation, semantic attempt, or official benchmark attempt.",
            "The request set is not executable until public trial workspaces, the controller-aware measurement envelope, and the common provider preflight are all independently bound.",
            "No private evaluator, hidden oracle, task solution, provider credential, raw response, user identifier, benchmark verdict, score, QoR, or PPA result is included.",
            "The common model and launch policy remain development candidates; any change requires a new request-set version and complete resource calibration rerun.",
            "Observed zeros are request-materialization activity counts and are not substituted for missing runtime resource or token measurements.",
        ],
    }
    _validated(SET_SCHEMA, result, "full workflow request set")
    rendered = json.dumps(result, sort_keys=True)
    if "/home/" in rendered or "/Users/" in rendered:
        raise ValueError("request set exposes a private host path")
    output_root.mkdir(parents=True)
    for relative_path, payload in request_payloads:
        _write_new(output_root / relative_path, payload)
    _write_new(output_root / "request-set.json", _render(result))
    for row in request_index:
        if _sha(output_root / row["request_relative_path"]) != row["request_sha256"]:
            raise RuntimeError("written request differs from its index digest")
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--workflow-release-candidate", type=Path, required=True)
    parser.add_argument("--expected-workflow-release-candidate-sha256", required=True)
    parser.add_argument("--primary-cohort-plan", type=Path, required=True)
    parser.add_argument("--expected-primary-cohort-plan-sha256", required=True)
    parser.add_argument("--oci-inventory", type=Path, required=True)
    parser.add_argument("--expected-oci-inventory-sha256", required=True)
    parser.add_argument("--launch-contract-intake", type=Path, required=True)
    parser.add_argument("--expected-launch-contract-intake-sha256", required=True)
    parser.add_argument("--observed-transport-probe", type=Path, required=True)
    parser.add_argument("--expected-observed-transport-probe-sha256", required=True)
    parser.add_argument("--common-model-candidate", type=Path, required=True)
    parser.add_argument("--expected-common-model-candidate-sha256", required=True)
    parser.add_argument("--launch-policy", type=Path, required=True)
    parser.add_argument("--expected-launch-policy-sha256", required=True)
    parser.add_argument("--public-workspace-set", type=Path)
    parser.add_argument("--expected-public-workspace-set-sha256")
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--request-set-id", required=True)
    parser.add_argument("--observed-at", required=True)
    args = parser.parse_args()
    try:
        result = build_request_set(
            repo_root=args.repo_root,
            workflow_release_candidate_path=args.workflow_release_candidate,
            expected_workflow_release_candidate_sha256=args.expected_workflow_release_candidate_sha256,
            primary_cohort_plan_path=args.primary_cohort_plan,
            expected_primary_cohort_plan_sha256=args.expected_primary_cohort_plan_sha256,
            oci_inventory_path=args.oci_inventory,
            expected_oci_inventory_sha256=args.expected_oci_inventory_sha256,
            launch_contract_intake_path=args.launch_contract_intake,
            expected_launch_contract_intake_sha256=args.expected_launch_contract_intake_sha256,
            observed_transport_probe_path=args.observed_transport_probe,
            expected_observed_transport_probe_sha256=args.expected_observed_transport_probe_sha256,
            common_model_candidate_path=args.common_model_candidate,
            expected_common_model_candidate_sha256=args.expected_common_model_candidate_sha256,
            launch_policy_path=args.launch_policy,
            expected_launch_policy_sha256=args.expected_launch_policy_sha256,
            public_workspace_set_path=args.public_workspace_set,
            expected_public_workspace_set_sha256=args.expected_public_workspace_set_sha256,
            output_root=args.output_root,
            request_set_id=args.request_set_id,
            observed_at=args.observed_at,
        )
    except Exception as exc:
        print(
            json.dumps(
                {
                    "status": "error",
                    "error_class": type(exc).__name__,
                    "error_message": str(exc),
                },
                sort_keys=True,
            )
        )
        return 2
    print(
        json.dumps(
            {
                "status": result["status"],
                "request_count": result["summary"]["request_count"],
                "resource_campaign_permitted": result["readiness"]["resource_campaign_permitted"],
                "official_attempts_started": result["attempt_accounting"]["official_attempts_started"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
