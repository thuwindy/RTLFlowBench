#!/usr/bin/env python3
"""Fail closed before a resource campaign lacks observable launch transport."""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import re
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


HERE = Path(__file__).resolve().parent
EVALUATION = HERE.parent / "evaluation"
REQUEST_SCHEMA = HERE / "workflow_resource_measurement_request.schema.json"
FULL_REQUEST_SCHEMA = HERE / "full_workflow_resource_measurement_request.schema.json"
REQUEST_SET_SCHEMA = HERE / "full_workflow_resource_measurement_request_set.schema.json"
MEASUREMENT_RUNNER = HERE / "run_workflow_resource_measurement.py"
ACTIVITY_LEDGER_SCHEMA = HERE / "workflow_activity_ledger.schema.json"
ACTIVITY_BUILDER = HERE / "build_workflow_activity_concurrency_receipt.py"
MERGED_SAMPLE_SCHEMA = HERE / "full_workflow_resource_measurement_receipt.schema.json"
RESOURCE_AGGREGATOR = HERE / "aggregate_full_workflow_resource_measurements.py"
PREFLIGHT_SCHEMA = HERE / "full_workflow_resource_campaign_preflight.schema.json"
LAUNCH_CONTRACT_SCHEMA = HERE / "workflow_launch_contract_intake.schema.json"
CONTROLLER_ENVELOPE_SCHEMA = HERE / "controller_aware_measurement_envelope.schema.json"
SLOTS = (
    ("chipflow", "chipflow"),
    ("same_model_vanilla_agent", "same_model_vanilla_agent"),
    ("external_airtl_1", "mage"),
    ("external_airtl_2", "verilogcoder"),
    ("external_airtl_3", "hdlagent"),
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


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
    if SHA256_RE.fullmatch(expected) is None:
        raise ValueError(f"{label} expected SHA256 is malformed")
    observed = _sha(path)
    if observed != expected:
        raise ValueError(f"{label} differs from its out-of-band trust anchor")
    return observed


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


def _module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ValueError(f"cannot load current source module: {path.name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def build_preflight(
    *,
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
    observed_at: str,
    full_workflow_request_set_path: Path | None = None,
    expected_full_workflow_request_set_sha256: str | None = None,
    controller_envelope_path: Path | None = None,
    expected_controller_envelope_sha256: str | None = None,
) -> dict[str, Any]:
    parsed = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("observed_at must include a timezone")
    paths = {
        "workflow_release_candidate": workflow_release_candidate_path.expanduser().resolve(strict=True),
        "primary_cohort_execution_plan": primary_cohort_plan_path.expanduser().resolve(strict=True),
        "oci_inventory": oci_inventory_path.expanduser().resolve(strict=True),
        "launch_contract_intake": launch_contract_intake_path.expanduser().resolve(strict=True),
        "observed_transport_probe": observed_transport_probe_path.expanduser().resolve(strict=True),
    }
    input_sha256 = {
        "workflow_release_candidate": _require_sha(
            paths["workflow_release_candidate"],
            expected_workflow_release_candidate_sha256,
            "workflow release candidate",
        ),
        "primary_cohort_execution_plan": _require_sha(
            paths["primary_cohort_execution_plan"],
            expected_primary_cohort_plan_sha256,
            "primary cohort plan",
        ),
        "oci_inventory": _require_sha(
            paths["oci_inventory"],
            expected_oci_inventory_sha256,
            "OCI inventory",
        ),
        "launch_contract_intake": _require_sha(
            paths["launch_contract_intake"],
            expected_launch_contract_intake_sha256,
            "launch contract intake",
        ),
        "observed_transport_probe": _require_sha(
            paths["observed_transport_probe"],
            expected_observed_transport_probe_sha256,
            "observed controller transport probe",
        ),
    }
    aggregator = _module(RESOURCE_AGGREGATOR, "rtlflowbench_resource_preflight_aggregator")
    release = _load(paths["workflow_release_candidate"], "workflow release candidate")
    plan = _load(paths["primary_cohort_execution_plan"], "primary cohort plan")
    inventory = _load(paths["oci_inventory"], "OCI inventory")
    launch_intake = _load(
        paths["launch_contract_intake"], "launch contract intake"
    )
    transport_probe = _load(
        paths["observed_transport_probe"],
        "observed controller transport probe",
    )
    release_rows = aggregator._release_rows(release)
    plan_counts, task_ids = aggregator._plan_counts(plan)
    inventory_rows = aggregator._inventory_rows(
        inventory, input_sha256["workflow_release_candidate"]
    )
    if set(release_rows) != {slot for slot, _ in SLOTS}:
        raise ValueError("workflow release candidate omits a workflow")
    if len(plan_counts) != 60 or len(task_ids) != 12 or sum(plan_counts.values()) != 200:
        raise ValueError("primary cohort plan is not the exact 200-slot schedule")
    if set(inventory_rows) != {slot for slot, _ in SLOTS}:
        raise ValueError("OCI inventory omits a workflow")
    _validated(
        LAUNCH_CONTRACT_SCHEMA,
        launch_intake,
        "launch contract intake",
    )
    launch_rows = launch_intake.get("workflows")
    if not (
        launch_intake.get("status") == "launch_contract_intake_complete"
        and launch_intake.get("decision") == "PASS"
        and launch_intake.get("input_sha256", {}).get(
            "workflow_release_candidate"
        )
        == input_sha256["workflow_release_candidate"]
        and launch_intake.get("input_sha256", {}).get("oci_inventory")
        == input_sha256["oci_inventory"]
        and launch_intake.get("summary")
        == {
            "workflow_count": 5,
            "offline_probe_container_count": 5,
            "launch_contract_count": 5,
            "missing_launch_contract_count": 0,
            "task_packet_load_count": 0,
            "provider_call_count": 0,
            "eda_call_count": 0,
            "private_evaluator_call_count": 0,
        }
        and launch_intake.get("attempt_accounting")
        == {
            "official_attempts_started": 0,
            "official_semantic_attempts_consumed": 0,
            "resource_calibration_attempts_consumed": 0,
            "benchmark_results_created": 0,
        }
        and launch_intake.get("readiness")
        == {
            "all_runtime_images_probed": True,
            "all_launch_contracts_bound": True,
            "measurement_requests_permitted": True,
            "resource_campaign_permitted": False,
            "official_attempts_permitted": False,
        }
        and launch_intake.get("blockers") == []
        and isinstance(launch_rows, list)
        and [
            (row.get("workflow_slot_id"), row.get("workflow_id"))
            for row in launch_rows
        ]
        == list(SLOTS)
    ):
        raise ValueError("launch contract intake binding drift")
    for row in launch_rows:
        slot = row["workflow_slot_id"]
        release_row = release_rows[slot]
        inventory_row = inventory_rows[slot]
        contract = row.get("launch_contract")
        if not (
            row.get("source_commit") == release_row.get("source_commit")
            and row.get("source_manifest_sha256")
            == release_row.get("source_manifest_sha256")
            and row.get("runtime_image_digest")
            == release_row.get("runtime_image_digest")
            and row.get("runtime_image_id")
            == inventory_row.get("resolved_image_id")
            and row.get("blockers") == []
            and isinstance(contract, dict)
            and contract.get("contract_version")
            == "rtlflowbench.task_neutral_launch_contract.v1"
            and contract.get("provider_transport")
            == "host_observed_openai_compatible_unix_socket"
            and contract.get("eda_observation")
            == "path_interposed_iverilog_vvp_yosys_unix_socket_events"
            and contract.get("task_solution_knowledge_included") is False
            and contract.get("hidden_evaluator_reachable") is False
        ):
            raise ValueError(
                f"launch contract identity or isolation drift: {slot}"
            )

    transport_rows = transport_probe.get("workflows")
    transport_summary = transport_probe.get("summary")
    if not (
        transport_probe.get("schema_version")
        == "rtlflowbench.observed_controller_oci_transport_probe.v1"
        and transport_probe.get("status") == "pass"
        and transport_probe.get("scope")
        == "task_free_no_network_five_workflow_oci_transport_probe"
        and transport_probe.get("input_sha256", {}).get("oci_inventory")
        == input_sha256["oci_inventory"]
        and isinstance(transport_rows, list)
        and [
            (row.get("workflow_slot_id"), row.get("workflow_id"))
            for row in transport_rows
        ]
        == list(SLOTS)
        and transport_summary
        == {
            "workflow_count": 5,
            "probe_pass_count": 5,
            "simulated_provider_request_count": 5,
            "real_provider_call_count": 0,
            "real_eda_call_count": 5,
            "nested_eda_broker_receipt_count": 1,
            "task_packet_load_count": 0,
            "private_evaluator_call_count": 0,
            "benchmark_result_count": 0,
        }
        and transport_probe.get("readiness")
        == {
            "unix_socket_transport_compatible_with_all_current_oci_images": True,
            "real_provider_transport_preflight_complete": False,
            "full_workflow_launch_contracts_complete": False,
            "resource_campaign_permitted": False,
            "official_attempts_permitted": False,
        }
    ):
        raise ValueError("observed controller transport probe binding drift")
    for row in transport_rows:
        slot = row["workflow_slot_id"]
        inventory_row = inventory_rows[slot]
        activity = row.get("activity_summary")
        nested = row.get("nested_eda_broker")
        if not (
            row.get("runtime_image_digest")
            == inventory_row.get("expected_image_digest")
            and row.get("runtime_image_id")
            == inventory_row.get("resolved_image_id")
            and row.get("exit_code") == 0
            and row.get("sentinel_observed") is True
            and row.get("transport_probe_passed") is True
            and row.get("raw_output_embedded") is False
            and activity
            == {
                "activity_count": 2,
                "llm_activity_count": 1,
                "eda_activity_count": 1,
                "unfinished_eda_activity_count": 0,
                "raw_content_embedded": False,
            }
            and isinstance(nested, dict)
            and nested.get("raw_output_embedded") is False
            and (
                (slot != "external_airtl_1" and nested.get("used") is False)
                or (
                    slot == "external_airtl_1"
                    and nested.get("used") is True
                    and nested.get("exit_code") == 0
                    and nested.get("receipt_count") == 1
                    and SHA256_RE.fullmatch(
                        nested.get("receipt_manifest_sha256", "")
                    )
                    is not None
                )
            )
        ):
            raise ValueError(
                f"observed controller transport workflow drift: {slot}"
            )

    request_schema = _load(REQUEST_SCHEMA, "measurement request schema")
    Draft202012Validator.check_schema(request_schema)
    runner = _module(MEASUREMENT_RUNNER, "rtlflowbench_resource_preflight_runner")
    if not (
        request_schema["properties"]["launcher_kind"].get("const") == "podman_oci"
        and request_schema["properties"]["network_policy"].get("const") == "offline"
        and request_schema["properties"]["inherited_environment_keys"].get("const")
        == ["HOME", "XDG_RUNTIME_DIR"]
        and "--network=none" in runner.PODMAN_REQUIRED_PREFIX
        and not any(
            "socket" in value or "gateway" in value
            for value in runner.PODMAN_REQUIRED_PREFIX
        )
    ):
        raise ValueError("measurement envelope differs from the reviewed offline profile")
    activity_schema = _load(ACTIVITY_LEDGER_SCHEMA, "activity ledger schema")
    Draft202012Validator.check_schema(activity_schema)
    if not (
        activity_schema["properties"]["completeness"]["properties"]
        ["provider_gateway_observation_complete"].get("const") is True
        and activity_schema["properties"]["completeness"]["properties"]
        ["eda_broker_observation_complete"].get("const") is True
    ):
        raise ValueError("activity ledger no longer requires complete controller observation")
    materialized_request_count = 0
    request_counts = {slot: 0 for slot, _ in SLOTS}
    request_set_bound = False
    public_workspace_count = 0
    public_workspaces_bound = False
    controller_envelope_bound = False
    controller_launch_plan_count = 0
    controller_nonlaunch_count = 0
    blockers = ["full_workflow_measurement_requests_missing_0_of_200"]
    if (
        full_workflow_request_set_path is None
        and expected_full_workflow_request_set_sha256 is not None
    ) or (
        full_workflow_request_set_path is not None
        and expected_full_workflow_request_set_sha256 is None
    ):
        raise ValueError("request set path and trust anchor must be supplied together")
    if full_workflow_request_set_path is not None:
        request_set_path = full_workflow_request_set_path.expanduser().resolve(
            strict=True
        )
        request_set_sha = _require_sha(
            request_set_path,
            str(expected_full_workflow_request_set_sha256),
            "full workflow request set",
        )
        request_set = _load(request_set_path, "full workflow request set")
        _validated(REQUEST_SET_SCHEMA, request_set, "full workflow request set")
        request_index = request_set.get("requests")
        request_set_input = request_set.get("input_sha256", {})
        request_set_summary = request_set.get("summary", {})
        request_set_readiness = request_set.get("readiness", {})
        public_workspace_count = request_set_summary.get(
            "public_workspace_count"
        )
        if public_workspace_count not in (0, 12):
            raise ValueError("full workflow request set public workspace count drift")
        public_workspaces_bound = public_workspace_count == 12
        expected_request_blockers = (
            [
                "controller_aware_measurement_envelope_not_bound",
                "common_provider_preflight_not_passed",
            ]
            if public_workspaces_bound
            else [
                "public_trial_workspace_not_materialized",
                "controller_aware_measurement_envelope_not_bound",
                "common_provider_preflight_not_passed",
            ]
        )
        expected_request_set_blockers = (
            expected_request_blockers
            if public_workspaces_bound
            else [
                "public_trial_workspaces_missing_0_of_12",
                "controller_aware_measurement_envelope_not_bound",
                "common_provider_preflight_not_passed",
            ]
        )
        public_workspace_set_sha = request_set_input.get("public_workspace_set")
        if public_workspaces_bound:
            if SHA256_RE.fullmatch(public_workspace_set_sha or "") is None:
                raise ValueError(
                    "full workflow request set lacks its public workspace trust anchor"
                )
        elif public_workspace_set_sha is not None:
            raise ValueError(
                "unmaterialized request set unexpectedly binds a public workspace set"
            )
        expected_request_identities = [
            (
                row.get("workflow_slot_id"),
                row.get("task_id"),
                row.get("independent_run_index"),
                row.get("attempt_id"),
            )
            for row in plan.get("attempts", [])
        ]
        observed_request_identities = [
            (
                row.get("workflow_slot_id"),
                row.get("task_id"),
                row.get("calibration_run_index"),
            )
            for row in request_index
        ] if isinstance(request_index, list) else []
        if not (
            request_set.get("status") == "requests_materialized_execution_blocked"
            and request_set.get("scope")
            == "five_workflows_all_twelve_tasks_resource_calibration_only"
            and request_set_input.get(
                "workflow_release_candidate"
            )
            == input_sha256["workflow_release_candidate"]
            and request_set_input.get(
                "primary_cohort_execution_plan"
            )
            == input_sha256["primary_cohort_execution_plan"]
            and request_set_input.get("oci_inventory")
            == input_sha256["oci_inventory"]
            and request_set_input.get(
                "launch_contract_intake"
            )
            == input_sha256["launch_contract_intake"]
            and request_set_input.get(
                "observed_transport_probe"
            )
            == input_sha256["observed_transport_probe"]
            and request_set_summary.get("request_count") == 200
            and request_set_summary.get("workflow_task_cell_count")
            == 60
            and request_set_readiness.get(
                "all_requests_materialized"
            )
            is True
            and request_set_readiness.get(
                "all_public_workspaces_materialized"
            )
            is public_workspaces_bound
            and request_set_readiness.get(
                "resource_campaign_permitted"
            )
            is False
            and request_set.get("blockers") == expected_request_set_blockers
            and request_set.get("attempt_accounting", {}).get(
                "official_attempts_started"
            )
            == 0
            and request_set.get("attempt_accounting", {}).get(
                "resource_calibration_attempts_consumed"
            )
            == 0
            and len(observed_request_identities) == 200
            and observed_request_identities
            == [identity[:3] for identity in expected_request_identities]
        ):
            raise ValueError("full workflow request set binding drift")
        request_root = request_set_path.parent.resolve(strict=True)
        full_request_schema = _load(
            FULL_REQUEST_SCHEMA, "full workflow request schema"
        )
        Draft202012Validator.check_schema(full_request_schema)
        workspace_bindings_by_task: dict[str, tuple[str, str, str]] = {}
        for index, (row, expected_identity) in enumerate(
            zip(request_index, expected_request_identities, strict=True)
        ):
            relative = PurePosixPath(row["request_relative_path"])
            if relative.is_absolute() or ".." in relative.parts:
                raise ValueError("full workflow request path escapes its set root")
            request_path = (
                request_root / Path(*relative.parts)
            ).resolve(strict=True)
            if not request_path.is_relative_to(request_root):
                raise ValueError("full workflow request path escapes its set root")
            if _sha(request_path) != row["request_sha256"]:
                raise ValueError("full workflow request differs from set index")
            request = _load(request_path, "full workflow request")
            errors = list(Draft202012Validator(full_request_schema).iter_errors(request))
            if errors:
                raise ValueError("full workflow request schema validation failed")
            slot, task_id, run_index, official_attempt_id = expected_identity
            public_input = request.get("public_input_binding", {})
            request_readiness = request.get("readiness", {})
            if not (
                request.get("measurement_id") == row.get("measurement_id")
                and request.get("workflow_slot_id") == slot
                and request.get("workflow_id") == row.get("workflow_id")
                and request.get("task_id") == task_id
                and request.get("calibration_run_index") == run_index
                and request.get("official_attempt_binding", {}).get("attempt_id")
                == official_attempt_id
                and request.get("launch_contract_binding", {}).get(
                    "intake_sha256"
                )
                == input_sha256["launch_contract_intake"]
                and request.get("controller_binding", {}).get(
                    "observed_transport_probe_sha256"
                )
                == input_sha256["observed_transport_probe"]
                and request.get("controller_binding", {}).get(
                    "private_evaluator_reachable"
                )
                is False
                and public_input.get("private_assets_included") is False
                and public_input.get("workspace_materialized")
                is public_workspaces_bound
                and request_readiness.get("public_workspace_materialized")
                is public_workspaces_bound
                and request.get("blockers") == expected_request_blockers
                and request.get("attempt_accounting", {}).get(
                    "official_attempts_started"
                )
                == 0
                and request.get("attempt_accounting", {}).get(
                    "resource_calibration_attempts_consumed"
                )
                == 0
            ):
                raise ValueError(f"full workflow request identity drift: {index}")
            if public_workspaces_bound:
                workspace_binding = (
                    public_input.get("workspace_receipt_sha256"),
                    public_input.get("workspace_payload_sha256"),
                    public_input.get("workspace_set_receipt_sha256"),
                )
                if not (
                    all(
                        SHA256_RE.fullmatch(value or "") is not None
                        for value in workspace_binding
                    )
                    and workspace_binding[2] == public_workspace_set_sha
                    and public_input.get("source_relative_root")
                    == f"benchmarks/golden12/tasks/{task_id}/public"
                ):
                    raise ValueError(
                        f"full workflow public workspace binding drift: {index}"
                    )
                previous = workspace_bindings_by_task.setdefault(
                    task_id, workspace_binding
                )
                if previous != workspace_binding:
                    raise ValueError(
                        f"full workflow public workspace is inconsistent: {task_id}"
                    )
            rendered_request = json.dumps(request, sort_keys=True)
            if "/home/" in rendered_request or "/Users/" in rendered_request:
                raise ValueError("full workflow request exposes a private host path")
            request_counts[slot] += 1
        if request_counts != {slot: 40 for slot, _ in SLOTS}:
            raise ValueError("full workflow request set is not balanced 40 per workflow")
        if public_workspaces_bound and set(workspace_bindings_by_task) != set(task_ids):
            raise ValueError("full workflow request set does not bind all 12 workspaces")
        materialized_request_count = 200
        request_set_bound = True
        blockers = expected_request_set_blockers
        input_sha256.update(
            {
                "full_workflow_request_set": request_set_sha,
                "full_workflow_request_schema": _sha(FULL_REQUEST_SCHEMA),
                "full_workflow_request_set_schema": _sha(REQUEST_SET_SCHEMA),
            }
        )
        if public_workspaces_bound:
            input_sha256["public_workspace_set"] = public_workspace_set_sha
    if (controller_envelope_path is None) != (
        expected_controller_envelope_sha256 is None
    ):
        raise ValueError("controller envelope path and SHA256 must be paired")
    if controller_envelope_path is not None:
        if not request_set_bound:
            raise ValueError("controller envelope requires the exact request set")
        envelope_path = controller_envelope_path.expanduser().resolve(strict=True)
        envelope_sha = _require_sha(
            envelope_path,
            expected_controller_envelope_sha256,
            "controller-aware measurement envelope",
        )
        envelope = _load(envelope_path, "controller-aware measurement envelope")
        _validated(
            CONTROLLER_ENVELOPE_SCHEMA,
            envelope,
            "controller-aware measurement envelope",
        )
        envelope_rows = envelope.get("requests", [])
        expected_envelope_rows = [
            (
                row["measurement_id"],
                row["workflow_slot_id"],
                row["workflow_id"],
                row["task_id"],
                row["calibration_run_index"],
                row["request_sha256"],
            )
            for row in request_index
        ]
        observed_envelope_rows = [
            (
                row.get("measurement_id"),
                row.get("workflow_slot_id"),
                row.get("workflow_id"),
                row.get("task_id"),
                row.get("calibration_run_index"),
                row.get("resource_request_sha256"),
            )
            for row in envelope_rows
        ]
        if not (
            envelope.get("status")
            == "controller_envelope_bound_provider_preflight_pending"
            and envelope.get("decision") == "BLOCK"
            and envelope.get("input_sha256", {}).get("resource_request_set")
            == request_set_sha
            and envelope.get("summary", {}).get("planned_slot_count") == 200
            and envelope.get("summary", {}).get("launch_plan_bound_count") == 98
            and envelope.get("summary", {}).get(
                "nonlaunch_disposition_bound_count"
            )
            == 102
            and envelope.get("summary", {}).get("resource_sample_count") == 0
            and envelope.get("readiness", {}).get("controller_envelope_bound")
            is True
            and envelope.get("readiness", {}).get(
                "all_200_controller_dispositions_bound"
            )
            is True
            and envelope.get("readiness", {}).get(
                "nonlaunch_metrics_are_null"
            )
            is True
            and envelope.get("readiness", {}).get(
                "common_provider_preflight_passed"
            )
            is False
            and envelope.get("blockers")
            == ["common_provider_preflight_not_passed"]
            and observed_envelope_rows == expected_envelope_rows
        ):
            raise ValueError("controller-aware measurement envelope binding drift")
        controller_envelope_bound = True
        controller_launch_plan_count = 98
        controller_nonlaunch_count = 102
        blockers = ["common_provider_preflight_not_passed"]
        input_sha256.update(
            {
                "controller_aware_measurement_envelope": envelope_sha,
                "controller_aware_measurement_envelope_schema": _sha(
                    CONTROLLER_ENVELOPE_SCHEMA
                ),
            }
        )
    slot_status = [
        {
            "workflow_slot_id": slot,
            "workflow_id": workflow_id,
            "launch_contract_bound": True,
            "measurement_request_count": request_counts[slot],
        }
        for slot, workflow_id in SLOTS
    ]
    result = {
        "schema_version": "rtlflowbench.full_workflow_resource_campaign_preflight.v1",
        "observed_at": observed_at,
        "status": "controller_preflight_blocked_not_started",
        "decision": "BLOCK",
        "scope": "five_workflows_all_twelve_tasks_resource_calibration_preflight_only",
        "input_sha256": {
            **input_sha256,
            "measurement_request_schema": _sha(REQUEST_SCHEMA),
            "measurement_runner": _sha(MEASUREMENT_RUNNER),
            "activity_ledger_schema": _sha(ACTIVITY_LEDGER_SCHEMA),
            "activity_concurrency_builder": _sha(ACTIVITY_BUILDER),
            "launch_contract_schema": _sha(LAUNCH_CONTRACT_SCHEMA),
            "merged_sample_schema": _sha(MERGED_SAMPLE_SCHEMA),
            "resource_aggregator": _sha(RESOURCE_AGGREGATOR),
            "preflight_schema": _sha(PREFLIGHT_SCHEMA),
            "preflight_builder": _sha(Path(__file__).resolve()),
        },
        "static_inputs": {
            "workflow_count": 5,
            "task_count": 12,
            "planned_sample_count": 200,
            "workflow_release_candidate_bound": True,
            "primary_cohort_plan_unopened": True,
            "oci_images_uniquely_resolved": True,
            "official_attempts_started": 0,
        },
        "measurement_envelope": {
            "launcher_kind": "podman_oci",
            "network_policy": "offline",
            "required_podman_network_option": "--network=none",
            "inherited_environment_keys": ["HOME", "XDG_RUNTIME_DIR"],
            "controller_socket_mount_supported": True,
            "observed_provider_gateway_reachable": True,
            "private_evaluator_reachable": False,
            "controller_envelope_bound": controller_envelope_bound,
            "bound_launch_plan_count": controller_launch_plan_count,
            "bound_nonlaunch_disposition_count": controller_nonlaunch_count,
            "nonlaunch_metrics_are_null": controller_envelope_bound,
        },
        "launch_contracts": {
            "required_workflow_count": 5,
            "bound_workflow_count": 5,
            "required_request_count": 200,
            "materialized_request_count": materialized_request_count,
            "workflow_slot_status": slot_status,
        },
        "activity_observation": {
            "ledger_schema_defined": True,
            "concurrency_receipt_builder_defined": True,
            "controller_ledger_producer_defined": True,
            "provider_gateway_observation_bound": True,
            "eda_broker_observation_bound": True,
        },
        "summary": {
            "static_input_gate_pass_count": 3,
            "static_input_gate_count": 3,
            "launch_contract_pass_count": 5,
            "launch_contract_gate_count": 5,
            "activity_observation_pass_count": 2,
            "activity_observation_gate_count": 2,
            "public_workspace_count": public_workspace_count,
            "resource_samples_created": 0,
            "resource_samples_eligible": 0,
        },
        "attempt_accounting": {
            "official_attempts_started": 0,
            "official_semantic_attempts_consumed": 0,
            "resource_calibration_attempts_consumed": 0,
            "benchmark_results_created": 0,
            "provider_calls": 0,
            "eda_calls": 5,
            "private_evaluator_calls": 0,
        },
        "readiness": {
            "static_inputs_complete": True,
            "launch_contracts_complete": True,
            "observed_provider_transport_complete": True,
            "observed_eda_transport_complete": True,
            "measurement_requests_materialized": request_set_bound,
            "all_public_workspaces_materialized": public_workspaces_bound,
            "controller_envelope_bound": controller_envelope_bound,
            "resource_campaign_permitted": False,
            "host_capacity_policy_derivation_permitted": False,
            "official_attempts_permitted": False,
        },
        "blockers": blockers,
        "excluded_claims": [
            "This controller preflight BLOCK is not a workflow capability BLOCK or benchmark verdict.",
            "The task-free transport probe used a simulated provider response and does not prove external provider availability or model behavior.",
            "Five no-network runtime probes and five task-free EDA calls are transport evidence, not workflow runs or benchmark results.",
            "Zero calls and samples are observed preflight counts and are not substituted missing resource metrics.",
            "Bound launch plans and nonlaunch dispositions are not resource samples; resource calibration and host-capacity policy derivation remain prohibited until every blocker is removed.",
        ],
    }
    _validated(PREFLIGHT_SCHEMA, result, "resource campaign preflight")
    rendered = json.dumps(result, sort_keys=True)
    if "/home/" in rendered or "/Users/" in rendered:
        raise ValueError("resource campaign preflight exposes a private host path")
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
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
    parser.add_argument("--full-workflow-request-set", type=Path)
    parser.add_argument("--expected-full-workflow-request-set-sha256")
    parser.add_argument("--controller-envelope", type=Path)
    parser.add_argument("--expected-controller-envelope-sha256")
    parser.add_argument("--observed-at", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.expanduser().absolute()
    if output.exists() or output.is_symlink():
        raise FileExistsError(f"refusing to overwrite: {output}")
    try:
        result = build_preflight(
            workflow_release_candidate_path=args.workflow_release_candidate,
            expected_workflow_release_candidate_sha256=args.expected_workflow_release_candidate_sha256,
            primary_cohort_plan_path=args.primary_cohort_plan,
            expected_primary_cohort_plan_sha256=args.expected_primary_cohort_plan_sha256,
            oci_inventory_path=args.oci_inventory,
            expected_oci_inventory_sha256=args.expected_oci_inventory_sha256,
            launch_contract_intake_path=args.launch_contract_intake,
            expected_launch_contract_intake_sha256=(
                args.expected_launch_contract_intake_sha256
            ),
            observed_transport_probe_path=args.observed_transport_probe,
            expected_observed_transport_probe_sha256=(
                args.expected_observed_transport_probe_sha256
            ),
            observed_at=args.observed_at,
            full_workflow_request_set_path=args.full_workflow_request_set,
            expected_full_workflow_request_set_sha256=(
                args.expected_full_workflow_request_set_sha256
            ),
            controller_envelope_path=args.controller_envelope,
            expected_controller_envelope_sha256=(
                args.expected_controller_envelope_sha256
            ),
        )
    except Exception as exc:
        print(json.dumps({"status": "error", "error_class": type(exc).__name__}))
        return 2
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
