#!/usr/bin/env python3
"""Bind the 200-slot public bridge to one task-neutral measurement envelope."""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import sys
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


HERE = Path(__file__).resolve().parent
SCHEMA = HERE / "controller_aware_measurement_envelope.schema.json"
BRIDGE_SCHEMA = HERE / "full_workflow_bridge_request_set.schema.json"
REQUEST_SET_SCHEMA = HERE / "full_workflow_resource_measurement_request_set.schema.json"
REQUEST_SCHEMA = HERE / "full_workflow_resource_measurement_request.schema.json"
RUNNER = HERE / "run_controller_aware_resource_measurement.py"
NONLAUNCH_SCHEMA = HERE / "controller_resource_nonlaunch_receipt.schema.json"
PROCESS_SCHEMA = HERE / "workflow_resource_measurement_receipt.schema.json"
LEDGER_SCHEMA = HERE / "workflow_activity_ledger.schema.json"
ACTIVITY_BUILDER = HERE / "build_workflow_activity_concurrency_receipt.py"
MERGER = HERE / "merge_full_workflow_resource_measurement.py"
SHA256 = "^[0-9a-f]{64}$"


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


def _canonical_sha(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
    ).hexdigest()


def _validate(schema_path: Path, value: dict[str, Any], label: str) -> None:
    schema = _load(schema_path, f"{label} schema")
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(value)


def _module():
    spec = importlib.util.spec_from_file_location(
        "rtlflowbench_controller_measurement_runner", RUNNER
    )
    if spec is None or spec.loader is None:
        raise ValueError("controller measurement runner cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _require(path: Path, expected: str, label: str) -> tuple[Path, str]:
    path = path.expanduser().resolve(strict=True)
    observed = _sha(path)
    if len(expected) != 64 or observed != expected:
        raise ValueError(f"{label} differs from its out-of-band SHA256")
    return path, observed


def _request_path(root: Path, value: str) -> Path:
    relative = PurePosixPath(value)
    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
        raise ValueError("resource request path escapes its set root")
    path = (root / Path(*relative.parts)).resolve(strict=True)
    if not path.is_relative_to(root):
        raise ValueError("resource request path escapes its set root")
    return path


def _null_metrics() -> dict[str, None]:
    return {
        "wall_time_seconds": None,
        "cpu_time_seconds": None,
        "peak_memory_bytes": None,
        "peak_scratch_bytes": None,
        "peak_process_count": None,
        "peak_eda_concurrency": None,
        "peak_llm_concurrency": None,
        "llm_call_count": None,
        "eda_call_count": None,
    }


def build_envelope(
    *,
    resource_request_set_path: Path,
    expected_resource_request_set_sha256: str,
    bridge_request_set_path: Path,
    expected_bridge_request_set_sha256: str,
    observed_at: str,
) -> dict[str, Any]:
    parsed = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("observed_at must include a timezone")
    resource_set_path, resource_set_sha = _require(
        resource_request_set_path,
        expected_resource_request_set_sha256,
        "resource request set",
    )
    bridge_set_path, bridge_set_sha = _require(
        bridge_request_set_path,
        expected_bridge_request_set_sha256,
        "bridge request set",
    )
    resource_set = _load(resource_set_path, "resource request set")
    bridge_set = _load(bridge_set_path, "bridge request set")
    _validate(REQUEST_SET_SCHEMA, resource_set, "resource request set")
    _validate(BRIDGE_SCHEMA, bridge_set, "bridge request set")
    if bridge_set["input_sha256"]["resource_request_set"] != resource_set_sha:
        raise ValueError("bridge set does not bind the exact resource request set")
    if not (
        resource_set["summary"]["request_count"] == 200
        and resource_set["summary"]["controller_envelope_count"] == 0
        and resource_set["readiness"]["all_requests_materialized"] is True
        and resource_set["readiness"]["all_public_workspaces_materialized"] is True
        and resource_set["readiness"]["resource_campaign_permitted"] is False
        and bridge_set["summary"]["planned_run_count"] == 200
        and bridge_set["summary"]["launch_request_materialized_count"] == 98
        and bridge_set["summary"]["controller_block_preclassified_count"] == 102
        and bridge_set["readiness"]["controller_envelope_bound"] is False
    ):
        raise ValueError("resource/bridge set state is not the reviewed pre-envelope state")
    resource_rows = resource_set["requests"]
    bridge_rows = bridge_set["requests"]
    if len(resource_rows) != 200 or len(bridge_rows) != 200:
        raise ValueError("controller envelope requires exactly 200 rows")
    runner = _module()
    request_root = resource_set_path.parent.resolve(strict=True)
    rows: list[dict[str, Any]] = []
    launch_count = 0
    nonlaunch_count = 0
    seen: set[tuple[str, str, int]] = set()
    for position, (resource_row, bridge_row) in enumerate(
        zip(resource_rows, bridge_rows, strict=True)
    ):
        identity = (
            resource_row["workflow_slot_id"],
            resource_row["task_id"],
            resource_row["calibration_run_index"],
        )
        if identity in seen:
            raise ValueError("controller envelope contains a duplicate schedule cell")
        seen.add(identity)
        if any(
            resource_row[key] != bridge_row[key]
            for key in (
                "measurement_id",
                "workflow_slot_id",
                "workflow_id",
                "task_id",
                "calibration_run_index",
            )
        ):
            raise ValueError(f"bridge/resource schedule order drift: {position}")
        request_path = _request_path(
            request_root, resource_row["request_relative_path"]
        )
        if _sha(request_path) != resource_row["request_sha256"]:
            raise ValueError("indexed resource request SHA256 drift")
        request = _load(request_path, "resource request")
        _validate(REQUEST_SCHEMA, request, "resource request")
        bound_request, _bound_set, bound_row, request_bridge_root = runner._bound_inputs(
            resource_request_path=request_path,
            bridge_set_path=bridge_set_path,
            expected_bridge_set_sha256=bridge_set_sha,
        )
        if bound_request != request or bound_row != bridge_row:
            raise ValueError("controller runner binding differs from envelope input")
        if bridge_row["disposition"] == "launch_request_materialized_not_run":
            if request_bridge_root is None:
                raise ValueError("launch row lacks a public bridge request root")
            plan = runner.build_launch_plan(
                request=request, bridge_row=bridge_row, observed_at=observed_at
            )
            plan_sha = _canonical_sha(plan)
            disposition_sha = None
            availability = "pending_observed_launch_measurement"
            launch_count += 1
        else:
            if request_bridge_root is not None:
                raise ValueError("nonlaunch row unexpectedly resolves a request root")
            receipt = runner.build_nonlaunch_receipt(
                request=request,
                bridge_set_sha256=bridge_set_sha,
                bridge_row=bridge_row,
                resource_request_sha256=_sha(request_path),
                observed_at=observed_at,
            )
            plan_sha = None
            disposition_sha = _canonical_sha(receipt)
            availability = "not_available_not_launched"
            nonlaunch_count += 1
        rows.append(
            {
                "measurement_id": request["measurement_id"],
                "workflow_slot_id": request["workflow_slot_id"],
                "workflow_id": request["workflow_id"],
                "task_id": request["task_id"],
                "calibration_run_index": request["calibration_run_index"],
                "resource_request_sha256": _sha(request_path),
                "bridge_request_payload_sha256": bridge_row[
                    "request_payload_sha256"
                ],
                "controller_disposition": bridge_row["disposition"],
                "launch_plan_sha256": plan_sha,
                "nonlaunch_receipt_sha256": disposition_sha,
                "resource_metric_availability": availability,
                "metrics": _null_metrics(),
                "provider_calls": 0,
                "eda_calls": 0,
                "private_evaluator_calls": 0,
                "resource_calibration_attempt_consumed": False,
                "official_semantic_attempt_consumed": False,
            }
        )
    if launch_count != 98 or nonlaunch_count != 102 or len(seen) != 200:
        raise ValueError("controller envelope disposition census drift")
    result = {
        "schema_version": "rtlflowbench.controller_aware_measurement_envelope.v1",
        "observed_at": observed_at,
        "status": "controller_envelope_bound_provider_preflight_pending",
        "decision": "BLOCK",
        "scope": "five_workflows_all_twelve_tasks_resource_measurement_control_only",
        "input_sha256": {
            "resource_request_set": resource_set_sha,
            "bridge_request_set": bridge_set_sha,
            "runner": _sha(RUNNER),
            "nonlaunch_receipt_schema": _sha(NONLAUNCH_SCHEMA),
            "process_receipt_schema": _sha(PROCESS_SCHEMA),
            "activity_ledger_schema": _sha(LEDGER_SCHEMA),
            "activity_concurrency_builder": _sha(ACTIVITY_BUILDER),
            "resource_merger": _sha(MERGER),
            "builder": _sha(Path(__file__).resolve()),
            "schema": _sha(SCHEMA),
        },
        "isolation": {
            "container_network": "none",
            "provider_credential_location": "host_controller_only",
            "raw_provider_content_persisted": False,
            "public_bridge_mount": "read_only",
            "workflow_scratch_mount": "read_write",
            "controller_socket_mount": "read_only",
            "private_evaluator_reachable": False,
            "task_solution_knowledge_included": False,
        },
        "requests": rows,
        "summary": {
            "workflow_count": 5,
            "task_count": 12,
            "planned_slot_count": 200,
            "launch_plan_bound_count": launch_count,
            "nonlaunch_disposition_bound_count": nonlaunch_count,
            "resource_sample_count": 0,
            "resource_attempt_count": 0,
            "provider_call_count": 0,
            "eda_call_count": 0,
            "private_evaluator_call_count": 0,
            "official_attempt_count": 0,
        },
        "readiness": {
            "all_200_controller_dispositions_bound": True,
            "controller_envelope_bound": True,
            "nonlaunch_metrics_are_null": True,
            "common_provider_preflight_passed": False,
            "resource_campaign_permitted": False,
            "host_capacity_policy_derivation_permitted": False,
            "official_attempts_permitted": False,
        },
        "blockers": ["common_provider_preflight_not_passed"],
        "excluded_claims": [
            "A bound controller measurement envelope is not a workflow run, resource sample, benchmark verdict, score, QoR result, or PPA result.",
            "The 102 public capability preclassifications remain controller dispositions and are not observed workflow BLOCK verdicts.",
            "Unavailable resource metrics remain null; zero provider and EDA calls are observed pre-execution counts only.",
            "No private evaluator, hidden oracle, provider request, EDA tool, official attempt, or semantic candidate is invoked.",
            "Resource calibration remains blocked until all five native provider routes pass the exact common-provider preflight.",
        ],
    }
    _validate(SCHEMA, result, "controller-aware measurement envelope")
    rendered = json.dumps(result, sort_keys=True)
    if "/home/" in rendered or "/Users/" in rendered:
        raise ValueError("controller envelope exposes host paths")
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--resource-request-set", type=Path, required=True)
    parser.add_argument("--expected-resource-request-set-sha256", required=True)
    parser.add_argument("--bridge-request-set", type=Path, required=True)
    parser.add_argument("--expected-bridge-request-set-sha256", required=True)
    parser.add_argument("--observed-at", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists() or args.output.is_symlink():
        raise FileExistsError("refusing to overwrite controller envelope receipt")
    try:
        result = build_envelope(
            resource_request_set_path=args.resource_request_set,
            expected_resource_request_set_sha256=args.expected_resource_request_set_sha256,
            bridge_request_set_path=args.bridge_request_set,
            expected_bridge_request_set_sha256=args.expected_bridge_request_set_sha256,
            observed_at=args.observed_at,
        )
    except Exception as exc:
        print(json.dumps({"status": "error", "error_class": type(exc).__name__}))
        return 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"status": result["status"], **result["summary"]}, sort_keys=True))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
