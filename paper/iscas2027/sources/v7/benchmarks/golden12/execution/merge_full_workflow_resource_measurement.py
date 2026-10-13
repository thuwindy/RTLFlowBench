#!/usr/bin/env python3
"""Bind cgroup/process metrics to controller-observed EDA/LLM concurrency."""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
import math
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


HERE = Path(__file__).resolve().parent
PROCESS_SCHEMA = HERE / "workflow_resource_measurement_receipt.schema.json"
ACTIVITY_SCHEMA = HERE / "workflow_activity_concurrency_receipt.schema.json"
MERGED_SCHEMA = HERE / "full_workflow_resource_measurement_receipt.schema.json"


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


def merge_receipts(
    *, process_receipt_path: Path, activity_receipt_path: Path, observed_at: str
) -> dict[str, Any]:
    parsed = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("observed_at must include a timezone")
    process_receipt_path = process_receipt_path.expanduser()
    activity_receipt_path = activity_receipt_path.expanduser()
    for path, label in (
        (process_receipt_path, "process measurement receipt"),
        (activity_receipt_path, "activity concurrency receipt"),
    ):
        if path.is_symlink():
            raise ValueError(f"{label} must not be a symlink")
    process_receipt_path = process_receipt_path.resolve(strict=True)
    activity_receipt_path = activity_receipt_path.resolve(strict=True)
    schemas = {
        "process": _load(PROCESS_SCHEMA, "process receipt schema"),
        "activity": _load(ACTIVITY_SCHEMA, "activity receipt schema"),
        "merged": _load(MERGED_SCHEMA, "merged receipt schema"),
    }
    for schema in schemas.values():
        Draft202012Validator.check_schema(schema)
    process = _load(process_receipt_path, "process measurement receipt")
    activity = _load(activity_receipt_path, "activity concurrency receipt")
    Draft202012Validator(
        schemas["process"], format_checker=FormatChecker()
    ).validate(process)
    Draft202012Validator(
        schemas["activity"], format_checker=FormatChecker()
    ).validate(activity)
    if activity["process_measurement_receipt_sha256"] != _sha(
        process_receipt_path
    ):
        raise ValueError(
            "activity ledger does not bind the exact process measurement receipt"
        )
    if process["measurement_scope"] != "full_workflow_calibration":
        raise ValueError("process measurement is not a full-workflow calibration")
    identity_keys = (
        "measurement_id", "workflow_slot_id", "workflow_id", "task_id", "attempt_id",
        "source_binding", "runtime_binding",
    )
    if any(process[key] != activity[key] for key in identity_keys):
        raise ValueError("process and activity receipt bindings differ")
    if process["attempt_accounting"] != activity["attempt_accounting"]:
        raise ValueError("attempt accounting differs across resource receipts")

    process_metrics = process["metrics"]
    activity_metrics = activity["metrics"]
    wall_ns = math.ceil(process_metrics["wall_time_seconds"] * 1_000_000_000)
    tolerance_ns = process_metrics["sampling_interval_ms"] * 1_000_000
    latest_activity = activity_metrics["latest_completed_offset_ns"]
    within_wall = latest_activity is None or latest_activity <= (
        wall_ns + tolerance_ns
    )
    completeness = {
        "process_tree_measurement_complete": process["readiness"][
            "process_tree_measurement_complete"
        ],
        "container_cgroup_measurement_complete": process["readiness"][
            "container_cgroup_measurement_complete"
        ],
        "scratch_integrity_valid": process_metrics["scratch_integrity_valid"],
        "activity_timeline_complete": activity["readiness"][
            "activity_timeline_complete"
        ],
        "provider_gateway_observation_complete": activity["completeness"][
            "provider_gateway_observation_complete"
        ],
        "eda_broker_observation_complete": activity["completeness"][
            "eda_broker_observation_complete"
        ],
        "all_provider_calls_routed_through_observer": activity["completeness"][
            "all_provider_calls_routed_through_observer"
        ],
        "all_eda_invocations_routed_through_observer": activity["completeness"][
            "all_eda_invocations_routed_through_observer"
        ],
        "activity_within_measured_wall_time": within_wall,
    }
    token_usage = activity_metrics["token_usage"]
    expected_provider_calls = token_usage["expected_call_count"]
    token_accounting_complete = (
        token_usage["measurement_complete"] is True
        and token_usage["observed_call_count"] == expected_provider_calls
        and token_usage["unobserved_call_count"] == 0
        and token_usage["cache_measurement_complete"] is True
        and token_usage["cache_observed_call_count"] == expected_provider_calls
        and token_usage["cache_unobserved_call_count"] == 0
        and token_usage.get("finish_reason_measurement_complete") is True
        and token_usage.get("finish_reason_observed_call_count")
        == expected_provider_calls
        and token_usage.get("finish_reason_unobserved_call_count") == 0
    )
    sample_complete = all(completeness.values()) and token_accounting_complete
    eligible = (
        sample_complete
        and process["status"] == "measurement_completed"
        and process["launcher"]["outcome"] in {"exited_zero", "exited_nonzero"}
        and process_metrics["peak_container_cgroup_memory_bytes"] > 0
        and process_metrics["peak_container_cgroup_pids"] > 0
    )
    result = {
        "schema_version": "rtlflowbench.full_workflow_resource_measurement_receipt.v1",
        "observed_at": observed_at,
        "status": (
            "full_workflow_resource_sample_complete"
            if eligible
            else "full_workflow_resource_sample_ineligible"
        ),
        "measurement_id": process["measurement_id"],
        "workflow_slot_id": process["workflow_slot_id"],
        "workflow_id": process["workflow_id"],
        "task_id": process["task_id"],
        "attempt_id": process["attempt_id"],
        "source_binding": process["source_binding"],
        "runtime_binding": process["runtime_binding"],
        "input_sha256": {
            "process_measurement_receipt": _sha(process_receipt_path),
            "activity_concurrency_receipt": _sha(activity_receipt_path),
            "merger": _sha(Path(__file__).resolve()),
            "process_receipt_schema": _sha(PROCESS_SCHEMA),
            "activity_receipt_schema": _sha(ACTIVITY_SCHEMA),
            "merged_receipt_schema": _sha(MERGED_SCHEMA),
        },
        "metrics": {
            "peak_memory_bytes": process_metrics[
                "peak_container_cgroup_memory_bytes"
            ],
            "cpu_time_seconds": process_metrics[
                "container_cgroup_cpu_time_seconds"
            ],
            "wall_time_seconds": process_metrics["wall_time_seconds"],
            "peak_scratch_bytes": process_metrics["peak_scratch_bytes"],
            "peak_process_count": process_metrics["peak_container_cgroup_pids"],
            "peak_eda_concurrency": activity_metrics["peak_eda_concurrency"],
            "peak_llm_concurrency": activity_metrics["peak_llm_concurrency"],
            "peak_eda_concurrency_by_kind": activity_metrics[
                "peak_eda_concurrency_by_kind"
            ],
            "forced_eda_activity_closure_count": process_metrics[
                "forced_eda_activity_closure_count"
            ],
            "activity_count": activity_metrics["activity_count"],
            "provider_call_limit": activity_metrics["provider_call_limit"],
            "provider_call_count": activity_metrics["provider_call_count"],
            "provider_budget_rejection_count": activity_metrics[
                "provider_budget_rejection_count"
            ],
            "provider_budget_exhausted": activity_metrics[
                "provider_budget_exhausted"
            ],
            "token_usage": dict(token_usage),
            "sample_count": process_metrics["sample_count"],
            "sampling_interval_ms": process_metrics["sampling_interval_ms"],
        },
        "launcher": {
            "outcome": process["launcher"]["outcome"],
            "exit_code": process["launcher"]["exit_code"],
            "timed_out": process["launcher"]["timed_out"],
            "controller_guard_terminated": process["launcher"].get(
                "controller_guard_terminated", False
            ),
            "controller_guard_reason": process["launcher"].get(
                "controller_guard_reason"
            ),
        },
        "completeness": completeness,
        "attempt_accounting": process["attempt_accounting"],
        "readiness": {
            "sample_complete": sample_complete,
            "sample_eligible_for_resource_cohort": eligible,
            "workflow_calibration_complete": False,
            "host_capacity_policy_derivation_permitted": False,
            "official_attempts_permitted": False,
        },
        "excluded_claims": [
            "One resource sample is not complete workflow calibration, a host-capacity policy, or release readiness.",
            "The merged measurement is not an RTL PASS, FAIL, BLOCK, INFRA verdict, score, or QoR result.",
            "The activity ledger contains no raw provider response, credential, hidden oracle, or private evaluator data.",
            "No official Golden-12 attempt is started or consumed, and no benchmark result is created.",
            "Workflow-wide calibration still requires the frozen all-task workload coverage and independent review gates.",
            "Forced EDA activity closures, if any, are counted explicitly and conservatively end at workflow process exit.",
            "Incomplete token, cache-token, or finish-reason accounting makes the sample ineligible for the resource cohort; partial observed values remain evidence only.",
        ],
    }
    Draft202012Validator(
        schemas["merged"], format_checker=FormatChecker()
    ).validate(result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--process-receipt", type=Path, required=True)
    parser.add_argument("--activity-receipt", type=Path, required=True)
    parser.add_argument("--observed-at", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.expanduser().absolute()
    if output.exists() or output.is_symlink():
        raise FileExistsError(f"refusing to overwrite: {output}")
    try:
        result = merge_receipts(
            process_receipt_path=args.process_receipt,
            activity_receipt_path=args.activity_receipt,
            observed_at=args.observed_at,
        )
    except Exception as exc:
        print(json.dumps({"status": "error", "error_class": type(exc).__name__}))
        return 2
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["readiness"]["sample_eligible_for_resource_cohort"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
