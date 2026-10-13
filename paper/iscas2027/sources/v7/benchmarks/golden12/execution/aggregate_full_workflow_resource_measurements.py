#!/usr/bin/env python3
"""Aggregate 98 launched samples plus 102 controller nonlaunch dispositions."""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


HERE = Path(__file__).resolve().parent
SET_SCHEMA = HERE / "full_workflow_resource_measurement_set.schema.json"
LAUNCH_SAMPLE_SCHEMA = HERE / "full_workflow_resource_measurement_receipt.schema.json"
NONLAUNCH_SAMPLE_SCHEMA = HERE / "controller_resource_nonlaunch_receipt.schema.json"
SUMMARY_SCHEMA = HERE / "full_workflow_resource_calibration_summary.schema.json"
SLOTS = (
    ("chipflow", "chipflow"),
    ("same_model_vanilla_agent", "same_model_vanilla_agent"),
    ("external_airtl_1", "mage"),
    ("external_airtl_2", "verilogcoder"),
    ("external_airtl_3", "hdlagent"),
)
EXPECTED_LAUNCH_SAMPLES = {
    "chipflow": 40,
    "same_model_vanilla_agent": 40,
    "external_airtl_1": 6,
    "external_airtl_2": 6,
    "external_airtl_3": 6,
}
EXPECTED_NONLAUNCH_SAMPLES = {
    "chipflow": 0,
    "same_model_vanilla_agent": 0,
    "external_airtl_1": 34,
    "external_airtl_2": 34,
    "external_airtl_3": 34,
}
EXPECTED_LAUNCHED_TASKS = {
    "chipflow": 12,
    "same_model_vanilla_agent": 12,
    "external_airtl_1": 2,
    "external_airtl_2": 2,
    "external_airtl_3": 2,
}
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


def _release_rows(candidate: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = candidate.get("workflows")
    if not (
        candidate.get("schema_version")
        == "rtlflowbench.workflow_release_set_candidate.v1"
        and isinstance(rows, list)
        and [
            (row.get("workflow_slot_id"), row.get("workflow_id"))
            for row in rows
        ]
        == list(SLOTS)
        and candidate.get("summary", {}).get("attempt_slot_count") == 200
        and candidate.get("readiness", {}).get("official_attempts_permitted")
        is False
    ):
        raise ValueError("workflow release candidate is not the unopened five-slot input")
    for row in rows:
        if not (
            row.get("runtime_candidate_bound") is True
            and row.get("scheduled_attempt_count") == 40
            and row.get("runtime_resource_calibration_complete") is False
            and row.get("official_attempts_permitted") is False
            and isinstance(row.get("source_commit"), str)
            and re.fullmatch(r"[0-9a-f]{40}", row["source_commit"])
            and SHA256_RE.fullmatch(str(row.get("source_manifest_sha256")))
            and re.fullmatch(
                r"sha256:[0-9a-f]{64}", str(row.get("runtime_image_digest"))
            )
        ):
            raise ValueError(
                f"workflow release binding is incomplete: {row.get('workflow_slot_id')}"
            )
    return {row["workflow_slot_id"]: row for row in rows}


def _plan_counts(plan: dict[str, Any]) -> tuple[Counter, set[str]]:
    attempts = plan.get("attempts")
    summary = plan.get("attempt_summary", {})
    if not (
        plan.get("schema_version") == "rtlflowbench.primary_cohort_execution_plan.v1"
        and plan.get("workflow_slot_ids") == [slot for slot, _ in SLOTS]
        and isinstance(attempts, list)
        and len(attempts) == 200
        and len({row.get("attempt_id") for row in attempts}) == 200
        and summary.get("workflow_count") == 5
        and summary.get("task_count") == 12
        and summary.get("attempts_per_workflow") == 40
        and summary.get("total_attempt_slots") == 200
        and summary.get("started_attempts") == 0
        and summary.get("semantic_attempts_consumed") == 0
        and summary.get("omitted_attempt_slots") == 0
    ):
        raise ValueError("primary cohort plan is not the unopened 200-slot schedule")
    if any(
        row.get("execution_status") != "controller_gate_blocked_not_started"
        or row.get("semantic_attempt_consumed") is not False
        or row.get("result_class") is not None
        for row in attempts
    ):
        raise ValueError("primary cohort plan already contains attempt execution state")
    counts = Counter(
        (row.get("workflow_slot_id"), row.get("task_id")) for row in attempts
    )
    task_ids = {row.get("task_id") for row in attempts}
    if len(task_ids) != 12 or None in task_ids:
        raise ValueError("primary cohort plan does not contain exactly twelve tasks")
    for slot, _ in SLOTS:
        rows = [row for row in attempts if row.get("workflow_slot_id") == slot]
        if len(rows) != 40 or {row.get("task_id") for row in rows} != task_ids:
            raise ValueError(f"primary cohort plan omits a task for {slot}")
    return counts, {str(value) for value in task_ids}


def _inventory_rows(
    inventory: dict[str, Any], release_sha256: str
) -> dict[str, dict[str, Any]]:
    rows = inventory.get("workflows")
    if not (
        inventory.get("schema_version")
        == "rtlflowbench.workflow_runtime_oci_inventory.v1"
        and inventory.get("workflow_release_candidate_sha256") == release_sha256
        and isinstance(rows, list)
        and [
            (row.get("workflow_slot_id"), row.get("workflow_id"))
            for row in rows
        ]
        == list(SLOTS)
        and inventory.get("summary", {}).get("workflow_count") == 5
        and inventory.get("summary", {}).get("unique_digest_match_count") == 5
        and inventory.get("summary", {}).get("missing_or_ambiguous_count") == 0
        and inventory.get("summary", {}).get("container_start_count") == 0
    ):
        raise ValueError("OCI inventory is not an exact task-free five-image binding")
    for row in rows:
        if not (
            row.get("inventory_status") == "available_unique_digest_match"
            and re.fullmatch(
                r"sha256:[0-9a-f]{64}", str(row.get("resolved_image_id"))
            )
        ):
            raise ValueError(
                f"OCI image is missing or ambiguous: {row.get('workflow_slot_id')}"
            )
    return {row["workflow_slot_id"]: row for row in rows}


def _receipt_path(root: Path, relative: str) -> Path:
    candidate = root / relative
    if candidate.is_symlink():
        raise ValueError("sample receipt must not be a symlink")
    resolved = candidate.resolve(strict=True)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError("sample receipt escapes the measurement root") from exc
    if not resolved.is_file():
        raise ValueError("sample receipt is not a regular file")
    return resolved


def aggregate(
    *,
    measurement_set_path: Path,
    expected_measurement_set_sha256: str,
    measurement_root: Path,
    workflow_release_candidate_path: Path,
    expected_workflow_release_candidate_sha256: str,
    primary_cohort_plan_path: Path,
    expected_primary_cohort_plan_sha256: str,
    oci_inventory_path: Path,
    expected_oci_inventory_sha256: str,
    observed_at: str,
) -> dict[str, Any]:
    parsed = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("observed_at must include a timezone")
    measurement_root = measurement_root.expanduser()
    if measurement_root.is_symlink() or not measurement_root.is_dir():
        raise ValueError("measurement root must be a regular non-symlink directory")
    measurement_root = measurement_root.resolve(strict=True)

    input_paths = {
        "measurement_set": measurement_set_path.expanduser().resolve(strict=True),
        "workflow_release_candidate": workflow_release_candidate_path.expanduser().resolve(strict=True),
        "primary_cohort_execution_plan": primary_cohort_plan_path.expanduser().resolve(strict=True),
        "oci_inventory": oci_inventory_path.expanduser().resolve(strict=True),
    }
    input_sha256 = {
        "measurement_set": _require_sha(
            input_paths["measurement_set"], expected_measurement_set_sha256,
            "measurement set",
        ),
        "workflow_release_candidate": _require_sha(
            input_paths["workflow_release_candidate"],
            expected_workflow_release_candidate_sha256,
            "workflow release candidate",
        ),
        "primary_cohort_execution_plan": _require_sha(
            input_paths["primary_cohort_execution_plan"],
            expected_primary_cohort_plan_sha256,
            "primary cohort execution plan",
        ),
        "oci_inventory": _require_sha(
            input_paths["oci_inventory"], expected_oci_inventory_sha256,
            "OCI inventory",
        ),
    }
    measurement_set = _load(input_paths["measurement_set"], "measurement set")
    _validated(SET_SCHEMA, measurement_set, "measurement set")
    if (
        measurement_set["workflow_release_candidate_sha256"]
        != input_sha256["workflow_release_candidate"]
        or measurement_set["primary_cohort_execution_plan_sha256"]
        != input_sha256["primary_cohort_execution_plan"]
        or measurement_set["oci_inventory_sha256"]
        != input_sha256["oci_inventory"]
        or measurement_set["launch_receipt_schema_sha256"]
        != _sha(LAUNCH_SAMPLE_SCHEMA)
        or measurement_set["nonlaunch_receipt_schema_sha256"]
        != _sha(NONLAUNCH_SAMPLE_SCHEMA)
    ):
        raise ValueError("measurement set input binding drift")

    release_rows = _release_rows(
        _load(input_paths["workflow_release_candidate"], "workflow release candidate")
    )
    plan_counts, task_ids = _plan_counts(
        _load(input_paths["primary_cohort_execution_plan"], "primary cohort plan")
    )
    inventory_rows = _inventory_rows(
        _load(input_paths["oci_inventory"], "OCI inventory"),
        input_sha256["workflow_release_candidate"],
    )
    launch_schema = _load(LAUNCH_SAMPLE_SCHEMA, "launch sample receipt schema")
    nonlaunch_schema = _load(
        NONLAUNCH_SAMPLE_SCHEMA, "controller nonlaunch receipt schema"
    )
    Draft202012Validator.check_schema(launch_schema)
    Draft202012Validator.check_schema(nonlaunch_schema)
    launch_validator = Draft202012Validator(
        launch_schema, format_checker=FormatChecker()
    )
    nonlaunch_validator = Draft202012Validator(
        nonlaunch_schema, format_checker=FormatChecker()
    )

    samples = measurement_set["samples"]
    slot_order = {slot: index for index, (slot, _) in enumerate(SLOTS)}
    expected_order = sorted(
        samples,
        key=lambda row: (
            slot_order[row["workflow_slot_id"]],
            row["task_id"],
            row["calibration_run_index"],
        ),
    )
    if samples != expected_order:
        raise ValueError("measurement set samples are not in canonical schedule order")
    unique_fields = (
        "sample_id", "measurement_id", "attempt_id", "receipt_relative_path",
        "receipt_sha256",
    )
    for field in unique_fields:
        values = [row[field] for row in samples]
        if len(values) != len(set(values)):
            raise ValueError(f"measurement set contains duplicate {field}")
    observed_counts = Counter(
        (row["workflow_slot_id"], row["task_id"]) for row in samples
    )
    if observed_counts != plan_counts:
        raise ValueError("resource sample coverage differs from the frozen schedule")
    for key, count in observed_counts.items():
        indexes = sorted(
            row["calibration_run_index"]
            for row in samples
            if (row["workflow_slot_id"], row["task_id"]) == key
        )
        if indexes != list(range(1, count + 1)):
            raise ValueError(f"resource calibration run indexes are gapped: {key}")
        kinds = {
            row["receipt_kind"]
            for row in samples
            if (row["workflow_slot_id"], row["task_id"]) == key
        }
        if len(kinds) != 1:
            raise ValueError(f"task dispositions are split across receipt kinds: {key}")

    metrics_by_slot: dict[str, list[tuple[str, dict[str, Any], str]]] = defaultdict(list)
    dispositions_by_slot: dict[str, list[tuple[str, str, str]]] = defaultdict(list)
    nonlaunch_tasks_by_slot: dict[str, set[str]] = defaultdict(set)
    for entry in samples:
        slot = entry["workflow_slot_id"]
        release = release_rows[slot]
        inventory = inventory_rows[slot]
        if entry["workflow_id"] != release["workflow_id"]:
            raise ValueError(f"workflow identity drift: {entry['sample_id']}")
        path = _receipt_path(measurement_root, entry["receipt_relative_path"])
        if _sha(path) != entry["receipt_sha256"]:
            raise ValueError(f"sample receipt digest drift: {entry['sample_id']}")
        receipt = _load(path, "resource disposition receipt")
        validator = (
            launch_validator
            if entry["receipt_kind"] == "measured_launch"
            else nonlaunch_validator
        )
        errors = sorted(
            validator.iter_errors(receipt),
            key=lambda error: list(error.absolute_path),
        )
        if errors:
            raise ValueError(
                f"sample receipt schema failure: {entry['sample_id']}: "
                f"{errors[0].message}"
            )
        identity = {
            "measurement_id": entry["measurement_id"],
            "workflow_slot_id": slot,
            "workflow_id": entry["workflow_id"],
            "task_id": entry["task_id"],
            "attempt_id": entry["attempt_id"],
        }
        if any(receipt[key] != value for key, value in identity.items()):
            raise ValueError(f"sample receipt identity drift: {entry['sample_id']}")
        dispositions_by_slot[slot].append(
            (entry["task_id"], entry["receipt_kind"], entry["receipt_sha256"])
        )
        if entry["receipt_kind"] == "measured_launch":
            if receipt["source_binding"] != {
                "commit": release["source_commit"],
                "manifest_sha256": release["source_manifest_sha256"],
            }:
                raise ValueError(f"sample source binding drift: {entry['sample_id']}")
            if receipt["runtime_binding"] != {
                "image_digest": release["runtime_image_digest"],
                "image_id": inventory["resolved_image_id"],
            }:
                raise ValueError(f"sample runtime binding drift: {entry['sample_id']}")
            if not (
                receipt["status"] == "full_workflow_resource_sample_complete"
                and receipt["readiness"]["sample_complete"] is True
                and receipt["readiness"]["sample_eligible_for_resource_cohort"] is True
                and receipt["readiness"]["workflow_calibration_complete"] is False
                and receipt["readiness"]["official_attempts_permitted"] is False
                and receipt["attempt_accounting"]
                == {
                    "official_attempt_started": False,
                    "official_semantic_attempt_consumed": False,
                    "resource_calibration_attempt_consumed": True,
                    "benchmark_result_created": False,
                    "private_evaluator_calls": 0,
                }
            ):
                raise ValueError(
                    f"sample is not eligible resource-only evidence: {entry['sample_id']}"
                )
            metrics_by_slot[slot].append(
                (entry["task_id"], receipt["metrics"], entry["receipt_sha256"])
            )
        else:
            if not (
                receipt["status"] == "not_available_not_launched"
                and receipt["input_sha256"]["schema"]
                == _sha(NONLAUNCH_SAMPLE_SCHEMA)
                and receipt["controller_disposition"]["workflow_process_started"]
                is False
                and receipt["controller_disposition"]["workflow_block_verdict_created"]
                is False
                and all(value is None for value in receipt["metrics"].values())
                and receipt["attempt_accounting"]
                == {
                    "resource_calibration_attempt_consumed": False,
                    "official_attempt_started": False,
                    "official_semantic_attempt_consumed": False,
                    "benchmark_result_created": False,
                    "private_evaluator_calls": 0,
                }
                and receipt["readiness"]
                == {
                    "resource_sample_created": False,
                    "resource_sample_eligible": False,
                    "host_capacity_policy_derivation_permitted": False,
                    "official_attempts_permitted": False,
                }
            ):
                raise ValueError(
                    f"controller nonlaunch receipt is not null fail-closed evidence: "
                    f"{entry['sample_id']}"
                )
            nonlaunch_tasks_by_slot[slot].add(entry["task_id"])

    workflows = []
    for slot, workflow_id in SLOTS:
        rows = metrics_by_slot[slot]
        dispositions = dispositions_by_slot[slot]
        release = release_rows[slot]
        inventory = inventory_rows[slot]
        launched_tasks = {task_id for task_id, _, _ in rows}
        if not (
            len(rows) == EXPECTED_LAUNCH_SAMPLES[slot]
            and len(dispositions) == 40
            and len(dispositions) - len(rows) == EXPECTED_NONLAUNCH_SAMPLES[slot]
            and len(launched_tasks) == EXPECTED_LAUNCHED_TASKS[slot]
            and launched_tasks | nonlaunch_tasks_by_slot[slot] == task_ids
            and not launched_tasks & nonlaunch_tasks_by_slot[slot]
        ):
            raise ValueError(f"resource cohort is incomplete: {slot}")
        peak_memory = max(metrics["peak_memory_bytes"] for _, metrics, _ in rows)
        peak_memory_tasks = sorted(
            {
                task_id
                for task_id, metrics, _ in rows
                if metrics["peak_memory_bytes"] == peak_memory
            }
        )
        disposition_receipt_set_sha256 = hashlib.sha256(
            (
                "\n".join(sorted(digest for _, _, digest in dispositions)) + "\n"
            ).encode()
        ).hexdigest()
        provider_call_limits = {
            metrics["provider_call_limit"] for _, metrics, _ in rows
        }
        if len(provider_call_limits) != 1:
            raise ValueError(
                f"resource cohort provider call limit drift: {slot}"
            )
        provider_call_limit = next(iter(provider_call_limits))
        workflows.append(
            {
                "workflow_slot_id": slot,
                "workflow_id": workflow_id,
                "source_commit": release["source_commit"],
                "source_manifest_sha256": release["source_manifest_sha256"],
                "runtime_image_digest": release["runtime_image_digest"],
                "runtime_image_id": inventory["resolved_image_id"],
                "scheduled_task_count": 12,
                "scheduled_slot_count": 40,
                "launched_task_count": len(launched_tasks),
                "measured_launch_sample_count": len(rows),
                "controller_nonlaunch_count": len(dispositions) - len(rows),
                "disposition_receipt_set_sha256": disposition_receipt_set_sha256,
                "resource_metric_slot_count": len(rows),
                "not_available_resource_metric_slot_count": len(dispositions) - len(rows),
                "metrics": {
                    "peak_memory_bytes": peak_memory,
                    "peak_cpu_time_seconds": max(
                        metrics["cpu_time_seconds"] for _, metrics, _ in rows
                    ),
                    "peak_wall_time_seconds": max(
                        metrics["wall_time_seconds"] for _, metrics, _ in rows
                    ),
                    "peak_scratch_bytes": max(
                        metrics["peak_scratch_bytes"] for _, metrics, _ in rows
                    ),
                    "peak_process_count": max(
                        metrics["peak_process_count"] for _, metrics, _ in rows
                    ),
                    "peak_eda_concurrency": max(
                        metrics["peak_eda_concurrency"] for _, metrics, _ in rows
                    ),
                    "peak_llm_concurrency": max(
                        metrics["peak_llm_concurrency"] for _, metrics, _ in rows
                    ),
                    "total_activity_count": sum(
                        metrics["activity_count"] for _, metrics, _ in rows
                    ),
                    "provider_call_limit": provider_call_limit,
                    "total_provider_call_count": sum(
                        metrics["provider_call_count"] for _, metrics, _ in rows
                    ),
                    "total_provider_budget_rejection_count": sum(
                        metrics["provider_budget_rejection_count"]
                        for _, metrics, _ in rows
                    ),
                    "provider_budget_exhausted_sample_count": sum(
                        metrics["provider_budget_exhausted"]
                        for _, metrics, _ in rows
                    ),
                    "zero_activity_sample_count": sum(
                        metrics["activity_count"] == 0 for _, metrics, _ in rows
                    ),
                    "peak_memory_task_ids": peak_memory_tasks,
                },
                "measurement_coverage_complete": True,
                "resource_calibration_complete": False,
                "independent_review_complete": False,
                "official_attempts_permitted": False,
                "blockers": [
                    "host_capacity_policy_not_frozen",
                    "independent_resource_review_pending",
                    "resource_calibration_release_not_frozen",
                ],
            }
        )

    result = {
        "schema_version": "rtlflowbench.full_workflow_resource_calibration_summary.v2",
        "observed_at": observed_at,
        "status": "full_workflow_measurement_coverage_complete_pending_policy_and_review",
        "scope": "five_workflows_all_twelve_tasks_resource_calibration_only",
        "measurement_set_id": measurement_set["measurement_set_id"],
        "input_sha256": {
            **input_sha256,
            "measurement_set_schema": _sha(SET_SCHEMA),
            "launch_receipt_schema": _sha(LAUNCH_SAMPLE_SCHEMA),
            "nonlaunch_receipt_schema": _sha(NONLAUNCH_SAMPLE_SCHEMA),
            "summary_schema": _sha(SUMMARY_SCHEMA),
            "aggregator": _sha(Path(__file__).resolve()),
        },
        "workflows": workflows,
        "summary": {
            "workflow_count": 5,
            "task_count": 12,
            "planned_slot_count": 200,
            "launched_sample_count": 98,
            "eligible_launched_sample_count": 98,
            "controller_nonlaunch_count": 102,
            "complete_disposition_count": 200,
            "workflow_measurement_coverage_complete_count": 5,
            "resource_calibration_complete_count": 0,
            "independent_review_complete_count": 0,
            "official_attempts_permitted_count": 0,
        },
        "attempt_accounting": measurement_set["attempt_accounting"],
        "readiness": {
            "all_five_measurement_cohorts_complete": True,
            "host_capacity_policy_derivation_permitted": True,
            "host_capacity_policy_frozen": False,
            "independent_review_complete": False,
            "resource_calibration_release_frozen": False,
            "official_attempts_permitted": False,
        },
        "blockers": [
            "host_capacity_thresholds_and_sampling_policy_not_frozen",
            "independent_resource_calibration_review_pending",
            "resource_calibration_release_not_frozen",
        ],
        "excluded_claims": [
            "Complete resource-measurement coverage is not a frozen host-capacity policy or workflow release.",
            "The resource-only cohort is disjoint from official attempts and produces no benchmark result or score.",
            "Peak resource metrics do not establish RTL correctness, QoR, PPA, PASS, FAIL, BLOCK, or INFRA outcomes.",
            "No private evaluator or hidden oracle is called or projected into the resource calibration summary.",
            "Controller nonlaunch slots preserve resource metrics as null and do not consume resource calibration attempts.",
            "Independent review and a separately frozen policy remain required before official attempts are permitted.",
        ],
    }
    _validated(SUMMARY_SCHEMA, result, "resource calibration summary")
    rendered = json.dumps(result, sort_keys=True)
    if "/home/" in rendered or "/Users/" in rendered:
        raise ValueError("resource calibration summary exposes a private host path")
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--measurement-set", type=Path, required=True)
    parser.add_argument("--expected-measurement-set-sha256", required=True)
    parser.add_argument("--measurement-root", type=Path, required=True)
    parser.add_argument("--workflow-release-candidate", type=Path, required=True)
    parser.add_argument("--expected-workflow-release-candidate-sha256", required=True)
    parser.add_argument("--primary-cohort-plan", type=Path, required=True)
    parser.add_argument("--expected-primary-cohort-plan-sha256", required=True)
    parser.add_argument("--oci-inventory", type=Path, required=True)
    parser.add_argument("--expected-oci-inventory-sha256", required=True)
    parser.add_argument("--observed-at", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.expanduser().absolute()
    if output.exists() or output.is_symlink():
        raise FileExistsError(f"refusing to overwrite: {output}")
    try:
        result = aggregate(
            measurement_set_path=args.measurement_set,
            expected_measurement_set_sha256=args.expected_measurement_set_sha256,
            measurement_root=args.measurement_root,
            workflow_release_candidate_path=args.workflow_release_candidate,
            expected_workflow_release_candidate_sha256=args.expected_workflow_release_candidate_sha256,
            primary_cohort_plan_path=args.primary_cohort_plan,
            expected_primary_cohort_plan_sha256=args.expected_primary_cohort_plan_sha256,
            oci_inventory_path=args.oci_inventory,
            expected_oci_inventory_sha256=args.expected_oci_inventory_sha256,
            observed_at=args.observed_at,
        )
    except Exception as exc:
        print(json.dumps({"status": "error", "error_class": type(exc).__name__}))
        return 2
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
