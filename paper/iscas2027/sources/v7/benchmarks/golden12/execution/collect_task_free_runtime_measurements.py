#!/usr/bin/env python3
"""Aggregate five validated task-free OCI measurements without promoting readiness."""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


HERE = Path(__file__).resolve().parent
REQUEST_SCHEMA = HERE / "workflow_resource_measurement_request.schema.json"
RECEIPT_SCHEMA = HERE / "workflow_resource_measurement_receipt.schema.json"
SET_SCHEMA = HERE / "task_free_runtime_measurement_request_set.schema.json"
SUMMARY_SCHEMA = HERE / "task_free_runtime_measurement_summary.schema.json"
RUNNER = HERE / "run_workflow_resource_measurement.py"
MARKER = b"TASK_FREE_OCI_PROBE_OK"
SLOTS = (
    ("chipflow", "chipflow"),
    ("same_model_vanilla_agent", "same_model_vanilla_agent"),
    ("external_airtl_1", "mage"),
    ("external_airtl_2", "verilogcoder"),
    ("external_airtl_3", "hdlagent"),
)


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


def collect_summary(
    *, request_set_path: Path, run_root: Path, observed_at: str
) -> dict[str, Any]:
    parsed = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("observed_at must include a timezone")
    request_set_path = request_set_path.expanduser()
    if request_set_path.is_symlink():
        raise ValueError("request set must not be a symlink")
    request_set_path = request_set_path.resolve(strict=True)
    request_root = request_set_path.parent
    run_root = run_root.expanduser()
    if run_root.is_symlink():
        raise ValueError("run root must not be a symlink")
    run_root = run_root.resolve(strict=True)
    request_schema = _load(REQUEST_SCHEMA, "measurement request schema")
    receipt_schema = _load(RECEIPT_SCHEMA, "measurement receipt schema")
    set_schema = _load(SET_SCHEMA, "measurement request set schema")
    summary_schema = _load(SUMMARY_SCHEMA, "measurement summary schema")
    for schema in (request_schema, receipt_schema, set_schema, summary_schema):
        Draft202012Validator.check_schema(schema)
    request_set = _load(request_set_path, "measurement request set")
    Draft202012Validator(set_schema, format_checker=FormatChecker()).validate(
        request_set
    )
    if request_set["summary"]["container_start_count"] != 0:
        raise ValueError("request set claims a container start")

    runner_sha = _sha(RUNNER)
    request_schema_sha = _sha(REQUEST_SCHEMA)
    receipt_schema_sha = _sha(RECEIPT_SCHEMA)
    rows = []
    for expected_pair, set_row in zip(SLOTS, request_set["requests"], strict=True):
        slot, workflow_id = expected_pair
        if (set_row["workflow_slot_id"], set_row["workflow_id"]) != expected_pair:
            raise ValueError("request-set workflow order or identity drift")
        request_path = request_root / set_row["request_path"]
        if request_path.parent.resolve(strict=True) != request_root:
            raise ValueError("request path escapes the request-set directory")
        if _sha(request_path) != set_row["request_sha256"]:
            raise ValueError(f"request SHA256 drift: {slot}")
        request = _load(request_path, f"request {slot}")
        Draft202012Validator(request_schema).validate(request)
        artifacts = run_root / slot / "artifacts"
        receipt_path = artifacts / "resource-measurement-receipt.json"
        invocation_path = artifacts / "invocation.json"
        stdout_path = artifacts / "stdout.log"
        stderr_path = artifacts / "stderr.log"
        receipt = _load(receipt_path, f"receipt {slot}")
        Draft202012Validator(
            receipt_schema, format_checker=FormatChecker()
        ).validate(receipt)
        if not (
            receipt["workflow_slot_id"] == slot
            and receipt["workflow_id"] == workflow_id
            and receipt["measurement_id"] == request["measurement_id"]
            and receipt["measurement_scope"] == "task_free_runtime_baseline"
            and receipt["task_id"] is None
            and receipt["attempt_id"] is None
            and receipt["request_sha256"] == set_row["request_sha256"]
            and receipt["runner_sha256"] == runner_sha
            and receipt["request_schema_sha256"] == request_schema_sha
            and receipt["receipt_schema_sha256"] == receipt_schema_sha
            and receipt["source_binding"] == request_set["source_binding"]
            and receipt["runtime_binding"]["image_digest"]
            == set_row["runtime_image_digest"]
            and receipt["runtime_binding"]["image_id"] == set_row["runtime_image_id"]
        ):
            raise ValueError(f"measurement receipt binding drift: {slot}")
        if not (
            receipt["raw_evidence"]["invocation_sha256"] == _sha(invocation_path)
            and receipt["raw_evidence"]["stdout_sha256"] == _sha(stdout_path)
            and receipt["raw_evidence"]["stderr_sha256"] == _sha(stderr_path)
            and stdout_path.read_bytes() == MARKER
            and stderr_path.read_bytes() == b""
        ):
            raise ValueError(f"raw measurement evidence mismatch: {slot}")
        metrics = receipt["metrics"]
        readiness = receipt["readiness"]
        accounting = receipt["attempt_accounting"]
        if not (
            receipt["status"] == "measurement_completed"
            and receipt["launcher"]["outcome"] == "exited_zero"
            and readiness["launcher_completed_successfully"] is True
            and readiness["process_tree_measurement_complete"] is True
            and readiness["container_cgroup_measurement_complete"] is True
            and readiness["full_workflow_resource_calibration_eligible"] is False
            and readiness["official_attempts_permitted"] is False
            and metrics["container_cgroup_sample_count"] > 0
            and metrics["peak_container_cgroup_memory_bytes"] > 0
            and metrics["peak_container_cgroup_pids"] > 0
            and metrics["peak_scratch_bytes"] == 2 * 1024 * 1024
            and metrics["peak_eda_concurrency"] is None
            and metrics["peak_llm_concurrency"] is None
            and accounting
            == {
                "official_attempt_started": False,
                "official_semantic_attempt_consumed": False,
                "resource_calibration_attempt_consumed": False,
                "benchmark_result_created": False,
                "private_evaluator_calls": 0,
            }
        ):
            raise ValueError(f"task-free measurement is incomplete: {slot}")
        rows.append(
            {
                "workflow_slot_id": slot,
                "workflow_id": workflow_id,
                "request_sha256": set_row["request_sha256"],
                "receipt_sha256": _sha(receipt_path),
                "runtime_image_digest": set_row["runtime_image_digest"],
                "runtime_image_id": set_row["runtime_image_id"],
                "metrics": {
                    "wall_time_seconds": metrics["wall_time_seconds"],
                    "peak_container_cgroup_memory_bytes": metrics[
                        "peak_container_cgroup_memory_bytes"
                    ],
                    "container_cgroup_cpu_time_seconds": metrics[
                        "container_cgroup_cpu_time_seconds"
                    ],
                    "peak_container_cgroup_pids": metrics[
                        "peak_container_cgroup_pids"
                    ],
                    "peak_scratch_bytes": metrics["peak_scratch_bytes"],
                    "peak_eda_concurrency": None,
                    "peak_llm_concurrency": None,
                },
                "task_free_measurement_complete": True,
                "full_workflow_resource_calibration_complete": False,
                "official_attempts_permitted": False,
            }
        )
    result = {
        "schema_version": "rtlflowbench.task_free_runtime_measurement_summary.v1",
        "observed_at": observed_at,
        "status": "five_task_free_runtime_baselines_complete_not_resource_calibration",
        "scope": "uniform_offline_task_free_oci_probe_without_task_or_provider",
        "source_binding": request_set["source_binding"],
        "request_set_sha256": _sha(request_set_path),
        "inputs_sha256": {
            "runner": runner_sha,
            "request_schema": request_schema_sha,
            "receipt_schema": receipt_schema_sha,
            "request_set_schema": _sha(SET_SCHEMA),
        },
        "workflows": rows,
        "summary": {
            "workflow_count": 5,
            "task_free_measurement_complete_count": 5,
            "container_cgroup_measurement_complete_count": 5,
            "raw_marker_match_count": 5,
            "stderr_empty_count": 5,
            "full_workflow_resource_calibration_complete_count": 0,
        },
        "attempt_accounting": {
            "official_attempts_started": 0,
            "official_semantic_attempts_consumed": 0,
            "resource_calibration_attempts_consumed": 0,
            "benchmark_results_created": 0,
            "private_evaluator_calls": 0,
        },
        "readiness": {
            "all_five_task_free_runtime_baselines_complete": True,
            "full_workflow_resource_calibration_complete": False,
            "host_capacity_policy_derivation_permitted": False,
            "official_attempts_permitted": False,
        },
        "excluded_claims": [
            "Task-free OCI launch measurements are not full-workflow resource calibration.",
            "No public task packet, model provider, EDA tool, private evaluator, or hidden oracle was invoked.",
            "Null EDA and LLM concurrency means not available and must not be converted to zero.",
            "These measurements do not create RTL verdicts, scores, QoR claims, or official attempts.",
        ],
    }
    Draft202012Validator(
        summary_schema, format_checker=FormatChecker()
    ).validate(result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--request-set", type=Path, required=True)
    parser.add_argument("--run-root", type=Path, required=True)
    parser.add_argument("--observed-at", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.expanduser().absolute()
    if output.exists() or output.is_symlink():
        raise FileExistsError(f"refusing to overwrite: {output}")
    result = collect_summary(
        request_set_path=args.request_set,
        run_root=args.run_root,
        observed_at=args.observed_at,
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
