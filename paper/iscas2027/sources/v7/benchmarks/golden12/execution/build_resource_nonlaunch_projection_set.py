#!/usr/bin/env python3
"""Bind the 102 current controller nonlaunch projections to supersession.

This builder never launches a workflow.  It proves that every historical
controller-nonlaunch cell marked for regeneration has one current,
content-bound null-metric projection, without rebinding the historical
receipt or authorizing reuse of any measured launch.
"""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[2]
SCHEMA = HERE / "resource_nonlaunch_projection_set.schema.json"
SUPERSESSION_SCHEMA = HERE / "resource_measurement_supersession_candidate.schema.json"
SUPERSESSION_BUILDER = HERE / "build_resource_measurement_supersession_candidate.py"
ENVELOPE_SCHEMA = HERE / "controller_aware_measurement_envelope.schema.json"
ENVELOPE_BUILDER = HERE / "build_controller_aware_measurement_envelope.py"
CONTROLLER_RUNNER = HERE / "run_controller_aware_resource_measurement.py"
NONLAUNCH_RECEIPT_SCHEMA = HERE / "controller_resource_nonlaunch_receipt.schema.json"
REQUEST_SET_SCHEMA = HERE / "full_workflow_resource_measurement_request_set.schema.json"
REQUEST_SET_BUILDER = HERE / "build_full_workflow_resource_measurement_requests.py"
BRIDGE_SET_SCHEMA = HERE / "full_workflow_bridge_request_set.schema.json"
BRIDGE_SET_BUILDER = HERE / "build_full_workflow_bridge_request_set.py"
WORKSPACE_SET_SCHEMA = (
    REPO_ROOT
    / "benchmarks/golden12/admission/public_trial_workspace_set_receipt.schema.json"
)
WORKSPACE_SET_BUILDER = (
    REPO_ROOT / "benchmarks/golden12/admission/build_public_trial_workspace_set.py"
)
RELEASE_SCHEMA = (
    REPO_ROOT / "benchmarks/golden12/evaluation/workflow_release_set_candidate.schema.json"
)
PUBLIC_SUITE_SERVER_SCHEMA = (
    REPO_ROOT
    / "docs/chipflow/research/golden12/"
    "protocol_public_suite_candidate_server_receipt.schema.json"
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _sha(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"expected regular non-symlink file: {path}")
    return hashlib.sha256(path.read_bytes()).hexdigest()


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


def _require(path: Path, expected: str, label: str) -> tuple[Path, str]:
    path = path.expanduser().resolve(strict=True)
    if SHA256_RE.fullmatch(expected) is None or _sha(path) != expected:
        raise ValueError(f"{label} differs from its out-of-band SHA256")
    return path, expected


def _index(rows: list[dict[str, Any]], key: str, label: str) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for row in rows:
        identity = row.get(key)
        if not isinstance(identity, str) or not identity or identity in result:
            raise ValueError(f"{label} has a missing or duplicate {key}")
        result[identity] = row
    return result


def _all_null_metrics(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and set(value)
        == {
            "wall_time_seconds",
            "cpu_time_seconds",
            "peak_memory_bytes",
            "peak_scratch_bytes",
            "peak_process_count",
            "peak_eda_concurrency",
            "peak_llm_concurrency",
            "llm_call_count",
            "eda_call_count",
        }
        and all(metric is None for metric in value.values())
    )


def build_projection_rows(
    *,
    supersession_rows: list[dict[str, Any]],
    envelope_rows: list[dict[str, Any]],
    request_rows: list[dict[str, Any]],
    bridge_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    targets = [
        row
        for row in supersession_rows
        if row.get("disposition") == "controller_nonlaunch_regeneration_required"
    ]
    current = [
        row
        for row in envelope_rows
        if row.get("controller_disposition")
        == "controller_block_preclassified_not_run"
    ]
    if len(targets) != 102 or len(current) != 102:
        raise ValueError("nonlaunch projection census is not exactly 102")
    targets_by_id = _index(targets, "sample_id", "supersession cohort")
    current_by_id = _index(current, "measurement_id", "controller envelope cohort")
    request_by_id = _index(request_rows, "measurement_id", "resource request cohort")
    bridge_by_id = _index(bridge_rows, "measurement_id", "bridge request cohort")
    if set(targets_by_id) != set(current_by_id):
        raise ValueError("supersession and current nonlaunch sample IDs differ")

    rows: list[dict[str, Any]] = []
    current_receipts: set[str] = set()
    for target in targets:
        sample_id = target["sample_id"]
        envelope = current_by_id[sample_id]
        request = request_by_id.get(sample_id)
        bridge = bridge_by_id.get(sample_id)
        if request is None or bridge is None:
            raise ValueError(f"current nonlaunch input is missing: {sample_id}")
        identity = (
            target.get("workflow_slot_id"),
            target.get("task_id"),
            target.get("calibration_run_index"),
        )
        for label, row in (
            ("envelope", envelope),
            ("request", request),
            ("bridge", bridge),
        ):
            if identity != (
                row.get("workflow_slot_id"),
                row.get("task_id"),
                row.get("calibration_run_index"),
            ):
                raise ValueError(
                    f"current nonlaunch identity drift in {label}: {sample_id}"
                )
        request_sha = request.get("request_sha256")
        current_receipt = envelope.get("nonlaunch_receipt_sha256")
        reason = target.get("reasons")
        public_tree_change_is_consistent = (
            reason == ["public_input_changed"]
            and target.get("previous_public_tree_sha256")
            != target.get("current_public_tree_sha256")
        ) or (
            reason == ["current_controller_projection_required"]
            and target.get("previous_public_tree_sha256")
            == target.get("current_public_tree_sha256")
        )
        if not (
            target.get("historical_receipt_kind") == "controller_nonlaunch"
            and target.get("historical_execution_hash_preserved") is True
            and public_tree_change_is_consistent
            and isinstance(request_sha, str)
            and SHA256_RE.fullmatch(request_sha)
            and bridge.get("resource_request_sha256") == request_sha
            and envelope.get("resource_request_sha256") == request_sha
            and bridge.get("disposition")
            == "controller_block_preclassified_not_run"
            and bridge.get("request_payload_sha256") is None
            and envelope.get("bridge_request_payload_sha256") is None
            and isinstance(current_receipt, str)
            and SHA256_RE.fullmatch(current_receipt)
            and envelope.get("resource_metric_availability")
            == "not_available_not_launched"
            and _all_null_metrics(envelope.get("metrics"))
            and envelope.get("provider_calls") == 0
            and envelope.get("eda_calls") == 0
            and envelope.get("private_evaluator_calls") == 0
            and envelope.get("resource_calibration_attempt_consumed") is False
            and envelope.get("official_semantic_attempt_consumed") is False
            and bridge.get("provider_calls") == 0
            and bridge.get("eda_calls") == 0
            and bridge.get("private_evaluator_calls") == 0
            and bridge.get("official_semantic_attempt_consumed") is False
        ):
            raise ValueError(f"current nonlaunch projection drift: {sample_id}")
        current_receipts.add(current_receipt)
        rows.append(
            {
                "sample_id": sample_id,
                "workflow_slot_id": target["workflow_slot_id"],
                "workflow_id": envelope["workflow_id"],
                "task_id": target["task_id"],
                "calibration_run_index": target["calibration_run_index"],
                "historical_nonlaunch_receipt_sha256": target[
                    "historical_receipt_sha256"
                ],
                "current_nonlaunch_receipt_sha256": current_receipt,
                "historical_execution_hash_preserved": True,
                "previous_public_tree_sha256": target[
                    "previous_public_tree_sha256"
                ],
                "current_public_tree_sha256": target["current_public_tree_sha256"],
                "current_resource_request_sha256": request_sha,
                "current_controller_disposition": (
                    "controller_block_preclassified_not_run"
                ),
                "resource_metric_availability": "not_available_not_launched",
                "metrics": dict(envelope["metrics"]),
                "provider_calls": 0,
                "eda_calls": 0,
                "private_evaluator_calls": 0,
                "resource_calibration_attempt_consumed": False,
                "official_semantic_attempt_consumed": False,
            }
        )
    if len(current_receipts) != 102:
        raise ValueError("current nonlaunch receipts are not unique per sample")
    return rows


def build_projection_set(
    *,
    supersession_path: Path,
    expected_supersession_sha256: str,
    controller_envelope_path: Path,
    expected_controller_envelope_sha256: str,
    resource_request_set_path: Path,
    expected_resource_request_set_sha256: str,
    bridge_request_set_path: Path,
    expected_bridge_request_set_sha256: str,
    public_workspace_set_path: Path,
    expected_public_workspace_set_sha256: str,
    workflow_release_candidate_path: Path,
    expected_workflow_release_candidate_sha256: str,
    public_suite_server_receipt_path: Path,
    expected_public_suite_server_receipt_sha256: str,
    observed_at: str,
) -> dict[str, Any]:
    parsed = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("observed_at must include a timezone")
    specifications = (
        (supersession_path, expected_supersession_sha256, "supersession candidate"),
        (
            controller_envelope_path,
            expected_controller_envelope_sha256,
            "controller envelope",
        ),
        (
            resource_request_set_path,
            expected_resource_request_set_sha256,
            "resource request set",
        ),
        (
            bridge_request_set_path,
            expected_bridge_request_set_sha256,
            "bridge request set",
        ),
        (
            public_workspace_set_path,
            expected_public_workspace_set_sha256,
            "public workspace set",
        ),
        (
            workflow_release_candidate_path,
            expected_workflow_release_candidate_sha256,
            "workflow release candidate",
        ),
        (
            public_suite_server_receipt_path,
            expected_public_suite_server_receipt_sha256,
            "public suite server receipt",
        ),
    )
    resolved: list[Path] = []
    for path, expected, label in specifications:
        resolved.append(_require(path, expected, label)[0])
    (
        supersession_path,
        controller_envelope_path,
        resource_request_set_path,
        bridge_request_set_path,
        public_workspace_set_path,
        workflow_release_candidate_path,
        public_suite_server_receipt_path,
    ) = resolved
    supersession = _load(supersession_path, "supersession candidate")
    envelope = _load(controller_envelope_path, "controller envelope")
    request_set = _load(resource_request_set_path, "resource request set")
    bridge_set = _load(bridge_request_set_path, "bridge request set")
    workspace_set = _load(public_workspace_set_path, "public workspace set")
    release = _load(workflow_release_candidate_path, "workflow release candidate")
    suite_receipt = _load(public_suite_server_receipt_path, "public suite receipt")
    for schema, value, label in (
        (SUPERSESSION_SCHEMA, supersession, "supersession candidate"),
        (ENVELOPE_SCHEMA, envelope, "controller envelope"),
        (REQUEST_SET_SCHEMA, request_set, "resource request set"),
        (BRIDGE_SET_SCHEMA, bridge_set, "bridge request set"),
        (WORKSPACE_SET_SCHEMA, workspace_set, "public workspace set"),
        (RELEASE_SCHEMA, release, "workflow release candidate"),
        (PUBLIC_SUITE_SERVER_SCHEMA, suite_receipt, "public suite server receipt"),
    ):
        _validate(schema, value, label)

    supersession_inputs = supersession["input_sha256"]
    request_inputs = request_set["input_sha256"]
    bridge_inputs = bridge_set["input_sha256"]
    envelope_inputs = envelope["input_sha256"]
    workspace_suite = workspace_set["public_suite"]
    if not (
        supersession["status"]
        == "technical_candidate_complete_reuse_not_authorized"
        and supersession["summary"]["controller_nonlaunch_regeneration_count"]
        == 102
        and supersession["summary"]["remeasurement_required_sample_count"] == 6
        and supersession["readiness"]["historical_execution_hashes_preserved"]
        is True
        and supersession["readiness"]["historical_receipt_reuse_authorized"]
        is False
        and supersession["readiness"]["independent_review_complete"] is False
        and supersession_inputs["current_workflow_release_candidate"]
        == expected_workflow_release_candidate_sha256
        and supersession_inputs["current_public_suite_server_receipt"]
        == expected_public_suite_server_receipt_sha256
        and workspace_suite["archive_sha256"]
        == supersession_inputs["current_public_suite_archive"]
        == suite_receipt["reproduction"]["archive_sha256"]
        and workspace_suite["server_receipt_sha256"]
        == expected_public_suite_server_receipt_sha256
        and workspace_suite["public_only"] is True
        and workspace_suite["task_count"] == 12
        and workspace_set["summary"]["workspace_count"] == 12
        and workspace_set["summary"]["private_file_count"] == 0
        and workspace_set["readiness"]["official_attempts_permitted"] is False
        and release["status"] == "automatic_inputs_assessed_release_pending"
        and release["summary"]["attempt_slot_count"] == 200
        and release["input_sha256"]["common_provider_gate"]
        == supersession_inputs["current_common_provider_gate"]
        and release["readiness"]["official_attempts_permitted"] is False
        and request_set["status"] == "requests_materialized_execution_blocked"
        and request_set["summary"]["request_count"] == 200
        and request_set["summary"]["public_workspace_count"] == 12
        and request_inputs["workflow_release_candidate"]
        == expected_workflow_release_candidate_sha256
        and request_inputs["public_workspace_set"]
        == expected_public_workspace_set_sha256
        and request_inputs["common_model_candidate"]
        == supersession_inputs["current_common_model_candidate"]
        and request_inputs["launch_policy"]
        == supersession_inputs["current_resource_launch_policy"]
        and request_set["readiness"]["resource_campaign_permitted"] is False
        and bridge_set["status"] == "bridge_inputs_materialized_execution_blocked"
        and bridge_set["summary"]["planned_run_count"] == 200
        and bridge_set["summary"]["launch_request_materialized_count"] == 98
        and bridge_set["summary"]["controller_block_preclassified_count"] == 102
        and bridge_set["summary"]["provider_call_count"] == 0
        and bridge_set["summary"]["eda_call_count"] == 0
        and bridge_set["summary"]["official_attempt_count"] == 0
        and bridge_inputs["resource_request_set"]
        == expected_resource_request_set_sha256
        and bridge_inputs["public_workspace_set"]
        == expected_public_workspace_set_sha256
        and envelope["status"]
        == "controller_envelope_bound_provider_preflight_pending"
        and envelope["decision"] == "BLOCK"
        and envelope["summary"]["planned_slot_count"] == 200
        and envelope["summary"]["launch_plan_bound_count"] == 98
        and envelope["summary"]["nonlaunch_disposition_bound_count"] == 102
        and envelope["summary"]["resource_sample_count"] == 0
        and envelope["summary"]["provider_call_count"] == 0
        and envelope["summary"]["eda_call_count"] == 0
        and envelope["summary"]["official_attempt_count"] == 0
        and envelope_inputs["resource_request_set"]
        == expected_resource_request_set_sha256
        and envelope_inputs["bridge_request_set"]
        == expected_bridge_request_set_sha256
        and envelope_inputs["builder"] == _sha(ENVELOPE_BUILDER)
        and envelope_inputs["schema"] == _sha(ENVELOPE_SCHEMA)
        and envelope_inputs["runner"] == _sha(CONTROLLER_RUNNER)
        and envelope_inputs["nonlaunch_receipt_schema"]
        == _sha(NONLAUNCH_RECEIPT_SCHEMA)
        and request_inputs["builder"] == _sha(REQUEST_SET_BUILDER)
        and bridge_inputs["builder"] == _sha(BRIDGE_SET_BUILDER)
        and workspace_set["source_sha256"]["workspace_set_builder"]
        == _sha(WORKSPACE_SET_BUILDER)
    ):
        raise ValueError("current nonlaunch projection input chain drift")

    projections = build_projection_rows(
        supersession_rows=supersession["sample_dispositions"],
        envelope_rows=envelope["requests"],
        request_rows=request_set["requests"],
        bridge_rows=bridge_set["requests"],
    )
    blockers = [
        "independent_resource_supersession_review_missing",
        "resource_remeasurement_required_samples_incomplete",
        "resource_calibration_release_receipt_missing",
    ]
    if supersession["readiness"]["current_provider_routes_5_of_5"] is False:
        blockers.append("current_common_provider_gate_not_5_of_5_pass")
    result = {
        "schema_version": "rtlflowbench.resource_nonlaunch_projection_set.v1",
        "status": (
            "current_controller_nonlaunch_projection_complete_not_resource_release"
        ),
        "observed_at": observed_at,
        "input_sha256": {
            "resource_measurement_supersession_candidate": expected_supersession_sha256,
            "current_controller_envelope": expected_controller_envelope_sha256,
            "current_resource_request_set": expected_resource_request_set_sha256,
            "current_bridge_request_set": expected_bridge_request_set_sha256,
            "current_public_workspace_set": expected_public_workspace_set_sha256,
            "current_workflow_release_candidate": (
                expected_workflow_release_candidate_sha256
            ),
            "current_public_suite_server_receipt": (
                expected_public_suite_server_receipt_sha256
            ),
        },
        "source_sha256": {
            "builder": _sha(Path(__file__).resolve()),
            "schema": _sha(SCHEMA),
            "supersession_builder": _sha(SUPERSESSION_BUILDER),
            "supersession_schema": _sha(SUPERSESSION_SCHEMA),
            "envelope_builder": _sha(ENVELOPE_BUILDER),
            "envelope_schema": _sha(ENVELOPE_SCHEMA),
            "controller_runner": _sha(CONTROLLER_RUNNER),
            "nonlaunch_receipt_schema": _sha(NONLAUNCH_RECEIPT_SCHEMA),
            "resource_request_builder": _sha(REQUEST_SET_BUILDER),
            "bridge_request_builder": _sha(BRIDGE_SET_BUILDER),
            "workspace_set_builder": _sha(WORKSPACE_SET_BUILDER),
        },
        "projections": projections,
        "summary": {
            "historical_nonlaunch_sample_count": 102,
            "supersession_nonlaunch_regeneration_required_count": 102,
            "current_controller_nonlaunch_projection_count": 102,
            "unique_current_nonlaunch_receipt_count": 102,
            "current_launch_plan_count": 98,
            "current_planned_slot_count": 200,
            "resource_metric_not_available_count": 102,
            "provider_call_count": 0,
            "eda_call_count": 0,
            "private_evaluator_call_count": 0,
            "official_attempt_count": 0,
        },
        "readiness": {
            "all_102_current_controller_projections_bound": True,
            "all_resource_metrics_not_available": True,
            "historical_execution_hashes_preserved": True,
            "historical_receipts_rebound": False,
            "independent_review_complete": False,
            "resource_calibration_release_frozen": False,
            "official_attempts_permitted": False,
        },
        "attempt_accounting": {
            "official_attempts_started": 0,
            "official_semantic_attempts_consumed": 0,
            "resource_calibration_attempts_consumed": 0,
            "provider_calls": 0,
            "eda_calls": 0,
            "private_evaluator_calls": 0,
            "benchmark_results_created": 0,
        },
        "blockers": blockers,
        "excluded_claims": [
            "A current controller nonlaunch projection is not an observed workflow capability BLOCK verdict.",
            "Null resource metrics mean not available because no workflow was launched; they are never numerical zero measurements.",
            "Historical execution and receipt hashes remain authoritative and are not rebound to the current source tree.",
            "This projection set does not authorize reuse of the ninety-two measured launch receipts pending independent review.",
            "This projection set does not complete the six required current-source remeasurements or resource release freeze.",
            "No provider, workflow, private evaluator, official attempt, benchmark result, score, QoR result, or PPA result is produced.",
        ],
    }
    _validate(SCHEMA, result, "resource nonlaunch projection set")
    rendered = json.dumps(result, sort_keys=True)
    if "/home/" in rendered or "/Users/" in rendered:
        raise ValueError("resource nonlaunch projection set exposes host paths")
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    inputs = (
        "supersession",
        "controller-envelope",
        "resource-request-set",
        "bridge-request-set",
        "public-workspace-set",
        "workflow-release-candidate",
        "public-suite-server-receipt",
    )
    for name in inputs:
        parser.add_argument(f"--{name}", type=Path, required=True)
        parser.add_argument(f"--expected-{name}-sha256", required=True)
    parser.add_argument("--observed-at", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists() or args.output.is_symlink():
        raise FileExistsError("refusing to overwrite nonlaunch projection set")
    result = build_projection_set(
        supersession_path=args.supersession,
        expected_supersession_sha256=args.expected_supersession_sha256,
        controller_envelope_path=args.controller_envelope,
        expected_controller_envelope_sha256=(
            args.expected_controller_envelope_sha256
        ),
        resource_request_set_path=args.resource_request_set,
        expected_resource_request_set_sha256=(
            args.expected_resource_request_set_sha256
        ),
        bridge_request_set_path=args.bridge_request_set,
        expected_bridge_request_set_sha256=args.expected_bridge_request_set_sha256,
        public_workspace_set_path=args.public_workspace_set,
        expected_public_workspace_set_sha256=(
            args.expected_public_workspace_set_sha256
        ),
        workflow_release_candidate_path=args.workflow_release_candidate,
        expected_workflow_release_candidate_sha256=(
            args.expected_workflow_release_candidate_sha256
        ),
        public_suite_server_receipt_path=args.public_suite_server_receipt,
        expected_public_suite_server_receipt_sha256=(
            args.expected_public_suite_server_receipt_sha256
        ),
        observed_at=args.observed_at,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(
        json.dumps(
            {
                "status": result["status"],
                "projection_count": result["summary"][
                    "current_controller_nonlaunch_projection_count"
                ],
                "official_attempts_started": result["attempt_accounting"][
                    "official_attempts_started"
                ],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
