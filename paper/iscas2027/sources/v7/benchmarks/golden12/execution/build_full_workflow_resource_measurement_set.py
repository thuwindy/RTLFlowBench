#!/usr/bin/env python3
"""Materialize a portable 98-launch/102-nonlaunch resource evidence set."""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


HERE = Path(__file__).resolve().parent
REQUEST_SET_SCHEMA = HERE / "full_workflow_resource_measurement_request_set.schema.json"
REQUEST_SCHEMA = HERE / "full_workflow_resource_measurement_request.schema.json"
BRIDGE_SET_SCHEMA = HERE / "full_workflow_bridge_request_set.schema.json"
MEASUREMENT_SET_SCHEMA = HERE / "full_workflow_resource_measurement_set.schema.json"
LAUNCH_RECEIPT_SCHEMA = HERE / "full_workflow_resource_measurement_receipt.schema.json"
NONLAUNCH_RECEIPT_SCHEMA = HERE / "controller_resource_nonlaunch_receipt.schema.json"
PROCESS_RECEIPT_SCHEMA = HERE / "workflow_resource_measurement_receipt.schema.json"
ACTIVITY_RECEIPT_SCHEMA = HERE / "workflow_activity_concurrency_receipt.schema.json"
ACTIVITY_LEDGER_SCHEMA = HERE / "workflow_activity_ledger.schema.json"
ACTIVITY_RECEIPT_BUILDER = HERE / "build_workflow_activity_concurrency_receipt.py"
MERGER = HERE / "merge_full_workflow_resource_measurement.py"
CONTROLLER_RUNNER = HERE / "run_controller_aware_resource_measurement.py"
LAUNCH_RECEIPT_NAME = "full-workflow-resource-receipt.json"
NONLAUNCH_RECEIPT_NAME = "controller-disposition-receipt.json"
PROCESS_RECEIPT_NAME = "resource-measurement-receipt.json"
ACTIVITY_RECEIPT_NAME = "activity-concurrency-receipt.json"
ACTIVITY_LEDGER_NAME = "activity-ledger.json"
INVOCATION_NAME = "invocation.json"
SLOTS = (
    ("chipflow", "chipflow"),
    ("same_model_vanilla_agent", "same_model_vanilla_agent"),
    ("external_airtl_1", "mage"),
    ("external_airtl_2", "verilogcoder"),
    ("external_airtl_3", "hdlagent"),
)
EXPECTED_LAUNCH = {
    "chipflow": 40,
    "same_model_vanilla_agent": 40,
    "external_airtl_1": 6,
    "external_airtl_2": 6,
    "external_airtl_3": 6,
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


def _require_sha(path: Path, expected: str, label: str) -> tuple[Path, str]:
    if SHA256_RE.fullmatch(expected) is None:
        raise ValueError(f"{label} expected SHA256 is malformed")
    path = path.expanduser()
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a regular non-symlink file")
    path = path.resolve(strict=True)
    observed = _sha(path)
    if observed != expected:
        raise ValueError(f"{label} differs from its out-of-band trust anchor")
    return path, observed


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


def _relative_file(root: Path, relative: str, label: str) -> Path:
    candidate = root / relative
    if candidate.is_symlink():
        raise ValueError(f"{label} must not be a symlink")
    resolved = candidate.resolve(strict=True)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"{label} escapes its content root") from exc
    if not resolved.is_file():
        raise ValueError(f"{label} is not a regular file")
    return resolved


def _scan_receipts(
    roots: list[Path],
) -> dict[str, tuple[str, Path, dict[str, Any], str]]:
    if not roots:
        raise ValueError("at least one receipt root is required")
    launch_schema = _load(LAUNCH_RECEIPT_SCHEMA, "launch receipt schema")
    nonlaunch_schema = _load(NONLAUNCH_RECEIPT_SCHEMA, "nonlaunch receipt schema")
    validators = {
        "measured_launch": Draft202012Validator(
            launch_schema, format_checker=FormatChecker()
        ),
        "controller_nonlaunch": Draft202012Validator(
            nonlaunch_schema, format_checker=FormatChecker()
        ),
    }
    found: dict[str, tuple[str, Path, dict[str, Any], str]] = {}
    for supplied_root in roots:
        root = supplied_root.expanduser()
        if root.is_symlink() or not root.is_dir():
            raise ValueError("receipt root must be a regular non-symlink directory")
        root = root.resolve(strict=True)
        for directory, directories, files in os.walk(root, followlinks=False):
            current = Path(directory)
            for name in directories:
                if (current / name).is_symlink():
                    raise ValueError("receipt root contains a symlink directory")
            for name in files:
                if name not in {LAUNCH_RECEIPT_NAME, NONLAUNCH_RECEIPT_NAME}:
                    continue
                path = current / name
                if path.is_symlink() or not path.is_file():
                    raise ValueError("resource receipt must be a regular non-symlink file")
                kind = (
                    "measured_launch"
                    if name == LAUNCH_RECEIPT_NAME
                    else "controller_nonlaunch"
                )
                receipt = _load(path, "resource disposition receipt")
                errors = sorted(
                    validators[kind].iter_errors(receipt),
                    key=lambda error: list(error.absolute_path),
                )
                if errors:
                    raise ValueError(
                        "resource disposition receipt schema validation failed: "
                        f"{errors[0].message}"
                    )
                measurement_id = receipt["measurement_id"]
                if measurement_id in found:
                    raise ValueError(
                        f"duplicate resource disposition receipt: {measurement_id}"
                    )
                found[measurement_id] = (kind, path, receipt, _sha(path))
    return found


def _request_rows(
    *, request_set_path: Path
) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    request_set = _load(request_set_path, "resource request set")
    _validated(REQUEST_SET_SCHEMA, request_set, "resource request set")
    root = request_set_path.parent.resolve(strict=True)
    rows: dict[str, dict[str, Any]] = {}
    for index in request_set["requests"]:
        path = _relative_file(root, index["request_relative_path"], "resource request")
        if _sha(path) != index["request_sha256"]:
            raise ValueError(f"resource request digest drift: {index['measurement_id']}")
        request = _load(path, "resource request")
        _validated(REQUEST_SCHEMA, request, "resource request")
        identity = {
            key: index[key]
            for key in (
                "measurement_id",
                "workflow_slot_id",
                "workflow_id",
                "task_id",
                "calibration_run_index",
            )
        }
        if any(request[key] != value for key, value in identity.items()):
            raise ValueError(f"resource request identity drift: {index['measurement_id']}")
        measurement_id = index["measurement_id"]
        if measurement_id in rows:
            raise ValueError(f"duplicate resource request: {measurement_id}")
        rows[measurement_id] = {
            **identity,
            "attempt_id": request["attempt_id"],
            "request_sha256": index["request_sha256"],
        }
    if len(rows) != 200:
        raise ValueError("resource request set does not contain exactly 200 requests")
    return request_set, rows


def _disposition_rows(
    *,
    bridge_set: dict[str, Any],
    bridge_sha256: str,
    request_set_sha256: str,
    request_rows: dict[str, dict[str, Any]],
) -> dict[str, str]:
    if bridge_set["input_sha256"]["resource_request_set"] != request_set_sha256:
        raise ValueError("bridge set does not bind the trusted resource request set")
    bridge_rows = {row["measurement_id"]: row for row in bridge_set["requests"]}
    if len(bridge_rows) != 200 or set(bridge_rows) != set(request_rows):
        raise ValueError("bridge dispositions differ from the 200 frozen requests")
    kinds: dict[str, str] = {}
    task_kinds: dict[tuple[str, str], set[str]] = defaultdict(set)
    for measurement_id, request in request_rows.items():
        row = bridge_rows[measurement_id]
        identity_keys = (
            "workflow_slot_id",
            "workflow_id",
            "task_id",
            "calibration_run_index",
        )
        if any(row[key] != request[key] for key in identity_keys):
            raise ValueError(f"bridge request identity drift: {measurement_id}")
        if row["resource_request_sha256"] != request["request_sha256"]:
            raise ValueError(f"bridge resource request digest drift: {measurement_id}")
        if not (
            row["provider_calls"] == 0
            and row["eda_calls"] == 0
            and row["private_evaluator_calls"] == 0
            and row["official_semantic_attempt_consumed"] is False
        ):
            raise ValueError(f"bridge disposition consumed execution: {measurement_id}")
        supported = row["support_classification"]["supported"]
        disposition = row["disposition"]
        if supported is True and disposition == "launch_request_materialized_not_run":
            kind = "measured_launch"
        elif (
            supported is False
            and disposition == "controller_block_preclassified_not_run"
        ):
            kind = "controller_nonlaunch"
        else:
            raise ValueError(f"unknown bridge disposition: {measurement_id}")
        kinds[measurement_id] = kind
        task_kinds[(request["workflow_slot_id"], request["task_id"])].add(kind)
    if any(len(values) != 1 for values in task_kinds.values()):
        raise ValueError("one workflow/task cell is split across receipt kinds")
    counts = Counter(
        request_rows[mid]["workflow_slot_id"]
        for mid, kind in kinds.items()
        if kind == "measured_launch"
    )
    if counts != Counter(EXPECTED_LAUNCH):
        raise ValueError("bridge launch counts differ from the frozen 98-sample cohort")
    if Counter(kinds.values()) != Counter(
        {"measured_launch": 98, "controller_nonlaunch": 102}
    ):
        raise ValueError("bridge disposition counts are not exactly 98 launch and 102 nonlaunch")
    return kinds


def _validate_receipt(
    *,
    request: dict[str, Any],
    expected_kind: str,
    observed_kind: str,
    receipt: dict[str, Any],
    request_sha256: str,
    bridge_sha256: str,
) -> None:
    measurement_id = request["measurement_id"]
    if observed_kind != expected_kind:
        raise ValueError(f"resource disposition kind drift: {measurement_id}")
    identity = {
        key: request[key]
        for key in (
            "measurement_id",
            "workflow_slot_id",
            "workflow_id",
            "task_id",
            "attempt_id",
        )
    }
    if any(receipt[key] != value for key, value in identity.items()):
        raise ValueError(f"resource disposition identity drift: {measurement_id}")
    if expected_kind == "measured_launch":
        if not (
            receipt["status"] == "full_workflow_resource_sample_complete"
            and receipt["attempt_accounting"]
            == {
                "official_attempt_started": False,
                "official_semantic_attempt_consumed": False,
                "resource_calibration_attempt_consumed": True,
                "benchmark_result_created": False,
                "private_evaluator_calls": 0,
            }
            and receipt["readiness"]["sample_complete"] is True
            and receipt["readiness"]["sample_eligible_for_resource_cohort"] is True
            and receipt["readiness"]["workflow_calibration_complete"] is False
            and receipt["readiness"]["official_attempts_permitted"] is False
        ):
            raise ValueError(f"launch receipt is not eligible resource-only evidence: {measurement_id}")
    else:
        if not (
            receipt["status"] == "not_available_not_launched"
            and receipt["input_sha256"]["resource_request"] == request_sha256
            and receipt["input_sha256"]["bridge_request_set"] == bridge_sha256
            and receipt["input_sha256"]["schema"] == _sha(NONLAUNCH_RECEIPT_SCHEMA)
            and receipt["controller_disposition"]["workflow_process_started"] is False
            and receipt["controller_disposition"]["workflow_block_verdict_created"] is False
            and all(value is None for value in receipt["metrics"].values())
            and receipt["attempt_accounting"]
            == {
                "resource_calibration_attempt_consumed": False,
                "official_attempt_started": False,
                "official_semantic_attempt_consumed": False,
                "benchmark_result_created": False,
                "private_evaluator_calls": 0,
            }
        ):
            raise ValueError(
                f"nonlaunch receipt is not content-bound null evidence: {measurement_id}"
            )


def _structured_launch_dependencies(
    *,
    primary_path: Path,
    primary: dict[str, Any],
    request: dict[str, Any],
    bridge_sha256: str,
) -> list[tuple[Path, str, str]]:
    directory = primary_path.parent
    paths = {
        "process": directory / PROCESS_RECEIPT_NAME,
        "activity": directory / ACTIVITY_RECEIPT_NAME,
        "ledger": directory / ACTIVITY_LEDGER_NAME,
        "invocation": directory / INVOCATION_NAME,
    }
    process = _load(paths["process"], "process measurement receipt")
    activity = _load(paths["activity"], "activity concurrency receipt")
    ledger = _load(paths["ledger"], "activity ledger")
    invocation = _load(paths["invocation"], "launch invocation receipt")
    _validated(PROCESS_RECEIPT_SCHEMA, process, "process measurement receipt")
    _validated(ACTIVITY_RECEIPT_SCHEMA, activity, "activity concurrency receipt")
    _validated(ACTIVITY_LEDGER_SCHEMA, ledger, "activity ledger")

    digests = {name: _sha(path) for name, path in paths.items()}
    expected_primary_inputs = {
        "process_measurement_receipt": digests["process"],
        "activity_concurrency_receipt": digests["activity"],
        "merger": _sha(MERGER),
        "process_receipt_schema": _sha(PROCESS_RECEIPT_SCHEMA),
        "activity_receipt_schema": _sha(ACTIVITY_RECEIPT_SCHEMA),
        "merged_receipt_schema": _sha(LAUNCH_RECEIPT_SCHEMA),
    }
    if primary["input_sha256"] != expected_primary_inputs:
        raise ValueError(
            f"merged receipt dependency drift: {request['measurement_id']}"
        )
    identity = {
        key: request[key]
        for key in (
            "measurement_id",
            "workflow_slot_id",
            "workflow_id",
            "task_id",
            "attempt_id",
        )
    }
    for label, value in (
        ("process", process),
        ("activity", activity),
        ("ledger", ledger),
    ):
        if any(value[key] != expected for key, expected in identity.items()):
            raise ValueError(
                f"{label} receipt identity drift: {request['measurement_id']}"
            )
        if value["source_binding"] != primary["source_binding"]:
            raise ValueError(
                f"{label} receipt source drift: {request['measurement_id']}"
            )
        if value["runtime_binding"] != primary["runtime_binding"]:
            raise ValueError(
                f"{label} receipt runtime drift: {request['measurement_id']}"
            )
        if value["attempt_accounting"] != primary["attempt_accounting"]:
            raise ValueError(
                f"{label} receipt accounting drift: {request['measurement_id']}"
            )
    if not (
        process["request_sha256"] == request["request_sha256"]
        and process["request_schema_sha256"] == _sha(REQUEST_SCHEMA)
        and process["receipt_schema_sha256"] == _sha(PROCESS_RECEIPT_SCHEMA)
        and process["runner_id"]
        == "rtlflowbench.controller_aware_resource_measurement_envelope.v1"
        and process["runner_sha256"] == _sha(CONTROLLER_RUNNER)
        and process["raw_evidence"]["invocation_sha256"]
        == digests["invocation"]
        and process["raw_evidence"]["raw_content_embedded"] is False
    ):
        raise ValueError(
            f"process receipt request or runner drift: {request['measurement_id']}"
        )
    if not (
        activity["process_measurement_receipt_sha256"] == digests["process"]
        and activity["ledger_sha256"] == digests["ledger"]
        and activity["ledger_schema_sha256"] == _sha(ACTIVITY_LEDGER_SCHEMA)
        and activity["receipt_schema_sha256"] == _sha(ACTIVITY_RECEIPT_SCHEMA)
        and activity["builder_sha256"] == _sha(ACTIVITY_RECEIPT_BUILDER)
        and ledger["process_measurement_receipt_sha256"] == digests["process"]
    ):
        raise ValueError(
            f"activity receipt dependency drift: {request['measurement_id']}"
        )
    expected_invocation_keys = {
        "argv_values_recorded",
        "bridge_request_set_sha256",
        "common_provider_gate_sha256",
        "host_paths_recorded",
        "launch_plan_sha256",
        "measurement_id",
        "podman_sha256",
        "private_evaluator_reachable",
        "resource_campaign_authorization_sha256",
        "resource_request_sha256",
        "runner_id",
    }
    if not (
        set(invocation) == expected_invocation_keys
        and invocation["measurement_id"] == request["measurement_id"]
        and invocation["resource_request_sha256"] == request["request_sha256"]
        and invocation["bridge_request_set_sha256"] == bridge_sha256
        and invocation["runner_id"]
        == "rtlflowbench.controller_aware_resource_measurement_envelope.v1"
        and invocation["argv_values_recorded"] is False
        and invocation["host_paths_recorded"] is False
        and invocation["private_evaluator_reachable"] is False
        and all(
            SHA256_RE.fullmatch(invocation[key])
            for key in (
                "common_provider_gate_sha256",
                "launch_plan_sha256",
                "podman_sha256",
                "resource_campaign_authorization_sha256",
            )
        )
    ):
        raise ValueError(
            f"launch invocation is not content-bound public evidence: "
            f"{request['measurement_id']}"
        )
    for label, value in (
        ("process", process),
        ("activity", activity),
        ("ledger", ledger),
        ("invocation", invocation),
    ):
        rendered = json.dumps(value, sort_keys=True)
        if "/home/" in rendered or "/Users/" in rendered:
            raise ValueError(
                f"{label} structured receipt exposes a private host path"
            )
    return [
        (paths["process"], PROCESS_RECEIPT_NAME, digests["process"]),
        (paths["activity"], ACTIVITY_RECEIPT_NAME, digests["activity"]),
        (paths["ledger"], ACTIVITY_LEDGER_NAME, digests["ledger"]),
        (paths["invocation"], INVOCATION_NAME, digests["invocation"]),
    ]


def build_measurement_set(
    *,
    request_set_path: Path,
    expected_request_set_sha256: str,
    bridge_set_path: Path,
    expected_bridge_set_sha256: str,
    workflow_release_candidate_path: Path,
    expected_workflow_release_candidate_sha256: str,
    primary_cohort_plan_path: Path,
    expected_primary_cohort_plan_sha256: str,
    oci_inventory_path: Path,
    expected_oci_inventory_sha256: str,
    receipt_roots: list[Path],
    output_root: Path,
    measurement_set_id: str,
) -> dict[str, Any]:
    request_set_path, request_set_sha256 = _require_sha(
        request_set_path, expected_request_set_sha256, "resource request set"
    )
    bridge_set_path, bridge_sha256 = _require_sha(
        bridge_set_path, expected_bridge_set_sha256, "bridge request set"
    )
    release_path, release_sha256 = _require_sha(
        workflow_release_candidate_path,
        expected_workflow_release_candidate_sha256,
        "workflow release candidate",
    )
    plan_path, plan_sha256 = _require_sha(
        primary_cohort_plan_path,
        expected_primary_cohort_plan_sha256,
        "primary cohort execution plan",
    )
    inventory_path, inventory_sha256 = _require_sha(
        oci_inventory_path, expected_oci_inventory_sha256, "OCI inventory"
    )
    request_set, request_rows = _request_rows(request_set_path=request_set_path)
    expected_bindings = {
        "workflow_release_candidate": release_sha256,
        "primary_cohort_execution_plan": plan_sha256,
        "oci_inventory": inventory_sha256,
    }
    if any(
        request_set["input_sha256"].get(key) != value
        for key, value in expected_bindings.items()
    ):
        raise ValueError("resource request set input binding drift")
    bridge_set = _load(bridge_set_path, "bridge request set")
    _validated(BRIDGE_SET_SCHEMA, bridge_set, "bridge request set")
    disposition_kinds = _disposition_rows(
        bridge_set=bridge_set,
        bridge_sha256=bridge_sha256,
        request_set_sha256=request_set_sha256,
        request_rows=request_rows,
    )
    receipts = _scan_receipts(receipt_roots)
    if set(receipts) != set(request_rows):
        missing = sorted(set(request_rows) - set(receipts))
        extra = sorted(set(receipts) - set(request_rows))
        raise ValueError(
            "resource disposition receipt coverage drift: "
            f"missing={len(missing)} extra={len(extra)}"
        )

    slot_order = {slot: index for index, (slot, _) in enumerate(SLOTS)}
    ordered_requests = sorted(
        request_rows.values(),
        key=lambda row: (
            slot_order[row["workflow_slot_id"]],
            row["task_id"],
            row["calibration_run_index"],
        ),
    )
    samples: list[dict[str, Any]] = []
    copy_rows: list[tuple[Path, str, str]] = []
    for request in ordered_requests:
        measurement_id = request["measurement_id"]
        observed_kind, source_path, receipt, receipt_sha256 = receipts[measurement_id]
        expected_kind = disposition_kinds[measurement_id]
        _validate_receipt(
            request=request,
            expected_kind=expected_kind,
            observed_kind=observed_kind,
            receipt=receipt,
            request_sha256=request["request_sha256"],
            bridge_sha256=bridge_sha256,
        )
        dependencies = (
            _structured_launch_dependencies(
                primary_path=source_path,
                primary=receipt,
                request=request,
                bridge_sha256=bridge_sha256,
            )
            if expected_kind == "measured_launch"
            else []
        )
        filename = (
            LAUNCH_RECEIPT_NAME
            if expected_kind == "measured_launch"
            else NONLAUNCH_RECEIPT_NAME
        )
        relative = (
            f"receipts/{request['workflow_slot_id']}/{request['task_id']}/"
            f"run-{request['calibration_run_index']}/{filename}"
        )
        samples.append(
            {
                "sample_id": measurement_id,
                "workflow_slot_id": request["workflow_slot_id"],
                "workflow_id": request["workflow_id"],
                "task_id": request["task_id"],
                "calibration_run_index": request["calibration_run_index"],
                "measurement_id": measurement_id,
                "attempt_id": request["attempt_id"],
                "receipt_kind": expected_kind,
                "receipt_relative_path": relative,
                "receipt_sha256": receipt_sha256,
            }
        )
        copy_rows.append((source_path, relative, receipt_sha256))
        destination_parent = str(Path(relative).parent)
        copy_rows.extend(
            (source, f"{destination_parent}/{name}", digest)
            for source, name, digest in dependencies
        )

    if len(copy_rows) != 592 or len({relative for _, relative, _ in copy_rows}) != 592:
        raise ValueError("portable resource evidence tree is not exactly 592 files")

    result = {
        "schema_version": "rtlflowbench.full_workflow_resource_measurement_set.v2",
        "measurement_set_id": measurement_set_id,
        "scope": "five_workflows_all_twelve_tasks_resource_calibration_only",
        "workflow_release_candidate_sha256": release_sha256,
        "primary_cohort_execution_plan_sha256": plan_sha256,
        "oci_inventory_sha256": inventory_sha256,
        "launch_receipt_schema_sha256": _sha(LAUNCH_RECEIPT_SCHEMA),
        "nonlaunch_receipt_schema_sha256": _sha(NONLAUNCH_RECEIPT_SCHEMA),
        "sample_count": 200,
        "launch_sample_count": 98,
        "controller_nonlaunch_count": 102,
        "samples": samples,
        "attempt_accounting": {
            "official_attempts_started": 0,
            "official_semantic_attempts_consumed": 0,
            "resource_calibration_attempts_consumed": 98,
            "benchmark_results_created": 0,
            "private_evaluator_calls": 0,
        },
        "excluded_claims": [
            "This portable manifest indexes resource-only calibration dispositions and is not an official attempt schedule.",
            "The measurement set contains no RTL verdict, benchmark score, hidden oracle, or private evaluator output.",
            "Controller nonlaunch slots retain null resource metrics and consume no resource calibration attempt.",
            "Each launched sample includes four content-bound structured dependency receipts while raw stdout and stderr remain excluded.",
            "All five workflows still require a frozen host policy and independent review before official attempts.",
        ],
    }
    _validated(MEASUREMENT_SET_SCHEMA, result, "resource measurement set")
    rendered = json.dumps(result, sort_keys=True)
    if "/home/" in rendered or "/Users/" in rendered:
        raise ValueError("resource measurement set exposes a private host path")

    output_root = output_root.expanduser()
    if output_root.exists() or output_root.is_symlink():
        raise ValueError("output root already exists; refusing to overwrite evidence")
    parent = output_root.parent
    if parent.is_symlink() or not parent.is_dir():
        raise ValueError("output parent must be an existing non-symlink directory")
    parent = parent.resolve(strict=True)
    output_root = parent / output_root.name
    temporary = Path(tempfile.mkdtemp(prefix=f".{output_root.name}.tmp-", dir=parent))
    try:
        for source_path, relative, expected_sha256 in copy_rows:
            destination = temporary / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source_path, destination)
            if _sha(destination) != expected_sha256:
                raise ValueError("copied resource receipt digest drift")
        manifest_path = temporary / "measurement-set.json"
        manifest_path.write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        if _sha(manifest_path) != hashlib.sha256(manifest_path.read_bytes()).hexdigest():
            raise AssertionError("measurement set digest self-check failed")
        os.replace(temporary, output_root)
    except Exception:
        shutil.rmtree(temporary)
        raise
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--request-set", type=Path, required=True)
    parser.add_argument("--expected-request-set-sha256", required=True)
    parser.add_argument("--bridge-set", type=Path, required=True)
    parser.add_argument("--expected-bridge-set-sha256", required=True)
    parser.add_argument("--workflow-release-candidate", type=Path, required=True)
    parser.add_argument("--expected-workflow-release-candidate-sha256", required=True)
    parser.add_argument("--primary-cohort-plan", type=Path, required=True)
    parser.add_argument("--expected-primary-cohort-plan-sha256", required=True)
    parser.add_argument("--oci-inventory", type=Path, required=True)
    parser.add_argument("--expected-oci-inventory-sha256", required=True)
    parser.add_argument("--receipt-root", type=Path, action="append", required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument(
        "--measurement-set-id",
        default="golden12-five-workflow-resource-calibration-v2",
    )
    args = parser.parse_args()
    result = build_measurement_set(
        request_set_path=args.request_set,
        expected_request_set_sha256=args.expected_request_set_sha256,
        bridge_set_path=args.bridge_set,
        expected_bridge_set_sha256=args.expected_bridge_set_sha256,
        workflow_release_candidate_path=args.workflow_release_candidate,
        expected_workflow_release_candidate_sha256=args.expected_workflow_release_candidate_sha256,
        primary_cohort_plan_path=args.primary_cohort_plan,
        expected_primary_cohort_plan_sha256=args.expected_primary_cohort_plan_sha256,
        oci_inventory_path=args.oci_inventory,
        expected_oci_inventory_sha256=args.expected_oci_inventory_sha256,
        receipt_roots=args.receipt_root,
        output_root=args.output_root,
        measurement_set_id=args.measurement_set_id,
    )
    manifest_path = args.output_root / "measurement-set.json"
    print(
        json.dumps(
            {
                "status": "resource_measurement_set_materialized",
                "measurement_set_sha256": _sha(manifest_path),
                "sample_count": result["sample_count"],
                "launch_sample_count": result["launch_sample_count"],
                "controller_nonlaunch_count": result["controller_nonlaunch_count"],
                "official_attempts_started": 0,
                "private_evaluator_calls": 0,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
