#!/usr/bin/env python3
"""Project privacy-safe ChipFlow BLOCK evidence from resource checkpoints.

This is a post-run diagnostic projection.  It never invokes a workflow, a
provider, EDA, or a private evaluator, and it never creates a benchmark
verdict.  Historical execution hashes remain authoritative; the current
controller is used only after proving that its delta from the execution-time
controller adds the public BLOCK projection and no execution behavior.
"""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import re
import sqlite3
import sys
from typing import Any, Callable
from urllib.parse import quote

from jsonschema import Draft202012Validator
from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer


ROOT = Path(__file__).resolve().parents[3]
EXECUTION_ROOT = ROOT / "benchmarks/golden12/execution"
MEASUREMENT_SET_SCHEMA = (
    EXECUTION_ROOT / "full_workflow_resource_measurement_set.schema.json"
)
RESOURCE_RECEIPT_SCHEMA = (
    EXECUTION_ROOT / "full_workflow_resource_measurement_receipt.schema.json"
)
PROJECTION_SCHEMA = EXECUTION_ROOT / "chipflow_resource_block_projection.schema.json"
CURRENT_CONTROLLER = ROOT / "benchmarks/golden12/chipflow/controller.py"
CONTROL_RECEIPT_NAME = "chipflow_public_control_receipt.json"
CHECKPOINT_NAME = "checkpoints.sqlite"

SCHEMA_VERSION = "rtlflowbench.chipflow_resource_block_projection.v1"
CONTROL_SCHEMA_VERSION = "rtlflowbench.chipflow_public_control_receipt.v1"
RUNTIME_DESCRIPTOR_SCHEMA_VERSION = "rtlflowbench.runtime_source_descriptor.v1"
MEASUREMENT_SET_SCHEMA_VERSION = (
    "rtlflowbench.full_workflow_resource_measurement_set.v2"
)
RESOURCE_RECEIPT_SCHEMA_VERSION = (
    "rtlflowbench.full_workflow_resource_measurement_receipt.v1"
)
APPROVAL_POLICY = "scope_hash_bound_controller_preapproval"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SAMPLE_ID_RE = re.compile(r"^resource-chipflow-g(?:0[1-9]|1[0-2])-run-[1-5]$")

TASK_RUNS = {
    "G01-common-fifo-spec": 3,
    "G02-common-rr-arbiter-spec": 3,
    "G03-axis-fifo-backpressure": 3,
    "G04-wb2axip-split-bridge": 3,
    "G05-picorv32-missing-irq": 3,
    "G06-ibex-debug-csr-exception": 3,
    "G07-ibex-ifetch-error-timing": 3,
    "G08-common-fifo-dv": 3,
    "G09-axis-fifo-dv": 3,
    "G10-serv-area-qor": 5,
    "G11-picorv32-qor": 5,
    "G12-common-cdc-missing-contract": 3,
}
EXPECTED_SAMPLE_KEYS = frozenset(
    (task_id, run_index)
    for task_id, run_count in TASK_RUNS.items()
    for run_index in range(1, run_count + 1)
)

SOURCE_CHANGE_CLASSIFICATION = (
    "public_block_evidence_projection_only_no_execution_semantics_change"
)
CHECKPOINT_READ_MODE = "sqlite_uri_mode_ro_immutable_1"


def _regular_file(path: Path, label: str) -> Path:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a regular non-symlink file")
    return path


def _load_object(path: Path, label: str) -> dict[str, Any]:
    value = json.loads(_regular_file(path, label).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{label} must contain one JSON object")
    return value


def _sha256(path: Path) -> str:
    return hashlib.sha256(_regular_file(path, "hash input").read_bytes()).hexdigest()


def _validate(schema_path: Path, value: dict[str, Any], label: str) -> None:
    schema = _load_object(schema_path, f"{label} schema")
    Draft202012Validator.check_schema(schema)
    errors = sorted(
        Draft202012Validator(schema).iter_errors(value),
        key=lambda error: list(error.absolute_path),
    )
    if errors:
        first = errors[0]
        location = "/".join(str(part) for part in first.absolute_path)
        raise ValueError(f"{label} schema error at {location or '<root>'}")


def _validate_observed_at(value: str) -> None:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError("observed_at must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError("observed_at must include a timezone")


def _derive_execution_controller_text(current_text: str) -> str:
    """Remove only the audited post-run BLOCK projection from current source."""

    projection_start = "\n\n_PUBLIC_BLOCK_CATEGORY_MARKERS = ("
    next_function = "\n\ndef _copy_regular_tree"
    if current_text.count(projection_start) != 1:
        raise ValueError("current controller lacks one public BLOCK projection block")
    start = current_text.index(projection_start)
    if current_text.count(next_function, start) != 1:
        raise ValueError("current controller projection boundary is ambiguous")
    end = current_text.index(next_function, start)
    without_helper = current_text[:start] + current_text[end:]

    receipt_projection = (
        '        "block_evidence": (\n'
        "            _public_block_evidence(state) if workflow_status == \"blocked\" else None\n"
        "        ),\n"
    )
    if without_helper.count(receipt_projection) != 1:
        raise ValueError("current controller receipt projection boundary is ambiguous")
    return without_helper.replace(receipt_projection, "", 1)


def _verify_projection_only_source_delta(
    *, execution_controller_path: Path, current_controller_path: Path
) -> tuple[str, str]:
    execution_text = _regular_file(
        execution_controller_path, "execution controller"
    ).read_text(encoding="utf-8")
    current_text = _regular_file(
        current_controller_path, "current controller"
    ).read_text(encoding="utf-8")
    if _derive_execution_controller_text(current_text) != execution_text:
        raise ValueError(
            "execution-to-current controller change is not the audited projection-only source delta"
        )
    return _sha256(execution_controller_path), _sha256(current_controller_path)


def _load_public_block_projector(
    current_controller_path: Path,
) -> Callable[[dict[str, Any]], dict[str, Any]]:
    spec = importlib.util.spec_from_file_location(
        "rtlflowbench_current_chipflow_controller_projection",
        _regular_file(current_controller_path, "current controller"),
    )
    if spec is None or spec.loader is None:
        raise ValueError("unable to load current controller projection")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    projector = getattr(module, "_public_block_evidence", None)
    if not callable(projector):
        raise ValueError("current controller lacks the public BLOCK projector")
    return projector


def _portable_child(root: Path, relative: str, label: str) -> Path:
    pure = PurePosixPath(relative)
    if pure.is_absolute() or ".." in pure.parts:
        raise ValueError(f"{label} must be a portable relative path")
    resolved_root = root.resolve(strict=True)
    candidate = (resolved_root / Path(*pure.parts)).resolve(strict=True)
    if not candidate.is_relative_to(resolved_root):
        raise ValueError(f"{label} escapes the measurement-set root")
    return _regular_file(candidate, label)


def _sample_id(task_id: str, run_index: int) -> str:
    return f"resource-chipflow-{task_id[:3].lower()}-run-{run_index}"


def _validate_measurement_set(
    *, measurement_set_path: Path, expected_sha256: str
) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    if not SHA256_RE.fullmatch(expected_sha256):
        raise ValueError("expected measurement-set SHA256 is malformed")
    if _sha256(measurement_set_path) != expected_sha256:
        raise ValueError("measurement-set SHA256 mismatch")
    measurement_set = _load_object(measurement_set_path, "measurement set")
    _validate(MEASUREMENT_SET_SCHEMA, measurement_set, "measurement set")
    if measurement_set.get("schema_version") != MEASUREMENT_SET_SCHEMA_VERSION:
        raise ValueError("unsupported measurement-set schema version")

    samples = measurement_set.get("samples")
    if not isinstance(samples, list):
        raise ValueError("measurement set samples must be a list")
    if sum(row.get("receipt_kind") == "measured_launch" for row in samples) != 98:
        raise ValueError("measurement-set measured-launch accounting mismatch")
    if sum(row.get("receipt_kind") == "controller_nonlaunch" for row in samples) != 102:
        raise ValueError("measurement-set nonlaunch accounting mismatch")

    chipflow_rows = [row for row in samples if row.get("workflow_id") == "chipflow"]
    if len(chipflow_rows) != 40:
        raise ValueError("measurement set must contain exactly 40 ChipFlow samples")
    by_sample: dict[str, dict[str, Any]] = {}
    keys: set[tuple[str, int]] = set()
    for row in chipflow_rows:
        if row.get("workflow_slot_id") != "chipflow":
            raise ValueError("ChipFlow sample is assigned to the wrong workflow slot")
        if row.get("receipt_kind") != "measured_launch":
            raise ValueError("all ChipFlow resource samples must be measured launches")
        task_id = row.get("task_id")
        run_index = row.get("calibration_run_index")
        key = (task_id, run_index)
        if key not in EXPECTED_SAMPLE_KEYS or key in keys:
            raise ValueError("ChipFlow task/run coverage is missing, duplicated, or unexpected")
        expected_sample_id = _sample_id(task_id, run_index)
        if row.get("sample_id") != expected_sample_id:
            raise ValueError("ChipFlow sample_id does not match task/run identity")
        if row.get("measurement_id") != expected_sample_id:
            raise ValueError("ChipFlow measurement_id does not match task/run identity")
        if row.get("attempt_id") != f"resource-calibration-chipflow-{task_id[:3].lower()}-run-{run_index}":
            raise ValueError("ChipFlow attempt_id does not match task/run identity")
        keys.add(key)
        by_sample[expected_sample_id] = row
    if keys != EXPECTED_SAMPLE_KEYS:
        raise ValueError("ChipFlow measurement coverage is not the frozen 40-sample schedule")
    return measurement_set, by_sample


def _discover_checkpoint_bindings(
    *,
    checkpoint_roots: list[Path],
    explicit_checkpoint_bindings: dict[str, Path],
) -> dict[str, Path]:
    bindings: dict[str, Path] = {}

    def add(sample_id: str, attempt_dir: Path) -> None:
        if not SAMPLE_ID_RE.fullmatch(sample_id):
            raise ValueError(f"invalid ChipFlow checkpoint sample_id: {sample_id}")
        if sample_id in bindings:
            raise ValueError(f"duplicate checkpoint binding for {sample_id}")
        if attempt_dir.is_symlink() or not attempt_dir.is_dir():
            raise ValueError(f"checkpoint binding for {sample_id} is not a regular directory")
        bindings[sample_id] = attempt_dir

    for root in checkpoint_roots:
        if root.is_symlink() or not root.is_dir():
            raise ValueError("checkpoint root must be a regular non-symlink directory")
        for control_path in sorted(root.rglob(CONTROL_RECEIPT_NAME)):
            control = _load_object(control_path, "ChipFlow control receipt")
            task_id = control.get("task_id")
            if task_id not in TASK_RUNS:
                raise ValueError("checkpoint root contains an unexpected ChipFlow task")
            run_parts = [part for part in control_path.parts if re.fullmatch(r"run-[1-5]", part)]
            if len(run_parts) != 1:
                raise ValueError("checkpoint root cannot infer exactly one run index")
            run_index = int(run_parts[0].split("-", 1)[1])
            if run_index > TASK_RUNS[task_id]:
                raise ValueError("checkpoint root contains an out-of-schedule run index")
            if task_id not in control_path.parts:
                raise ValueError("checkpoint path task does not match its control receipt")
            add(_sample_id(task_id, run_index), control_path.parent)

    for sample_id, attempt_dir in sorted(explicit_checkpoint_bindings.items()):
        add(sample_id, attempt_dir)
    return bindings


def _read_latest_checkpoint(path: Path) -> tuple[dict[str, Any], dict[str, int]]:
    before_sha256 = _sha256(path)
    resolved = path.resolve(strict=True)
    uri = f"file:{quote(str(resolved), safe='/')}?mode=ro&immutable=1"
    try:
        with sqlite3.connect(uri, uri=True) as connection:
            rows = connection.execute(
                """
                SELECT thread_id, checkpoint_ns, checkpoint_id, type, checkpoint
                FROM checkpoints
                ORDER BY checkpoint_id DESC
                """
            ).fetchall()
    except sqlite3.Error as exc:
        raise ValueError("unable to read immutable ChipFlow checkpoint") from exc
    after_sha256 = _sha256(path)
    if before_sha256 != after_sha256:
        raise ValueError("checkpoint changed during immutable projection read")
    if not rows:
        raise ValueError("checkpoint database contains no checkpoints")
    if len({row[0] for row in rows}) != 1:
        raise ValueError("checkpoint database contains multiple thread IDs")
    if len({row[1] for row in rows}) != 1:
        raise ValueError("checkpoint database contains multiple namespaces")
    checkpoint_type, checkpoint_blob = rows[0][3], rows[0][4]
    if not isinstance(checkpoint_type, str) or not isinstance(checkpoint_blob, bytes):
        raise ValueError("latest checkpoint payload is malformed")
    try:
        checkpoint = JsonPlusSerializer().loads_typed(
            (checkpoint_type, checkpoint_blob)
        )
    except Exception as exc:  # serializer exceptions are implementation-specific
        raise ValueError("unable to decode latest ChipFlow checkpoint") from exc
    if not isinstance(checkpoint, dict):
        raise ValueError("latest checkpoint must decode to one object")
    state = checkpoint.get("channel_values")
    if not isinstance(state, dict):
        raise ValueError("latest checkpoint lacks channel_values state")
    return state, {
        "row_count": len(rows),
        "thread_count": 1,
        "namespace_count": 1,
    }


def _validate_control_receipt(
    *, control: dict[str, Any], task_id: str, checkpoint_sha256: str
) -> None:
    exact = {
        "schema_version": CONTROL_SCHEMA_VERSION,
        "workflow_id": "chipflow",
        "task_id": task_id,
        "status": "workflow_capability_block",
        "reason_code": "native_workflow_blocked",
        "native_stage": "BLOCKED",
        "native_status": "blocked",
        "approval_policy": APPROVAL_POLICY,
        "human_intervention_count": 0,
        "machine_preapproval_count": 1,
        "submission_observed": False,
        "private_evaluator_run": False,
        "benchmark_verdict_produced": False,
        "official_attempt": False,
    }
    for key, expected in exact.items():
        if control.get(key) != expected:
            raise ValueError(f"control receipt {key} does not match BLOCK projection contract")
    if control.get("checkpoint_sha256") != checkpoint_sha256:
        raise ValueError("control receipt checkpoint SHA mismatch")
    machine_preapprovals = control.get("machine_preapprovals")
    if not isinstance(machine_preapprovals, list) or len(machine_preapprovals) != 1:
        raise ValueError("control receipt machine-preapproval evidence is incomplete")
    if control.get("block_evidence") is not None:
        raise ValueError("historical control receipt unexpectedly contains post-run block evidence")
    if not isinstance(control.get("artifact_count"), int) or control["artifact_count"] < 0:
        raise ValueError("control receipt artifact_count is malformed")


def _validate_resource_receipt(
    *,
    receipt: dict[str, Any],
    sample_row: dict[str, Any],
    runtime_descriptor: dict[str, Any],
) -> None:
    _validate(RESOURCE_RECEIPT_SCHEMA, receipt, "resource receipt")
    expected = {
        "schema_version": RESOURCE_RECEIPT_SCHEMA_VERSION,
        "status": "full_workflow_resource_sample_complete",
        "measurement_id": sample_row["measurement_id"],
        "workflow_slot_id": "chipflow",
        "workflow_id": "chipflow",
        "task_id": sample_row["task_id"],
        "attempt_id": sample_row["attempt_id"],
    }
    for key, value in expected.items():
        if receipt.get(key) != value:
            raise ValueError(f"resource receipt {key} does not match measurement index")
    if receipt.get("source_binding") != {
        "commit": runtime_descriptor.get("source_commit"),
        "manifest_sha256": runtime_descriptor.get(
            "runtime_component_manifest_sha256"
        ),
    }:
        raise ValueError("resource receipt source binding differs from runtime descriptor")
    launcher = receipt.get("launcher") or {}
    if any(
        launcher.get(key) != value
        for key, value in {
            "outcome": "exited_nonzero",
            "exit_code": 5,
            "timed_out": False,
        }.items()
    ) or launcher.get("controller_guard_terminated", False) is not False or (
        "controller_guard_reason" in launcher
        and launcher["controller_guard_reason"] is not None
    ):
        raise ValueError("ChipFlow resource launcher disposition is not the frozen exit-5 BLOCK")
    if receipt.get("attempt_accounting") != {
        "official_attempt_started": False,
        "official_semantic_attempt_consumed": False,
        "resource_calibration_attempt_consumed": True,
        "benchmark_result_created": False,
        "private_evaluator_calls": 0,
    }:
        raise ValueError("resource receipt attempt accounting is not projection-eligible")
    readiness = receipt.get("readiness") or {}
    if readiness.get("official_attempts_permitted") is not False:
        raise ValueError("resource receipt incorrectly permits official attempts")


def _binding_sha256(
    *, sample_id: str, resource_sha256: str, control_sha256: str, checkpoint_sha256: str
) -> str:
    value = {
        "sample_id": sample_id,
        "resource_receipt_sha256": resource_sha256,
        "control_receipt_sha256": control_sha256,
        "checkpoint_sha256": checkpoint_sha256,
    }
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def build_projection(
    *,
    measurement_set_path: Path,
    expected_measurement_set_sha256: str,
    runtime_source_descriptor_path: Path,
    execution_controller_path: Path,
    checkpoint_roots: list[Path],
    explicit_checkpoint_bindings: dict[str, Path],
    output_path: Path,
    projection_id: str,
    observed_at: str,
    current_controller_path: Path = CURRENT_CONTROLLER,
) -> dict[str, Any]:
    if output_path.exists() or output_path.is_symlink():
        raise FileExistsError("refusing to overwrite an existing projection receipt")
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,127}", projection_id):
        raise ValueError("projection_id is malformed")
    _validate_observed_at(observed_at)

    measurement_set, sample_rows = _validate_measurement_set(
        measurement_set_path=measurement_set_path,
        expected_sha256=expected_measurement_set_sha256,
    )
    runtime_descriptor = _load_object(
        runtime_source_descriptor_path, "runtime source descriptor"
    )
    if runtime_descriptor.get("schema_version") != RUNTIME_DESCRIPTOR_SCHEMA_VERSION:
        raise ValueError("unsupported runtime source descriptor schema version")
    if runtime_descriptor.get("workflow_id") != "chipflow":
        raise ValueError("runtime source descriptor is not for ChipFlow")
    if runtime_descriptor.get("private_evaluator_included") is not False:
        raise ValueError("runtime source descriptor exposes a private evaluator")

    execution_controller_sha256, current_controller_sha256 = (
        _verify_projection_only_source_delta(
            execution_controller_path=execution_controller_path,
            current_controller_path=current_controller_path,
        )
    )
    if runtime_descriptor.get("controller_source_sha256") != execution_controller_sha256:
        raise ValueError("execution controller does not match runtime source descriptor")
    projector = _load_public_block_projector(current_controller_path)

    bindings = _discover_checkpoint_bindings(
        checkpoint_roots=checkpoint_roots,
        explicit_checkpoint_bindings=explicit_checkpoint_bindings,
    )
    if set(bindings) != set(sample_rows):
        missing = sorted(set(sample_rows) - set(bindings))
        extra = sorted(set(bindings) - set(sample_rows))
        raise ValueError(
            f"checkpoint bindings do not match 40-sample schedule; missing={missing}, extra={extra}"
        )

    measurement_root = measurement_set_path.parent
    samples: list[dict[str, Any]] = []
    category_counts: Counter[str] = Counter()
    task_sample_counts: Counter[str] = Counter()
    runtime_binding: dict[str, Any] | None = None
    for task_id, run_index in sorted(EXPECTED_SAMPLE_KEYS):
        sample_id = _sample_id(task_id, run_index)
        sample_row = sample_rows[sample_id]
        resource_path = _portable_child(
            measurement_root,
            sample_row["receipt_relative_path"],
            "resource receipt",
        )
        resource_sha256 = _sha256(resource_path)
        if resource_sha256 != sample_row["receipt_sha256"]:
            raise ValueError("resource receipt SHA256 differs from measurement index")
        resource = _load_object(resource_path, "resource receipt")
        _validate_resource_receipt(
            receipt=resource,
            sample_row=sample_row,
            runtime_descriptor=runtime_descriptor,
        )
        if runtime_binding is None:
            runtime_binding = resource["runtime_binding"]
        elif resource["runtime_binding"] != runtime_binding:
            raise ValueError("ChipFlow resource receipts use inconsistent runtime images")

        attempt_dir = bindings[sample_id]
        control_path = _regular_file(
            attempt_dir / CONTROL_RECEIPT_NAME, "ChipFlow control receipt"
        )
        checkpoint_path = _regular_file(
            attempt_dir / CHECKPOINT_NAME, "ChipFlow checkpoint"
        )
        control = _load_object(control_path, "ChipFlow control receipt")
        control_sha256 = _sha256(control_path)
        checkpoint_sha256 = _sha256(checkpoint_path)
        _validate_control_receipt(
            control=control,
            task_id=task_id,
            checkpoint_sha256=checkpoint_sha256,
        )
        state, checkpoint_summary = _read_latest_checkpoint(checkpoint_path)
        if state.get("current_stage") != control["native_stage"]:
            raise ValueError("checkpoint stage differs from control receipt")
        if state.get("status") != control["native_status"]:
            raise ValueError("checkpoint status differs from control receipt")
        artifacts = state.get("artifacts") or []
        if not isinstance(artifacts, list) or len(artifacts) != control["artifact_count"]:
            raise ValueError("checkpoint artifact count differs from control receipt")
        block_evidence = projector(state)
        if block_evidence.get("raw_reason_included") is not False:
            raise ValueError("public BLOCK projector attempted to include a raw reason")
        categories = block_evidence.get("categories")
        if not isinstance(categories, list) or not categories:
            raise ValueError("public BLOCK projector produced no category")
        category_counts.update(categories)
        task_sample_counts[task_id] += 1
        samples.append(
            {
                "sample_id": sample_id,
                "task_id": task_id,
                "calibration_run_index": run_index,
                "resource_receipt_sha256": resource_sha256,
                "control_receipt_sha256": control_sha256,
                "checkpoint_sha256": checkpoint_sha256,
                "binding_assertion_sha256": _binding_sha256(
                    sample_id=sample_id,
                    resource_sha256=resource_sha256,
                    control_sha256=control_sha256,
                    checkpoint_sha256=checkpoint_sha256,
                ),
                "checkpoint_read_mode": CHECKPOINT_READ_MODE,
                "checkpoint_summary": checkpoint_summary,
                "native_stage": control["native_stage"],
                "native_status": control["native_status"],
                "artifact_count": control["artifact_count"],
                "block_evidence": block_evidence,
                "submission_observed": False,
                "private_evaluator_run": False,
                "benchmark_verdict_produced": False,
                "official_attempt": False,
            }
        )

    assert runtime_binding is not None
    result = {
        "schema_version": SCHEMA_VERSION,
        "projection_id": projection_id,
        "observed_at": observed_at,
        "status": "projection_complete_not_benchmark_verdict",
        "scope": "chipflow_40_resource_calibration_checkpoint_blocks_only",
        "input_sha256": {
            "measurement_set": expected_measurement_set_sha256,
            "measurement_set_schema": _sha256(MEASUREMENT_SET_SCHEMA),
            "resource_receipt_schema": _sha256(RESOURCE_RECEIPT_SCHEMA),
            "runtime_source_descriptor": _sha256(runtime_source_descriptor_path),
            "execution_controller": execution_controller_sha256,
            "current_controller": current_controller_sha256,
            "projection_builder": _sha256(Path(__file__)),
            "projection_schema": _sha256(PROJECTION_SCHEMA),
        },
        "historical_execution_binding": {
            "source_commit": runtime_descriptor["source_commit"],
            "runtime_component_manifest_sha256": runtime_descriptor[
                "runtime_component_manifest_sha256"
            ],
            "runtime_image_digest": runtime_binding["image_digest"],
            "runtime_image_id": runtime_binding["image_id"],
            "execution_controller_source_sha256": execution_controller_sha256,
        },
        "post_run_source_changes": [
            {
                "path": "benchmarks/golden12/chipflow/controller.py",
                "execution_sha256": execution_controller_sha256,
                "current_sha256": current_controller_sha256,
                "classification": SOURCE_CHANGE_CLASSIFICATION,
                "affects_execution_semantics": False,
                "affects_result_projection": True,
            }
        ],
        "sample_count": 40,
        "task_count": 12,
        "samples": samples,
        "summary": {
            "projected_block_sample_count": 40,
            "task_sample_counts": dict(sorted(task_sample_counts.items())),
            "category_counts": dict(sorted(category_counts.items())),
            "raw_block_reason_count": 0,
            "benchmark_verdict_count": 0,
        },
        "attempt_accounting": {
            "historical_resource_calibration_samples_projected": 40,
            "projection_provider_calls": 0,
            "projection_eda_calls": 0,
            "projection_private_evaluator_calls": 0,
            "official_attempts_started": 0,
            "official_semantic_attempts_consumed": 0,
            "benchmark_results_created": 0,
        },
        "readiness": {
            "diagnostic_projection_complete": True,
            "resource_workflow_calibration_complete": False,
            "independent_review_complete": False,
            "official_attempts_permitted": False,
            "benchmark_verdict_produced": False,
        },
        "excluded_claims": [
            "This post-run checkpoint projection is not an RTL PASS, FAIL, BLOCK, or INFRA benchmark verdict.",
            "The historical resource samples remain resource calibration only and consume no official semantic attempts.",
            "No provider, EDA tool, private evaluator, or hidden oracle is invoked by this projection.",
            "Only category labels and content hashes are exported; raw block reasons, model responses, credentials, user IDs, and host paths are excluded.",
            "The execution-time controller hash remains authoritative and is not replaced by the current projection source hash.",
            "Independent review, policy freeze, and official campaign release gates remain pending.",
        ],
    }
    _validate(PROJECTION_SCHEMA, result, "ChipFlow resource BLOCK projection")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


def _parse_explicit_bindings(values: list[str]) -> dict[str, Path]:
    bindings: dict[str, Path] = {}
    for value in values:
        if "=" not in value:
            raise ValueError("checkpoint binding must be SAMPLE_ID=ATTEMPT_DIRECTORY")
        sample_id, raw_path = value.split("=", 1)
        if not sample_id or not raw_path or sample_id in bindings:
            raise ValueError("checkpoint binding is empty or duplicated")
        bindings[sample_id] = Path(raw_path)
    return bindings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--measurement-set", type=Path, required=True)
    parser.add_argument("--expected-measurement-set-sha256", required=True)
    parser.add_argument("--runtime-source-descriptor", type=Path, required=True)
    parser.add_argument("--execution-controller", type=Path, required=True)
    parser.add_argument("--checkpoint-root", type=Path, action="append", default=[])
    parser.add_argument("--checkpoint-binding", action="append", default=[])
    parser.add_argument("--projection-id", required=True)
    parser.add_argument("--observed-at", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = build_projection(
        measurement_set_path=args.measurement_set,
        expected_measurement_set_sha256=args.expected_measurement_set_sha256,
        runtime_source_descriptor_path=args.runtime_source_descriptor,
        execution_controller_path=args.execution_controller,
        checkpoint_roots=args.checkpoint_root,
        explicit_checkpoint_bindings=_parse_explicit_bindings(
            args.checkpoint_binding
        ),
        output_path=args.output,
        projection_id=args.projection_id,
        observed_at=args.observed_at,
    )
    print(
        json.dumps(
            {
                "status": result["status"],
                "sample_count": result["sample_count"],
                "task_count": result["task_count"],
                "benchmark_verdict_count": result["summary"][
                    "benchmark_verdict_count"
                ],
                "output_sha256": _sha256(args.output),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
