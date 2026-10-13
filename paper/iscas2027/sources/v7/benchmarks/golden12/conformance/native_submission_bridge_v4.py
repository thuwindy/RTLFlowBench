"""Opt-in exec-gated export using schema-compatible source-manifest binding.

The canonical runtime_binding remains exactly the image identity. Successor
code identities belong in a byte-bound source manifest, never extra schema
fields silently accepted by transport-only mocks.
"""

from collections import Counter
import importlib.util
import json
from pathlib import Path
import re
import sys

from jsonschema import Draft202012Validator, FormatChecker


SCHEMAS = {
    "resource_request_path": "native_resource_request_v2.schema.json",
    "process_receipt_path": "../execution/workflow_resource_measurement_receipt.schema.json",
    "activity_ledger_path": "../execution/workflow_activity_ledger.schema.json",
    "activity_concurrency_path": "../execution/workflow_activity_concurrency_receipt.schema.json",
    "resource_summary_path": "../execution/full_workflow_resource_measurement_receipt.schema.json",
}

COMPONENTS = (
    "native_submission_bridge_v4.py",
    "native_exec_reconcile_v3.py",
    "native_exec_reconcile_v2.py",
    "native_artifact_handoff.py",
    "chipflow_submission_bridge_v2.py",
    "package_submission.py",
    "../execution/build_workflow_activity_concurrency_receipt.py",
    "../execution/merge_full_workflow_resource_measurement.py",
    *SCHEMAS.values(),
    "../schemas/task.schema.json",
    "../schemas/submission.schema.json",
)


def _module(name, filename):
    spec = importlib.util.spec_from_file_location(
        name, Path(__file__).parent / filename
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def validate_code_manifest(manifest_bytes, request, *, component_bytes):
    audit = _module("native_export_binding_audit", "native_exec_reconcile_v3.py")
    manifest = audit.base.document(manifest_bytes)
    source = request.get("source_binding")
    runtime = request.get("runtime_binding")
    if not isinstance(source, dict) or set(source) != {"commit", "manifest_sha256"}:
        raise ValueError("canonical_source_binding_required")
    if not isinstance(runtime, dict) or set(runtime) != {"image_id", "image_digest"}:
        raise ValueError("canonical_image_binding_required")
    if not all(
        isinstance(value, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", value)
        for value in runtime.values()
    ):
        raise ValueError("invalid_image_identity")
    if (
        not isinstance(source["commit"], str)
        or re.fullmatch(r"[0-9a-f]{40}", source["commit"]) is None
    ):
        raise ValueError("invalid_source_commit")
    if source["manifest_sha256"] != audit.base.digest(manifest_bytes):
        raise ValueError("successor_source_manifest_required")
    if set(manifest) != {
        "schema_version",
        "source_commit",
        "runtime_binding",
        "workflow_source_manifest_sha256",
        "components",
    }:
        raise ValueError("invalid_export_source_manifest")
    if (
        manifest["schema_version"] != "chipflow.native_export_source_manifest.v1"
        or manifest["source_commit"] != source["commit"]
        or manifest["runtime_binding"] != runtime
    ):
        raise ValueError("export_source_identity_drift")
    audit.base.sha_value(manifest["workflow_source_manifest_sha256"])
    if (
        not isinstance(manifest["components"], dict)
        or set(manifest["components"]) != set(COMPONENTS)
        or set(component_bytes) != set(COMPONENTS)
    ):
        raise ValueError("incomplete_export_code_closure")
    if any(
        manifest["components"][name] != audit.base.digest(component_bytes[name])
        for name in COMPONENTS
    ):
        raise ValueError("export_component_source_drift")
    return manifest


def collect_with_native_exec_gate(
    *,
    trace_path,
    native_observation_path,
    executable_inventory_path,
    trace_process_receipt_path,
    absence_probe_path,
    code_manifest_path,
    gate_receipt_output,
    **export_kwargs,
):
    audit = _module("native_export_exec_audit", "native_exec_reconcile_v3.py")
    safe = _module("native_export_safe_read", "native_artifact_handoff.py")

    def read(path):
        p = Path(path)
        return safe.read_regular(p.parent, p.name)

    def sha(path):
        return audit.base.digest(read(path))

    output = Path(gate_receipt_output)
    if output.exists() or output.is_symlink():
        raise FileExistsError("fresh_gate_receipt_required")
    paths = [
        trace_path,
        native_observation_path,
        executable_inventory_path,
        trace_process_receipt_path,
        absence_probe_path,
    ]
    component_paths = {name: Path(__file__).parent / name for name in COMPONENTS}
    # Snapshot BEFORE parsing or delegation; a later hash cannot authenticate an
    # earlier version of the evidence. Caller must keep these outside the tracee.
    input_paths = [
        *paths,
        code_manifest_path,
        *component_paths.values(),
        *[export_kwargs[key] for key in SCHEMAS],
        *[
            export_kwargs[key]
            for key in (
                "task_path",
                "request_path",
                "workflow_binding_path",
                "control_receipt_path",
            )
        ],
    ]
    captured = {str(p): read(p) for p in input_paths}
    watched = {p: audit.base.digest(value) for p, value in captured.items()}
    data = [captured[str(p)] for p in paths]
    reconciled = audit.reconcile(*data)
    if reconciled["status"] != "reconciled":
        raise ValueError("native_exec_reconciliation_blocked")
    process, observation = audit.base.document(data[3]), audit.base.document(data[1])
    request_path = Path(export_kwargs["resource_request_path"])
    process_path = Path(export_kwargs["process_receipt_path"])
    ledger_path = Path(export_kwargs["activity_ledger_path"])
    request, measured_process, ledger = [
        audit.base.document(captured[str(p)])
        for p in [request_path, process_path, ledger_path]
    ]
    if process.get("resource_process_receipt_sha256") != sha(
        process_path
    ) or process.get("controller_activity_ledger_sha256") != sha(ledger_path):
        raise ValueError("native_trace_resource_chain_unbound")
    for key in [
        "measurement_id",
        "workflow_slot_id",
        "workflow_id",
        "task_id",
        "attempt_id",
        "source_binding",
        "runtime_binding",
    ]:
        value = request.get(key)
        if not value or any(
            item.get(key) != value for item in [process, measured_process, ledger]
        ):
            raise ValueError("native_trace_resource_identity_drift")
    components = {name: captured[str(p)] for name, p in component_paths.items()}
    manifest = validate_code_manifest(
        captured[str(code_manifest_path)], request, component_bytes=components
    )
    for key, name in SCHEMAS.items():
        schema = audit.base.document(components[name])
        payload = audit.base.document(captured[str(export_kwargs[key])])
        Draft202012Validator.check_schema(schema)
        if not Draft202012Validator(schema, format_checker=FormatChecker()).is_valid(
            payload
        ):
            # Do not echo an invalid artifact, raw provider content or a path.
            raise ValueError("canonical_resource_schema_invalid:" + key)
    builder = _module(
        "native_export_activity_builder",
        "../execution/build_workflow_activity_concurrency_receipt.py",
    )
    merger = _module(
        "native_export_resource_merger",
        "../execution/merge_full_workflow_resource_measurement.py",
    )
    concurrency = audit.base.document(
        captured[str(export_kwargs["activity_concurrency_path"])]
    )
    summary = audit.base.document(captured[str(export_kwargs["resource_summary_path"])])
    if (
        builder.build_receipt(
            ledger_path=ledger_path, observed_at=concurrency["observed_at"]
        )
        != concurrency
    ):
        raise ValueError("canonical_activity_projection_drift")
    if (
        merger.merge_receipts(
            process_receipt_path=process_path,
            activity_receipt_path=export_kwargs["activity_concurrency_path"],
            observed_at=summary["observed_at"],
        )
        != summary
    ):
        raise ValueError("canonical_resource_projection_drift")
    if summary["status"] != "full_workflow_resource_sample_complete":
        raise ValueError("canonical_resource_sample_incomplete")
    # The exec preflight also pins the mounted workflow closure and actual image.
    if (
        process.get("image_id")
        != request["runtime_binding"]["image_id"].removeprefix("sha256:")
        or process.get("source_closure_sha256")
        != manifest["workflow_source_manifest_sha256"]
    ):
        raise ValueError("exec_environment_source_drift")
    kinds = {
        "iverilog": "eda_compile_or_lint",
        "vvp": "eda_simulation",
        "yosys": "eda_synthesis",
    }
    expected = Counter(
        (kinds[row["tool"]], row["outcome"]) for row in observation["invocations"]
    )
    measured = Counter(
        (row.get("kind"), row.get("outcome"))
        for row in ledger.get("activities", [])
        if row.get("kind") != "llm_call"
    )
    if measured != expected:
        raise ValueError("native_trace_controller_count_mismatch")
    if any(sha(Path(p)) != value for p, value in watched.items()):
        raise ValueError("native_gate_input_changed_before_export")
    bridge = _module("native_export_v2_packager", "chipflow_submission_bridge_v2.py")
    bridge.collect_chipflow_submission(**export_kwargs)
    if any(sha(Path(p)) != value for p, value in watched.items()):
        raise ValueError("native_gate_input_changed_during_export_outputs_unqualified")
    receipt = {
        "schema_version": "rtlflowbench.native_exec_gated_export.v4",
        "status": "neutral_submission_exported",
        "benchmark_verdict": None,
        "gate_sha256": sha(Path(__file__)),
        "source_manifest_sha256": sha(code_manifest_path),
        "reconciliation": reconciled,
        "v2_export_receipt_sha256": sha(export_kwargs["receipt_output"]),
        "submission_sha256": sha(export_kwargs["submission_output"]),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x") as stream:
        json.dump(receipt, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write("\n")
    return receipt
