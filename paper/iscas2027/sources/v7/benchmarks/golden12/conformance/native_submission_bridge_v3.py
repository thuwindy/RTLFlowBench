"""Opt-in native exec gate ahead of the unchanged v2 neutral packager.

This successor requires its own runtime binding. A reconciled trace is only
one prerequisite: v2 still validates the complete resource and public contract
chain. No task, model result or missing measurement is synthesized here.
"""

from collections import Counter
import importlib.util
import json
from pathlib import Path
import sys


def _module(name, filename):
    spec = importlib.util.spec_from_file_location(
        name, Path(__file__).with_name(filename)
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def collect_with_native_exec_gate(
    *,
    trace_path,
    native_observation_path,
    executable_inventory_path,
    trace_process_receipt_path,
    gate_receipt_output,
    **export_kwargs,
):
    audit = _module("native_exec_gate_audit", "native_exec_reconcile_v2.py")
    handoff = _module("native_exec_gate_safe_read", "native_artifact_handoff.py")

    def read(path):
        p = Path(path)
        return handoff.read_regular(p.parent, p.name)

    def sha(path):
        return audit.digest(read(path))

    output = Path(gate_receipt_output)
    if output.exists() or output.is_symlink():
        raise FileExistsError("fresh_gate_receipt_required")
    data = [
        read(p)
        for p in [
            trace_path,
            native_observation_path,
            executable_inventory_path,
            trace_process_receipt_path,
        ]
    ]
    result = audit.reconcile(*data)
    if result["status"] != "reconciled":
        raise ValueError("native_exec_reconciliation_blocked")
    process = audit.document(data[3])
    observation = audit.document(data[1])
    resource_process_path = Path(export_kwargs["process_receipt_path"])
    ledger_path = Path(export_kwargs["activity_ledger_path"])
    request_path = Path(export_kwargs["resource_request_path"])
    resource_process = audit.document(read(resource_process_path))
    ledger = audit.document(read(ledger_path))
    request = audit.document(read(request_path))
    if process.get("resource_process_receipt_sha256") != sha(
        resource_process_path
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
            item.get(key) != value for item in [process, resource_process, ledger]
        ):
            raise ValueError("native_trace_resource_identity_drift")
    binding = request["runtime_binding"]
    if binding.get("native_exec_gate_sha256") != sha(Path(__file__)) or binding.get(
        "native_exec_auditor_sha256"
    ) != sha(Path(audit.__file__)):
        raise ValueError("successor_runtime_identity_required")
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
    # The v2 bridge performs its complete existing identity, budget, output and
    # accounting validations. It remains unchanged for historical consumers.
    bridge = _module("native_exec_gate_exporter", "chipflow_submission_bridge_v2.py")
    watched = {
        str(p): sha(p)
        for p in [
            trace_path,
            native_observation_path,
            executable_inventory_path,
            trace_process_receipt_path,
            resource_process_path,
            ledger_path,
            request_path,
        ]
    }
    bridge.collect_chipflow_submission(**export_kwargs)
    if any(sha(Path(p)) != value for p, value in watched.items()):
        raise ValueError("native_gate_input_changed_during_export_outputs_unqualified")
    receipt = {
        "schema_version": "rtlflowbench.native_exec_gated_export.v3",
        "status": "neutral_submission_exported",
        "benchmark_verdict": None,
        "gate_sha256": sha(Path(__file__)),
        "reconciliation": result,
        "v2_export_receipt_sha256": sha(export_kwargs["receipt_output"]),
        "submission_sha256": sha(export_kwargs["submission_output"]),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x") as stream:
        json.dump(receipt, stream, indent=2, sort_keys=True)
        stream.write("\n")
    return receipt
