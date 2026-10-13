"""Read-only native v4 handoff to public control metadata, never an RTL verdict.

Trusted host observation, canonical resources and the exec-gated neutral
exporter remain mandatory. Content consistency does not authenticate a caller.
"""

import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).parent
spec = importlib.util.spec_from_file_location(
    "native_control_handoff", HERE / "native_artifact_handoff.py"
)
handoff = importlib.util.module_from_spec(spec)
spec.loader.exec_module(handoff)


def collect_control(
    *,
    native_work_root,
    mounted_work_root,
    native_request_path,
    public_launch_request_path,
    public_task_path,
    output_dir,
):
    work = Path(native_work_root)
    output = Path(output_dir).absolute()
    if output.exists() or output.is_symlink():
        raise FileExistsError("fresh_control_output_required")
    if output.resolve().is_relative_to(work.resolve()):
        raise ValueError("external_control_output_required")
    captured = {}

    def read(path):
        path = Path(path)
        raw = handoff.read_regular(path.parent, path.name)
        captured[path] = handoff.digest(raw)
        return raw

    def doc(path):
        return handoff.decode(read(path))

    native = doc(native_request_path)
    launch = doc(public_launch_request_path)
    task = doc(public_task_path)
    session = doc(work / "session.json")
    binding = doc(work / "request-binding.json")
    state = doc(work / "native-state.json")
    contract = doc(work / "artifact-contract.json")
    source_sha = handoff.digest(read(HERE / "native_full_session_v4.py"))
    if (
        native.get("schema_version") != "chipflow.full_native_session_request.v3"
        or session.get("schema_version") != "chipflow.full_native_session.v4"
        or session.get("source_sha256") != source_sha
        or native.get("output") != mounted_work_root
        or session.get("request_file_sha256") != captured[Path(native_request_path)]
        or binding.get("request_file_sha256") != captured[Path(native_request_path)]
        or binding.get("request_model_sha256") != handoff.canonical(native)
        or binding.get("public_tree_sha256") != native.get("public_tree_sha256")
        or binding.get("workspace_tree_sha256") != native.get("workspace_tree_sha256")
        or binding.get("controller_health_sha256")
        != native.get("controller_health_sha256")
    ):
        raise ValueError("native_session_request_or_source_drift")
    if (
        not isinstance(native.get("attempt_id"), str)
        or native["attempt_id"] != session.get("attempt_id")
        or native["attempt_id"] != (launch.get("attempt") or {}).get("attempt_id")
        or task.get("task_id") != session.get("task_id")
        or task.get("task_id") != launch.get("task_id")
        or launch.get("workflow_id") != "chipflow"
        or not isinstance(native.get("model"), str)
        or native["model"] != launch.get("model")
        or (launch.get("sha256") or {}).get("task") != captured[Path(public_task_path)]
    ):
        raise ValueError("native_public_launch_identity_drift")
    if (
        session.get("native_state_sha256") != captured[work / "native-state.json"]
        or session.get("checkpoint_sha256")
        != handoff.digest(read(work / "checkpoints.sqlite"))
        or session.get("observation_sha256")
        != handoff.digest(read(work / "observation/observation.json"))
        or session.get("native_status") != state.get("status")
        or session.get("native_stage") != state.get("current_stage")
        or session.get("judge_decision") != state.get("judge_decision")
        or session.get("neutral_submission_exported") is not False
        or session.get("benchmark_verdict") is not None
    ):
        raise ValueError("native_terminal_content_drift")
    expected_observation = {"mode": "fresh_process_no_human_callback", "count": 0}
    if handoff.canonical(
        session.get("human_intervention_observation")
    ) != handoff.canonical(expected_observation):
        raise ValueError("missing_or_unsupported_intervention_observation")
    if (
        native.get("approval_policy") != "scope_hash_bound_controller_preapproval"
        or session.get("approval_policy") != native["approval_policy"]
    ):
        raise ValueError("unbound_machine_approval_policy")
    count = session.get("machine_preapproval_count")
    if type(count) is not int or not 1 <= count <= 16:
        raise ValueError("machine_approval_evidence_missing")
    names = ["approval-" + str(i) + ".json" for i in range(1, count + 1)]
    hashes = session.get("approval_evidence_sha256")
    if (
        not isinstance(hashes, dict)
        or set(hashes) != set(names)
        or {p.name for p in work.glob("approval-*.json")} != set(names)
    ):
        raise ValueError("machine_approval_inventory_drift")
    generation = 0
    for name in names:
        approval = doc(work / name)
        if hashes[name] != captured[work / name]:
            raise ValueError("machine_approval_content_drift")
        if (
            approval.get("gate") != "patch_plan"
            or approval.get("judge_accept_required") is not True
            or approval.get("public_allowed_scope_required") is not True
            or approval.get("design_unit_route") is not True
            or type(approval.get("approval_generation")) is not int
            or approval["approval_generation"] <= generation
        ):
            raise ValueError("machine_approval_evidence_invalid")
        generation = approval["approval_generation"]
    current = state.get("approval_request") or {}
    if (
        approval.get("approval_request_id") != current.get("request_id")
        or approval.get("scope_hash") != current.get("scope_hash")
        or generation != state.get("approval_generation")
    ):
        raise ValueError("machine_approval_not_current")
    scope = task["submission_contract"]
    expected_contract = {
        "schema_version": "chipflow.native_artifact_contract.v1",
        "task_id": task["task_id"],
        "public_input_manifest_sha256": handoff.canonical(
            state["public_input_manifest"]
        ),
        "public_scope_relative": "inputs/public/allowed_scope.json",
        "required_files": scope["required_files"],
        "editable_paths": scope["editable_paths"],
        "max_files_changed": scope["max_files_changed"],
        "transport_max_bytes": scope["max_submission_bytes"],
    }
    if handoff.canonical(contract) != handoff.canonical(expected_contract):
        raise ValueError("native_public_output_contract_drift")
    public_entries = [
        item
        for item in state["public_input_manifest"]
        if item.get("path") == "inputs/public/external_task.json"
    ]
    if (
        len(public_entries) != 1
        or public_entries[0].get("sha256") != captured[Path(public_task_path)]
    ):
        raise ValueError("native_state_public_task_unbound")
    expected_handoff = str(
        Path(mounted_work_root).with_name(Path(mounted_work_root).name + "-handoff")
        / "ready"
    )
    if session.get("artifact_handoff") != expected_handoff:
        raise ValueError("native_session_handoff_path_drift")
    original = work.with_name(work.name + "-handoff") / "ready"
    original_docs = {
        name: doc(original / name)
        for name in ["handoff.json", "manifest.json", "evidence-digests.json"]
    }
    for item in original_docs["manifest.json"]["artifacts"]:
        raw = read(original / handoff.relative(item["source_path"]))
        if handoff.digest(raw) != item["sha256"] or len(raw) != item["bytes"]:
            raise ValueError("native_handoff_artifact_drift")
    # Re-run the real validator against the stopped native state. Do not trust a
    # success flag in a supplied handoff receipt or grant a new approval here.
    handoff.capture(
        contract_path=work / "artifact-contract.json",
        work_root=work,
        state_relative="native-state.json",
        mounted_work_root=mounted_work_root,
        expected_state_sha256=captured[work / "native-state.json"],
        output_dir=output / "recapture",
    )
    ready = output / "recapture/ready"
    for name, value in original_docs.items():
        if handoff.canonical(doc(ready / name)) != handoff.canonical(value):
            raise ValueError("native_handoff_recapture_drift")
    control = {
        "schema_version": "rtlflowbench.chipflow_public_control_receipt.v1",
        "status": "workflow_completed_neutral_export_ready",
        "task_id": task["task_id"],
        "model": native["model"],
        "submission_observed": True,
        "benchmark_verdict_produced": False,
        "private_evaluator_run": False,
        "human_intervention_count": 0,
        "submission_manifest": original_docs["manifest.json"],
        "native_status": state["status"],
        "native_verification_status": state["verification_result"]["status"],
        "binding": {
            "native_request_sha256": captured[Path(native_request_path)],
            "public_launch_request_sha256": captured[Path(public_launch_request_path)],
            "native_session_sha256": captured[work / "session.json"],
            "native_state_sha256": captured[work / "native-state.json"],
            "native_session_source_sha256": source_sha,
            "projector_source_sha256": handoff.digest(
                read(HERE / "native_terminal_control_v1.py")
            ),
            "native_handoff_sha256": captured[original / "handoff.json"],
        },
        "benchmark_verdict": None,
        "neutral_submission_exported": False,
        "formal_campaign_eligible": False,
    }
    for path, digest in captured.items():
        if handoff.digest(handoff.read_regular(path.parent, path.name)) != digest:
            raise ValueError("native_control_source_changed")
    with (output / "control.json").open("x") as stream:
        json.dump(control, stream, sort_keys=True, indent=2, allow_nan=False)
        stream.write("\n")
    return control
