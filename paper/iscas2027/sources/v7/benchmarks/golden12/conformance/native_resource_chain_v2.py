"""Bind native resource sidecars to canonical process telemetry, without zero-fill.

This content validator trusts the separately protected host collector. It does
not authenticate an arbitrary caller, grant execution, or score task artifacts.
"""

import hashlib
import importlib.util
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker


HERE = Path(__file__).parent
IDENTITIES = (
    "measurement_id",
    "workflow_slot_id",
    "workflow_id",
    "task_id",
    "attempt_id",
    "source_binding",
    "runtime_binding",
)


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, HERE / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


base = load("native_resource_json", "native_exec_reconcile_v2.py")
terminal = load("native_resource_terminal", "native_terminal_resources_v1.py")
workspace = load("native_resource_workspace", "native_workspace_usage_v1.py")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def validate_request(request_bytes):
    value = base.document(request_bytes)
    schema = base.document(
        (HERE / "native_bound_resource_request_v1.schema.json").read_bytes()
    )
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(value)
    return value


def validate_public_launch(request, launch_bytes):
    """Bind declared scheduling metadata; never infer an observed provider seed."""
    launch = base.document(launch_bytes)
    if (
        sha(launch_bytes) != request["public_launch_request_sha256"]
        or launch.get("task_id") != request["task_id"]
        or launch.get("workflow_id") != request["workflow_id"]
        or base.canonical(launch.get("attempt"))
        != base.canonical(request["official_attempt_binding"])
        or request["official_attempt_binding"]["attempt_id"] != request["attempt_id"]
        or (launch.get("sha256") or {}).get("task")
        != request["public_input_binding"]["external_task_sha256"]
    ):
        raise ValueError("native_public_launch_binding_drift")
    return launch


def project_process(
    *, request_bytes, artifacts, observed_at, runner_sha256, podman_sha256
):
    request = validate_request(request_bytes)
    for digest in [runner_sha256, podman_sha256]:
        base.sha_value(digest)
    required = {
        "observation",
        "launch",
        "inspection",
        "native_request",
        "supervisor_request",
        "terminal",
        "snapshot",
        "release",
        "released",
        "workspace_samples",
        "workspace_terminal",
        "source_manifest",
        "collector_manifest",
        "public_task",
        "public_launch_request",
        "stdout",
        "stderr",
    }
    if set(artifacts) != required or not all(
        isinstance(v, bytes) for v in artifacts.values()
    ):
        raise ValueError("resource_artifact_set_incomplete")
    validate_public_launch(request, artifacts["public_launch_request"])
    docs = {
        k: base.document(v)
        for k, v in artifacts.items()
        if k not in {"stdout", "stderr"}
    }
    obs, launch, inspection = (docs[k] for k in ["observation", "launch", "inspection"])
    if obs.get("schema_version") != "chipflow.native_same_run_resource_observation.v1":
        raise ValueError("unknown_process_observation")
    bindings = {
        "native_request_sha256": "native_request",
        "supervisor_request_sha256": "supervisor_request",
        "workflow_source_manifest_sha256": "source_manifest",
        "collector_source_manifest_sha256": "collector_manifest",
    }
    if any(request[k] != sha(artifacts[name]) for k, name in bindings.items()):
        raise ValueError("request_resource_source_drift")
    if (
        request["public_input_binding"]["external_task_sha256"]
        != sha(artifacts["public_task"])
        or docs["public_task"].get("task_id") != request["task_id"]
    ):
        raise ValueError("public_task_identity_drift")
    if runner_sha256 not in docs["collector_manifest"].values():
        raise ValueError("runner_not_in_collector_closure")
    for key, name in [
        ("launch_sha256", "launch"),
        ("native_request_sha256", "native_request"),
        ("source_manifest_sha256", "source_manifest"),
        ("collector_sources_sha256", "collector_manifest"),
        ("terminal_resources_sha256", "snapshot"),
        ("workspace_samples_sha256", "workspace_samples"),
        ("workspace_terminal_sha256", "workspace_terminal"),
    ]:
        if obs.get(key) != sha(artifacts[name]):
            raise ValueError("process_observation_content_drift")
    if (
        launch.get("native_request_sha256") != request["native_request_sha256"]
        or launch.get("supervisor_request_sha256")
        != request["supervisor_request_sha256"]
    ):
        raise ValueError("launch_request_drift")
    native = docs["native_request"]
    if native.get("schema_version") != "chipflow.full_native_session_request.v3":
        raise ValueError("native_request_version_drift")
    if (
        native.get("attempt_id") != request["attempt_id"]
        or native.get("public_tree_sha256")
        != request["public_input_binding"]["public_tree_sha256"]
    ):
        raise ValueError("native_attempt_or_public_drift")
    terminal.verify_chain(
        terminal_bytes=artifacts["terminal"],
        snapshot_bytes=artifacts["snapshot"],
        release_bytes=artifacts["release"],
        released_bytes=artifacts["released"],
        expected_native_request_sha256=request["native_request_sha256"],
        expected_supervisor_request_sha256=request["supervisor_request_sha256"],
    )
    normalized = terminal.normalize(docs["snapshot"]["raw_cgroup"])
    origin, end = (
        obs.get("measurement_origin_monotonic_ns"),
        obs.get("launcher_end_monotonic_ns"),
    )
    if type(origin) is not int or type(end) is not int or not 0 <= origin < end:
        raise ValueError("invalid_measurement_interval")
    if obs.get("wall_time_seconds") != (end - origin) / 1_000_000_000:
        raise ValueError("wall_time_projection_drift")
    if (
        not origin
        <= docs["snapshot"]["sample_start_monotonic_ns"]
        <= docs["snapshot"]["sample_end_monotonic_ns"]
        <= end
    ):
        raise ValueError("terminal_snapshot_outside_measurement")
    accumulation = workspace.Accumulator()
    ws = docs["workspace_samples"]
    for row in ws["samples"]:
        sample = {
            k: v
            for k, v in row.items()
            if k not in {"started_monotonic_ns", "completed_monotonic_ns"}
        }
        if (
            not origin
            <= row["started_monotonic_ns"]
            <= row["completed_monotonic_ns"]
            <= end
        ):
            raise ValueError("workspace_sample_outside_measurement")
        accumulation.observe(
            sample,
            started_ns=row["started_monotonic_ns"],
            completed_ns=row["completed_monotonic_ns"],
        )
    failed = ws["summary"].get("failed_probe_count")
    if type(failed) is not int or failed < 0:
        raise ValueError("invalid_failed_probe_count")
    accumulation.failed_probe_count = failed
    if accumulation.summary() != ws["summary"] or obs["workspace"] != ws["summary"]:
        raise ValueError("workspace_projection_drift")
    final_scan = docs["workspace_terminal"]
    final_accumulation = workspace.Accumulator()
    final_accumulation.observe(
        final_scan["sample"],
        started_ns=final_scan["started_monotonic_ns"],
        completed_ns=final_scan["completed_monotonic_ns"],
    )
    if (
        final_scan["started_monotonic_ns"] < end
        or not accumulation.summary()["sampling_complete"]
        or not final_accumulation.summary()["sampling_complete"]
    ):
        raise ValueError("incomplete_workspace_measurement")
    argv = launch.get("argv")
    image = request["runtime_binding"]["image_id"].removeprefix("sha256:")
    if (
        not isinstance(argv, list)
        or argv.count(image) != 1
        or argv.count("--network=none") != 1
        or argv.count("--read-only") != 1
    ):
        raise ValueError("unsafe_or_unbound_launch")
    if (
        inspection.get("image") != image
        or inspection.get("network_mode") != "none"
        or inspection.get("read_only_rootfs") is not True
        or inspection.get("state") != "exited"
    ):
        raise ValueError("offline_container_inspection_mismatch")
    code = obs["launcher_exit_code"]
    if type(code) is not int or inspection.get("exit_code") != code:
        raise ValueError("launcher_exit_mismatch")
    sample_count = obs["container_cgroup_sample_count"]
    if type(sample_count) is not int or sample_count <= 0 or obs["sample_count"] <= 0:
        raise ValueError("missing_resource_samples")
    pairs = [
        ("sampled_container_cpu_seconds", "terminal_container_cpu_seconds"),
        ("sampled_container_memory_peak_bytes", "terminal_container_memory_peak_bytes"),
        ("sampled_container_pids_peak", "terminal_container_pids_peak"),
    ]
    if any(
        type(obs.get(a)) not in {int, float} or not 0 <= obs[a] <= normalized[b]
        for a, b in pairs
    ):
        raise ValueError("sampled_terminal_resource_conflict")
    metrics = {
        key: obs[key]
        for key in [
            "wall_time_seconds",
            "envelope_child_user_cpu_time_seconds",
            "envelope_child_system_cpu_time_seconds",
            "peak_launcher_process_tree_rss_bytes",
            "peak_launcher_process_tree_count",
            "container_cgroup_sample_count",
            "container_cgroup_lookup_error_count",
            "container_cgroup_read_error_count",
            "sample_count",
            "sampling_interval_ms",
        ]
    }
    metrics.update(
        envelope_child_cpu_time_seconds=metrics["envelope_child_user_cpu_time_seconds"]
        + metrics["envelope_child_system_cpu_time_seconds"],
        peak_container_cgroup_memory_bytes=normalized[
            "terminal_container_memory_peak_bytes"
        ],
        container_cgroup_cpu_time_seconds=normalized["terminal_container_cpu_seconds"],
        peak_container_cgroup_pids=normalized["terminal_container_pids_peak"],
        peak_scratch_bytes=max(
            accumulation.summary()["sampled_peak_scratch_bytes"],
            final_scan["sample"]["observed_regular_file_bytes"],
        ),
        peak_eda_concurrency=None,
        peak_llm_concurrency=None,
        scratch_integrity_valid=True,
    )
    forced = obs.get("forced_eda_activity_closure_count")
    if type(forced) is not int or forced < 0:
        raise ValueError("missing_forced_closure_observation")
    metrics["forced_eda_activity_closure_count"] = forced
    result = {
        "schema_version": "rtlflowbench.workflow_resource_measurement_receipt.v1",
        "observed_at": observed_at,
        "status": "measurement_completed",
        "runner_id": "rtlflowbench.controller_aware_resource_measurement_envelope.v1",
        **{key: request[key] for key in (*IDENTITIES, "measurement_scope")},
        "request_sha256": sha(request_bytes),
        "runner_sha256": runner_sha256,
        "request_schema_sha256": sha(
            (HERE / "native_bound_resource_request_v1.schema.json").read_bytes()
        ),
        "receipt_schema_sha256": sha(
            (
                HERE / "../execution/workflow_resource_measurement_receipt.schema.json"
            ).read_bytes()
        ),
        "launcher": {
            "kind": "podman_oci",
            "executable_sha256": podman_sha256,
            "exit_code": code,
            "timed_out": False,
            "outcome": "exited_zero" if code == 0 else "exited_nonzero",
            "argv_sha256": base.canonical(argv),
            "argument_count": len(argv) - 1,
            "argv_values_recorded": False,
            "launcher_path_recorded": False,
            "runtime_image_argv_index": argv.index(image),
            "runtime_image_binding_enforced_by_measurement_envelope": True,
            "network_policy_declared": "offline",
            "network_policy_enforced_by_measurement_envelope": True,
        },
        "metrics": metrics,
        "missing_measurements": ["peak_eda_concurrency", "peak_llm_concurrency"],
        "raw_evidence": {
            "invocation_sha256": sha(artifacts["launch"]),
            "stdout_sha256": sha(artifacts["stdout"]),
            "stderr_sha256": sha(artifacts["stderr"]),
            "raw_content_embedded": False,
        },
        "attempt_accounting": {
            "official_attempt_started": False,
            "official_semantic_attempt_consumed": False,
            "resource_calibration_attempt_consumed": True,
            "benchmark_result_created": False,
            "private_evaluator_calls": 0,
        },
        "readiness": {
            "launcher_completed_successfully": code == 0,
            "process_tree_measurement_complete": metrics[
                "peak_launcher_process_tree_rss_bytes"
            ]
            > 0
            and metrics["peak_launcher_process_tree_count"] > 0,
            "container_cgroup_measurement_complete": metrics[
                "container_cgroup_lookup_error_count"
            ]
            == metrics["container_cgroup_read_error_count"]
            == 0,
            "full_workflow_resource_calibration_eligible": False,
            "host_capacity_policy_derivation_permitted": False,
            "official_attempts_permitted": False,
        },
        "excluded_claims": [
            "This versioned native projection is resource telemetry, not an RTL or benchmark verdict.",
            "Container CPU ends at the protected snapshot; host CPU includes monitoring children and excludes the final workspace scan.",
            "Workspace bytes are sampled logical file sizes plus the terminal scan, not an exact disk or lifetime peak.",
            "Native request and runner source identities differ from historical envelopes; do not silently pool these cost observations.",
        ],
    }
    schema = base.document(
        (
            HERE / "../execution/workflow_resource_measurement_receipt.schema.json"
        ).read_bytes()
    )
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(result)
    return result


def close_observed_ledger(
    *,
    state,
    request_bytes,
    process_bytes,
    trace_process_bytes,
    reconciliation,
    inspection,
    origin_ns,
):
    """Use only after trusted launcher stop/isolation checks, not arbitrary receipts."""
    request = validate_request(request_bytes)
    process = base.document(process_bytes)
    traced = base.document(trace_process_bytes)
    if (
        reconciliation.get("process_sha256") != sha(trace_process_bytes)
        or traced.get("command_argv_sha256") != request["traced_command_argv_sha256"]
        or traced.get("source_closure_sha256")
        != request["workflow_source_manifest_sha256"]
        or traced.get("image_id")
        != request["runtime_binding"]["image_id"].removeprefix("sha256:")
    ):
        raise ValueError("reconciled_trace_belongs_to_different_run")
    if any(
        state.measurement.get(k) != request[k] or process.get(k) != request[k]
        for k in IDENTITIES
    ):
        raise ValueError("controller_resource_identity_drift")
    if (
        process.get("request_sha256") != sha(request_bytes)
        or state._origin_ns != origin_ns
    ):
        raise ValueError("controller_resource_origin_drift")
    if (
        inspection.get("state") != "exited"
        or inspection.get("network_mode") != "none"
        or inspection.get("read_only_rootfs") is not True
        or inspection.get("image")
        != request["runtime_binding"]["image_id"].removeprefix("sha256:")
    ):
        raise ValueError("controller_isolation_not_closed")
    summary = state.activity_summary()
    if (
        reconciliation.get("status") != "reconciled"
        or reconciliation.get("matched_invocations") != summary["eda_activity_count"]
        or summary["unfinished_eda_activity_count"] != 0
    ):
        raise ValueError("controller_exec_routing_incomplete")
    for name, key in [
        ("provider_gateway", "provider_source_sha256"),
        ("eda_broker", "eda_source_sha256"),
    ]:
        if (
            state.controller_bindings[name]["source_sha256"]
            != request["controller_binding"][key]
        ):
            raise ValueError("controller_source_drift")
    return state.build_ledger(
        observed_at=process["observed_at"],
        process_measurement_receipt_sha256=sha(process_bytes),
    )
