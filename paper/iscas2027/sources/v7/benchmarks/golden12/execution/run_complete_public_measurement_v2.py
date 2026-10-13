"""Versioned full-public-input controller entry, preserving the frozen budget.

Diagnostic modes cannot access a provider. Authorized measurements require a
separate content-bound full200 authorization and the existing five-route gate.
The v1 resource telemetry wire format is retained; runner_sha256 identifies this
new implementation and the invocation binds its complete source dependency set.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

import complete_public_cohort_v2 as cohort

MODES = {"native-preflight", "provider-denial", "authorized"}
MODEL_CANDIDATE = "58205f12e9b24453fb3cb5c1a84fff6b3cf6670504b882fcf2f8ee9abb3a750b"


def validate_authorization(value, *, campaign_sha, provider_gate_sha, runner_sha):
    expected = {
        "schema_version": "rtlflowbench.complete_public_authorization.v2",
        "campaign_sha256": campaign_sha,
        "common_provider_gate_sha256": provider_gate_sha,
        "runner_sha256": runner_sha,
        "decision": "ALLOW_AUTHOR_ALPHA_RESOURCE_MEASUREMENTS_ONLY",
        "planned_slots": 200,
        "official_release": False,
        "private_evaluator_reachable": False,
        "maximum_provider_calls_per_slot": 4,
        "maximum_input_tokens_per_slot": 163840,
        "maximum_output_tokens_per_slot": 16384,
    }
    if set(value) != set(expected) or any(
        type(value[k]) is not type(v) or value[k] != v for k, v in expected.items()
    ):
        raise ValueError("full200 authorization identity/scope/budget drift")


def provider_route(
    *,
    mode,
    base,
    campaign_sha,
    provider_gate_path=None,
    provider_gate_sha=None,
    authorization_path=None,
    authorization_sha=None,
):
    if mode not in MODES:
        raise ValueError("unknown execution mode")
    counter = {"intentional_local_denials": 0, "external_provider_calls": 0}
    if mode != "authorized":

        def deny(*args, **kwargs):
            counter["intentional_local_denials"] += 1
            return (
                503,
                {},
                b'{"error":{"message":"intentional offline controller diagnostic denial"}}',
            )

        return deny, counter
    if None in (
        provider_gate_path,
        provider_gate_sha,
        authorization_path,
        authorization_sha,
    ):
        raise ValueError(
            "new campaign authorization and provider gate required before model access"
        )
    validate_authorization(
        cohort.read(authorization_path, authorization_sha),
        campaign_sha=campaign_sha,
        provider_gate_sha=provider_gate_sha,
        runner_sha=cohort.sha(Path(__file__)),
    )
    gate, _ = base._provider_gate(provider_gate_path, provider_gate_sha)
    if gate["provider_binding"]["common_model_candidate_sha256"] != MODEL_CANDIDATE:
        raise ValueError("common model candidate drift")
    key = os.environ.get("DEEPSEEK_API_KEY")
    if not key:
        raise ValueError("host-only provider credential unavailable")
    transport = base._module(base.TRANSPORT, "complete_public_transport_for_provider")
    real = transport.DeepSeekForwarder(api_key=key)

    def forward(*args, **kwargs):
        counter["external_provider_calls"] += 1
        return real(*args, **kwargs)

    return forward, counter


def commands(
    *,
    repo,
    campaign_root,
    row,
    base,
    mods,
    podman,
    work,
    client,
    controller_root,
    broker_root,
    broker_evidence,
    broker_scratch,
    session,
    observed_at,
    mode,
):
    request = row["baseline_resource_request"]
    request_root = cohort.child(campaign_root, row["request_relative_root"])
    if row["route"] == "existing_native":
        if mode == "native-preflight":
            raise ValueError(
                "existing native runtime has no generic preflight-only API"
            )
        argv, index = base._actual_podman_argv(
            podman=podman,
            request=request,
            request_root=request_root,
            work_root=work,
            controller_root=controller_root,
            client_runtime=client,
            session_id=session,
            observed_at=observed_at,
            provider_runtime_config=base._provider_runtime_config_path(request),
            mage_broker_root=None,
        )
        return (
            argv,
            index,
            None,
            {"route": "existing_native", "new_native_algorithm": False},
            base.CLIENT,
        )
    runtime = cohort.child(campaign_root, row["runtime_relative_root"])
    common = {
        "request_root": request_root,
        "bundle_root": cohort.child(campaign_root, row["bundle_relative_root"]),
        "runtime_root": runtime,
        "expected_runtime_sha256": row["runtime_manifest_sha256"],
        "work_root": work,
        "controller_root": controller_root,
        "client_root": client,
        "session": session,
        "preflight_only": mode == "native-preflight",
        "policy_path": base.LAUNCH_POLICY,
    }
    if row["route"] == "mage_complete_public":
        argv, broker, plan = mods["mage_plan"].build_commands(
            **common,
            expected_request_binding_sha256=row["request_binding_sha256"],
            broker_root=broker_root,
            broker_evidence=broker_evidence,
            broker_scratch=broker_scratch,
            observed_at=observed_at,
        )
        source = runtime / "mage_controller_client_v2.py"
    else:
        argv, plan = mods["external_plan"].build_command(
            **common, expected_request_sha256=row["request_binding_sha256"]
        )
        broker = None
        source = runtime / "controller_client_public_inputs_v2.py"
    argv[0] = str(podman)
    argv.insert(2, "--name=" + request["measurement_id"])
    image = request["runtime_binding"]["image_id"]
    if argv.count(image) != 1:
        raise ValueError("declared native image differs from generated command")
    index = argv.index(image)
    return argv, index, broker, plan, source


def create_socket_mount_roots(controller_root, broker_root):
    """Plan validation precedes socket binding and therefore needs directories."""
    controller_root.mkdir(mode=0o700)
    if broker_root is not None:
        broker_root.mkdir(mode=0o700)


def prepare_client_bindings(client, route):
    # The launch planner must see fresh scratch; create the required binding
    # receipt directory only after its validation, before entering the image.
    if any(client.iterdir()):
        raise FileExistsError("controller client scratch must still be fresh")
    if route == "external_complete_public":
        (client / "bindings").mkdir(mode=0o700)


def positive_balance(value):
    return (
        value.get("http_status") == 200
        and value.get("credential_present") is True
        and value.get("is_available") is True
        and value.get("positive_total_balance_present") is True
        and value.get("error_classification") is None
        and value.get("raw_response_persisted") is False
        and value.get("exact_balance_persisted") is False
    )


def run_slot(**kwargs):
    """Record a failed owned invocation without rewriting evidence or retrying."""
    context = {"output_owned": False, "stage": "input_validation"}
    try:
        return _run_slot(_context=context, **kwargs)
    except Exception as error:
        if not context["output_owned"]:
            # Never create artifacts in a rejected/pre-existing caller path.
            raise
        return operational_failure(context=context, error=error, **kwargs)


def operational_failure(
    *, context, error, output, mode, measurement_id, campaign_sha, **kwargs
):
    base = context["base"]
    evidence = {}
    for name in (
        "invocation.json",
        "observation.json",
        "stdout.log",
        "stderr.log",
        "balance-before.json",
        "balance-after.json",
        "resource-measurement-receipt.json",
        "activity-ledger.json",
        "activity-concurrency-receipt.json",
    ):
        path = output / name
        if path.is_file() and not path.is_symlink():
            evidence[name] = cohort.sha(path)
    result = {
        "schema_version": "rtlflowbench.complete_public_operational_failure.v2",
        "status": "OPERATIONAL_FAILURE_REQUIRES_REVIEW",
        "mode": mode,
        "measurement_id": measurement_id,
        "campaign_sha256": campaign_sha,
        "runner_sha256": cohort.sha(Path(__file__)),
        "stage": context["stage"],
        "error_class": type(error).__name__,
        "cleanup_error_classes": context.get("cleanup_error_classes", []),
        "process_exit_code": None,
        "process_timed_out": None,
        "launcher_process_started": context.get("launcher_process_started", False),
        "workflow_process_started": None
        if context.get("launcher_process_started")
        else False,
        "usage_boundary": dict(context["counts"]) if "counts" in context else None,
        "preserved_evidence_sha256": evidence,
        "benchmark_verdict": None,
        "automatic_retry_permitted": False,
        "raw_exception_message_recorded": False,
    }
    failure_path = output / "operational-failure.json"
    base._write_new(failure_path, result)
    state = context.get("state")
    if state is not None and not (output / "activity-ledger.json").exists():
        try:
            state.close_unfinished_eda_on_process_exit(outcome="failed")
            ledger = state.build_ledger(
                observed_at=datetime.now(timezone.utc).isoformat(),
                process_measurement_receipt_sha256=cohort.sha(failure_path),
            )
            base._validate(
                base.ACTIVITY_LEDGER_SCHEMA, ledger, "incomplete activity ledger"
            )
            base._write_new(output / "incomplete-activity-ledger.json", ledger)
        except Exception as ledger_error:
            base._write_new(
                output / "ledger-capture-failure.json",
                {
                    "error_class": type(ledger_error).__name__,
                    "operational_failure_sha256": cohort.sha(failure_path),
                    "missing_usage_must_not_be_zero": True,
                },
            )
    return result


def record_missing_cgroup(*, base, output, observation, process):
    """The frozen v1 merger cannot express absent cgroup memory; don't fake it."""
    metrics = process["metrics"]
    if (
        metrics["container_cgroup_sample_count"] > 0
        and metrics["peak_container_cgroup_memory_bytes"] > 0
        and metrics["peak_container_cgroup_pids"] > 0
    ):
        return False
    result = {
        "schema_version": "rtlflowbench.complete_public_telemetry_incomplete.v2",
        "status": "TELEMETRY_INCOMPLETE_REQUIRES_REVIEW",
        "measurement_id": observation["measurement_id"],
        "campaign_sha256": observation["campaign_sha256"],
        "reason_code": "cgroup_measurement_unavailable",
        "benchmark_verdict": None,
        "automatic_retry_permitted": False,
        "metrics": {
            "peak_memory_bytes": None,
            "cpu_time_seconds": None,
            "peak_process_count": None,
        },
        "missing_measurements": [
            "peak_memory_bytes",
            "cpu_time_seconds",
            "peak_process_count",
        ],
        "preserved_evidence_sha256": {
            name: cohort.sha(output / name)
            for name in (
                "observation.json",
                "resource-measurement-receipt.json",
                "activity-ledger.json",
                "activity-concurrency-receipt.json",
            )
        },
        "raw_sampler_zero_is_missing_not_measured_zero": True,
        "frozen_merger_schema_modified": False,
    }
    base._write_new(output / "telemetry-incomplete.json", result)
    return True


def _run_slot(
    *,
    repo,
    campaign_path,
    campaign_sha,
    measurement_id,
    mode,
    scratch,
    output,
    podman,
    podman_sha,
    provider_gate_path=None,
    provider_gate_sha=None,
    authorization_path=None,
    authorization_sha=None,
    _context,
):
    campaign = cohort.validate_campaign(
        repo=repo, path=campaign_path, expected_sha=campaign_sha
    )
    rows = [r for r in campaign["rows"] if r["measurement_id"] == measurement_id]
    if len(rows) != 1:
        raise ValueError("exactly one frozen schedule cell required")
    row = rows[0]
    request = row["baseline_resource_request"]
    base = cohort.base_runner(repo)
    mods = cohort.public_modules(repo)
    if (
        cohort.sha(podman) != podman_sha
        or podman.name != "podman"
        or not os.access(podman, os.X_OK)
    ):
        raise ValueError("unbound Podman executable")
    # Only fully specified native launch inputs can enter a paid run. A gap
    # remains an adapter/API prerequisite, not a scored workflow BLOCK/FAIL.
    if mode == "authorized" and row["native_prerequisite_gaps"]:
        raise ValueError(
            "native input prerequisites unresolved; execute an offline preflight, not a paid slot"
        )
    forwarder, counts = provider_route(
        mode=mode,
        base=base,
        campaign_sha=campaign_sha,
        provider_gate_path=provider_gate_path,
        provider_gate_sha=provider_gate_sha,
        authorization_path=authorization_path,
        authorization_sha=authorization_sha,
    )
    for root in (scratch, output):
        if not root.is_absolute() or root.exists() or root.is_symlink():
            raise FileExistsError("fresh absolute output/scratch required")
    roots = [scratch.resolve(), output.resolve(), campaign_path.parent.resolve()]
    if any(
        a == b or a.is_relative_to(b) or b.is_relative_to(a)
        for i, a in enumerate(roots)
        for b in roots[i + 1 :]
    ):
        raise ValueError("output, scratch, campaign must not overlap")
    output.mkdir(parents=True)
    _context.update(
        output_owned=True, base=base, counts=counts, stage="balance_preflight"
    )
    balance_probe = None
    if mode == "authorized":
        # Each low-level invocation is a one-slot microbatch. Larger orchestration
        # may group up to three slots but cannot skip these before/after probes.
        balance_probe = base._module(
            repo / "benchmarks/golden12/execution/run_guarded_resource_batch.py",
            "complete_public_balance_probe",
        ).probe_deepseek_balance
        before_balance = balance_probe()
        base._write_new(output / "balance-before.json", before_balance)
        if not positive_balance(before_balance):
            raise ValueError(
                "positive official provider balance not verified; no workflow launch"
            )
    scratch.mkdir(parents=True)
    _context["stage"] = "launch_preparation"
    work = scratch / "work"
    work.mkdir()
    client = scratch / "client"
    client.mkdir()
    controller_root, socket = base._controller_socket_path(
        measurement_id=measurement_id, expected_bridge_set_sha256=campaign_sha
    )
    session = (
        "session-"
        + hashlib.sha256((measurement_id + campaign_sha).encode()).hexdigest()[:32]
    )
    broker_root = broker_socket = None
    if row["workflow_id"] == "mage":
        broker_root, broker_socket = base._mage_broker_socket_path(
            measurement_id=measurement_id, expected_bridge_set_sha256=campaign_sha
        )
    create_socket_mount_roots(controller_root, broker_root)
    observed_at = datetime.now(timezone.utc).isoformat()
    argv, image_index, broker_argv, plan, eda_source = commands(
        repo=repo,
        campaign_root=campaign_path.parent,
        row=row,
        base=base,
        mods=mods,
        podman=podman,
        work=work,
        client=client,
        controller_root=controller_root,
        broker_root=broker_root,
        broker_evidence=output / "mage-eda-calls",
        broker_scratch=scratch / "mage-eda-scratch",
        session=session,
        observed_at=observed_at,
        mode=mode,
    )
    prepare_client_bindings(client, row["route"])
    transport = base._module(base.TRANSPORT, "complete_public_live_transport")
    measurement = {
        k: request[k]
        for k in [
            "measurement_id",
            "measurement_scope",
            "workflow_slot_id",
            "workflow_id",
            "task_id",
            "attempt_id",
            "source_binding",
            "runtime_binding",
        ]
    }
    policy = request["resource_policy"]
    state = transport.ControllerState(
        session_id=session,
        measurement=measurement,
        expected_model="deepseek-v4-pro",
        maximum_provider_calls=policy["maximum_provider_calls"],
        maximum_output_tokens_per_call=policy["maximum_output_tokens_per_call"],
        maximum_input_tokens=policy["maximum_input_tokens"],
        maximum_output_tokens=policy["maximum_output_tokens"],
        maximum_consecutive_identical_requests=policy[
            "maximum_consecutive_identical_requests"
        ],
        maximum_consecutive_identical_errors=policy[
            "maximum_consecutive_identical_errors"
        ],
        provider_forwarder=forwarder,
        provider_config_sha256=MODEL_CANDIDATE,
        provider_source_sha256=cohort.sha(base.TRANSPORT),
        eda_config_sha256=cohort.identity(
            {"campaign": campaign_sha, "input_row": cohort.identity(row)}
        ),
        eda_source_sha256=cohort.sha(eda_source),
    )
    _context["state"] = state
    invocation = {
        "schema_version": "rtlflowbench.complete_public_controller_invocation.v2",
        "mode": mode,
        "campaign_sha256": campaign_sha,
        "row_canonical_sha256": cohort.identity(row),
        "measurement_id": measurement_id,
        "host_source_binding": campaign["source_binding"],
        "argv_sha256": cohort.identity(argv),
        "broker_argv_sha256": cohort.identity(broker_argv) if broker_argv else None,
        "native_plan": plan,
        "host_plan_adjustments": [
            "bind_absolute_podman_executable",
            "add_measurement_name_for_cgroup_sampling",
        ]
        if row["route"] != "existing_native"
        else [],
        "common_provider_gate_sha256": provider_gate_sha,
        "authorization_sha256": authorization_sha,
        "private_evaluator_mounted": False,
        "raw_provider_content_embedded": False,
        "podman_sha256": podman_sha,
    }
    base._write_new(output / "invocation.json", invocation)
    process_module = base._module(
        base.PROCESS_ENVELOPE, "complete_public_process_sampler"
    )
    environment = {
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "HOME": os.environ["HOME"],
        "XDG_RUNTIME_DIR": os.environ["XDG_RUNTIME_DIR"],
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    broker = None
    process = None
    broker_code = None
    sampler = None
    started = time.monotonic()
    cpu_before = process_module._cpu_snapshot()
    _context["stage"] = "native_process_launch"
    try:
        with transport.ControllerServer(socket_path=socket, state=state):
            if broker_argv:
                broker = subprocess.Popen(
                    broker_argv,
                    env=environment,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                base._wait_socket(broker, broker_socket)
            with (
                (output / "stdout.log").open("wb") as stdout,
                (output / "stderr.log").open("wb") as stderr,
            ):
                state.set_origin(time.monotonic_ns())
                process = subprocess.Popen(
                    argv,
                    cwd=work,
                    env=environment,
                    stdin=subprocess.DEVNULL,
                    stdout=stdout,
                    stderr=stderr,
                    start_new_session=True,
                )
                _context.update(
                    launcher_process_started=True, stage="native_process_wait"
                )
                sampler = process_module._Sampler(
                    root_pid=process.pid,
                    scratch_root=scratch,
                    interval_seconds=policy["sampling_interval_ms"] / 1000,
                    podman=podman,
                    container_name=measurement_id,
                    environment=environment,
                )
                try:
                    sampler.start()
                    code, timed_out, guard_stopped, guard_reason = (
                        base._wait_for_workflow_process(
                            process=process,
                            state=state,
                            timeout_seconds=policy["wall_time_seconds"]
                            if mode == "authorized"
                            else min(55, policy["wall_time_seconds"]),
                        )
                    )
                finally:
                    sampler.finish()
    finally:
        cleanup_errors = []
        try:
            if process is not None and process.poll() is None:
                base._terminate_process_group(process)
        except Exception as error:
            cleanup_errors.append(type(error).__name__)
        try:
            if broker:
                broker_code, bout, berr = base._finish_process(broker)
                (output / "mage-broker.stdout.log").write_bytes(bout)
                (output / "mage-broker.stderr.log").write_bytes(berr)
        except Exception as error:
            cleanup_errors.append(type(error).__name__)
        for root in (broker_root, controller_root):
            try:
                if root is not None and root.exists():
                    root.rmdir()
            except Exception as error:
                cleanup_errors.append(type(error).__name__)
        try:
            if balance_probe is not None:
                base._write_new(output / "balance-after.json", balance_probe())
        except Exception as error:
            cleanup_errors.append(type(error).__name__)
        _context["cleanup_error_classes"] = cleanup_errors
    if cleanup_errors:
        _context["stage"] = "process_cleanup_or_balance_after"
        raise RuntimeError("owned process cleanup or post-run balance evidence failed")
    _context["stage"] = "resource_telemetry_serialization"
    forced = state.close_unfinished_eda_on_process_exit(
        outcome="timed_out" if timed_out else "failed"
    )
    cpu_after = process_module._cpu_snapshot()
    wall = time.monotonic() - started
    usage = {**counts, "forced_eda_activity_closure_count": forced}
    status = (
        "DIAGNOSTIC_OBSERVED_NOT_BENCHMARK_RESULT"
        if mode != "authorized"
        else "WORKFLOW_RESOURCE_OBSERVED_NOT_EVALUATED"
    )
    observation = {
        "schema_version": "rtlflowbench.complete_public_controller_observation.v2",
        "status": status,
        "mode": mode,
        "measurement_id": measurement_id,
        "campaign_sha256": campaign_sha,
        "row_canonical_sha256": cohort.identity(row),
        "runner_sha256": cohort.sha(Path(__file__)),
        "invocation_sha256": cohort.sha(output / "invocation.json"),
        "process_exit_code": code,
        "process_timed_out": timed_out,
        "controller_guard_stopped": guard_stopped,
        "controller_guard_reason": guard_reason,
        "broker_returncode": broker_code,
        "wall_time_seconds": wall,
        "peak_container_memory_bytes": sampler.peak_container_memory_bytes
        if sampler.container_cgroup_sample_count > 0
        and sampler.peak_container_memory_bytes > 0
        else None,
        "usage_boundary": usage,
        "benchmark_verdict": None,
        "private_evaluator_mounted": False,
        "stdout_sha256": cohort.sha(output / "stdout.log"),
        "stderr_sha256": cohort.sha(output / "stderr.log"),
    }
    base._write_new(output / "observation.json", observation)
    if mode != "authorized":
        ledger = state.build_ledger(
            observed_at=observed_at,
            process_measurement_receipt_sha256=cohort.sha(output / "observation.json"),
        )
        base._validate(base.ACTIVITY_LEDGER_SCHEMA, ledger, "diagnostic ledger")
        base._write_new(output / "diagnostic-activity-ledger.json", ledger)
        return observation
    # Same telemetry wire schema, new exact runner identity. This file is not
    # the old envelope; baseline requests are explicitly separate in campaign.
    user_cpu = max(0.0, cpu_after[0] - cpu_before[0])
    system_cpu = max(0.0, cpu_after[1] - cpu_before[1])
    receipt = {
        "schema_version": "rtlflowbench.workflow_resource_measurement_receipt.v1",
        "observed_at": observed_at,
        "status": "measurement_timeout" if timed_out else "measurement_completed",
        "runner_id": base.RUNNER_ID,
        **measurement,
        "request_sha256": cohort.identity(row),
        "runner_sha256": cohort.sha(Path(__file__)),
        "request_schema_sha256": cohort.sha(
            Path(__file__).with_name(
                "complete_public_measurement_request_v2.schema.json"
            )
        ),
        "receipt_schema_sha256": cohort.sha(base.PROCESS_RECEIPT_SCHEMA),
        "launcher": {
            "kind": "podman_oci",
            "executable_sha256": podman_sha,
            "exit_code": code,
            "timed_out": timed_out,
            "controller_guard_terminated": guard_stopped,
            "controller_guard_reason": guard_reason,
            "outcome": "timed_out"
            if timed_out
            else "exited_zero"
            if code == 0
            else "exited_nonzero",
            "argv_sha256": cohort.identity(argv),
            "argument_count": len(argv),
            "argv_values_recorded": False,
            "launcher_path_recorded": False,
            "runtime_image_argv_index": image_index,
            "runtime_image_binding_enforced_by_measurement_envelope": True,
            "network_policy_declared": "offline",
            "network_policy_enforced_by_measurement_envelope": True,
        },
        "metrics": {
            "wall_time_seconds": round(wall, 6),
            "envelope_child_user_cpu_time_seconds": user_cpu,
            "envelope_child_system_cpu_time_seconds": system_cpu,
            "envelope_child_cpu_time_seconds": user_cpu + system_cpu,
            "peak_launcher_process_tree_rss_bytes": sampler.peak_rss_bytes,
            "peak_launcher_process_tree_count": sampler.peak_process_count,
            "peak_container_cgroup_memory_bytes": sampler.peak_container_memory_bytes,
            "container_cgroup_cpu_time_seconds": sampler.container_cpu_time_seconds,
            "peak_container_cgroup_pids": sampler.peak_container_pids,
            "container_cgroup_sample_count": sampler.container_cgroup_sample_count,
            "container_cgroup_lookup_error_count": sampler.container_cgroup_lookup_error_count,
            "container_cgroup_read_error_count": sampler.container_cgroup_read_error_count,
            "peak_scratch_bytes": sampler.peak_scratch_bytes,
            "peak_eda_concurrency": None,
            "peak_llm_concurrency": None,
            "forced_eda_activity_closure_count": forced,
            "sample_count": sampler.sample_count,
            "sampling_interval_ms": policy["sampling_interval_ms"],
            "scratch_integrity_valid": sampler.scratch_integrity_valid,
        },
        "missing_measurements": ["peak_eda_concurrency", "peak_llm_concurrency"],
        "raw_evidence": {
            "invocation_sha256": cohort.sha(output / "invocation.json"),
            "stdout_sha256": cohort.sha(output / "stdout.log"),
            "stderr_sha256": cohort.sha(output / "stderr.log"),
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
            "launcher_completed_successfully": not timed_out and code == 0,
            "process_tree_measurement_complete": not timed_out
            and sampler.sample_count > 0
            and sampler.scratch_integrity_valid,
            "container_cgroup_measurement_complete": not timed_out
            and sampler.container_cgroup_sample_count > 0
            and sampler.peak_container_memory_bytes > 0
            and sampler.peak_container_pids > 0,
            "full_workflow_resource_calibration_eligible": False,
            "host_capacity_policy_derivation_permitted": False,
            "official_attempts_permitted": False,
        },
        "excluded_claims": [
            "This is resource telemetry, not an RTL verdict, score, physical improvement, or benchmark release.",
            "The retained telemetry wire protocol version does not identify the old execution implementation: runner_sha256 binds this new host entry.",
            "Raw provider content, credentials and private evaluator material are never embedded in this telemetry.",
            "Diagnostics and unresolved native API prerequisites are not scored workflow FAIL or BLOCK results.",
        ],
    }
    base._validate(
        base.PROCESS_RECEIPT_SCHEMA, receipt, "complete-input process telemetry"
    )
    base._write_new(output / "resource-measurement-receipt.json", receipt)
    ledger = state.build_ledger(
        observed_at=observed_at,
        process_measurement_receipt_sha256=cohort.sha(
            output / "resource-measurement-receipt.json"
        ),
    )
    base._validate(base.ACTIVITY_LEDGER_SCHEMA, ledger, "activity ledger")
    base._write_new(output / "activity-ledger.json", ledger)
    activity = base._module(
        base.ACTIVITY_BUILDER, "complete_public_activity_builder"
    ).build_receipt(
        ledger_path=output / "activity-ledger.json", observed_at=observed_at
    )
    base._write_new(output / "activity-concurrency-receipt.json", activity)
    if record_missing_cgroup(
        base=base, output=output, observation=observation, process=receipt
    ):
        return observation
    merged = base._module(
        base.MERGER, "complete_public_resource_merger"
    ).merge_receipts(
        process_receipt_path=output / "resource-measurement-receipt.json",
        activity_receipt_path=output / "activity-concurrency-receipt.json",
        observed_at=observed_at,
    )
    if broker_code not in (None, 0):
        merged["readiness"]["sample_complete"] = False
        merged["readiness"]["sample_eligible_for_resource_cohort"] = False
        merged["status"] = "full_workflow_resource_sample_ineligible"
    base._validate(
        base.MERGED_RECEIPT_SCHEMA, merged, "merged complete-input resource telemetry"
    )
    base._write_new(output / "full-workflow-resource-receipt.json", merged)
    return observation


def main():
    parser = argparse.ArgumentParser(__doc__)
    for name in [
        "repo",
        "campaign",
        "scratch",
        "output",
        "podman",
        "provider-gate",
        "authorization",
    ]:
        parser.add_argument(
            "--" + name,
            type=Path,
            required=name not in {"provider-gate", "authorization"},
        )
    for name in [
        "campaign-sha",
        "measurement-id",
        "podman-sha",
        "provider-gate-sha",
        "authorization-sha",
    ]:
        parser.add_argument(
            "--" + name, required=name not in {"provider-gate-sha", "authorization-sha"}
        )
    parser.add_argument("--mode", choices=sorted(MODES), required=True)
    args = parser.parse_args()
    result = run_slot(
        repo=args.repo,
        campaign_path=args.campaign,
        campaign_sha=args.campaign_sha,
        measurement_id=args.measurement_id,
        mode=args.mode,
        scratch=args.scratch,
        output=args.output,
        podman=args.podman,
        podman_sha=args.podman_sha,
        provider_gate_path=args.provider_gate,
        provider_gate_sha=args.provider_gate_sha,
        authorization_path=args.authorization,
        authorization_sha=args.authorization_sha,
    )
    print(
        json.dumps(
            {
                k: result[k]
                for k in [
                    "status",
                    "mode",
                    "measurement_id",
                    "process_exit_code",
                    "process_timed_out",
                    "usage_boundary",
                ]
            }
        )
    )


if __name__ == "__main__":
    main()
