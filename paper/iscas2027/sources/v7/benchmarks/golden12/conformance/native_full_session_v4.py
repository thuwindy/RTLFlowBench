"""Full native session using a pre-authorized host controller, not a solver.

Caller owns authorization, immutable source/environment, isolation, host trace
and canonical resources. This entry cannot authorize spending or publication.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
from types import SimpleNamespace

import native_full_intake_v3 as intake
import native_runner_observer_v3 as observer


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def handoff_destination(output):
    destination = output.with_name(output.name + "-handoff")
    if destination.exists() or destination.is_symlink():
        raise ValueError("fresh_external_handoff_output_required")
    return destination


def load_request(path, expected_sha256):
    if path.is_symlink():
        raise ValueError("session_request_symlink")
    data = path.read_bytes()
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected_sha256:
        raise ValueError("session_request_byte_binding_mismatch")
    value = json.loads(data)
    if not isinstance(value, dict):
        raise ValueError("session_request_object_required")
    return value, actual


def validate_provider_runtime(health, task, *, expected_model):
    runtime = health.get("provider_runtime")
    if (
        health.get("status") != "ready"
        or health.get("schema_version") != observer.base.PROTOCOL
    ):
        raise ValueError("controller_not_ready")
    if not isinstance(runtime, dict) or runtime.get("model") != expected_model:
        raise ValueError("controller_model_mismatch")
    for key, value in {
        "temperature": 0,
        "top_p": 1,
        "thinking": {"type": "disabled"},
    }.items():
        if runtime.get(key) != value:
            raise ValueError("controller_sampling_mismatch")
    budget = task["budget"]
    limits = {
        "maximum_calls_per_measurement": budget["llm_calls"]["maximum"],
        "maximum_input_tokens_per_measurement": budget["tokens"][
            "maximum_input_tokens"
        ],
        "maximum_output_tokens_per_measurement": budget["tokens"][
            "maximum_output_tokens"
        ],
        "maximum_output_tokens": budget["tokens"]["maximum_output_tokens"],
    }
    for key, cap in limits.items():
        value = runtime.get(key)
        if type(value) is not int or type(cap) is not int or not 0 < value <= cap:
            raise ValueError("controller_exceeds_public_budget_or_missing_limit")
    for key in [
        "maximum_consecutive_identical_requests",
        "maximum_consecutive_identical_errors",
    ]:
        if type(runtime.get(key)) is not int or runtime[key] <= 0:
            raise ValueError("controller_stop_rule_missing")
    if (
        runtime["maximum_output_tokens"]
        > runtime["maximum_output_tokens_per_measurement"]
    ):
        raise ValueError("single_call_exceeds_cumulative_output_limit")
    return dict(runtime)


def bind_public_runners(oracle, *, cwd, public_script, eda, tools):
    """Project only the declared public script; never learn code from a model."""
    bindings = []
    direct = {b["path"] for b in tools}
    for command in oracle["commands"]:
        argv = command["argv"]
        executable = eda._resolve_eda_executable(
            argv[0], os.environ.get("PATH", os.defpath)
        )
        if executable is None:
            raise ValueError("public_command_executable_missing")
        if executable in direct:
            continue
        if len(argv) < 2 or (Path(cwd) / argv[1]).resolve() != public_script:
            raise ValueError("public_command_has_no_declared_runner_route")
        bindings.append(
            {
                "executable": executable,
                "executable_sha256": intake.digest(executable),
                "script": str(public_script),
                "script_sha256": intake.digest(public_script),
                "script_index": 1,
                "argv_sha256": observer.base.canonical([executable, *argv[1:]]),
            }
        )
    return bindings


def completed_output_candidate(state):
    """Select only completed executor post-images; capture performs full checks."""
    if state.get("status") == "verified":
        return True
    return (
        state.get("status") == "blocked"
        and state.get("current_stage") == "BLOCKED"
        and (state.get("executor_result") or {}).get("status") == "pass"
        and (state.get("verification_result") or {}).get("status") == "fail"
    )


def run_session(request, *, request_file_sha256):
    if (
        not isinstance(request_file_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", request_file_sha256) is None
    ):
        raise ValueError("request_file_binding_required")
    if request.get("schema_version") != "chipflow.full_native_session_request.v3":
        raise ValueError("unsupported_session_request")
    root = Path(request["source_root"]).resolve(strict=True)
    public = Path(request["public_root"]).resolve(strict=True)
    workspace = Path(request["workspace_source"]).resolve(strict=True)
    output = Path(request["output"]).absolute()
    if (
        output.exists()
        or output.is_symlink()
        or any(output.resolve().is_relative_to(p) for p in [root, public, workspace])
    ):
        raise ValueError("fresh_disjoint_session_output_required")
    handoff_root = handoff_destination(output)
    policy = request["approval_policy"]
    if policy not in {
        "fail_closed_zero_intervention",
        "scope_hash_bound_controller_preapproval",
    }:
        raise ValueError("unsupported_approval_policy")
    attempt = request["attempt_id"]
    if (
        not isinstance(attempt, str)
        or re.fullmatch(r"[a-z0-9][a-z0-9-]{1,80}", attempt) is None
    ):
        raise ValueError("invalid_attempt_id")
    public_binding = intake.tree_binding(public)
    workspace_binding = intake.tree_binding(workspace)
    for actual, expected in [
        (public_binding, request["public_tree_sha256"]),
        (workspace_binding, request["workspace_tree_sha256"]),
    ]:
        if observer.base.canonical(actual) != expected:
            raise ValueError("session_input_binding_drift")
    task = json.loads((public / "external_task.json").read_text())
    client = load(
        "_native_session_controller_client",
        root / "benchmarks/golden12/execution/controller_client.py",
    )
    transport = load(
        "_native_session_transport",
        root / "benchmarks/golden12/execution/observed_controller_transport.py",
    )

    def rpc(value):
        return transport.rpc(Path(request["controller_socket"]), value, timeout=10)

    def health_check():
        health = rpc(
            {
                "schema_version": observer.base.PROTOCOL,
                "session_id": request["session_id"],
                "operation": "health",
            }
        )
        if observer.base.canonical(health) != request["controller_health_sha256"]:
            raise ValueError("controller_policy_binding_drift")
        return health

    runtime = validate_provider_runtime(
        health_check(), task, expected_model=request["model"]
    )
    output.mkdir(mode=0o700)
    intake.save(
        output / "request-binding.json",
        {
            "request_file_sha256": request_file_sha256,
            "request_model_sha256": observer.base.canonical(request),
            "controller_health_sha256": request["controller_health_sha256"],
            "public_tree_sha256": request["public_tree_sha256"],
            "workspace_tree_sha256": request["workspace_tree_sha256"],
        },
    )
    sys.path.insert(0, str(root / "backend/packages/harness"))
    approvals = []
    with client.ProviderProxy(
        socket_path=request["controller_socket"], session_id=request["session_id"]
    ) as proxy:
        config = {
            "models": [
                {
                    "name": "deepseek-chip-reasoner",
                    "use": "langchain_openai:ChatOpenAI",
                    "model": runtime["model"],
                    "api_key": client.PROVIDER_SENTINEL,
                    "base_url": proxy.base_url,
                    "temperature": runtime["temperature"],
                    "top_p": runtime["top_p"],
                    "max_tokens": runtime["maximum_output_tokens"],
                    "max_retries": 0,
                    "timeout": 90,
                    "extra_body": {"thinking": runtime["thinking"]},
                }
            ],
            "sandbox": {"use": "deerflow.sandbox.local:LocalSandboxProvider"},
            "skills": {"path": str(root / "skills")},
            "tools": [
                {
                    "name": "ls",
                    "group": "file",
                    "use": "deerflow.sandbox.tools:ls_tool",
                },
                {
                    "name": "read_file",
                    "group": "file",
                    "use": "deerflow.sandbox.tools:read_file_tool",
                },
            ],
        }
        intake.save(output / "observed-model-config.json", config)
        os.environ["DEER_FLOW_CONFIG_PATH"] = str(output / "observed-model-config.json")
        os.environ["DEER_FLOW_HOME"] = str(output / "deerflow-home")
        from deerflow.chipflow.native_subagents import dispatch_native_chipflow_subagent
        from deerflow.chipflow.tools import eda
        from deerflow.runtime.user_context import set_current_user
        from langchain_core.load.dump import dumpd
        from langgraph.checkpoint.sqlite import SqliteSaver
        from langgraph.types import Command

        set_current_user(SimpleNamespace(id="benchmark-native-session"))
        cfg = {
            "configurable": {
                "thread_id": attempt,
                "run_id": attempt,
                "user_id": "benchmark-native-session",
                "model_name": "deepseek-chip-reasoner",
            },
            "recursion_limit": 60,
        }
        with SqliteSaver.from_conn_string(str(output / "checkpoints.sqlite")) as saver:
            context, initial, graph, oracle, prepared = intake.prepare(
                root=root,
                public_root=public,
                workspace_source=workspace,
                output=output / "intake",
                runnable_config=cfg,
                owner_id="benchmark-native-session",
                thread_id=attempt,
                request_id=attempt,
                dispatch=dispatch_native_chipflow_subagent,
                checkpointer=saver,
            )
            script = json.loads((public / "visible/runner_contract.json").read_text())[
                "runner_path"
            ]
            script = (context.run_dir / "inputs/public" / script).resolve(strict=True)
            bindings = bind_public_runners(
                oracle,
                cwd=context.workspace_root,
                public_script=script,
                eda=eda,
                tools=request["tool_bindings"],
            )
            observer_args = dict(
                eda_module=eda,
                rpc=rpc,
                session_id=request["session_id"],
                expected_source_sha256=intake.digest(eda.__file__),
                tool_bindings=request["tool_bindings"],
                evidence_root=output / "observation",
            )
            selected = (
                observer.RunnerEDAObservation(
                    **observer_args,
                    runner_bindings=bindings,
                    controller_socket=request["controller_socket"],
                    shim_python=request["shim_python"],
                    shim_python_sha256=request["shim_python_sha256"],
                )
                if bindings
                else observer.base.NativeEDAObservation(**observer_args)
            )
            with selected:
                result = graph.invoke(initial, cfg)
                while (
                    result.get("__interrupt__")
                    and policy == "scope_hash_bound_controller_preapproval"
                ):
                    if len(approvals) >= 16:
                        raise ValueError("machine_preapproval_limit_reached")
                    health_check()
                    payload, evidence = intake.load_controller(
                        root
                    )._research_preapproval_payload(
                        graph_result=result,
                        state=dict(graph.get_state(cfg).values),
                        public_root=public,
                        task_id=task["task_id"],
                    )
                    approvals.append(evidence)
                    intake.save(
                        output / ("approval-" + str(len(approvals)) + ".json"), evidence
                    )
                    result = graph.invoke(Command(resume=payload), cfg)
                state = dict(graph.get_state(cfg).values)
                intake.save(output / "native-state.json", dumpd(state))
    health_check()
    if (
        intake.tree_binding(public) != public_binding
        or intake.tree_binding(workspace) != workspace_binding
    ):
        raise ValueError("session_input_drift_during_execution")
    handoff = None
    if completed_output_candidate(state):
        handoff_module = load(
            "_native_session_handoff",
            root / "benchmarks/golden12/conformance/native_artifact_handoff.py",
        )
        scope = task["submission_contract"]
        contract = {
            "schema_version": "chipflow.native_artifact_contract.v1",
            "task_id": task["task_id"],
            "public_input_manifest_sha256": state["public_input_manifest_sha256"],
            "public_scope_relative": "inputs/public/allowed_scope.json",
            "required_files": scope["required_files"],
            "editable_paths": scope["editable_paths"],
            "max_files_changed": scope["max_files_changed"],
            "transport_max_bytes": scope["max_submission_bytes"],
        }
        intake.save(output / "artifact-contract.json", contract)
        handoff_module.capture(
            contract_path=output / "artifact-contract.json",
            work_root=output,
            state_relative="native-state.json",
            mounted_work_root=str(output),
            expected_state_sha256=intake.digest(output / "native-state.json"),
            output_dir=handoff_root,
        )
        handoff = str(handoff_root / "ready")
    receipt = {
        "schema_version": "chipflow.full_native_session.v4",
        "request_file_sha256": request_file_sha256,
        "human_intervention_observation": {
            "mode": "fresh_process_no_human_callback",
            "count": 0,
        },
        "task_id": task["task_id"],
        "attempt_id": attempt,
        "native_status": state.get("status"),
        "native_stage": state.get("current_stage"),
        "judge_decision": state.get("judge_decision"),
        "machine_preapproval_count": len(approvals),
        "approval_policy": policy,
        "approval_evidence_sha256": {
            "approval-" + str(i) + ".json": intake.digest(
                output / ("approval-" + str(i) + ".json")
            )
            for i in range(1, len(approvals) + 1)
        },
        "configured_reviewers": prepared["topology"]["reviewer_ids"],
        "review_records_observed": len(state.get("review_records") or {}),
        "native_state_sha256": intake.digest(output / "native-state.json"),
        "checkpoint_sha256": intake.digest(output / "checkpoints.sqlite"),
        "observation_sha256": intake.digest(output / "observation/observation.json"),
        "artifact_handoff": handoff,
        "neutral_submission_exported": False,
        "benchmark_verdict": None,
        "adapter_ready": False,
        "benchmark_ready": False,
        "resource_measurement": None,
        "provider_usage": None,
        "missing_gates": [
            "host_exec_reconciliation",
            "canonical_provider_resource_chain",
            "neutral_submission_validation",
        ],
        "source_sha256": intake.digest(__file__),
    }
    intake.save(output / "session.json", receipt)
    return receipt


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--request-sha256", required=True)
    args = parser.parse_args()
    value, file_sha256 = load_request(args.request, args.request_sha256)
    run_session(value, request_file_sha256=file_sha256)
