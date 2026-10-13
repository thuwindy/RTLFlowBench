"""Versioned full-public-input launcher for unmodified external native agents.

Not a campaign authorizer. The host must bind this source closure, request,
image and common controller to a fresh eligible experiment identity.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit

from external_complete_public_request_v2 import validate_request
from public_dependency_transport_v2 import declared_dependency_plan
from public_input_bundle_v2 import (
    byte_digest,
    load_bundle,
    read_object,
    regular_bytes,
    safe_relative,
)

PROFILE = "external-complete-public-native-entry-v2"
COMMON_POLICY = {
    "model": "deepseek-v4-pro",
    "thinking": {"type": "disabled"},
    "temperature": 0,
    "top_p": 1,
    "maximum_output_tokens": 8192,
    "maximum_calls_per_measurement": 4,
    "maximum_input_tokens_per_measurement": 163840,
    "maximum_output_tokens_per_measurement": 16384,
    "maximum_consecutive_identical_requests": 2,
    "maximum_consecutive_identical_errors": 2,
}
RUNTIME_FILES = (
    "native_complete_public_launcher_v2.py",
    "external_complete_public_request_v2.py",
    "public_input_bundle_v2.py",
    "public_interface_projection_v2.py",
    "public_dependency_transport_v2.py",
    "native_public_eda_v2.py",
    "controller_client_public_inputs_v2.py",
    "controller_client.py",
    "public_spec_submission_bridge.py",
    "source_snapshot_binding.py",
    "run_hdlagent_public.py",
)
PINNED = {
    "source_snapshot_binding.py": "44964c68afe84d9568443f7ba03cdd1daa70bc33029f682252472b674589152f",
    "run_hdlagent_public.py": "301b031eb104ff308756a8c8a21591b7cabfa37b00cea5d272457f6dcbf8a355",
    "controller_client.py": "f65d26aa5f93ef39e4c72e6261fffacbd161502f2cbeb7d7e534a95500c86590",
}


def runtime_manifest(root):
    return {
        "schema_version": "rtlflowbench.external_native_launch_runtime.v2",
        "profile": PROFILE,
        "common_policy": COMMON_POLICY,
        "files": {
            name: byte_digest(regular_bytes(root / name)) for name in RUNTIME_FILES
        },
        "host_authorization_created": False,
        "benchmark_ready": False,
    }


def verify_runtime(root, expected_sha256):
    if root.is_symlink() or not root.is_dir():
        raise ValueError("unsafe runtime root")
    if sorted(p.name for p in root.iterdir()) != sorted(
        [*RUNTIME_FILES, "runtime-manifest.json"]
    ):
        raise ValueError("runtime contains missing or undeclared files")
    actual = read_object(root / "runtime-manifest.json", expected_sha256)
    if actual != runtime_manifest(root):
        raise ValueError("runtime source or policy drift")
    return actual


def pinned_module(root, name):
    path = root / name
    if byte_digest(regular_bytes(path)) != PINNED[name]:
        raise ValueError("historical helper source drift")
    module_name = path.stem
    spec = importlib.util.spec_from_file_location(module_name, path)
    result = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = result
    spec.loader.exec_module(result)
    return result


def entry_contract(request, *, dependency_plan, dependency_error):
    workflow = request["workflow_id"]
    if workflow not in {"verilogcoder", "hdlagent"}:
        raise ValueError("unknown workflow entry")
    task_id = request["task_id"]
    if not isinstance(task_id, str) or not re.fullmatch(
        r"[A-Za-z0-9_-]{1,128}", task_id
    ):
        raise ValueError("unsafe public task identifier")
    gaps = list(request["native_api_gaps"])
    if dependency_error is not None:
        gaps.append(
            {"gate": "adapter_public_dependency_contract", "reason": dependency_error}
        )
    compile_limit = None
    output = None
    native = request["native_api_input"]
    if native is not None:
        if workflow == "verilogcoder":
            output = f"generated_verilog/{task_id}_0.v"
        else:
            filename = native["filename"]
            if safe_relative(filename).name != filename or not filename.endswith(
                ".yaml"
            ):
                raise ValueError("unsafe native spec filename")
            name = Path(filename).stem
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
                raise ValueError("unsafe native module name")
            output = f"{name}/{name}.v"
            compile_limit = (
                request["public_budget"]
                .get("eda_call_limits", {})
                .get("compile_or_lint")
            )
            if type(compile_limit) is not int or not 1 <= compile_limit <= 4096:
                raise ValueError("explicit positive public compile budget required")
    return {
        "schema_version": "rtlflowbench.external_native_entry_contract.v2",
        "profile": PROFILE,
        "workflow_id": workflow,
        "task_id": task_id,
        "status": "NATIVE_ENTRY_PREREQUISITES_UNAVAILABLE"
        if gaps
        else "NATIVE_ENTRY_VALIDATED_NOT_EXECUTED",
        "gaps": gaps,
        "public_dependency_plan": dependency_plan,
        "compile_limit": compile_limit,
        "expected_native_output": output,
        "output_shape": request["output_shape"],
        "workflow_executed": False,
        "benchmark_verdict": None,
        "host_authorization_created": False,
    }


def check_controller(client, *, bundle_root, intake_sha256):
    if (
        os.environ.get("RTLFLOWBENCH_PUBLIC_INPUT_BUNDLE") != str(bundle_root)
        or os.environ.get("RTLFLOWBENCH_PUBLIC_INTAKE_SHA256") != intake_sha256
    ):
        raise ValueError("controller public bundle binding mismatch")
    endpoint = os.environ.get("OPENAI_BASE_URL", "")
    try:
        parsed = urlsplit(endpoint)
        port = parsed.port
    except ValueError as error:
        raise ValueError("invalid provider loopback endpoint") from error
    if not (
        endpoint == os.environ.get("RTLFLOWBENCH_PROVIDER_PROXY_BASE_URL")
        and parsed.scheme == "http"
        and parsed.hostname == "127.0.0.1"
        and port is not None
        and 1 <= port <= 65535
        and parsed.path == "/v1"
        and not parsed.username
        and not parsed.password
        and not parsed.query
        and not parsed.fragment
        and os.environ.get("OPENAI_API_KEY") == "rtlflowbench-observed-host-gateway"
    ):
        raise ValueError("observed controller proxy identity missing")
    health = client._rpc(
        os.environ["RTLFLOWBENCH_CONTROLLER_SOCKET"],
        {
            "schema_version": client.PROTOCOL_VERSION,
            "session_id": os.environ["RTLFLOWBENCH_CONTROLLER_SESSION"],
            "operation": "health",
        },
    )
    if (
        health.get("status") != "ready"
        or health.get("provider_runtime") != COMMON_POLICY
    ):
        raise ValueError("common controller policy drift")
    return health


def prepare_work(work):
    if work.exists() or work.is_symlink():
        raise FileExistsError("native work directory must be fresh")
    work.mkdir(parents=True)


def run_verilogcoder(request, *, source, work, agent_class=None, configs=None):
    prepare_work(work)
    for name in ["generated_plans", "generated_verilog", "tool_tmp", "tmp"]:
        (work / name).mkdir()
    sys.path.insert(0, str(source))
    if agent_class is None:
        from hardware_agent.examples.VerilogCoder.verilogcoder import VerilogCoder

        agent_class = VerilogCoder
    if configs is None:
        from autogen import config_list_from_json

        configs = config_list_from_json(env_or_file="OAI_CONFIG_LIST")
    if not configs:
        raise ValueError("native provider configuration unavailable")
    llm_type = "llama3" if "llama3" in configs[0].get("model", "") else "gpt"
    previous = Path.cwd()
    try:
        os.chdir(work)
        agent = agent_class(
            task_planner_llm_config=configs,
            kg_llm_config=configs,
            graph_retrieval_llm_config=configs,
            verilog_writing_llm_config=configs,
            debug_llm_config=configs,
            llm_types={
                key: llm_type
                for key in [
                    "task_planner_llm",
                    "kg_llm",
                    "graph_retrieval_llm",
                    "verilog_writing_llm",
                    "verilog_debug_llm",
                ]
            },
            generate_plan_dir="generated_plans/",
            generate_verilog_dir="generated_verilog/",
            verilog_tmp_dir="tool_tmp/",
        )
        return agent.write_Verilog_module(**request["native_api_input"])
    finally:
        os.chdir(previous)


def run_hdlagent(request, *, entry, source, work, handler_class=None):
    prepare_work(work)
    public = work / "public-input"
    public.mkdir()
    native = request["native_api_input"]
    spec_path = public / native["filename"]
    with spec_path.open("x") as stream:
        json.dump(native["spec"], stream)
        stream.write("\n")
    sys.path.insert(0, str(source / "hdlagent"))
    if handler_class is None:
        from handler import Handler

        handler_class = Handler
    handler = handler_class()
    handler.set_comp_iter(entry["compile_limit"])
    handler.create_agents(
        spath=str(source / "hdlagent/resources"),
        llms=[COMMON_POLICY["model"]],
        lang="Verilog",
        use_spec=True,
        temperature=None,
        w_dir=str(work),
        init_context=[],
        supp_context=False,
        short_context=False,
    )
    handler.spec_run(
        target_spec=str(spec_path),
        lec_iterations=0,
        comp_iterations=entry["compile_limit"],
        w_dir=str(work),
        skip_completed=False,
        skip_successful=False,
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--request-root", type=Path, required=True)
    parser.add_argument("--request-sha256", required=True)
    parser.add_argument("--public-bundle", type=Path, required=True)
    parser.add_argument("--runtime-sha256", required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--source-manifest", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--preflight-only", action="store_true")
    args = parser.parse_args()
    runtime = Path(__file__).resolve().parent
    verify_runtime(runtime, args.runtime_sha256)
    request = validate_request(
        request_root=args.request_root,
        bundle_root=args.public_bundle,
        bridge_source=runtime / "public_spec_submission_bridge.py",
        expected_request_sha256=args.request_sha256,
    )
    intake = request["public_intake_receipt_sha256"]
    loaded = load_bundle(args.public_bundle, expected_receipt_sha256=intake)
    dependency_plan = None
    dependency_error = None
    try:
        dependency_plan = declared_dependency_plan(loaded)
    except ValueError as error:
        dependency_error = str(error)
    entry = entry_contract(
        request, dependency_plan=dependency_plan, dependency_error=dependency_error
    )
    binding = pinned_module(runtime, "source_snapshot_binding.py")
    source = binding.bind_source(
        args.source_root,
        expected_commit=request["upstream_binding"]["commit"],
        expected_manifest_sha256=request["upstream_binding"]["tracked_manifest_sha256"],
        snapshot_manifest=args.source_manifest,
    )
    client = pinned_module(runtime, "controller_client.py")
    check_controller(client, bundle_root=args.public_bundle, intake_sha256=intake)
    entry.update(
        {
            "runtime_manifest_sha256": args.runtime_sha256,
            "request_sha256": args.request_sha256,
            "source_snapshot_verified": True,
            "common_controller_policy_verified": True,
        }
    )
    if args.preflight_only or entry["gaps"]:
        print(json.dumps(entry, sort_keys=True))
        return 0 if not entry["gaps"] else 78
    work = args.work_dir.absolute()
    if request["workflow_id"] == "verilogcoder":
        reported_success = run_verilogcoder(request, source=source, work=work)
    else:
        old = pinned_module(runtime, "run_hdlagent_public.py")
        sys.path.insert(0, str(source / "hdlagent"))
        import agent as agent_module

        old._configure_networkless_deepseek(agent_module, COMMON_POLICY["model"])
        run_hdlagent(request, entry=entry, source=source, work=work)
        reported_success = None
    # Recheck frozen input after native execution. This is an output observation,
    # never an evaluator PASS, and an upstream completion flag is not trusted.
    verify_runtime(runtime, args.runtime_sha256)
    validate_request(
        request_root=args.request_root,
        bundle_root=args.public_bundle,
        bridge_source=runtime / "public_spec_submission_bridge.py",
        expected_request_sha256=args.request_sha256,
    )
    output = work / safe_relative(entry["expected_native_output"])
    if (
        output.is_symlink()
        or not output.is_file()
        or output.resolve().parent != output.parent.resolve()
    ):
        raise ValueError("native workflow did not produce a regular declared output")
    if not output.resolve().is_relative_to(work.resolve()):
        raise ValueError("native output escaped work directory")
    print(
        json.dumps(
            {
                "schema_version": "rtlflowbench.external_native_completion.v2",
                "workflow_id": request["workflow_id"],
                "task_id": request["task_id"],
                "native_method_returned": True,
                "upstream_reported_success": reported_success,
                "output_sha256": byte_digest(regular_bytes(output)),
                "output_path": entry["expected_native_output"],
                "request_sha256": args.request_sha256,
                "runtime_sha256": args.runtime_sha256,
                "benchmark_verdict": None,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
