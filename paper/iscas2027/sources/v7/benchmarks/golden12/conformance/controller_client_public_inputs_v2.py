"""Opt-in full-public-input wrapper around the unchanged observed controller client.

Native tools still pass through the original eda_start/eda_finish accounting.
Only explicit public dependency arguments are projected before the real tool.
No provider parameters, budgets, task data or upstream source are rewritten.
"""

import importlib.util
import json
import os
import sys
from pathlib import Path

from public_input_bundle_v2 import byte_digest, load_bundle, regular_bytes
from public_dependency_transport_v2 import declared_dependency_plan
from native_public_eda_v2 import project_argv

BASE_SHA256 = "f65d26aa5f93ef39e4c72e6261fffacbd161502f2cbeb7d7e534a95500c86590"


def configure_client(
    *,
    base_source: Path,
    bundle_root: Path,
    intake_receipt_sha256: str,
    binding_root: Path,
):
    if byte_digest(regular_bytes(base_source)) != BASE_SHA256:
        raise ValueError("controller client source binding drift")
    load_bundle(bundle_root, expected_receipt_sha256=intake_receipt_sha256)
    if binding_root.is_symlink() or not binding_root.is_dir():
        raise ValueError("binding output must be a pre-existing regular directory")
    spec = importlib.util.spec_from_file_location(
        "rtlflowbench_pinned_controller_input_v2_base", base_source
    )
    client = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = client
    spec.loader.exec_module(client)
    original_run, original_rpc = client._run_eda_shim, client._rpc
    state = {}

    def rpc(socket_path, request):
        response = original_rpc(socket_path, request)
        if state and request.get("operation") in {"eda_start", "eda_finish"}:
            invocation = request["invocation_id"]
            if state.get("invocation_id") not in (None, invocation):
                raise ValueError("multiple EDA invocations in one native shim")
            state["invocation_id"] = invocation
            state[request["operation"] + "_acknowledged"] = True
            if request["operation"] == "eda_finish":
                state["controller_outcome"] = request["outcome"]
        return response

    def run(tool):
        loaded = load_bundle(bundle_root, expected_receipt_sha256=intake_receipt_sha256)
        plan = declared_dependency_plan(loaded)
        original_argv = list(sys.argv)
        effective = project_argv(
            tool, original_argv[1:], plan, bundle_root / "inputs/repository"
        )
        state.clear()
        state.update(
            {
                "tool": tool,
                "invocation_id": None,
                "eda_start_acknowledged": False,
                "eda_finish_acknowledged": False,
                "controller_outcome": None,
            }
        )
        exit_code = None
        try:
            sys.argv = [original_argv[0], *effective]
            exit_code = original_run(tool)
            return exit_code
        finally:
            sys.argv = original_argv
            load_bundle(bundle_root, expected_receipt_sha256=intake_receipt_sha256)
            if state["invocation_id"] is not None:
                value = {
                    "schema_version": "rtlflowbench.native_controller_public_dependency_binding.v2",
                    **state,
                    "exit_code": exit_code,
                    "public_intake_receipt_sha256": intake_receipt_sha256,
                    "base_controller_sha256": BASE_SHA256,
                    "wrapper_sha256": byte_digest(Path(__file__).read_bytes()),
                    "dependency_plan": plan,
                    "native_argv_sha256": byte_digest(
                        json.dumps(original_argv[1:]).encode()
                    ),
                    "effective_argv_sha256": byte_digest(
                        json.dumps(effective).encode()
                    ),
                    "provider_settings_changed": False,
                    "benchmark_verdict": None,
                }
                target = binding_root / (state["invocation_id"] + ".json")
                # The original client owns invocation IDs; never accept a path
                # chosen by a workflow or overwrite an earlier observation.
                if (
                    target.name != state["invocation_id"] + ".json"
                    or "/" in state["invocation_id"]
                ):
                    raise ValueError("unsafe invocation identity")
                with target.open("x") as stream:
                    json.dump(value, stream, indent=2, sort_keys=True)
                    stream.write("\n")
            state.clear()

    client._rpc = rpc
    client._run_eda_shim = run
    # Original shim creation points its subprocess at this versioned wrapper.
    # All other original proxy/health/provider-budget logic remains unchanged.
    client.__file__ = str(Path(__file__).resolve())
    return client


def main():
    base = Path(os.environ["RTLFLOWBENCH_BASE_CONTROLLER_CLIENT"])
    bundle = Path(os.environ["RTLFLOWBENCH_PUBLIC_INPUT_BUNDLE"])
    expected = os.environ["RTLFLOWBENCH_PUBLIC_INTAKE_SHA256"]
    bindings = Path(os.environ["RTLFLOWBENCH_PUBLIC_EDA_BINDING_ROOT"])
    return configure_client(
        base_source=base,
        bundle_root=bundle,
        intake_receipt_sha256=expected,
        binding_root=bindings,
    ).main()


if __name__ == "__main__":
    raise SystemExit(main())
