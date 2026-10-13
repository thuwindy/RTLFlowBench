"""Byte-complete native input projections, without capability-family routing.

These envelopes are candidates, not authority to start a model. API prerequisites
and output shape remain separate from observed workflow correctness.
"""

import importlib.util
import json
import sys
from pathlib import Path

from public_input_bundle_v2 import (
    byte_digest,
    classify_output_transport,
    load_bundle,
    read_object,
    regular_bytes,
)
from public_interface_projection_v2 import project_interface

SCHEMA = "rtlflowbench.external_complete_public_request.v2"
PUBLIC_HELPER_SHA = "dfbaf86491bab0573b279570d77c71ee5567f29d3e1247db5785123edc151174"
WORKFLOWS = {"verilogcoder", "hdlagent"}


def public_helper(source):
    if byte_digest(regular_bytes(source)) != PUBLIC_HELPER_SHA:
        raise ValueError("reviewed public projection helper source drift")
    spec = importlib.util.spec_from_file_location(
        "pinned_external_public_projection_v2", source
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def render(*, workflow_id, bundle_root, intake_receipt_sha256, bridge_source):
    if workflow_id not in WORKFLOWS:
        raise ValueError("unknown native input protocol")
    loaded = load_bundle(bundle_root, expected_receipt_sha256=intake_receipt_sha256)
    context = regular_bytes(bundle_root / "public_context.json")
    helper = public_helper(bridge_source)
    native_input = None
    projection = None
    gaps = []
    public = bundle_root / "inputs/public"
    if workflow_id == "verilogcoder":
        try:
            # Reuse the reviewed public-only naming/verdict-wire conversion.
            # Do not produce a replacement TB when the public task lacks one.
            testbench, _, projection = helper._visible_testbench(public)
        except ValueError as error:
            gaps.append(
                {"gate": "native_public_testbench_projection", "reason": str(error)}
            )
        else:
            native_input = {
                "cur_task_id": loaded["task"]["task_id"],
                "spec": context.decode("utf-8"),
                "golden_test_bench": testbench.decode("utf-8"),
            }
    else:
        interface_path = public / "spec/interface_spec.json"
        if not interface_path.exists():
            gaps.append(
                {
                    "gate": "native_public_interface_projection",
                    "reason": "No explicit public interface_spec.json; do not infer ports.",
                }
            )
        else:
            interface = json.loads(regular_bytes(interface_path))
            try:
                declaration, projection = project_interface(interface)
            except ValueError as error:
                gaps.append(
                    {"gate": "native_public_interface_projection", "reason": str(error)}
                )
            else:
                native_input = {
                    "filename": projection["native_design_name"] + ".yaml",
                    "spec": {
                        "description": context.decode("utf-8"),
                        "interface": declaration,
                    },
                }
    task = loaded["task"]
    request = {
        "schema_version": SCHEMA,
        "workflow_id": workflow_id,
        "task_id": task["task_id"],
        "status": "COMPLETE_INPUT_PROJECTED_NOT_LAUNCHED"
        if not gaps
        else "COMPLETE_INPUT_NATIVE_API_GAPS_NOT_LAUNCHED",
        "public_intake_receipt_sha256": intake_receipt_sha256,
        "context_path": "public_context.json",
        "context_sha256": byte_digest(context),
        "full_input_file_count": loaded["receipt"]["summary"]["input_file_count"],
        "public_budget": task["budget"],
        "submission_contract": task["submission_contract"],
        "native_api_input": native_input,
        "native_api_gaps": gaps,
        "native_projection": projection,
        "output_shape": classify_output_transport(task),
        "upstream_binding": {
            "commit": helper.WORKFLOWS[workflow_id].commit,
            "tracked_manifest_sha256": helper.WORKFLOWS[
                workflow_id
            ].tracked_manifest_sha256,
        },
        "source_bindings": {
            "request_builder_sha256": byte_digest(Path(__file__).read_bytes()),
            "public_helper_sha256": PUBLIC_HELPER_SHA,
            "interface_projector_sha256": byte_digest(
                regular_bytes(Path(sys.modules[project_interface.__module__].__file__))
            ),
        },
        "private_oracle_included": False,
        "reference_rtl_included": False,
        "provider_calls": 0,
        "eda_calls": 0,
        "workflow_attempts": 0,
        "native_workflow_verified": False,
        "host_budget_authorization_created": False,
        "adapter_ready": False,
        "benchmark_ready": False,
        "benchmark_verdict": None,
    }
    return context, request


def prepare_request(
    *, workflow_id, bundle_root, intake_receipt_sha256, bridge_source, output_root
):
    if output_root.exists() or output_root.is_symlink():
        raise FileExistsError("request output must be fresh")
    context, request = render(
        workflow_id=workflow_id,
        bundle_root=bundle_root,
        intake_receipt_sha256=intake_receipt_sha256,
        bridge_source=bridge_source,
    )
    output_root.mkdir(parents=True)
    for name, payload in [
        ("public_context.json", context),
        (
            "native_input.json",
            (json.dumps(request, indent=2, sort_keys=True) + "\n").encode(),
        ),
    ]:
        with (output_root / name).open("xb") as stream:
            stream.write(payload)
    return request


def validate_request(
    *, request_root, bundle_root, bridge_source, expected_request_sha256
):
    if request_root.is_symlink() or not request_root.is_dir():
        raise ValueError("unsafe request root")
    if sorted(p.name for p in request_root.iterdir()) != [
        "native_input.json",
        "public_context.json",
    ]:
        raise ValueError("undeclared request files")
    actual = read_object(request_root / "native_input.json", expected_request_sha256)
    context, expected = render(
        workflow_id=actual["workflow_id"],
        bundle_root=bundle_root,
        intake_receipt_sha256=actual["public_intake_receipt_sha256"],
        bridge_source=bridge_source,
    )
    if (
        regular_bytes(request_root / "public_context.json") != context
        or actual != expected
    ):
        raise ValueError("native request differs from exact neutral projection")
    return actual
