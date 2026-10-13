"""Complete-input MAGE request projection; no capability-family filter or launch."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from public_input_bundle_v2 import (
    byte_digest,
    classify_output_transport,
    digest,
    load_bundle,
    read_object,
    regular_bytes,
)

SCHEMA = "rtlflowbench.mage_complete_public_request_binding.v2"
NATIVE_RUNNER_SHA256 = (
    "e98720d174df591840cc8b0a348fc99c60e659c4d21d6213e8da1901ee612c02"
)


def native_request(loaded, intake_sha, context_bytes):
    configuration = {
        "projection_version": SCHEMA,
        "public_intake_receipt_sha256": intake_sha,
        "context_sha256": byte_digest(context_bytes),
        "expected_native_runner_sha256": NATIVE_RUNNER_SHA256,
        "submission_contract": loaded["task"]["submission_contract"],
        "public_budget": loaded["task"]["budget"],
    }
    return {
        "schema_version": "rtlflowbench.mage_bridge_request.v1",
        "mode": "development",
        "status": "development_only_not_run",
        "task_id": loaded["task"]["task_id"],
        "configuration_sha256": digest(configuration),
        "configuration": configuration,
        "mage": {
            "top_agent": {
                "golden_tb_path": None,
                "golden_rtl_blackbox_path": None,
                "expected_output_file": "rtl.sv",
            }
        },
        "airtl_run_observed": False,
        "rtl_verdict_produced": False,
        "adapter_ready": False,
        "benchmark_ready": False,
        "prompt": {
            "path": "public_context.json",
            "bytes": len(context_bytes),
            "sha256": byte_digest(context_bytes),
        },
        "public_budget": loaded["task"]["budget"],
    }


def prepare_request(
    *, bundle_root: Path, intake_receipt_sha256: str, output_root: Path
):
    if output_root.exists() or output_root.is_symlink():
        raise FileExistsError("request output must be fresh")
    loaded = load_bundle(bundle_root, expected_receipt_sha256=intake_receipt_sha256)
    context_bytes = regular_bytes(bundle_root / "public_context.json")
    request = native_request(loaded, intake_receipt_sha256, context_bytes)
    native_bytes = (json.dumps(request, indent=2, sort_keys=True) + "\n").encode()
    binding = {
        "schema_version": SCHEMA,
        "status": "COMPLETE_PUBLIC_INPUT_REQUEST_PREPARED_NOT_LAUNCHED",
        "task_id": loaded["task"]["task_id"],
        "public_intake_receipt_sha256": intake_receipt_sha256,
        "public_context_sha256": byte_digest(context_bytes),
        "native_request_sha256": byte_digest(native_bytes),
        "native_output_file": "rtl.sv",
        "output_shape": classify_output_transport(loaded["task"]),
        "full_input_file_count": loaded["receipt"]["summary"]["input_file_count"],
        "provider_calls": 0,
        "eda_calls": 0,
        "native_workflow_verified": False,
        "host_budget_authorization_created": False,
        "adapter_ready": False,
        "benchmark_ready": False,
        "source_sha256": byte_digest(Path(__file__).read_bytes()),
        "exclusions": [
            "No model/task-specific instruction or missing interface is inferred.",
            "This request preserves every source byte in its complete context; compilation needs the separately bound public dependency transport.",
            "Public budget metadata does not replace the campaign controller hard limits or authorize a paid launch.",
        ],
    }
    output_root.mkdir(parents=True)
    for name, payload in [
        ("mage_request.json", native_bytes),
        ("public_context.json", context_bytes),
        (
            "public-request-binding.json",
            (json.dumps(binding, indent=2, sort_keys=True) + "\n").encode(),
        ),
    ]:
        with (output_root / name).open("xb") as stream:
            stream.write(payload)
    return binding


def validate_request(
    *, request_root: Path, bundle_root: Path, expected_binding_sha256: str
):
    if request_root.is_symlink() or not request_root.is_dir():
        raise ValueError("unsafe request root")
    if sorted(x.name for x in request_root.iterdir()) != [
        "mage_request.json",
        "public-request-binding.json",
        "public_context.json",
    ]:
        raise ValueError("undeclared request files")
    binding = read_object(
        request_root / "public-request-binding.json", expected_binding_sha256
    )
    if (
        binding.get("schema_version") != SCHEMA
        or binding.get("status")
        != "COMPLETE_PUBLIC_INPUT_REQUEST_PREPARED_NOT_LAUNCHED"
    ):
        raise ValueError("unsupported request binding")
    loaded = load_bundle(
        bundle_root, expected_receipt_sha256=binding["public_intake_receipt_sha256"]
    )
    context_bytes = regular_bytes(request_root / "public_context.json")
    if (
        context_bytes != regular_bytes(bundle_root / "public_context.json")
        or byte_digest(context_bytes) != binding["public_context_sha256"]
    ):
        raise ValueError("complete public prompt drift")
    native = read_object(
        request_root / "mage_request.json", binding["native_request_sha256"]
    )
    if native != native_request(
        loaded, binding["public_intake_receipt_sha256"], context_bytes
    ):
        raise ValueError("native request is not an exact neutral projection")
    if binding["task_id"] != loaded["task"]["task_id"] or binding[
        "output_shape"
    ] != classify_output_transport(loaded["task"]):
        raise ValueError("native output binding drift")
    for key in [
        "native_workflow_verified",
        "host_budget_authorization_created",
        "adapter_ready",
        "benchmark_ready",
    ]:
        if binding.get(key) is not False:
            raise ValueError(
                "request contains an unearned execution/authorization claim"
            )
    if (
        binding.get("provider_calls") != 0
        or binding.get("eda_calls") != 0
        or binding["full_input_file_count"]
        != loaded["receipt"]["summary"]["input_file_count"]
        or binding["native_output_file"] != "rtl.sv"
    ):
        raise ValueError("request input/accounting disagreement")
    return binding


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--public-input-bundle", type=Path, required=True)
    parser.add_argument("--public-intake-receipt-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = prepare_request(
        bundle_root=args.public_input_bundle,
        intake_receipt_sha256=args.public_intake_receipt_sha256,
        output_root=args.output,
    )
    print(
        json.dumps(
            {
                "status": result["status"],
                "task_id": result["task_id"],
                "native_workflow_verified": False,
            }
        )
    )


if __name__ == "__main__":
    main()
