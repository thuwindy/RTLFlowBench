"""Full-public-input MAGE entry, delegating design to the unchanged native runner."""

import argparse
import importlib.util
import json
import os
import sys
from pathlib import Path

from mage_complete_public_request_v2 import NATIVE_RUNNER_SHA256, validate_request
from native_complete_public_launcher_v2 import (
    RUNTIME_FILES as EXTERNAL_RUNTIME_FILES,
    check_controller,
    pinned_module,
)
from public_dependency_transport_v2 import declared_dependency_plan
from public_input_bundle_v2 import byte_digest, load_bundle, read_object, regular_bytes

RUNTIME_FILES = (
    *EXTERNAL_RUNTIME_FILES,
    "mage_complete_native_entry_v2.py",
    "mage_controller_client_v2.py",
    "mage_complete_public_request_v2.py",
    "mage_public_dependency_broker_v2.py",
    "mage_eda_broker.py",
)
NATIVE_RUNNER = Path("/usr/local/libexec/rtlflowbench/mage_provider_runner.py")
COMPAT = Path("/usr/local/libexec/rtlflowbench/mage_openai_compat.py")
COMPAT_SHA256 = "006c514d7413d088d3098cf51708d77c8499548633e9d0a007a63f5a2710f0de"
SOURCE_DESCRIPTOR_SHA256 = (
    "90a2cee96659412c07e6b54ea4d133b4820719b63721702cca3d72dc1762e3ba"
)


def runtime_manifest(root):
    return {
        "schema_version": "rtlflowbench.mage_complete_native_runtime.v2",
        "files": {
            name: byte_digest(regular_bytes(root / name)) for name in RUNTIME_FILES
        },
        "accounting_policy": {
            "iverilog": "host_broker_only",
            "vvp": "host_broker_only",
            "yosys": "original_container_controller",
        },
        "native_runner_sha256": NATIVE_RUNNER_SHA256,
        "native_compat_sha256": COMPAT_SHA256,
        "native_source_descriptor_sha256": SOURCE_DESCRIPTOR_SHA256,
        "host_authorization_created": False,
        "benchmark_ready": False,
    }


def verify_runtime(root, expected_sha256):
    if root.is_symlink() or not root.is_dir():
        raise ValueError("unsafe MAGE runtime root")
    if sorted(p.name for p in root.iterdir()) != sorted(
        [*RUNTIME_FILES, "runtime-manifest.json"]
    ):
        raise ValueError("missing or extra MAGE runtime files")
    value = read_object(root / "runtime-manifest.json", expected_sha256)
    if value != runtime_manifest(root):
        raise ValueError("MAGE runtime source/ownership drift")
    return value


def native_arguments(args):
    return {
        "request_root": args.request_root,
        "workspace_root": args.work_root,
        "result_path": args.work_root / "provider_result.json",
        "observed_at": args.observed_at,
        "model": "deepseek-v4-pro",
        "context_window": 1000000,
        "max_tokens": 8192,
        "max_retries": 0,
        "timeout_seconds": 120.0,
        "thinking_mode": "disabled",
        "sim_max_retry": 1,
        "rtl_max_candidates": 1,
        "rtl_selected_candidates": 1,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--request-root", type=Path, required=True)
    parser.add_argument("--request-binding-sha256", required=True)
    parser.add_argument("--public-bundle", type=Path, required=True)
    parser.add_argument("--runtime-sha256", required=True)
    parser.add_argument("--work-root", type=Path, required=True)
    parser.add_argument("--observed-at", required=True)
    parser.add_argument("--preflight-only", action="store_true")
    args = parser.parse_args()
    runtime = Path(__file__).resolve().parent
    verify_runtime(runtime, args.runtime_sha256)
    binding = validate_request(
        request_root=args.request_root,
        bundle_root=args.public_bundle,
        expected_binding_sha256=args.request_binding_sha256,
    )
    intake = binding["public_intake_receipt_sha256"]
    loaded = load_bundle(args.public_bundle, expected_receipt_sha256=intake)
    gaps = []
    plan = None
    try:
        plan = declared_dependency_plan(loaded)
    except ValueError as error:
        gaps.append(
            {"gate": "adapter_public_dependency_contract", "reason": str(error)}
        )
    for path, sha in [
        (NATIVE_RUNNER, NATIVE_RUNNER_SHA256),
        (COMPAT, COMPAT_SHA256),
        (Path("/opt/source_snapshot.json"), SOURCE_DESCRIPTOR_SHA256),
    ]:
        if byte_digest(regular_bytes(path)) != sha:
            raise ValueError("pinned MAGE image source identity drift")
    client = pinned_module(runtime, "controller_client.py")
    check_controller(client, bundle_root=args.public_bundle, intake_sha256=intake)
    if os.environ.get("RTLFLOWBENCH_MAGE_EDA_ACCOUNTING") != "host-broker-v2":
        raise ValueError("MAGE EDA accounting owner not bound")
    spec = importlib.util.spec_from_file_location(
        "pinned_mage_complete_native_runner", NATIVE_RUNNER
    )
    native = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = native
    spec.loader.exec_module(native)
    _, prompt, _ = native.load_public_request(args.request_root)
    if prompt.encode() != regular_bytes(args.public_bundle / "public_context.json"):
        raise ValueError("native MAGE context drift")
    entry = {
        "schema_version": "rtlflowbench.mage_complete_native_entry.v2",
        "task_id": binding["task_id"],
        "runtime_manifest_sha256": args.runtime_sha256,
        "request_binding_sha256": args.request_binding_sha256,
        "status": "NATIVE_ENTRY_PREREQUISITES_UNAVAILABLE"
        if gaps
        else "NATIVE_ENTRY_VALIDATED_NOT_EXECUTED",
        "gaps": gaps,
        "public_dependency_plan": plan,
        "output_shape": binding["output_shape"],
        "workflow_executed": False,
        "benchmark_verdict": None,
        "host_authorization_created": False,
    }
    if args.preflight_only or gaps:
        print(json.dumps(entry, sort_keys=True))
        return 0 if not gaps else 78
    # The original runner requires an empty mounted work root and cwd equality.
    # Preserve its TopAgent algorithm, candidate counts and result semantics.
    result = native.run_provider(**native_arguments(args))
    verify_runtime(runtime, args.runtime_sha256)
    validate_request(
        request_root=args.request_root,
        bundle_root=args.public_bundle,
        expected_binding_sha256=args.request_binding_sha256,
    )
    print(
        json.dumps(
            {
                "status": "NATIVE_RUNNER_RETURNED",
                "task_id": binding["task_id"],
                "native_status": result["status"],
                "benchmark_verdict": None,
                "runtime_manifest_sha256": args.runtime_sha256,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
