"""Opt-in broker wrapper; historical broker source stays immutable.

The controller supplies a pinned complete public bundle outside the native
workspace. Every tool call revalidates it. Only explicit public dependencies
are added to Icarus, as full sources (not black boxes), through a read-only
repository mount. Native-generated RTL and TB are never rewritten.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path

from public_input_bundle_v2 import byte_digest, load_bundle
from public_dependency_transport_v2 import (
    declared_dependency_plan,
    extend_iverilog_command,
)

BASE_SHA256 = "b17d727a91e1d575fe3d03020a78d471a39183d762f8360dada8fb920b1ba1ea"


def configure_broker(
    *, base_source: Path, bundle_root: Path, expected_receipt_sha256: str
):
    if base_source.is_symlink() or byte_digest(base_source.read_bytes()) != BASE_SHA256:
        raise ValueError("historical EDA broker source binding drift")
    load_bundle(bundle_root, expected_receipt_sha256=expected_receipt_sha256)
    spec = importlib.util.spec_from_file_location(
        "rtlflowbench_pinned_mage_dependency_base", base_source
    )
    broker = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = broker
    spec.loader.exec_module(broker)
    original_command, original_execute = (
        broker.build_offline_command,
        broker.execute_request,
    )
    # The argv socket protocol is unchanged, so the pinned native shim remains
    # usable. Execution semantics are separately versioned by the broker and
    # dependency-binding receipts; this does not reuse a campaign identity.
    broker.RECEIPT_SCHEMA_VERSION = (
        "rtlflowbench.mage_eda_call_receipt.public_dependencies.v2"
    )
    context = {}

    def build_command(request, *, snapshot_root, output_root, image_digest):
        loaded = load_bundle(
            bundle_root, expected_receipt_sha256=expected_receipt_sha256
        )
        plan = declared_dependency_plan(loaded)
        command = original_command(
            request,
            snapshot_root=snapshot_root,
            output_root=output_root,
            image_digest=image_digest,
        )
        # Keep the public input mount separate from both generated sources and
        # private evaluator storage. The full repository is read-only; only
        # explicitly declared compilation units become compiler arguments.
        repository = bundle_root / "inputs/repository"
        if plan["dependencies"]:
            if repository.is_symlink() or not repository.is_dir():
                raise ValueError("repository mount is missing")
            command[3:3] = [
                "--volume",
                str(repository.resolve()) + ":/public-repository:ro",
            ]
        if request.tool == "iverilog":
            command = extend_iverilog_command(command, plan)
        context.clear()
        context.update(
            {
                "plan": plan,
                "effective_argv_sha256": byte_digest(
                    json.dumps(command, separators=(",", ":")).encode()
                ),
            }
        )
        return command

    def execute_request(request_payload, **kwargs):
        # Reject stale public input before accounting/start, rather than hiding
        # drift behind a compiler outcome. The socket loop is serial.
        load_bundle(bundle_root, expected_receipt_sha256=expected_receipt_sha256)
        context.clear()
        result = original_execute(request_payload, **kwargs)
        load_bundle(bundle_root, expected_receipt_sha256=expected_receipt_sha256)
        receipt_dir = Path(kwargs["evidence_root"]) / result["receipt_id"]
        binding = {
            "schema_version": "rtlflowbench.mage_eda_public_dependency_binding.v2",
            "base_broker_sha256": BASE_SHA256,
            "wrapper_sha256": byte_digest(Path(__file__).read_bytes()),
            "public_intake_receipt_sha256": expected_receipt_sha256,
            "base_call_receipt_sha256": byte_digest(
                (receipt_dir / "receipt.json").read_bytes()
            ),
            "dependency_plan": context["plan"],
            "effective_command_sha256": context["effective_argv_sha256"],
            "tool": request_payload["tool"],
            "provider_environment_forwarded": False,
            "private_evaluator_mounted": False,
            "benchmark_verdict": None,
        }
        with (receipt_dir / "public-dependency-binding.json").open("x") as stream:
            json.dump(binding, stream, indent=2, sort_keys=True)
            stream.write("\n")
        return result

    broker.build_offline_command = build_command
    broker.execute_request = execute_request
    return broker


def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--base-broker", type=Path, required=True)
    parser.add_argument("--public-input-bundle", type=Path, required=True)
    parser.add_argument("--public-intake-receipt-sha256", required=True)
    args, remaining = parser.parse_known_args()
    broker = configure_broker(
        base_source=args.base_broker,
        bundle_root=args.public_input_bundle,
        expected_receipt_sha256=args.public_intake_receipt_sha256,
    )
    sys.argv = [sys.argv[0], *remaining]
    return broker.main()


if __name__ == "__main__":
    raise SystemExit(main())
