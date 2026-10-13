"""Verify complete public transport, not native capability or benchmark results."""

import argparse
import json
from pathlib import Path

from public_input_bundle_v2 import build_bundle, byte_digest, load_bundle, read_object


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace-set", type=Path, required=True)
    parser.add_argument("--workspace-set-sha256", required=True)
    parser.add_argument("--workspace-parent", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError("audit output must be fresh")
    source = read_object(args.workspace_set, args.workspace_set_sha256)
    if len(source["tasks"]) != 12:
        raise ValueError("expected exactly twelve pinned inputs")
    rows = []
    args.output.mkdir(parents=True)
    for task in source["tasks"]:
        task_id = task["task_id"]
        out = args.output / "bundles" / task_id
        result = build_bundle(
            workspace_root=args.workspace_parent / task_id,
            workspace_set_path=args.workspace_set,
            expected_workspace_set_sha256=args.workspace_set_sha256,
            task_id=task_id,
            output_root=out,
        )
        sha = byte_digest((out / "intake_receipt.json").read_bytes())
        loaded = load_bundle(out, expected_receipt_sha256=sha)
        rows.append(
            {
                "task_id": task_id,
                "status": result["status"],
                "intake_receipt_sha256": sha,
                "summary": result["summary"],
                "family": loaded["task"]["family"],
                "output_transport": loaded["contract"]["native_output_shape"],
                "runtime_verified": False,
            }
        )
    summary = {
        "schema_version": "rtlflowbench.all12_public_transport_audit.v2",
        "status": "COMPLETE_INPUT_TRANSPORT_VERIFIED_ONLY",
        "workspace_set_sha256": args.workspace_set_sha256,
        "tasks": rows,
        "totals": {
            key: sum(row["summary"][key] for row in rows)
            for key in [
                "public_file_count",
                "repository_file_count",
                "input_file_count",
                "input_bytes",
                "omitted_file_count",
            ]
        },
        "attempt_accounting": {
            "provider_calls": 0,
            "eda_calls": 0,
            "workflow_launches": 0,
        },
        "benchmark_results_created": 0,
        "native_execution_verified": False,
    }
    with (args.output / "audit.json").open("x") as stream:
        json.dump(summary, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(
        json.dumps(
            {key: summary[key] for key in ["status", "totals", "attempt_accounting"]}
        )
    )


if __name__ == "__main__":
    main()
