"""Content-bound, provider-free audit of explicit public interface projection."""

import argparse
import json
from pathlib import Path

from public_input_bundle_v2 import byte_digest, load_bundle, read_object
from public_interface_projection_v2 import project_interface


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--intake-audit", type=Path, required=True)
    parser.add_argument("--intake-audit-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError("output must be fresh")
    audit = read_object(args.intake_audit, args.intake_audit_sha256)
    rows = []
    for row in audit["tasks"]:
        bundle = args.intake_audit.parent / "bundles" / row["task_id"]
        load_bundle(bundle, expected_receipt_sha256=row["intake_receipt_sha256"])
        path = bundle / "inputs/public/spec/interface_spec.json"
        result = {
            "task_id": row["task_id"],
            "intake_receipt_sha256": row["intake_receipt_sha256"],
            "native_execution_verified": False,
            "benchmark_verdict": None,
        }
        if not path.exists():
            result.update(
                status="PUBLIC_INTERFACE_NOT_PROVIDED",
                reason="Do not infer an interface or restore intentionally withheld information.",
                projection=None,
            )
        else:
            result["interface_file_sha256"] = byte_digest(path.read_bytes())
            try:
                declaration, projection = project_interface(read_object(path))
                result.update(
                    status="PUBLIC_INTERFACE_PROJECTION_VALIDATED_ONLY",
                    reason=None,
                    projection=projection,
                    declaration_sha256=byte_digest(declaration.encode()),
                )
            except ValueError as exc:
                result.update(
                    status="PUBLIC_INTERFACE_PROJECTION_REJECTED",
                    reason=str(exc),
                    projection=None,
                )
        rows.append(result)
        load_bundle(bundle, expected_receipt_sha256=row["intake_receipt_sha256"])
    result = {
        "schema_version": "rtlflowbench.public_interface_projection_audit.v2",
        "intake_audit_sha256": args.intake_audit_sha256,
        "source_sha256": byte_digest(
            Path(__file__).with_name("public_interface_projection_v2.py").read_bytes()
        ),
        "rows": rows,
        "summary": {
            status: sum(row["status"] == status for row in rows)
            for status in sorted({row["status"] for row in rows})
        },
        "attempt_accounting": {
            "provider_calls": 0,
            "eda_calls": 0,
            "workflow_launches": 0,
        },
        "native_runtime_verified": False,
        "caveat": "Default-width parser compatibility only; unchanged public specs and parameter contracts remain authoritative. No RTL/testbench file is written.",
    }
    args.output.mkdir(parents=True)
    with (args.output / "audit.json").open("x") as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(
        json.dumps(
            {
                "summary": result["summary"],
                "attempt_accounting": result["attempt_accounting"],
            }
        )
    )


if __name__ == "__main__":
    main()
