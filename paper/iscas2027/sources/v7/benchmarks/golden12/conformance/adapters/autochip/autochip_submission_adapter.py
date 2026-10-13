#!/usr/bin/env python3
"""Fail-closed AutoChip output adapter for the public G01 pilot."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator


AUTOCHIP_COMMIT = "3abe0b606d8819dfe548661b0245b55a1ebab40b"
ADAPTER_ROOT = Path(__file__).resolve().parent
RECEIPT_SCHEMA = ADAPTER_ROOT / "autochip_run_receipt.schema.json"
SCAN_ADAPTER = ADAPTER_ROOT.parent / "scan_submission_adapter.py"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load(path: Path, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a regular non-symlink file")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise TypeError(f"{label} must contain one JSON object")
    return value


def _canonical_sha256(value: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _tree_sha256(root: Path) -> str:
    if root.is_symlink() or not root.is_dir():
        raise ValueError("public root must be a regular non-symlink directory")
    entries = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            raise ValueError(f"public root contains symlink: {relative}")
        if path.is_file():
            entries.append(
                {
                    "path": relative,
                    "bytes": path.stat().st_size,
                    "sha256": _sha256(path),
                }
            )
    return hashlib.sha256(
        json.dumps(entries, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    ).hexdigest()


def _scan_module() -> Any:
    spec = importlib.util.spec_from_file_location(
        "rtlflowbench_autochip_scan_adapter", SCAN_ADAPTER
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load neutral scan adapter")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def adapt_autochip_output(
    *,
    task_path: Path,
    autochip_receipt_path: Path,
    expected_autochip_receipt_sha256: str,
    autochip_output_root: Path,
    bundle_root: Path,
    submission_id: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    task_path = task_path.expanduser().resolve(strict=True)
    public_root = task_path.parent
    if task_path != public_root / "external_task.json":
        raise ValueError("task descriptor must be public_root/external_task.json")
    task = _load(task_path, "task descriptor")
    if task.get("task_id") != "G01-common-fifo-spec":
        raise ValueError("AutoChip adapter currently supports only G01")
    if task.get("family") != "spec_to_rtl":
        raise ValueError("AutoChip adapter requires a Spec-to-RTL task")

    receipt_path = autochip_receipt_path.expanduser().resolve(strict=True)
    if _sha256(receipt_path) != expected_autochip_receipt_sha256:
        raise ValueError("AutoChip receipt differs from its trust anchor")
    receipt = _load(receipt_path, "AutoChip receipt")
    schema = _load(RECEIPT_SCHEMA, "AutoChip receipt schema")
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(receipt)
    if receipt["status"] != "completed_public_only_not_evaluated":
        raise ValueError("AutoChip run did not produce an adaptable output")
    if receipt["task_id"] != task["task_id"]:
        raise ValueError("AutoChip receipt task id drifted")
    if receipt["task_descriptor_sha256"] != _canonical_sha256(task):
        raise ValueError("AutoChip task descriptor binding drifted")
    if receipt["public_tree_sha256"] != _tree_sha256(public_root):
        raise ValueError("AutoChip public packet tree binding drifted")
    if receipt["source"]["commit"] != AUTOCHIP_COMMIT:
        raise ValueError("AutoChip source commit is not the audited revision")

    output_root = autochip_output_root.expanduser().resolve(strict=True)
    if output_root.is_symlink() or not output_root.is_dir():
        raise ValueError("AutoChip output root must be a regular directory")
    rtl_path = output_root / receipt["output"]["relative_path"]
    if rtl_path.is_symlink() or not rtl_path.is_file():
        raise ValueError("AutoChip rtl.sv must be a regular non-symlink file")
    if rtl_path.stat().st_size != receipt["output"]["bytes"]:
        raise ValueError("AutoChip rtl.sv byte count differs from receipt")
    if _sha256(rtl_path) != receipt["output"]["sha256"]:
        raise ValueError("AutoChip rtl.sv digest differs from receipt")

    if bundle_root.exists() or bundle_root.is_symlink():
        raise FileExistsError("refusing to overwrite submission bundle root")
    required_files = task["submission_contract"]["required_files"]
    editable_paths = task["submission_contract"]["editable_paths"]
    if len(required_files) != 1 or required_files != editable_paths:
        raise ValueError("AutoChip adapter requires one exact editable file")
    target = bundle_root / required_files[0]
    target.parent.mkdir(parents=True, exist_ok=False)
    target.write_bytes(rtl_path.read_bytes())
    target.chmod(0o600)

    metadata = {
        "schema_version": "rtlflowbench.submission_metadata.v1",
        "submission_id": submission_id,
        "workflow": {
            "name": "AutoChip",
            "version": AUTOCHIP_COMMIT,
            "adapter_name": "rtlflowbench-autochip-public-visible-only",
            "adapter_version": "development-v1",
            "model": receipt["workflow"]["model"],
            "config_sha256": receipt["workflow"]["config_sha256"],
        },
        "attempt": receipt["attempt"],
        "resource_usage": receipt["resource_usage"],
        "network_access_observed": receipt["execution_policy"][
            "workspace_network_access_observed"
        ],
        "claims": [
            "AutoChip used the public packet and public visible test only.",
            "This development submission has not received an offline benchmark verdict.",
        ],
    }
    submission = _scan_module().package_submission(
        task=task, metadata=metadata, bundle_root=bundle_root
    )
    adapter_receipt = {
        "schema_version": "rtlflowbench.autochip_adapter_receipt.v1",
        "status": "adapted_not_evaluated",
        "task_id": task["task_id"],
        "autochip_run_receipt_sha256": expected_autochip_receipt_sha256,
        "autochip_source_commit": AUTOCHIP_COMMIT,
        "submission_sha256": _canonical_sha256(submission),
        "artifact_sha256": _sha256(target),
        "private_evaluator_run": False,
        "benchmark_ready": False,
        "publication_permitted": False,
        "excluded_claims": [
            "Adapter success is not a functional or benchmark PASS.",
            "No hidden evaluator, score, PPA, ranking, or readiness claim is made.",
        ],
    }
    return submission, adapter_receipt


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--task", type=Path, required=True)
    parser.add_argument("--autochip-receipt", type=Path, required=True)
    parser.add_argument("--expected-autochip-receipt-sha256", required=True)
    parser.add_argument("--autochip-output-root", type=Path, required=True)
    parser.add_argument("--bundle-root", type=Path, required=True)
    parser.add_argument("--submission-id", required=True)
    parser.add_argument("--submission-output", type=Path, required=True)
    parser.add_argument("--adapter-receipt-output", type=Path, required=True)
    args = parser.parse_args()
    for output in (args.submission_output, args.adapter_receipt_output):
        if output.exists() or output.is_symlink():
            raise FileExistsError(f"refusing to overwrite output: {output}")
    submission, receipt = adapt_autochip_output(
        task_path=args.task,
        autochip_receipt_path=args.autochip_receipt,
        expected_autochip_receipt_sha256=args.expected_autochip_receipt_sha256,
        autochip_output_root=args.autochip_output_root,
        bundle_root=args.bundle_root,
        submission_id=args.submission_id,
    )
    args.submission_output.write_text(
        json.dumps(submission, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    args.adapter_receipt_output.write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "status": receipt["status"],
                "task_id": receipt["task_id"],
                "private_evaluator_run": False,
                "benchmark_ready": False,
                "publication_permitted": False,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
