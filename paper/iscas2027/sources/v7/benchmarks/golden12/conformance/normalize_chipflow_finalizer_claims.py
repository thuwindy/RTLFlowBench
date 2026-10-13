#!/usr/bin/env python3
"""Normalize the one known legacy ChipFlow finalizer disclaimer.

Early development finalizers placed a negated PASS disclaimer in the neutral
submission's ``claims`` array.  Strict Trust/BLOCK evaluators intentionally
treat claim-shaped PASS text as a claim.  This one-shot compatibility adapter
accepts only that exact legacy value, changes only ``claims`` to ``[]``, and
materializes a new bundle/submission without overwriting the original run.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
from types import ModuleType
from typing import Any

from jsonschema import Draft202012Validator


CONFORMANCE_ROOT = Path(__file__).resolve().parent
ADAPTER_ROOT = CONFORMANCE_ROOT / "adapters"
ADAPTER_PATH = ADAPTER_ROOT / "chipflow_submission_adapter.py"
EXPORT_SCHEMA_PATH = ADAPTER_ROOT / "chipflow_export.schema.json"
SUBMISSION_SCHEMA_PATH = (
    CONFORMANCE_ROOT.parent / "schemas/submission.schema.json"
)
LEGACY_CLAIMS = [
    (
        "ChipFlow attempt finalization only; no RTL evaluator verdict "
        "or benchmark PASS is claimed."
    )
]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def _load(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"not a regular JSON file: {path.name}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} must contain one JSON object")
    return value


def _write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            value,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n",
        encoding="utf-8",
    )


def _load_module(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load module: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def normalize_legacy_finalizer_claims(
    *,
    task_path: Path,
    run_root: Path,
    original_export_path: Path,
    original_submission_path: Path,
    output_root: Path,
) -> dict[str, Any]:
    task_path = task_path.expanduser().resolve(strict=True)
    if run_root.is_symlink():
        raise ValueError("run root must not be a symlink")
    run_root = run_root.expanduser().resolve(strict=True)
    if not run_root.is_dir():
        raise ValueError("run root must be a directory")
    original_export_path = original_export_path.expanduser().resolve(
        strict=True
    )
    original_submission_path = (
        original_submission_path.expanduser().resolve(strict=True)
    )
    output_root = output_root.expanduser().resolve()
    if output_root == run_root or output_root.is_relative_to(run_root):
        raise ValueError(
            "normalization output must stay outside the workflow run"
        )
    if output_root.exists() or output_root.is_symlink():
        raise FileExistsError(
            f"refusing to overwrite output root: {output_root}"
        )

    task = _load(task_path)
    original_export = _load(original_export_path)
    original_submission = _load(original_submission_path)
    export_schema = _load(EXPORT_SCHEMA_PATH)
    submission_schema = _load(SUBMISSION_SCHEMA_PATH)
    Draft202012Validator(export_schema).validate(original_export)
    Draft202012Validator(submission_schema).validate(
        original_submission
    )
    if (
        original_export["claims"] != LEGACY_CLAIMS
        or original_submission["claims"] != LEGACY_CLAIMS
    ):
        raise ValueError(
            "input does not contain the exact known legacy disclaimer"
        )
    if (
        original_export["task_id"] != task["task_id"]
        or original_submission["task_id"] != task["task_id"]
        or original_export["submission_id"]
        != original_submission["submission_id"]
        or original_export["chipflow_run_id"]
        != original_submission["attempt"]["attempt_id"]
    ):
        raise ValueError("legacy export/submission identity disagrees")

    normalized_export = {**original_export, "claims": []}
    output_root.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(
        tempfile.mkdtemp(
            prefix=f".{output_root.name}.",
            dir=output_root.parent,
        )
    )
    committed = False
    try:
        adapter = _load_module(
            ADAPTER_PATH,
            "rtlflowbench_legacy_claim_normalization_adapter",
        )
        normalized_submission, adapter_receipt = (
            adapter.adapt_chipflow_run(
                task=task,
                export=normalized_export,
                run_root=run_root,
                bundle_output=stage / "neutral-submission",
            )
        )
        expected_submission = {
            **original_submission,
            "claims": [],
        }
        if normalized_submission != expected_submission:
            raise ValueError(
                "normalization changed fields other than claims"
            )
        _write(stage / "normalized_export.json", normalized_export)
        _write(
            stage / "normalized_submission.json",
            normalized_submission,
        )
        _write(stage / "adapter_receipt.json", adapter_receipt)
        receipt = {
            "schema_version": (
                "rtlflowbench.chipflow_claim_normalization.v1"
            ),
            "status": "legacy_disclaimer_removed",
            "task_id": task["task_id"],
            "chipflow_run_id": normalized_export["chipflow_run_id"],
            "submission_id": normalized_export["submission_id"],
            "semantic_delta": {
                "field": "claims",
                "before": LEGACY_CLAIMS,
                "after": [],
                "other_fields_value_equivalent": True,
            },
            "source_sha256": {
                "normalizer": _sha256(Path(__file__).resolve()),
                "adapter": _sha256(ADAPTER_PATH),
                "export_schema": _sha256(EXPORT_SCHEMA_PATH),
                "submission_schema": _sha256(
                    SUBMISSION_SCHEMA_PATH
                ),
                "task": _sha256(task_path),
                "original_export": _sha256(original_export_path),
                "original_submission": _sha256(
                    original_submission_path
                ),
            },
            "normalized_sha256": {
                "export": _canonical_sha256(normalized_export),
                "submission": _canonical_sha256(
                    normalized_submission
                ),
                "bundle_files": {
                    item["path"]: item["sha256"]
                    for item in normalized_submission["artifact"][
                        "files"
                    ]
                },
            },
            "private_evaluator_run": False,
            "benchmark_ready": False,
            "chipflow_adapter_ready": False,
            "excluded_claims": [
                "Normalization is not a benchmark verdict.",
                "No model, RTL, usage, or repository evidence changed.",
                "The original legacy artifacts remain preserved.",
            ],
        }
        _write(stage / "normalization_receipt.json", receipt)
        os.replace(stage, output_root)
        committed = True
    finally:
        if not committed and stage.exists():
            shutil.rmtree(stage)
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--task", type=Path, required=True)
    parser.add_argument("--run-root", type=Path, required=True)
    parser.add_argument("--original-export", type=Path, required=True)
    parser.add_argument("--original-submission", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    try:
        receipt = normalize_legacy_finalizer_claims(
            task_path=args.task,
            run_root=args.run_root,
            original_export_path=args.original_export,
            original_submission_path=args.original_submission,
            output_root=args.output_root,
        )
    except Exception as exc:
        print(
            json.dumps(
                {
                    "status": "fail",
                    "error": f"{type(exc).__name__}: {exc}",
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 2
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
