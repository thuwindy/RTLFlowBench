#!/usr/bin/env python3
"""Finalize one evidence-complete ChipFlow run as a neutral submission.

This is a post-run adapter boundary, not an RTL evaluator.  It refuses to
invent missing usage evidence, expand the task scope, or attach a PASS claim.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
from types import ModuleType
from typing import Any

from jsonschema import Draft202012Validator


CONFORMANCE_ROOT = Path(__file__).resolve().parent
ADAPTER_ROOT = CONFORMANCE_ROOT / "adapters"
TASK_SCHEMA_PATH = CONFORMANCE_ROOT.parent / "schemas" / "task.schema.json"
EXPORT_SCHEMA_PATH = ADAPTER_ROOT / "chipflow_export.schema.json"
COLLECTOR_PATH = (
    CONFORMANCE_ROOT / "collect_chipflow_runtime_usage_events.py"
)
USAGE_BUILDER_PATH = (
    CONFORMANCE_ROOT / "build_chipflow_usage_receipt.py"
)
ADAPTER_PATH = ADAPTER_ROOT / "chipflow_submission_adapter.py"
LEDGER_RELATIVE = Path("benchmark_evidence/usage_events.json")
USAGE_RELATIVE = Path("benchmark_usage_receipt.json")
EXPORT_RELATIVE = Path("benchmark_export.json")
SUBMISSION_RELATIVE = Path("benchmark_submission.json")
ADAPTER_RECEIPT_RELATIVE = Path("benchmark_adapter_receipt.json")


def _load_module(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load local module: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_object(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"not a regular JSON file: {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} must contain one JSON object")
    return value


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _safe_run_file(
    run_root: Path,
    relative: Path,
    *,
    label: str,
) -> tuple[str, Path]:
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError(f"{label} path is not canonical: {relative}")
    candidate = run_root / relative
    if candidate.is_symlink():
        raise ValueError(f"{label} must not be a symlink: {relative}")
    resolved = candidate.resolve(strict=True)
    if not resolved.is_file():
        raise ValueError(f"{label} must be a regular file: {relative}")
    try:
        normalized = resolved.relative_to(run_root).as_posix()
    except ValueError as exc:
        raise ValueError(f"{label} escapes the run root: {relative}") from exc
    current = run_root
    for part in Path(normalized).parts:
        current = current / part
        if current.is_symlink():
            raise ValueError(f"{label} path contains a symlink: {normalized}")
    if normalized != relative.as_posix():
        raise ValueError(f"{label} path is not canonical: {relative}")
    return normalized, resolved


def _safe_run_directory(
    run_root: Path,
    relative: Path,
    *,
    label: str,
) -> Path:
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError(f"{label} path is not canonical: {relative}")
    candidate = run_root / relative
    if candidate.is_symlink():
        raise ValueError(f"{label} must not be a symlink")
    resolved = candidate.resolve(strict=True)
    if not resolved.is_dir() or not resolved.is_relative_to(run_root):
        raise ValueError(f"{label} must be a directory inside the run root")
    current = run_root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError(f"{label} path contains a symlink")
    return resolved


def _write_new(path: Path, value: dict[str, Any]) -> None:
    path = path.expanduser().resolve()
    if path.exists() or path.is_symlink():
        raise FileExistsError(f"refusing to overwrite output: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    stage = path.with_name(f".{path.name}.tmp")
    if stage.exists() or stage.is_symlink():
        raise FileExistsError(f"temporary output already exists: {stage}")
    stage.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.replace(stage, path)


def _preflight_output(path: Path) -> None:
    if path.exists() or path.is_symlink():
        raise FileExistsError(f"refusing to overwrite output: {path}")


def finalize_chipflow_attempt(
    *,
    task_path: Path,
    run_root: Path,
    artifact_source_root: Path,
    config_evidence: Path,
    bundle_output: Path,
    chipflow_run_id: str,
    submission_id: str,
    workflow_version: str,
    adapter_version: str,
    model_provider: str,
    model_name: str,
    attempt_index: int,
    repeat_group_id: str,
    seed: int | None,
    started_at: str,
    completed_at: str,
) -> dict[str, Any]:
    if run_root.is_symlink():
        raise ValueError("ChipFlow run root must not be a symlink")
    run_root = run_root.expanduser().resolve(strict=True)
    if not run_root.is_dir():
        raise ValueError("ChipFlow run root must be a directory")
    for name, value in (
        ("chipflow_run_id", chipflow_run_id),
        ("submission_id", submission_id),
        ("workflow_version", workflow_version),
        ("adapter_version", adapter_version),
        ("model_provider", model_provider),
        ("model_name", model_name),
        ("repeat_group_id", repeat_group_id),
    ):
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{name} must be non-empty")
    if type(attempt_index) is not int or attempt_index < 1:
        raise ValueError("attempt_index must be a positive integer")

    task_path = task_path.expanduser().resolve(strict=True)
    task = _load_object(task_path)
    task_schema = _load_object(TASK_SCHEMA_PATH)
    Draft202012Validator(task_schema).validate(task)
    artifact_root = _safe_run_directory(
        run_root,
        artifact_source_root,
        label="artifact source root",
    )
    config_relative, config_path = _safe_run_file(
        run_root,
        config_evidence,
        label="workflow config evidence",
    )

    artifacts = []
    for submission_path in task["submission_contract"]["required_files"]:
        source = artifact_root / submission_path
        try:
            source_relative = source.relative_to(run_root)
        except ValueError as exc:
            raise ValueError("artifact source escaped the run root") from exc
        normalized, source_path = _safe_run_file(
            run_root,
            source_relative,
            label="submission artifact",
        )
        artifacts.append(
            {
                "source_path": normalized,
                "submission_path": submission_path,
                "sha256": _sha256(source_path),
                "bytes": source_path.stat().st_size,
            }
        )

    output_paths = [
        run_root / LEDGER_RELATIVE,
        run_root / USAGE_RELATIVE,
        run_root / EXPORT_RELATIVE,
        run_root / SUBMISSION_RELATIVE,
        run_root / ADAPTER_RECEIPT_RELATIVE,
    ]
    for path in output_paths:
        _preflight_output(path)
    bundle_output = bundle_output.expanduser().resolve()
    if bundle_output == run_root or bundle_output.is_relative_to(run_root):
        raise ValueError("neutral bundle output must stay outside the run root")
    _preflight_output(bundle_output)

    collector = _load_module(
        COLLECTOR_PATH,
        "rtlflowbench_chipflow_runtime_collector_finalize",
    )
    usage_builder = _load_module(
        USAGE_BUILDER_PATH,
        "rtlflowbench_chipflow_usage_builder_finalize",
    )
    adapter = _load_module(
        ADAPTER_PATH,
        "rtlflowbench_chipflow_submission_adapter_finalize",
    )
    ledger = collector.collect_runtime_usage_events(
        run_root=run_root,
        chipflow_run_id=chipflow_run_id,
    )
    _write_new(run_root / LEDGER_RELATIVE, ledger)
    usage = usage_builder.build_usage_receipt(
        run_root=run_root,
        event_ledger_path=run_root / LEDGER_RELATIVE,
        chipflow_run_id=chipflow_run_id,
        started_at=started_at,
        completed_at=completed_at,
    )
    _write_new(run_root / USAGE_RELATIVE, usage)
    export = {
        "schema_version": "rtlflowbench.chipflow_export.v1",
        "task_id": task["task_id"],
        "chipflow_run_id": chipflow_run_id,
        "submission_id": submission_id,
        "workflow": {
            "name": "ChipFlow",
            "version": workflow_version,
            "adapter_name": "chipflow-run-export",
            "adapter_version": adapter_version,
            "model": {
                "provider": model_provider,
                "name": model_name,
            },
            "config_sha256": _sha256(config_path),
        },
        "attempt": {
            "attempt_id": chipflow_run_id,
            "attempt_index": attempt_index,
            "repeat_group_id": repeat_group_id,
            "seed": seed,
        },
        "usage_receipt": {
            "path": USAGE_RELATIVE.as_posix(),
            "sha256": _sha256(run_root / USAGE_RELATIVE),
        },
        "artifacts": artifacts,
        # Claims are positive workflow assertions consumed by task-specific
        # evaluators.  A negated PASS disclaimer is still claim-shaped text
        # and can correctly trip strict trust parsers.  Keep disclaimers in
        # adapter receipts/excluded_claims; a neutral submission has none.
        "claims": [],
    }
    export_schema = _load_object(EXPORT_SCHEMA_PATH)
    Draft202012Validator(export_schema).validate(export)
    _write_new(run_root / EXPORT_RELATIVE, export)
    submission, adapter_receipt = adapter.adapt_chipflow_run(
        task=task,
        export=export,
        run_root=run_root,
        bundle_output=bundle_output,
    )
    _write_new(run_root / SUBMISSION_RELATIVE, submission)
    adapter_receipt = {
        **adapter_receipt,
        "config_evidence": {
            "path": config_relative,
            "sha256": _sha256(config_path),
        },
    }
    _write_new(run_root / ADAPTER_RECEIPT_RELATIVE, adapter_receipt)
    return {
        "status": "neutral_submission_finalized",
        "task_id": task["task_id"],
        "chipflow_run_id": chipflow_run_id,
        "submission_id": submission_id,
        "usage_event_count": len(ledger["events"]),
        "artifact_count": len(artifacts),
        "ledger_path": LEDGER_RELATIVE.as_posix(),
        "usage_receipt_path": USAGE_RELATIVE.as_posix(),
        "export_path": EXPORT_RELATIVE.as_posix(),
        "submission_path": SUBMISSION_RELATIVE.as_posix(),
        "adapter_receipt_path": ADAPTER_RECEIPT_RELATIVE.as_posix(),
        "bundle_output": str(bundle_output),
        "rtl_evaluator_run": False,
        "benchmark_pass_claimed": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--task", type=Path, required=True)
    parser.add_argument("--run-root", type=Path, required=True)
    parser.add_argument("--artifact-source-root", type=Path, required=True)
    parser.add_argument("--config-evidence", type=Path, required=True)
    parser.add_argument("--bundle-output", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--submission-id", required=True)
    parser.add_argument("--workflow-version", required=True)
    parser.add_argument("--adapter-version", required=True)
    parser.add_argument("--model-provider", required=True)
    parser.add_argument("--model-name", required=True)
    parser.add_argument("--attempt-index", type=int, required=True)
    parser.add_argument("--repeat-group-id", required=True)
    parser.add_argument("--seed", type=int)
    parser.add_argument("--started-at", required=True)
    parser.add_argument("--completed-at", required=True)
    args = parser.parse_args()
    try:
        result = finalize_chipflow_attempt(
            task_path=args.task,
            run_root=args.run_root,
            artifact_source_root=args.artifact_source_root,
            config_evidence=args.config_evidence,
            bundle_output=args.bundle_output,
            chipflow_run_id=args.run_id,
            submission_id=args.submission_id,
            workflow_version=args.workflow_version,
            adapter_version=args.adapter_version,
            model_provider=args.model_provider,
            model_name=args.model_name,
            attempt_index=args.attempt_index,
            repeat_group_id=args.repeat_group_id,
            seed=args.seed,
            started_at=args.started_at,
            completed_at=args.completed_at,
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
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
