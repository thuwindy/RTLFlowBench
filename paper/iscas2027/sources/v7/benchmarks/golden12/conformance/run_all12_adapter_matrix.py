#!/usr/bin/env python3
"""Calibrate the neutral submission boundary against all Golden-12 tasks.

The generated bundles are deliberately synthetic protocol fixtures.  They are
never evaluated as RTL and cannot produce a benchmark verdict or score.
"""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import sys
import tempfile
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


HERE = Path(__file__).resolve().parent
MATRIX_SCHEMA = HERE / "all12_adapter_matrix.schema.json"
TASK_SCHEMA_RELATIVE = "benchmarks/golden12/schemas/task.schema.json"
MULTI_ADAPTER = HERE / "run_multi_adapter_suite.py"
TASK_IDS = (
    "G01-common-fifo-spec",
    "G02-common-rr-arbiter-spec",
    "G03-axis-fifo-backpressure",
    "G04-wb2axip-split-bridge",
    "G05-picorv32-missing-irq",
    "G06-ibex-debug-csr-exception",
    "G07-ibex-ifetch-error-timing",
    "G08-common-fifo-dv",
    "G09-axis-fifo-dv",
    "G10-serv-area-qor",
    "G11-picorv32-qor",
    "G12-common-cdc-missing-contract",
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"JSON input must be a regular non-symlink file: {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain one JSON object")
    return value


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ValueError(f"could not load module: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _validate(value: dict[str, Any], schema_path: Path, label: str) -> None:
    schema = _load(schema_path)
    Draft202012Validator.check_schema(schema)
    errors = sorted(
        Draft202012Validator(
            schema, format_checker=FormatChecker()
        ).iter_errors(value),
        key=lambda error: tuple(str(part) for part in error.path),
    )
    if errors:
        raise ValueError(f"{label} schema validation failed: {errors[0].message}")


def _safe_relative(value: str) -> Path:
    pure = PurePosixPath(value)
    if pure.is_absolute() or not pure.parts or ".." in pure.parts:
        raise ValueError(f"unsafe submission path: {value}")
    return Path(*pure.parts)


def _load_and_verify_task(
    *, repo_root: Path, task_id: str
) -> tuple[dict[str, Any], str, str, str]:
    descriptor_relative = (
        f"benchmarks/golden12/tasks/{task_id}/public/external_task.json"
    )
    descriptor_path = repo_root / descriptor_relative
    lock_path = (
        repo_root / "benchmarks/golden12/tasks" / task_id
        / "private/admission/candidate.lock.json"
    )
    task = _load(descriptor_path)
    lock = _load(lock_path)
    _validate(task, repo_root / TASK_SCHEMA_RELATIVE, f"{task_id} task")
    if task.get("task_id") != task_id or lock.get("task_id") != task_id:
        raise ValueError(f"task identity mismatch: {task_id}")
    descriptor_sha256 = _sha256(descriptor_path)
    if lock.get("component_sha256", {}).get(descriptor_relative) != descriptor_sha256:
        raise ValueError(f"task descriptor is not current in candidate lock: {task_id}")
    return task, descriptor_relative, descriptor_sha256, _sha256(lock_path)


def _fixture_payload(task_id: str, relative: str) -> bytes:
    suffix = PurePosixPath(relative).suffix.lower()
    marker = f"synthetic submission-only fixture for {task_id}: {relative}"
    if suffix == ".json":
        return (
            json.dumps(
                {
                    "fixture": "synthetic_submission_only",
                    "task_id": task_id,
                    "path": relative,
                },
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
    if suffix == ".py":
        return f"# {marker}; not a verification result\n".encode("utf-8")
    return f"// {marker}; not correct RTL\n".encode("utf-8")


def _build_fixture(task: dict[str, Any], bundle_root: Path) -> None:
    contract = task["submission_contract"]
    required = contract["required_files"]
    editable = set(contract["editable_paths"])
    if not required or not set(required).issubset(editable):
        raise ValueError("required submission paths are not an editable subset")
    for relative in required:
        path = bundle_root / _safe_relative(relative)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(_fixture_payload(task["task_id"], relative))


def _metadata(task_id: str) -> dict[str, Any]:
    return {
        "schema_version": "rtlflowbench.submission_metadata.v1",
        "submission_id": f"all12-conformance-{task_id.lower()}-attempt-1",
        "workflow": {
            "name": "rtlflowbench-all12-conformance-fixture",
            "version": "1",
            "adapter_name": "neutral-matrix-driver",
            "adapter_version": "1",
            "model": {"provider": None, "name": None},
            "config_sha256": _sha256(Path(__file__).resolve()),
        },
        "attempt": {
            "attempt_id": f"{task_id.lower()}-synthetic-attempt-1",
            "attempt_index": 1,
            "repeat_group_id": "all12-neutral-protocol-calibration",
            "seed": 0,
        },
        "resource_usage": {
            "wall_time_seconds": 0.0,
            "input_tokens": 0,
            "output_tokens": 0,
            "llm_calls": 0,
            "eda_calls": {
                "compile_or_lint": 0,
                "simulation": 0,
                "formal": 0,
                "synthesis": 0,
            },
            "human_interventions": 0,
            "missing_measurements": [],
        },
        "network_access_observed": False,
        "claims": [
            "Synthetic submission-protocol fixture; no RTL verdict is claimed."
        ],
    }


def run_all12_adapter_matrix(
    *, repo_root: Path, output_dir: Path, observed_at: str
) -> dict[str, Any]:
    datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
    repo_root = repo_root.expanduser().resolve(strict=True)
    output_dir = output_dir.expanduser().resolve()
    if output_dir.exists() or output_dir.is_symlink():
        raise FileExistsError(f"refusing to overwrite output: {output_dir}")
    suite = _load_module("rtlflowbench_all12_multi_adapter", MULTI_ADAPTER)
    task_results: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="rtlflowbench-all12-fixtures-") as temp:
        fixture_root = Path(temp)
        output_dir.mkdir(parents=True)
        for task_id in TASK_IDS:
            task, descriptor_relative, descriptor_sha256, lock_sha256 = (
                _load_and_verify_task(repo_root=repo_root, task_id=task_id)
            )
            bundle_root = fixture_root / task_id
            bundle_root.mkdir()
            _build_fixture(task, bundle_root)
            task_output = output_dir / "tasks" / task_id
            result = suite.run_multi_adapter_suite(
                task=task,
                metadata=_metadata(task_id),
                bundle_root=bundle_root,
                output_dir=task_output,
                observed_at=observed_at,
            )
            task_results.append(
                {
                    "task_id": task_id,
                    "task_descriptor_relative": descriptor_relative,
                    "task_descriptor_sha256": descriptor_sha256,
                    "candidate_lock_sha256": lock_sha256,
                    "candidate_descriptor_bound": True,
                    "status": result["status"],
                    "submission_sha256": result["submission_sha256"],
                    "check_count": result["summary"]["check_count"],
                    "pass_count": result["summary"]["pass_count"],
                    "fail_count": result["summary"]["fail_count"],
                    "result_relative": (
                        f"tasks/{task_id}/multi-adapter-conformance.json"
                    ),
                }
            )
    all_conformant = bool(
        len(task_results) == len(TASK_IDS)
        and all(
            item["status"] == "multi_adapter_conformant_submission_only"
            and item["candidate_descriptor_bound"] is True
            and item["check_count"] == 15
            and item["pass_count"] == 15
            and item["fail_count"] == 0
            for item in task_results
        )
    )
    result = {
        "schema_version": "rtlflowbench.all12_adapter_matrix.v1",
        "observed_at": observed_at,
        "status": (
            "all12_multi_adapter_conformant_submission_only"
            if all_conformant
            else "fail"
        ),
        "tasks": task_results,
        "summary": {
            "task_count": len(task_results),
            "candidate_bound_task_count": sum(
                item["candidate_descriptor_bound"] for item in task_results
            ),
            "adapter_count_per_task": 2,
            "check_count": sum(item["check_count"] for item in task_results),
            "pass_count": sum(item["pass_count"] for item in task_results),
            "fail_count": sum(item["fail_count"] for item in task_results),
        },
        "source": {
            "matrix_runner_sha256": _sha256(Path(__file__).resolve()),
            "matrix_schema_sha256": _sha256(MATRIX_SCHEMA),
            "multi_adapter_suite_sha256": _sha256(MULTI_ADAPTER),
            "task_schema_sha256": _sha256(repo_root / TASK_SCHEMA_RELATIVE),
        },
        "admission_impact": {
            "all12_external_submission_coverage_candidate": all_conformant,
            "hidden_evaluator_run": False,
            "rtl_verdict_produced": False,
            "workflow_workspace_private_assets_exposed": False,
            "protocol_ready": False,
            "benchmark_ready": False,
            "chipflow_adapter_ready": False,
        },
        "excluded_claims": [
            "Synthetic submission fixtures are not AIRTL workflow runs.",
            "Submission conformance is not RTL correctness or benchmark PASS.",
            "No hidden evaluator, QoR flow, PPA measurement, or score is run.",
            "All-12 descriptor coverage does not freeze or admit the protocol.",
        ],
    }
    _validate(result, MATRIX_SCHEMA, "all12 adapter matrix")
    (output_dir / "all12-adapter-matrix.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--observed-at", required=True)
    args = parser.parse_args()
    try:
        result = run_all12_adapter_matrix(
            repo_root=args.repo_root,
            output_dir=args.output_dir,
            observed_at=args.observed_at,
        )
    except Exception as exc:
        print(
            json.dumps(
                {"status": "fail", "error": f"{type(exc).__name__}: {exc}"},
                indent=2,
                sort_keys=True,
            )
        )
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == (
        "all12_multi_adapter_conformant_submission_only"
    ) else 2


if __name__ == "__main__":
    raise SystemExit(main())
