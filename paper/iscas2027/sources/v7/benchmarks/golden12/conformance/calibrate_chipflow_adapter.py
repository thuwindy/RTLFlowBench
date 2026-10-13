#!/usr/bin/env python3
"""Calibrate the ChipFlow neutral-submission adapter with synthetic fixtures."""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import tempfile
from pathlib import Path
from typing import Any, Callable

from jsonschema import Draft202012Validator


CONFORMANCE_ROOT = Path(__file__).resolve().parent
REPO_ROOT = CONFORMANCE_ROOT.parents[2]
ADAPTER_ROOT = CONFORMANCE_ROOT / "adapters"
ADAPTER_PATH = ADAPTER_ROOT / "chipflow_submission_adapter.py"
CANONICAL_PATH = CONFORMANCE_ROOT / "package_submission.py"
USAGE_BUILDER_PATH = (
    CONFORMANCE_ROOT / "build_chipflow_usage_receipt.py"
)
CALIBRATION_SCHEMA_PATH = (
    ADAPTER_ROOT / "chipflow_adapter_calibration.schema.json"
)
TASK_PATH = (
    REPO_ROOT
    / "benchmarks/golden12/tasks/G01-common-fifo-spec/"
    "public/external_task.json"
)


def _module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} must contain one JSON object")
    return value


def _write(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _entry(root: Path, relative: str) -> dict[str, Any]:
    path = root / relative
    return {
        "path": relative,
        "sha256": _sha256(path),
        "bytes": path.stat().st_size,
    }


def _fixture(root: Path) -> tuple[dict[str, Any], dict[str, Any], Path]:
    run_root = root / "chipflow-run"
    artifact = run_root / "artifacts/golden12_fifo.sv"
    artifact.parent.mkdir(parents=True)
    artifact.write_text(
        "module golden12_fifo; endmodule\n",
        encoding="utf-8",
    )
    trace = run_root / "evidence/agent_trace.jsonl"
    raw_eda = run_root / "evidence/raw_eda_results.json"
    trace.parent.mkdir(parents=True)
    trace.write_text('{"event":"llm_call"}\n', encoding="utf-8")
    raw_eda.write_text(
        '{"commands":["iverilog","vvp"]}\n',
        encoding="utf-8",
    )
    ledger = {
        "schema_version": "rtlflowbench.chipflow_usage_events.v1",
        "chipflow_run_id": "chipflow-g01-calibration-attempt",
        "collection_evidence_refs": [
            "evidence/agent_trace.jsonl",
            "evidence/raw_eda_results.json",
        ],
        "network_monitor": {
            "evidence_ref": "evidence/agent_trace.jsonl",
            "method": (
                "synthetic bubblewrap plus strace calibration receipt"
            ),
        },
        "events": [
            {
                "event_id": "llm-1",
                "event_type": "llm_call",
                "input_tokens": 100,
                "output_tokens": 20,
                "evidence_refs": ["evidence/agent_trace.jsonl"],
            },
            {
                "event_id": "eda-compile-1",
                "event_type": "eda_compile_or_lint",
                "input_tokens": None,
                "output_tokens": None,
                "evidence_refs": ["evidence/raw_eda_results.json"],
            },
            {
                "event_id": "eda-sim-1",
                "event_type": "eda_simulation",
                "input_tokens": None,
                "output_tokens": None,
                "evidence_refs": ["evidence/raw_eda_results.json"],
            },
        ],
    }
    ledger_path = run_root / "evidence/usage_events.json"
    _write(ledger_path, ledger)
    usage = {
        "schema_version": "rtlflowbench.chipflow_usage_receipt.v1",
        "chipflow_run_id": "chipflow-g01-calibration-attempt",
        "started_at": "2026-07-30T09:00:00+00:00",
        "completed_at": "2026-07-30T09:00:12+00:00",
        "collection_status": {
            "wall_time": "complete",
            "llm_calls": "complete",
            "eda_calls": "complete",
            "human_interventions": "complete",
        },
        "resource_usage": {
            "wall_time_seconds": 12.0,
            "input_tokens": 100,
            "output_tokens": 20,
            "llm_calls": 1,
            "eda_calls": {
                "compile_or_lint": 1,
                "simulation": 1,
                "formal": 0,
                "synthesis": 0,
            },
            "human_interventions": 0,
            "missing_measurements": [],
        },
        "network_monitor": {
            "status": "complete",
            "network_access_observed": False,
            "attempt_count": 0,
            "method": "synthetic bubblewrap plus strace calibration receipt",
        },
        "event_ledger": {
            "path": "evidence/usage_events.json",
            "sha256": _sha256(ledger_path),
        },
        "evidence_manifest": [
            _entry(run_root, "evidence/agent_trace.jsonl"),
            _entry(run_root, "evidence/raw_eda_results.json"),
            _entry(run_root, "evidence/usage_events.json"),
        ],
    }
    usage_path = run_root / "benchmark_usage_receipt.json"
    _write(usage_path, usage)
    export = {
        "schema_version": "rtlflowbench.chipflow_export.v1",
        "task_id": "G01-common-fifo-spec",
        "chipflow_run_id": "chipflow-g01-calibration-attempt",
        "submission_id": "chipflow-g01-calibration-submission",
        "workflow": {
            "name": "ChipFlow",
            "version": "development",
            "adapter_name": "chipflow-run-export",
            "adapter_version": "development",
            "model": {
                "provider": "synthetic-provider",
                "name": "synthetic-model",
            },
            "config_sha256": "1" * 64,
        },
        "attempt": {
            "attempt_id": "chipflow-g01-calibration-attempt",
            "attempt_index": 1,
            "repeat_group_id": "chipflow-g01-calibration-group",
            "seed": 101,
        },
        "usage_receipt": {
            "path": "benchmark_usage_receipt.json",
            "sha256": _sha256(usage_path),
        },
        "artifacts": [
            {
                "source_path": "artifacts/golden12_fifo.sv",
                "submission_path": "rtl/golden12_fifo.sv",
                "sha256": _sha256(artifact),
                "bytes": artifact.stat().st_size,
            }
        ],
        "claims": [
            "Synthetic adapter calibration; no RTL PASS is claimed."
        ],
    }
    return _load(TASK_PATH), export, run_root


def _rewrite_usage(run_root: Path, export: dict[str, Any], usage: dict[str, Any]) -> None:
    path = run_root / "benchmark_usage_receipt.json"
    _write(path, usage)
    export["usage_receipt"]["sha256"] = _sha256(path)


def _mutate_usage_count(
    task: dict[str, Any],
    export: dict[str, Any],
    run_root: Path,
) -> None:
    del task
    path = run_root / "benchmark_usage_receipt.json"
    usage = _load(path)
    usage["resource_usage"]["eda_calls"]["simulation"] = 0
    _rewrite_usage(run_root, export, usage)


def _mutate_network_monitor(
    task: dict[str, Any],
    export: dict[str, Any],
    run_root: Path,
) -> None:
    del task
    usage = _load(run_root / "benchmark_usage_receipt.json")
    usage["network_monitor"]["status"] = "not_observed"
    _rewrite_usage(run_root, export, usage)


def _mutate_network_attempt(
    task: dict[str, Any],
    export: dict[str, Any],
    run_root: Path,
) -> None:
    del task
    ledger_path = run_root / "evidence/usage_events.json"
    ledger = _load(ledger_path)
    ledger["events"].append(
        {
            "event_id": "network-1",
            "event_type": "network_attempt",
            "input_tokens": None,
            "output_tokens": None,
            "evidence_refs": ["evidence/agent_trace.jsonl"],
        }
    )
    _write(ledger_path, ledger)
    usage = _load(run_root / "benchmark_usage_receipt.json")
    usage["event_ledger"]["sha256"] = _sha256(ledger_path)
    for item in usage["evidence_manifest"]:
        if item["path"] == "evidence/usage_events.json":
            item.update(_entry(run_root, "evidence/usage_events.json"))
    usage["network_monitor"]["network_access_observed"] = True
    usage["network_monitor"]["attempt_count"] = 1
    _rewrite_usage(run_root, export, usage)


def _mutate_wall_time(
    task: dict[str, Any],
    export: dict[str, Any],
    run_root: Path,
) -> None:
    del task
    usage = _load(run_root / "benchmark_usage_receipt.json")
    usage["resource_usage"]["wall_time_seconds"] = 11.0
    _rewrite_usage(run_root, export, usage)


def _mutate_usage_digest(
    task: dict[str, Any],
    export: dict[str, Any],
    run_root: Path,
) -> None:
    del task, run_root
    export["usage_receipt"]["sha256"] = "0" * 64


def _mutate_artifact_digest(
    task: dict[str, Any],
    export: dict[str, Any],
    run_root: Path,
) -> None:
    del task, run_root
    export["artifacts"][0]["sha256"] = "0" * 64


def _mutate_symlink(
    task: dict[str, Any],
    export: dict[str, Any],
    run_root: Path,
) -> None:
    del task, export
    artifact = run_root / "artifacts/golden12_fifo.sv"
    target = run_root / "artifacts/actual_fifo.sv"
    artifact.rename(target)
    artifact.symlink_to(target.name)


def _mutate_model_identity(
    task: dict[str, Any],
    export: dict[str, Any],
    run_root: Path,
) -> None:
    del task, run_root
    export["workflow"]["model"]["provider"] = ""


def _run_positive(
    *,
    adapter: Any,
    canonical: Any,
    root: Path,
) -> tuple[str, str]:
    task, export, run_root = _fixture(root)
    bundle = root / "bundle"
    submission, receipt = adapter.adapt_chipflow_run(
        task=task,
        export=export,
        run_root=run_root,
        bundle_output=bundle,
    )
    metadata = {
        "schema_version": "rtlflowbench.submission_metadata.v1",
        "submission_id": export["submission_id"],
        "workflow": export["workflow"],
        "attempt": export["attempt"],
        "resource_usage": submission["resource_usage"],
        "network_access_observed": submission["network_access_observed"],
        "claims": export["claims"],
    }
    independent = canonical.package_submission(
        task=task,
        metadata=metadata,
        bundle_root=bundle,
    )
    accepted = bool(
        submission == independent
        and receipt["status"] == "submission_materialized"
    )
    return (
        "accept" if accepted else "reject",
        (
            "ChipFlow and canonical packagers emitted the same neutral submission."
            if accepted
            else "Positive adapter output diverged from the canonical packager."
        ),
    )


def _run_usage_builder(
    *,
    builder: Any,
    root: Path,
) -> tuple[str, str]:
    _, _, run_root = _fixture(root)
    expected = _load(run_root / "benchmark_usage_receipt.json")
    observed = builder.build_usage_receipt(
        run_root=run_root,
        event_ledger_path=run_root / "evidence/usage_events.json",
        chipflow_run_id="chipflow-g01-calibration-attempt",
        started_at="2026-07-30T09:00:00+00:00",
        completed_at="2026-07-30T09:00:12+00:00",
        network_method="synthetic bubblewrap plus strace calibration receipt",
    )
    matches = observed == expected
    return (
        "accept" if matches else "reject",
        (
            "Typed usage events reproduced the content-addressed usage receipt."
            if matches
            else "Usage receipt builder diverged from the typed fixture."
        ),
    )


def _run_negative(
    *,
    adapter: Any,
    root: Path,
    mutate: Callable[[dict[str, Any], dict[str, Any], Path], None],
) -> tuple[str, str]:
    task, export, run_root = _fixture(root)
    mutate(task, export, run_root)
    try:
        adapter.adapt_chipflow_run(
            task=task,
            export=export,
            run_root=run_root,
            bundle_output=root / "bundle",
        )
    except Exception as exc:
        return "reject", f"{type(exc).__name__}: {exc}"
    return "accept", "Invalid fixture was unexpectedly accepted."


def calibrate(*, observed_at: str) -> dict[str, Any]:
    adapter = _module(ADAPTER_PATH, "rtlflowbench_chipflow_adapter_calibration")
    canonical = _module(CANONICAL_PATH, "rtlflowbench_canonical_calibration")
    builder = _module(USAGE_BUILDER_PATH, "rtlflowbench_usage_builder_calibration")
    definitions = [
        ("accept_canonical_equivalence", "accept", None),
        ("reject_usage_receipt_digest_drift", "reject", _mutate_usage_digest),
        ("reject_artifact_digest_drift", "reject", _mutate_artifact_digest),
        ("reject_symlinked_artifact", "reject", _mutate_symlink),
        ("reject_usage_event_count_mismatch", "reject", _mutate_usage_count),
        ("reject_incomplete_network_monitor", "reject", _mutate_network_monitor),
        ("reject_offline_network_attempt", "reject", _mutate_network_attempt),
        ("reject_wall_time_mismatch", "reject", _mutate_wall_time),
        ("reject_missing_model_identity", "reject", _mutate_model_identity),
    ]
    cases: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="chipflow-adapter-calibration-") as temp:
        root = Path(temp)
        builder_root = root / "case-usage-builder"
        builder_root.mkdir()
        observed, reason = _run_usage_builder(
            builder=builder,
            root=builder_root,
        )
        cases.append(
            {
                "case_id": "accept_usage_builder_roundtrip",
                "expected": "accept",
                "observed": observed,
                "status": "pass" if observed == "accept" else "fail",
                "reason": reason,
            }
        )
        for index, (case_id, expected, mutate) in enumerate(definitions):
            case_root = root / f"case-{index:02d}"
            case_root.mkdir()
            if mutate is None:
                observed, reason = _run_positive(
                    adapter=adapter,
                    canonical=canonical,
                    root=case_root,
                )
            else:
                observed, reason = _run_negative(
                    adapter=adapter,
                    root=case_root,
                    mutate=mutate,
                )
            cases.append(
                {
                    "case_id": case_id,
                    "expected": expected,
                    "observed": observed,
                    "status": "pass" if observed == expected else "fail",
                    "reason": reason,
                }
            )
    pass_count = sum(case["status"] == "pass" for case in cases)
    result = {
        "schema_version": "rtlflowbench.chipflow_adapter_calibration.v1",
        "observed_at": observed_at,
        "status": "pass" if pass_count == len(cases) else "fail",
        "synthetic_conformance_only": True,
        "actual_airtl_run_observed": False,
        "rtl_evaluator_run": False,
        "task_id": "G01-common-fifo-spec",
        "case_count": len(cases),
        "pass_count": pass_count,
        "fail_count": len(cases) - pass_count,
        "cases": cases,
        "source_sha256": {
            str(path.relative_to(REPO_ROOT)): _sha256(path)
            for path in (
                Path(__file__).resolve(),
                ADAPTER_PATH,
                ADAPTER_ROOT / "chipflow_export.schema.json",
                ADAPTER_ROOT / "chipflow_usage_receipt.schema.json",
                ADAPTER_ROOT / "chipflow_usage_events.schema.json",
                CALIBRATION_SCHEMA_PATH,
                CANONICAL_PATH,
                USAGE_BUILDER_PATH,
                TASK_PATH,
            )
        },
        "excluded_claims": [
            "Synthetic adapter calibration is not an AIRTL workflow run.",
            "Adapter conformance is not RTL correctness or benchmark PASS.",
            "The G01 task, ChipFlow adapter, and protocol remain not ready.",
            "No hidden evaluator, EDA benchmark, score, or PPA measurement ran.",
        ],
    }
    schema = _load(CALIBRATION_SCHEMA_PATH)
    Draft202012Validator(schema).validate(result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--observed-at", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.expanduser().resolve()
    if output.exists() or output.is_symlink():
        raise FileExistsError(f"refusing to overwrite output: {output}")
    result = calibrate(observed_at=args.observed_at)
    output.parent.mkdir(parents=True, exist_ok=True)
    _write(output, result)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
