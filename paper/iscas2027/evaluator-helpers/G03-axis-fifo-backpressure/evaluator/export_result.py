#!/usr/bin/env python3
"""Export a sanitized workflow-neutral result from G03 evaluator phases."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
from typing import Any, Callable

from jsonschema import Draft202012Validator


REPO_ROOT = Path(__file__).resolve().parents[6]
PRIVATE_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_ROOT = REPO_ROOT / "benchmarks/golden12/schemas"
VERDICT_MAP = {
    "invalid_submission": "invalid_submission",
    "scope_violation": "scope_violation",
    "infra_error": "infra_error",
    "timeout": "timeout",
    "compile_error": "compile_error",
    "fail_f2p": "fail_f2p",
    "fail_p2p": "fail_p2p",
    "incomplete": "infra_error",
    "pass": "pass",
}
ALL_METRICS = (
    "functional_correctness",
    "protocol_correctness",
    "f2p",
    "p2p",
    "formal_depth",
    "simulation_coverage",
    "mutation_kill_rate",
    "false_positive_rate",
    "area",
    "timing",
    "performance",
    "scope_violation_count",
    "trust_event_count",
    "wall_time_seconds",
    "input_tokens",
    "output_tokens",
    "llm_calls",
    "eda_calls",
    "human_interventions",
)
EDA_CLASSES = ("compile_or_lint", "simulation", "formal", "synthesis")


def _load(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain one JSON object")
    return payload


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical_json_sha256(value: dict[str, Any]) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _validate(
    schema_path: Path,
    payload: dict[str, Any],
) -> None:
    schema = _load(schema_path)
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(payload)


def _load_score() -> Callable[[dict[str, Any]], dict[str, Any]]:
    source = PRIVATE_ROOT / "scoring/score.py"
    spec = importlib.util.spec_from_file_location(
        "rtlflowbench_g03_neutral_score",
        source,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load G03 score source: {source}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module.score_g03


def _metric(
    metric_id: str,
    *,
    evidence: str,
    value: Any = None,
    unit: str | None = None,
    status: str = "measured",
    missing_reason: str | None = None,
) -> dict[str, Any]:
    return {
        "metric_id": metric_id,
        "status": status,
        "value": value if status == "measured" else None,
        "unit": unit,
        "evidence_refs": [evidence] if status == "measured" else [],
        "missing_reason": None if status == "measured" else missing_reason,
    }


def _layer_status(
    hidden: dict[str, Any],
    layer: str,
) -> tuple[str, bool | None]:
    checks = [
        item
        for item in hidden["checks"]
        if item["layer"] == layer and item["stage"] != "compile"
    ]
    if not checks:
        return "not_run", None
    verdicts = {str(item["verdict"]) for item in checks}
    if verdicts == {"pass"}:
        return "pass", True
    if "timeout" in verdicts:
        return "timeout", False
    if "infra_error" in verdicts or "incomplete" in verdicts:
        return "infra_error", False
    return "fail", False


def _oracle_status(verdict: str | None) -> str:
    if verdict == "pass":
        return "pass"
    if verdict == "timeout":
        return "timeout"
    if verdict == "infra_error":
        return "infra_error"
    if verdict is None:
        return "not_run"
    return "fail"


def _oracle_failure_verdict(status: str, failure: str) -> str | None:
    if status in {"pass", "not_run"}:
        return None
    if status in {"timeout", "infra_error"}:
        return status
    return failure


def _sanitize_tool_versions(payload: dict[str, Any]) -> dict[str, Any]:
    sanitized: dict[str, Any] = {}
    for name, item in payload.get("tool_versions", {}).items():
        if isinstance(item, dict):
            sanitized[name] = {
                "status": item.get("status"),
                "version": item.get("version"),
            }
        else:
            sanitized[name] = {
                "status": "available" if item else "unavailable",
                "version": item,
            }
    return sanitized


def _hidden_eda_calls(hidden: dict[str, Any]) -> dict[str, int]:
    calls = {key: 0 for key in EDA_CLASSES}
    for check in hidden.get("checks", []):
        if "process" not in check:
            continue
        stage = check.get("stage")
        count = int(check.get("eda_calls", 1))
        if count < 0:
            raise ValueError("private hidden EDA accounting is negative")
        if stage in {"compile", "structure"}:
            calls["compile_or_lint"] += count
        elif stage in {"simulation", "parameter_rejection"}:
            calls["simulation"] += count
    expected = hidden.get("raw_metrics", {}).get("eda_calls")
    if expected is not None and sum(calls.values()) != int(expected):
        raise ValueError("private hidden EDA accounting is inconsistent")
    return calls


def _phase_eda_calls(
    payload: dict[str, Any] | None,
) -> dict[str, int]:
    if payload is None:
        return {key: 0 for key in EDA_CLASSES}
    calls = payload.get("eda_calls")
    if not isinstance(calls, dict) or set(calls) != set(EDA_CLASSES):
        raise ValueError("private evaluator phase EDA accounting is invalid")
    return {key: int(calls[key]) for key in EDA_CLASSES}


def export_result(
    *,
    task: dict[str, Any],
    submission: dict[str, Any],
    hidden: dict[str, Any],
    build: dict[str, Any] | None,
    coverage: dict[str, Any] | None,
    output_root: Path,
    result_id: str,
    run_id: str,
) -> dict[str, Any]:
    _validate(SCHEMA_ROOT / "task.schema.json", task)
    _validate(SCHEMA_ROOT / "submission.schema.json", submission)
    _validate(PRIVATE_ROOT / "evaluator/result.schema.json", hidden)
    if build is not None:
        _validate(PRIVATE_ROOT / "build/result.schema.json", build)
    if coverage is not None:
        _validate(PRIVATE_ROOT / "coverage/result.schema.json", coverage)
    if task["task_id"] != submission["task_id"]:
        raise ValueError("task and submission task_id values disagree")
    expected_binding = {
        "benchmark_id": task["benchmark_id"],
        "benchmark_version": task["benchmark_version"],
        "task_descriptor_sha256": _canonical_json_sha256(task),
        "public_packet_sha256": task["public_packet"]["sha256"],
    }
    if submission["task_binding"] != expected_binding:
        raise ValueError("submission task content binding disagrees with task")
    if hidden["task_id"] != task["task_id"]:
        raise ValueError("private hidden result task_id disagrees")
    if build is not None and build["task_id"] != task["task_id"]:
        raise ValueError("private build result task_id disagrees")
    if coverage is not None and coverage["task_id"] != task["task_id"]:
        raise ValueError("private coverage result task_id disagrees")

    artifact = next(
        (
            item
            for item in submission["artifact"]["files"]
            if item["path"] == "rtl/golden12_axis_fifo.sv"
        ),
        None,
    )
    if not isinstance(artifact, dict):
        raise ValueError("submission is missing the required G03 wrapper")
    wrapper_sha256 = artifact["sha256"]
    phase_hashes = {
        "hidden": hidden.get("scope_receipt", {}).get("submission_sha256"),
        "build": (
            build.get("scope_receipt", {}).get("wrapper_sha256")
            if build is not None
            else None
        ),
        "coverage": (
            coverage.get("scope_receipt", {}).get("wrapper_sha256")
            if coverage is not None
            else None
        ),
    }
    for phase, observed in phase_hashes.items():
        if observed is not None and observed != wrapper_sha256:
            raise ValueError(
                f"private {phase} result binds a different wrapper"
            )
    if output_root.exists():
        raise FileExistsError(f"refusing to overwrite output: {output_root}")

    hidden_verdict = VERDICT_MAP.get(str(hidden["verdict"]))
    if hidden_verdict is None:
        raise ValueError(f"unsupported hidden verdict: {hidden['verdict']}")
    build_verdict = (
        VERDICT_MAP.get(str(build["verdict"]))
        if build is not None
        else None
    )
    if build is not None and build_verdict is None:
        raise ValueError(f"unsupported build verdict: {build['verdict']}")
    coverage_pass = bool(
        coverage is not None
        and coverage.get("pass") is True
        and coverage.get("status") == "development_measured_not_frozen"
        and coverage.get("coverage", {})
        .get("totals", {})
        .get("line_coverage")
        is not None
    )
    if hidden_verdict != "pass":
        neutral_verdict = hidden_verdict
    elif build_verdict != "pass":
        neutral_verdict = build_verdict or "infra_error"
    elif not coverage_pass:
        neutral_verdict = "infra_error"
    else:
        neutral_verdict = "pass"

    evidence_root = output_root / "evidence"
    evidence_root.mkdir(parents=True)
    scope_path = "evidence/scope.json"
    usage_path = "evidence/resource_usage.json"
    hidden_path = "evidence/hidden_summary.json"
    build_path = "evidence/build_summary.json"
    coverage_path = "evidence/coverage_summary.json"

    scope_receipt = hidden["scope_receipt"]
    scope_status = (
        "pass" if scope_receipt.get("status") == "pass" else "violation"
    )
    scope = {
        "status": scope_status,
        "violation_count": len(scope_receipt.get("violations", [])),
        "violations": list(scope_receipt.get("violations", [])),
        "repository_before_sha256": None,
        "repository_after_sha256": None,
    }
    workflow_usage = submission["resource_usage"]
    hidden_calls = _hidden_eda_calls(hidden)
    build_calls = _phase_eda_calls(build)
    coverage_calls = _phase_eda_calls(coverage)
    eda_calls = {
        key: int(workflow_usage["eda_calls"][key])
        + hidden_calls[key]
        + build_calls[key]
        + coverage_calls[key]
        for key in EDA_CLASSES
    }
    resource_usage = {
        "wall_time_seconds": round(
            float(workflow_usage["wall_time_seconds"])
            + float(hidden.get("wall_time_seconds") or 0)
            + float(build.get("wall_time_seconds") or 0 if build else 0)
            + float(
                coverage.get("wall_time_seconds") or 0
                if coverage
                else 0
            ),
            6,
        ),
        "input_tokens": workflow_usage["input_tokens"],
        "output_tokens": workflow_usage["output_tokens"],
        "llm_calls": workflow_usage["llm_calls"],
        "eda_calls": eda_calls,
        "human_interventions": workflow_usage["human_interventions"],
        "missing_measurements": workflow_usage["missing_measurements"],
    }
    layer_statuses = {
        layer: _layer_status(hidden, layer) for layer in ("f2p", "p2p")
    }
    hidden_summary = {
        "schema_version": "rtlflowbench.g03_sanitized_hidden_summary.v1",
        "task_id": task["task_id"],
        "suite_status": hidden["suite_status"],
        "verdict": hidden["verdict"],
        "layers": {
            layer: status
            for layer, (status, _) in layer_statuses.items()
        },
        "tool_versions": _sanitize_tool_versions(hidden),
        "private_commands_disclosed": False,
        "private_paths_disclosed": False,
    }
    build_summary = {
        "schema_version": "rtlflowbench.g03_sanitized_build_summary.v1",
        "task_id": task["task_id"],
        "status": (
            "pass"
            if build_verdict == "pass"
            else _oracle_status(build_verdict)
        ),
        "verdict": build_verdict,
        "tool_versions": (
            _sanitize_tool_versions(build) if build is not None else {}
        ),
        "generic_synthesis_only": True,
        "physical_ppa_claimed": False,
        "private_commands_disclosed": False,
        "private_paths_disclosed": False,
    }
    coverage_totals = (
        coverage.get("coverage", {}).get("totals", {})
        if coverage is not None
        else {}
    )
    coverage_summary = {
        "schema_version": "rtlflowbench.g03_sanitized_coverage_summary.v1",
        "task_id": task["task_id"],
        "status": (
            "measured_not_frozen"
            if coverage_pass
            else "not_available"
        ),
        "simulation_coverage": (
            coverage_totals["line_coverage"] if coverage_pass else None
        ),
        "line_points": (
            coverage_totals.get("line_points") if coverage_pass else None
        ),
        "line_points_hit": (
            coverage_totals.get("line_points_hit")
            if coverage_pass
            else None
        ),
        "lcov_branch_or_toggle_coverage": (
            coverage_totals.get("lcov_branch_or_toggle_coverage")
            if coverage_pass
            else None
        ),
        "source_scope": [
            "rtl/axis_fifo.v",
            "rtl/golden12_axis_fifo.sv",
        ],
        "testbench_sources_excluded": True,
        "threshold_status": "not_frozen",
        "tool_versions": (
            _sanitize_tool_versions(coverage)
            if coverage is not None
            else {}
        ),
        "private_commands_disclosed": False,
        "private_paths_disclosed": False,
    }
    _write_json(output_root / scope_path, scope)
    _write_json(output_root / usage_path, resource_usage)
    _write_json(output_root / hidden_path, hidden_summary)
    _write_json(output_root / build_path, build_summary)
    _write_json(output_root / coverage_path, coverage_summary)

    build_status = _oracle_status(build_verdict)
    coverage_status = "pass" if coverage_pass else "not_run"
    oracle_results = [
        {
            "oracle_id": "yosys-build",
            "oracle_class": "build",
            "status": build_status,
            "failure_verdict": _oracle_failure_verdict(
                build_status, "compile_error"
            ),
            "reason": "Sanitized Yosys hierarchy/check/synthesis gate.",
            "pass_sentinel_observed": None,
            "evidence_refs": [build_path],
        },
        {
            "oracle_id": "yosys-lint",
            "oracle_class": "lint",
            "status": build_status,
            "failure_verdict": _oracle_failure_verdict(
                build_status, "compile_error"
            ),
            "reason": "Sanitized Yosys read/hierarchy/check gate.",
            "pass_sentinel_observed": None,
            "evidence_refs": [build_path],
        },
        {
            "oracle_id": "f2p-protocol-differential",
            "oracle_class": "differential",
            "status": layer_statuses["f2p"][0],
            "failure_verdict": _oracle_failure_verdict(
                layer_statuses["f2p"][0], "fail_f2p"
            ),
            "reason": "Sanitized seeded backpressure/boundary aggregate.",
            "pass_sentinel_observed": layer_statuses["f2p"][1],
            "evidence_refs": [hidden_path],
        },
        {
            "oracle_id": "p2p-protocol-simulation",
            "oracle_class": "simulation",
            "status": layer_statuses["p2p"][0],
            "failure_verdict": _oracle_failure_verdict(
                layer_statuses["p2p"][0], "fail_p2p"
            ),
            "reason": "Sanitized reset/parameter aggregate.",
            "pass_sentinel_observed": layer_statuses["p2p"][1],
            "evidence_refs": [hidden_path],
        },
        {
            "oracle_id": "simulation-coverage",
            "oracle_class": "coverage",
            "status": coverage_status,
            "failure_verdict": None,
            "reason": (
                "Sanitized DUT/dependency line coverage was measured after "
                "all seven fixed functional sentinels passed."
                if coverage_pass
                else "No matching complete coverage phase was supplied."
            ),
            "pass_sentinel_observed": True if coverage_pass else None,
            "evidence_refs": [coverage_path],
        },
        {
            "oracle_id": "yosys-synthesis",
            "oracle_class": "synthesis",
            "status": build_status,
            "failure_verdict": _oracle_failure_verdict(
                build_status, "compile_error"
            ),
            "reason": "Sanitized generic Yosys synthesis gate; no PPA claim.",
            "pass_sentinel_observed": None,
            "evidence_refs": [build_path],
        },
        {
            "oracle_id": "scope",
            "oracle_class": "scope",
            "status": "pass" if scope_status == "pass" else "fail",
            "failure_verdict": (
                None if scope_status == "pass" else "scope_violation"
            ),
            "reason": "Submission and repository-projection scope aggregate.",
            "pass_sentinel_observed": None,
            "evidence_refs": [scope_path],
        },
    ]

    hidden_metrics = hidden.get("raw_metrics", {})
    metric_values = {
        "functional_correctness": (
            hidden_metrics.get("functional_correctness"),
            "ratio",
            hidden_path,
        ),
        "protocol_correctness": (
            hidden_metrics.get("protocol_correctness"),
            "ratio",
            hidden_path,
        ),
        "f2p": (hidden_metrics.get("f2p"), "ratio", hidden_path),
        "p2p": (hidden_metrics.get("p2p"), "ratio", hidden_path),
        "simulation_coverage": (
            coverage_summary["simulation_coverage"],
            "ratio",
            coverage_path,
        ),
        "scope_violation_count": (
            scope["violation_count"],
            "count",
            scope_path,
        ),
        "trust_event_count": (
            1 if scope_status == "violation" else 0,
            "count",
            scope_path,
        ),
        "wall_time_seconds": (
            resource_usage["wall_time_seconds"],
            "seconds",
            usage_path,
        ),
        "input_tokens": (
            resource_usage["input_tokens"],
            "tokens",
            usage_path,
        ),
        "output_tokens": (
            resource_usage["output_tokens"],
            "tokens",
            usage_path,
        ),
        "llm_calls": (
            resource_usage["llm_calls"],
            "count",
            usage_path,
        ),
        "eda_calls": (sum(eda_calls.values()), "count", usage_path),
        "human_interventions": (
            resource_usage["human_interventions"],
            "count",
            usage_path,
        ),
    }
    raw_metrics = []
    for metric_id in ALL_METRICS:
        if metric_id in metric_values:
            value, unit, evidence = metric_values[metric_id]
            if value is None:
                raw_metrics.append(
                    _metric(
                        metric_id,
                        evidence=evidence,
                        status="not_available",
                        missing_reason=f"{metric_id} was not measured",
                    )
                )
            else:
                raw_metrics.append(
                    _metric(
                        metric_id,
                        evidence=evidence,
                        value=value,
                        unit=unit,
                    )
                )
        elif metric_id in {
            "formal_depth",
            "mutation_kill_rate",
            "false_positive_rate",
        }:
            raw_metrics.append(
                _metric(
                    metric_id,
                    evidence=hidden_path,
                    status="not_applicable",
                    missing_reason=(
                        "Formal is outside this task budget, while mutation "
                        "and false-positive rates are suite-level calibration."
                    ),
                )
            )
        else:
            raw_metrics.append(
                _metric(
                    metric_id,
                    evidence=hidden_path,
                    status="not_available",
                    missing_reason=(
                        "No frozen measurement method exists for this metric."
                    ),
                )
            )

    trust_events = []
    if scope_status == "violation":
        trust_events.append(
            {
                "event_type": "scope_violation",
                "severity": "error",
                "message": "Submission violated the editable-path contract.",
                "evidence_refs": [scope_path],
            }
        )
    if neutral_verdict == "pass":
        private_score = _load_score()(hidden)
        score = {
            "status": private_score["status"],
            "total": private_score["total"],
            "dimensions": private_score["dimensions"],
            "reason": private_score["reason"],
        }
    else:
        score = {
            "status": "not_scored",
            "total": None,
            "dimensions": {},
            "reason": "Non-pass or incomplete evaluator phases are not scored.",
        }
    evidence_files = sorted(evidence_root.glob("*.json"))
    result = {
        "schema_version": "rtlflowbench.result.v1",
        "result_id": result_id,
        "task_id": task["task_id"],
        "submission_id": submission["submission_id"],
        "document_bindings": {
            "task_descriptor_sha256": _canonical_json_sha256(task),
            "submission_sha256": _canonical_json_sha256(submission),
        },
        "run_id": run_id,
        "verdict": neutral_verdict,
        "verdict_reason": (
            "All required development build, protocol, coverage and scope "
            "evaluator phases passed."
            if neutral_verdict == "pass"
            else "Evaluator phases were mapped without promoting a failure."
        ),
        "oracle_results": oracle_results,
        "raw_metrics": raw_metrics,
        "scope": scope,
        "trust_events": trust_events,
        "resource_usage": resource_usage,
        "score": score,
        "evidence_manifest": [
            {
                "path": path.relative_to(output_root).as_posix(),
                "sha256": _sha256(path),
                "bytes": path.stat().st_size,
            }
            for path in evidence_files
        ],
    }
    _validate(SCHEMA_ROOT / "result.schema.json", result)
    rendered = json.dumps(result, sort_keys=True)
    if "/private/" in rendered or "private/evaluator" in rendered:
        raise ValueError("sanitized result leaks an evaluator-private path")
    _write_json(output_root / "result.json", result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--task", type=Path, required=True)
    parser.add_argument("--submission", type=Path, required=True)
    parser.add_argument("--hidden-result", type=Path, required=True)
    parser.add_argument("--build-result", type=Path)
    parser.add_argument("--coverage-result", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--result-id", required=True)
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    try:
        result = export_result(
            task=_load(args.task),
            submission=_load(args.submission),
            hidden=_load(args.hidden_result),
            build=(
                _load(args.build_result)
                if args.build_result is not None
                else None
            ),
            coverage=(
                _load(args.coverage_result)
                if args.coverage_result is not None
                else None
            ),
            output_root=args.output_dir.expanduser().resolve(),
            result_id=args.result_id,
            run_id=args.run_id,
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
