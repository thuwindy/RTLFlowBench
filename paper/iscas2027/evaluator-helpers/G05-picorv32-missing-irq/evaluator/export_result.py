#!/usr/bin/env python3
"""Export one sanitized workflow-neutral G05 result.

The private composite remains the verdict authority.  This exporter projects
only task-neutral oracle summaries, raw metrics, workflow resource usage, and
content hashes into ``rtlflowbench.result.v1``.  It never copies private
commands, testbench names, absolute paths, or hidden source into the result.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator


TASK_ID = "G05-picorv32-missing-irq"
REPO_ROOT = Path(__file__).resolve().parents[6]
PRIVATE_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_ROOT = REPO_ROOT / "benchmarks/golden12/schemas"
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
GENERIC_VERDICTS = {
    "invalid_instance",
    "infra_error",
    "invalid_submission",
    "scope_violation",
    "blocked",
    "timeout",
    "compile_error",
    "fail_f2p",
    "fail_p2p",
    "fail_formal",
    "fail_ppa",
    "pass",
}


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
    label: str,
) -> None:
    schema = _load(schema_path)
    Draft202012Validator.check_schema(schema)
    errors = sorted(
        Draft202012Validator(schema).iter_errors(payload),
        key=lambda error: list(error.absolute_path),
    )
    if errors:
        first = errors[0]
        location = "/".join(
            str(part) for part in first.absolute_path
        )
        raise ValueError(
            f"{label} schema error at {location or '<root>'}: "
            f"{first.message}"
        )


def _metric(
    metric_id: str,
    *,
    evidence: str,
    value: Any = None,
    unit: str | None = None,
    status: str = "measured",
    missing_reason: str | None = None,
) -> dict[str, Any]:
    measured = status == "measured"
    return {
        "metric_id": metric_id,
        "status": status,
        "value": value if measured else None,
        "unit": unit if measured else None,
        "evidence_refs": [evidence] if measured else [],
        "missing_reason": None if measured else missing_reason,
    }


def _layer_map(composite: dict[str, Any]) -> dict[str, dict[str, Any]]:
    checks = composite.get("checks")
    if not isinstance(checks, list):
        raise ValueError("composite result has no check list")
    layers: dict[str, dict[str, Any]] = {}
    for check in checks:
        if not isinstance(check, dict):
            raise ValueError("composite check is not an object")
        layer = check.get("layer")
        if not isinstance(layer, str) or layer in layers:
            raise ValueError("composite layers are missing or duplicated")
        layers[layer] = check
    expected = {
        "scope",
        "build",
        "f2p",
        "p2p",
        "formal",
        "firmware",
        "coverage",
    }
    if set(layers) != expected:
        raise ValueError("composite layer set is incomplete")
    return layers


def _oracle_status(verdict: str) -> str:
    if verdict == "pass":
        return "pass"
    if verdict == "timeout":
        return "timeout"
    if verdict in {"infra_error", "invalid_evidence", "incomplete"}:
        return "infra_error"
    return "fail"


def _oracle_failure_verdict(
    verdict: str,
    fallback: str,
) -> str | None:
    status = _oracle_status(verdict)
    if status in {"pass", "not_run"}:
        return None
    if status in {"timeout", "infra_error"}:
        return status
    if verdict in GENERIC_VERDICTS and verdict != "pass":
        return verdict
    return fallback


def _submission_artifact(
    submission: dict[str, Any],
) -> dict[str, Any]:
    files = submission.get("artifact", {}).get("files")
    if not isinstance(files, list) or len(files) != 1:
        raise ValueError("G05 submission must contain exactly one artifact")
    artifact = files[0]
    if not isinstance(artifact, dict) or artifact.get("path") != "picorv32.v":
        raise ValueError("G05 submission artifact must be picorv32.v")
    return artifact


def export_result(
    *,
    task: dict[str, Any],
    submission: dict[str, Any],
    composite: dict[str, Any],
    output_root: Path,
    result_id: str,
    run_id: str,
) -> dict[str, Any]:
    _validate(SCHEMA_ROOT / "task.schema.json", task, "task")
    _validate(
        SCHEMA_ROOT / "submission.schema.json",
        submission,
        "submission",
    )
    _validate(
        PRIVATE_ROOT / "evaluator/composite_result.schema.json",
        composite,
        "private composite",
    )
    if (
        task.get("task_id") != TASK_ID
        or submission.get("task_id") != TASK_ID
        or composite.get("task_id") != TASK_ID
    ):
        raise ValueError("G05 task/submission/composite identity mismatch")
    expected_binding = {
        "benchmark_id": task["benchmark_id"],
        "benchmark_version": task["benchmark_version"],
        "task_descriptor_sha256": _canonical_json_sha256(task),
        "public_packet_sha256": task["public_packet"]["sha256"],
    }
    if submission["task_binding"] != expected_binding:
        raise ValueError("submission task content binding disagrees with task")
    if output_root.exists() or output_root.is_symlink():
        raise FileExistsError(f"refusing to overwrite output: {output_root}")
    if not result_id or not run_id:
        raise ValueError("result_id and run_id must be non-empty")
    if composite.get("workflow_workspace_exposed") is not False:
        raise ValueError("private evaluator exposure marker is unsafe")

    artifact = _submission_artifact(submission)
    if artifact.get("sha256") != composite.get("submission_sha256"):
        raise ValueError("submission and composite bind different RTL")
    layers = _layer_map(composite)
    generic_verdict = str(composite["verdict"])
    if generic_verdict in {"invalid_evidence", "incomplete"}:
        generic_verdict = "infra_error"
    if generic_verdict not in GENERIC_VERDICTS:
        raise ValueError(f"unsupported G05 verdict: {generic_verdict}")

    scope_pass = (
        layers["scope"].get("verdict") == "pass"
        and composite.get("scope_receipt", {}).get("status") == "pass"
    )
    scope_violation_count = 0 if scope_pass else 1
    scope_path = "evidence/scope.json"
    usage_path = "evidence/workflow_resource_usage.json"
    evaluator_path = "evidence/evaluator_summary.json"
    isolation_path = "evidence/isolation_summary.json"
    output_root.mkdir(parents=True)
    scope = {
        "status": "pass" if scope_pass else "violation",
        "violation_count": scope_violation_count,
        "violations": (
            []
            if scope_pass
            else ["Private composite reported a scope failure."]
        ),
        "repository_before_sha256": None,
        "repository_after_sha256": None,
    }
    workflow_usage = submission["resource_usage"]
    resource_usage = {
        "wall_time_seconds": workflow_usage["wall_time_seconds"],
        "input_tokens": workflow_usage["input_tokens"],
        "output_tokens": workflow_usage["output_tokens"],
        "llm_calls": workflow_usage["llm_calls"],
        "eda_calls": workflow_usage["eda_calls"],
        "human_interventions": workflow_usage["human_interventions"],
        "missing_measurements": workflow_usage["missing_measurements"],
    }
    raw = composite["raw_metrics"]
    evaluator_summary = {
        "schema_version": "rtlflowbench.g05_sanitized_evaluator_summary.v1",
        "task_id": TASK_ID,
        "status": composite["status"],
        "verdict": composite["verdict"],
        "layers": {
            name: str(check["verdict"])
            for name, check in sorted(layers.items())
        },
        "raw_metrics": {
            "dut_branch_or_toggle_coverage": raw.get(
                "dut_branch_or_toggle_coverage"
            ),
            "dut_line_coverage": raw.get("dut_line_coverage"),
            "formal_depth": raw.get("formal_depth"),
            "formal_properties_passed": raw.get(
                "formal_properties_passed"
            ),
            "hidden_f2p_suites_passed": raw.get(
                "hidden_f2p_suites_passed"
            ),
            "hidden_p2p_suites_passed": raw.get(
                "hidden_p2p_suites_passed"
            ),
            "wrapper_tops_elaborated": raw.get(
                "wrapper_tops_elaborated"
            ),
        },
        "development_score": {
            "status": composite["score"].get("status"),
            "total": composite["score"].get("total"),
            "profile_status": composite["score"].get("profile_status"),
            "frozen": False,
        },
        "private_commands_disclosed": False,
        "private_paths_disclosed": False,
    }
    usage_summary = {
        "schema_version": "rtlflowbench.g05_workflow_resource_usage.v1",
        "task_id": TASK_ID,
        "measurement_scope": "airtl_workflow_only",
        "resource_usage": resource_usage,
        "offline_evaluator_wall_time_included": False,
        "reason": (
            "Legacy G05 formal and firmware layer results did not record "
            "complete wall time; workflow usage remains the comparable "
            "source-locked AIRTL measurement."
        ),
    }
    isolation_summary = {
        "schema_version": "rtlflowbench.g05_isolation_summary.v1",
        "task_id": TASK_ID,
        "network_access_observed": submission[
            "network_access_observed"
        ],
        "workflow_workspace_exposed": False,
        "private_evaluator_after_neutral_finalization": True,
        "private_commands_disclosed": False,
        "private_paths_disclosed": False,
    }
    _write_json(output_root / scope_path, scope)
    _write_json(output_root / usage_path, usage_summary)
    _write_json(output_root / evaluator_path, evaluator_summary)
    _write_json(output_root / isolation_path, isolation_summary)

    def oracle(
        oracle_id: str,
        oracle_class: str,
        layer: str,
        reason: str,
        sentinel: bool | None,
        failure: str,
    ) -> dict[str, Any]:
        verdict = str(layers[layer]["verdict"])
        return {
            "oracle_id": oracle_id,
            "oracle_class": oracle_class,
            "status": _oracle_status(verdict),
            "failure_verdict": _oracle_failure_verdict(verdict, failure),
            "reason": reason,
            "pass_sentinel_observed": sentinel,
            "evidence_refs": [evaluator_path],
        }

    oracle_results = [
        oracle(
            "wrapper-elaboration",
            "build",
            "build",
            "Sanitized three-top wrapper elaboration result.",
            None,
            "compile_error",
        ),
        oracle(
            "compile-lint",
            "lint",
            "build",
            "Sanitized compile/elaboration structural gate.",
            None,
            "compile_error",
        ),
        oracle(
            "held-out-service-edge-repair",
            "differential",
            "f2p",
            "Sanitized held-out F2P repository-repair check.",
            layers["f2p"]["verdict"] == "pass",
            "fail_f2p",
        ),
        oracle(
            "held-out-preservation",
            "simulation",
            "p2p",
            "Sanitized three-suite P2P regression aggregate.",
            layers["p2p"]["verdict"] == "pass",
            "fail_p2p",
        ),
        oracle(
            "bounded-irq-safety",
            "formal",
            "formal",
            "Sanitized bounded formal property aggregate.",
            None,
            "fail_formal",
        ),
        oracle(
            "upstream-firmware",
            "simulation",
            "firmware",
            "Sanitized pinned firmware preservation result.",
            layers["firmware"]["verdict"] == "pass",
            "fail_p2p",
        ),
        oracle(
            "dut-simulation-coverage",
            "coverage",
            "coverage",
            "Sanitized submitted-DUT coverage observation.",
            layers["coverage"]["verdict"] == "pass",
            "fail_p2p",
        ),
        {
            "oracle_id": "scope",
            "oracle_class": "scope",
            "status": "pass" if scope_pass else "fail",
            "failure_verdict": None if scope_pass else "scope_violation",
            "reason": "Sanitized one-file submission scope aggregate.",
            "pass_sentinel_observed": None,
            "evidence_refs": [scope_path],
        },
    ]

    trust_events = []
    if not scope_pass:
        trust_events.append(
            {
                "event_type": "scope_violation",
                "severity": "error",
                "message": (
                    "Submission violated the one-file scope contract."
                ),
                "evidence_refs": [scope_path],
            }
        )

    pass_result = generic_verdict == "pass"
    measured = {
        "functional_correctness": (
            1.0 if pass_result else 0.0,
            "ratio",
            evaluator_path,
        ),
        "f2p": (
            1.0 if layers["f2p"]["verdict"] == "pass" else 0.0,
            "ratio",
            evaluator_path,
        ),
        "p2p": (
            1.0 if layers["p2p"]["verdict"] == "pass" else 0.0,
            "ratio",
            evaluator_path,
        ),
        "formal_depth": (
            raw.get("formal_depth"),
            "cycles",
            evaluator_path,
        ),
        "simulation_coverage": (
            raw.get("dut_line_coverage"),
            "ratio",
            evaluator_path,
        ),
        "scope_violation_count": (
            scope_violation_count,
            "count",
            scope_path,
        ),
        "trust_event_count": (
            len(trust_events),
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
        "eda_calls": (
            sum(resource_usage["eda_calls"].values()),
            "count",
            usage_path,
        ),
        "human_interventions": (
            resource_usage["human_interventions"],
            "count",
            usage_path,
        ),
    }
    not_applicable = {
        "protocol_correctness": (
            "G05 is a repository repair task, not a protocol task."
        ),
        "mutation_kill_rate": (
            "Mutation kill rate is suite-level calibration, not a "
            "per-submission G05 measurement."
        ),
        "false_positive_rate": (
            "False-positive rate is suite-level calibration, not a "
            "per-submission G05 measurement."
        ),
    }
    not_available = {
        "area": "No frozen G05 physical area flow exists.",
        "timing": "No frozen G05 timing flow exists.",
        "performance": "No frozen G05 performance flow exists.",
    }
    raw_metrics: list[dict[str, Any]] = []
    for metric_id in ALL_METRICS:
        if metric_id in measured:
            value, unit, evidence = measured[metric_id]
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
        elif metric_id in not_applicable:
            raw_metrics.append(
                _metric(
                    metric_id,
                    evidence=evaluator_path,
                    status="not_applicable",
                    missing_reason=not_applicable[metric_id],
                )
            )
        else:
            raw_metrics.append(
                _metric(
                    metric_id,
                    evidence=evaluator_path,
                    status="not_available",
                    missing_reason=not_available[metric_id],
                )
            )

    private_score = composite["score"]
    score = (
        {
            "status": "scored",
            "total": private_score["total"],
            "dimensions": private_score["dimensions"],
            "reason": (
                "Development-only G05 score; the scoring profile is not "
                "independently frozen."
            ),
        }
        if pass_result and private_score.get("status") == "scored"
        else {
            "status": "not_scored",
            "total": None,
            "dimensions": {},
            "reason": "Non-pass G05 results are not scored.",
        }
    )
    evidence_files = sorted((output_root / "evidence").glob("*.json"))
    result = {
        "schema_version": "rtlflowbench.result.v1",
        "result_id": result_id,
        "task_id": TASK_ID,
        "submission_id": submission["submission_id"],
        "document_bindings": {
            "task_descriptor_sha256": _canonical_json_sha256(task),
            "submission_sha256": _canonical_json_sha256(submission),
        },
        "run_id": run_id,
        "verdict": generic_verdict,
        "verdict_reason": (
            "All required development G05 build, F2P, P2P, bounded formal, "
            "firmware, coverage, and scope layers passed."
            if pass_result
            else "Private G05 layers were mapped without promoting failure."
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
    _validate(SCHEMA_ROOT / "result.schema.json", result, "result")
    rendered = json.dumps(result, sort_keys=True)
    forbidden = ("/home/", "/Users/", "/private/", "private/evaluator")
    if any(token in rendered for token in forbidden):
        raise ValueError("sanitized result leaks evaluator-private context")
    _write_json(output_root / "result.json", result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--task", type=Path, required=True)
    parser.add_argument("--submission", type=Path, required=True)
    parser.add_argument("--composite-result", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--result-id", required=True)
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    try:
        result = export_result(
            task=_load(args.task),
            submission=_load(args.submission),
            composite=_load(args.composite_result),
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
