#!/usr/bin/env python3
"""Opt-in v2 neutral-result conformance; keeps legacy v1 untouched."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator


EDA_KEYS = ("compile_or_lint", "simulation", "formal", "synthesis")
PARENT_SHA256 = "87c08e07a749c95e7475a41ba4117af49c0a28bfe2006b3910203d7499143f77"
SCHEMA_SHA256 = "857c6b3d1608c76b74b56bcb9050fca2d3bf66636062fd46ea62c5cc002426fd"


def _read_pinned(path: Path, expected: str) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError("pinned input must be a regular non-symlink file")
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError("pinned source/schema SHA256 mismatch")
    return data


def _load_parent(path: Path):
    _read_pinned(path, PARENT_SHA256)
    spec = importlib.util.spec_from_file_location(
        "golden12_conformance_v1_parent", path
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate_documents_v2(
    *,
    task: dict[str, Any],
    submission: dict[str, Any],
    result: dict[str, Any],
    parent_validator: Path,
    result_schema: Path,
    expected_execution_bindings: dict[str, str],
    bundle_root: Path | None = None,
    evidence_root: Path | None = None,
) -> dict[str, Any]:
    """Validate a complete v2 result against externally pinned execution identity."""
    base = _load_parent(parent_validator)
    schema = json.loads(_read_pinned(result_schema, SCHEMA_SHA256))
    issues = base._schema_issues("task", task) + base._schema_issues(
        "submission", submission
    )
    issues += [
        f"result-v2 schema: {err.message}"
        for err in Draft202012Validator(schema).iter_errors(result)
    ]
    if issues:
        return {
            "schema_version": "rtlflowbench.conformance.v2",
            "status": "fail",
            "checks": {"schemas": False},
            "issues": issues,
        }

    checks, submission_issues = base._submission_semantics(
        task=task, submission=submission, bundle_root=bundle_root
    )
    issues.extend(submission_issues)
    checks = {"schemas": True, **checks}
    if (
        result["task_id"] != task["task_id"]
        or result["submission_id"] != submission["submission_id"]
    ):
        issues.append("task/submission IDs disagree with result")
    if result["document_bindings"] != {
        "task_descriptor_sha256": base._canonical_json_sha256(task),
        "submission_sha256": base._canonical_json_sha256(submission),
    }:
        issues.append("result document bindings mismatch")
    checks["document_content_bindings"] = checks[
        "document_content_bindings"
    ] and not any("bindings mismatch" in i for i in issues)
    if (
        set(expected_execution_bindings) != set(result["execution_bindings"])
        or result["execution_bindings"] != expected_execution_bindings
    ):
        issues.append(
            "execution bindings mismatch externally pinned runner/source/runtime"
        )
    checks["execution_bindings"] = not any("execution bindings" in i for i in issues)

    usage = result["resource_usage"]
    sent = submission["resource_usage"]
    missing = set(usage["missing_measurements"])
    for field in ("input_tokens", "output_tokens"):
        if (usage[field] is None) != (field in missing):
            issues.append(f"result {field} missing declaration mismatch")
        if usage[field] != sent[field]:
            issues.append(f"result {field} must preserve submission usage")
    for field in ("llm_calls", "human_interventions"):
        if usage[field] != sent[field]:
            issues.append(f"result {field} must preserve submission usage")
    if usage["wall_time_seconds"] < sent["wall_time_seconds"]:
        issues.append("result wall time below submission time")
    for field in EDA_KEYS:
        val = usage["eda_calls"][field]
        if (val is None) != (f"eda_calls.{field}" in missing):
            issues.append(f"result {field} EDA missing declaration mismatch")
        if val is not None and val < sent["eda_calls"][field]:
            issues.append(f"result {field} EDA count below submission count")

    scope = result["scope"]
    count = scope["violation_count"]
    violations = scope["violations"]
    if (count is None) != ("scope_violation_count" in missing):
        issues.append("scope missing declaration mismatch")
    if scope["status"] == "not_available":
        if count is not None or violations is not None:
            issues.append("unobserved scope cannot assert zero violations")
    elif count is None or not isinstance(violations, list) or count != len(violations):
        issues.append("observed scope count/violations disagree")
    elif scope["status"] == "pass" and count != 0:
        issues.append("scope pass requires observed zero violations")
    elif scope["status"] == "violation" and count == 0:
        issues.append("scope violation requires positive count")
    trust = result["trust_events"]
    if (trust is None) != ("trust_event_count" in missing):
        issues.append("trust missing declaration mismatch")
    checks["resource_accounting"] = checks["resource_accounting"] and not any(
        token in item
        for item in issues
        for token in (
            "missing declaration",
            "preserve submission",
            "below submission",
            "scope count",
            "unobserved scope",
            "scope pass",
            "scope violation requires",
        )
    )

    manifest = result["evidence_manifest"]
    paths = [item["path"] for item in manifest]
    if len(paths) != len(set(paths)):
        issues.append("duplicate evidence paths")
    if any("private" in Path(path).parts for path in paths):
        issues.append("private path in evidence manifest")
    refs = [ref for item in result["oracle_results"] for ref in item["evidence_refs"]]
    refs += [ref for item in result["raw_metrics"] for ref in item["evidence_refs"]]
    if trust is not None:
        refs += [ref for item in trust for ref in item["evidence_refs"]]
    if set(refs) - set(paths):
        issues.append("evidence reference absent from manifest")
    if evidence_root is not None:
        base._check_evidence_bundle(
            evidence_root=evidence_root, files=manifest, issues=issues
        )
    checks["evidence_references"] = not any(
        "evidence" in item or "private path" in item for item in issues
    )

    metrics = result["raw_metrics"]
    metric_ids = [m["metric_id"] for m in metrics]
    if len(metric_ids) != len(set(metric_ids)):
        issues.append("duplicate metric IDs")
    if not set(task["scoring_contract"]["raw_metric_ids"]).issubset(metric_ids):
        issues.append("missing required raw metrics")
    by_metric = {m["metric_id"]: m for m in metrics}
    expected_metrics = {
        "wall_time_seconds": usage["wall_time_seconds"],
        "input_tokens": usage["input_tokens"],
        "output_tokens": usage["output_tokens"],
        "llm_calls": usage["llm_calls"],
        "eda_calls": None
        if any(usage["eda_calls"][k] is None for k in EDA_KEYS)
        else sum(usage["eda_calls"].values()),
        "human_interventions": usage["human_interventions"],
        "scope_violation_count": count,
        "trust_event_count": None if trust is None else len(trust),
    }
    for field, value in expected_metrics.items():
        metric = by_metric.get(field)
        if metric is None:
            continue
        if value is None and metric["status"] != "not_available":
            issues.append(
                f"metric {field} must be not_available when observation is null"
            )
        elif value is not None and (
            metric["status"] != "measured" or metric["value"] != value
        ):
            issues.append(f"metric {field} disagrees with accounting")
    checks["raw_metrics"] = not any("metric" in item for item in issues)

    oracles = result["oracle_results"]
    ids = [item["oracle_id"] for item in oracles]
    if len(ids) != len(set(ids)):
        issues.append("duplicate oracle IDs")
    scope_oracles = [o for o in oracles if o["oracle_class"] == "scope"]
    if scope["status"] == "pass" and any(o["status"] != "pass" for o in scope_oracles):
        issues.append("scope receipt and oracle disagree")
    if scope["status"] == "not_available" and any(
        o["status"] == "pass" for o in scope_oracles
    ):
        issues.append("unobserved scope cannot have passing oracle")
    if scope["status"] == "violation" and not any(
        o["status"] == "fail" and o["failure_verdict"] == "scope_violation"
        for o in scope_oracles
    ):
        issues.append("scope violation lacks oracle")
    failures = [
        o["failure_verdict"] for o in oracles if o["failure_verdict"] is not None
    ]
    verdict = result["verdict"]
    if verdict in base.ORACLE_EVIDENCE_REQUIRED_VERDICTS and verdict not in failures:
        issues.append("verdict lacks matching oracle failure")
    if failures:
        priority = {name: n for n, name in enumerate(base.VERDICT_PRIORITY)}
        if priority[verdict] > min(priority[x] for x in failures):
            issues.append("verdict lower priority than oracle failure")
    if verdict == "pass":
        if scope["status"] != "pass" or trust is None:
            issues.append("PASS needs observed scope and trust")
        if any(o["status"] not in {"pass", "not_run"} for o in oracles):
            issues.append("PASS contains failing oracle")
        if trust is not None and any(x["severity"] == "error" for x in trust):
            issues.append("PASS contains trust error")
        for required in task["evaluation_contract"]["required_oracle_classes"]:
            matching = [o for o in oracles if o["oracle_class"] == required]
            if not matching or any(o["status"] != "pass" for o in matching):
                issues.append(f"PASS lacks passing {required} oracle")
            if required in {"simulation", "formal", "differential", "coverage"} and any(
                o["pass_sentinel_observed"] is not True for o in matching
            ):
                issues.append(f"PASS lacks explicit {required} sentinel")
        functional = by_metric.get("functional_correctness")
        if (
            not functional
            or functional["status"] != "measured"
            or functional["value"] != 1
        ):
            issues.append("PASS needs measured functional correctness")
    if verdict == "blocked":
        if any(o["status"] not in {"pass", "not_run"} for o in oracles):
            issues.append("BLOCK cannot mask failing oracle")
        if scope["status"] != "pass":
            issues.append("BLOCK needs observed passing scope")
        if task["family"] == "trust_block" and not any(
            o["oracle_class"] == "trust" and o["status"] == "pass" for o in oracles
        ):
            issues.append("trust BLOCK needs passing trust oracle")
    if verdict not in task["evaluation_contract"]["canonical_verdicts"]:
        issues.append("verdict not enabled by task")
    score = result["score"]
    if score["status"] == "scored":
        if missing:
            issues.append("scored result cannot have missing measurements")
        if verdict not in (
            {"pass", "blocked"} if task["family"] == "trust_block" else {"pass"}
        ):
            issues.append("failed/infra result cannot be scored")
        if (
            not score["dimensions"]
            or abs(sum(score["dimensions"].values()) - score["total"]) > 1e-9
        ):
            issues.append("score dimensions do not sum to total")
    checks["strict_verdict_and_score"] = not any(
        token in item
        for item in issues
        for token in ("verdict", "PASS", "BLOCK", "oracle", "score", "scope receipt")
    )
    return {
        "schema_version": "rtlflowbench.conformance.v2",
        "status": "pass" if not issues else "fail",
        "checks": checks,
        "issues": issues,
        "summary": {
            "task_id": task["task_id"],
            "submission_id": submission["submission_id"],
            "result_id": result["result_id"],
            "verdict": verdict,
            "missing_measurements": sorted(missing),
        },
    }


def main() -> int:
    p = argparse.ArgumentParser()
    for name in (
        "task",
        "submission",
        "result",
        "parent-validator",
        "result-schema",
        "execution-bindings",
    ):
        p.add_argument("--" + name, required=True, type=Path)
    p.add_argument("--bundle-root", type=Path)
    p.add_argument("--evidence-root", type=Path)
    a = p.parse_args()

    def read(path: Path) -> dict:
        if path.is_symlink() or not path.is_file():
            raise ValueError("document must be regular non-symlink file")
        return json.loads(path.read_text(encoding="utf-8"))

    audit = validate_documents_v2(
        task=read(a.task),
        submission=read(a.submission),
        result=read(a.result),
        parent_validator=a.parent_validator,
        result_schema=a.result_schema,
        expected_execution_bindings=read(a.execution_bindings),
        bundle_root=a.bundle_root,
        evidence_root=a.evidence_root,
    )
    print(json.dumps(audit, sort_keys=True, indent=2))
    return 0 if audit["status"] == "pass" else 2


if __name__ == "__main__":
    raise SystemExit(main())
