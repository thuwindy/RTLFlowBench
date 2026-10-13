#!/usr/bin/env python3
"""Validate workflow-neutral RTLFlowBench task/submission/result documents."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator


SCHEMA_ROOT = Path(__file__).resolve().parents[1] / "schemas"
SCHEMA_PATHS = {
    "task": SCHEMA_ROOT / "task.schema.json",
    "submission": SCHEMA_ROOT / "submission.schema.json",
    "result": SCHEMA_ROOT / "result.schema.json",
}
VERDICT_PRIORITY = (
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
)
ORACLE_EVIDENCE_REQUIRED_VERDICTS = {
    "infra_error",
    "scope_violation",
    "timeout",
    "compile_error",
    "fail_f2p",
    "fail_p2p",
    "fail_formal",
    "fail_ppa",
}


def _load_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain one JSON object")
    return payload


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_json_sha256(value: dict[str, Any]) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _schema_issues(
    document_name: str,
    payload: dict[str, Any],
) -> list[str]:
    schema = _load_json(SCHEMA_PATHS[document_name])
    validator = Draft202012Validator(schema)
    issues = []
    for error in sorted(
        validator.iter_errors(payload),
        key=lambda item: tuple(str(part) for part in item.absolute_path),
    ):
        location = ".".join(str(part) for part in error.absolute_path)
        issues.append(
            f"{document_name} schema"
            + (f" at {location}" if location else "")
            + f": {error.message}"
        )
    return issues


def _check_measurement_nulls(
    *,
    owner: str,
    usage: dict[str, Any],
    issues: list[str],
) -> None:
    missing = set(usage["missing_measurements"])
    for field in ("input_tokens", "output_tokens"):
        value = usage[field]
        if value is None and field not in missing:
            issues.append(
                f"{owner} {field} is null but not declared missing"
            )
        if value is not None and field in missing:
            issues.append(
                f"{owner} {field} is measured but declared missing"
            )


def _token_accounting_cohort(
    *,
    task: dict[str, Any],
    usage: dict[str, Any],
) -> str:
    policy = task["budget"]["tokens"]["accounting_policy"]
    if policy == "provisional_not_frozen":
        return "provisional_not_comparable"
    if policy == "enforced_limits":
        return "enforced_limits"
    if usage["missing_measurements"]:
        return "report_only_missing_noncomparable"
    return "report_only_measured"


def _check_bundle(
    *,
    bundle_root: Path,
    files: list[dict[str, Any]],
    issues: list[str],
) -> None:
    if (
        not bundle_root.exists()
        or not bundle_root.is_dir()
        or bundle_root.is_symlink()
    ):
        issues.append(
            "submission bundle root must be a non-symlink directory"
        )
        return
    declared = {str(item["path"]): item for item in files}
    if len(declared) != len(files):
        issues.append("submission artifact paths must be unique")
    observed: set[str] = set()
    for path in sorted(bundle_root.rglob("*")):
        relative = str(path.relative_to(bundle_root))
        if path.is_symlink():
            issues.append(f"submission bundle contains symlink: {relative}")
        elif path.is_file():
            observed.add(relative)
    if observed != set(declared):
        issues.append(
            "submission bundle files disagree with the manifest: "
            f"declared={sorted(declared)} observed={sorted(observed)}"
        )
    for relative, item in declared.items():
        path = bundle_root / relative
        if not path.is_file() or path.is_symlink():
            continue
        if path.stat().st_size != item["bytes"]:
            issues.append(f"submission size mismatch: {relative}")
        if _sha256(path) != item["sha256"]:
            issues.append(f"submission SHA256 mismatch: {relative}")


def _check_evidence_bundle(
    *,
    evidence_root: Path,
    files: list[dict[str, Any]],
    issues: list[str],
) -> None:
    if (
        not evidence_root.exists()
        or not evidence_root.is_dir()
        or evidence_root.is_symlink()
    ):
        issues.append(
            "result evidence root must be a non-symlink directory"
        )
        return
    declared = {str(item["path"]): item for item in files}
    if len(declared) != len(files):
        issues.append("result evidence paths must be unique")
    observed: set[str] = set()
    for path in sorted(evidence_root.rglob("*")):
        relative = str(path.relative_to(evidence_root))
        if path.is_symlink():
            issues.append(f"result evidence bundle contains symlink: {relative}")
        elif path.is_file():
            observed.add(relative)
    allowed_control_files = {"result.json"}
    if observed - allowed_control_files != set(declared):
        issues.append(
            "result evidence files disagree with evidence_manifest: "
            f"declared={sorted(declared)} "
            f"observed={sorted(observed - allowed_control_files)}"
        )
    for relative, item in declared.items():
        path = evidence_root / relative
        if not path.is_file() or path.is_symlink():
            continue
        if path.stat().st_size != item["bytes"]:
            issues.append(f"result evidence size mismatch: {relative}")
        if _sha256(path) != item["sha256"]:
            issues.append(f"result evidence SHA256 mismatch: {relative}")


def _submission_semantics(
    *,
    task: dict[str, Any],
    submission: dict[str, Any],
    bundle_root: Path | None,
) -> tuple[dict[str, bool], list[str]]:
    issues: list[str] = []
    checks: dict[str, bool] = {}
    task_id = task["task_id"]
    if submission["task_id"] != task_id:
        issues.append("task_id must agree across task and submission")
    task_binding = submission["task_binding"]
    expected_task_binding = {
        "benchmark_id": task["benchmark_id"],
        "benchmark_version": task["benchmark_version"],
        "task_descriptor_sha256": _canonical_json_sha256(task),
        "public_packet_sha256": task["public_packet"]["sha256"],
    }
    if task_binding != expected_task_binding:
        issues.append(
            "submission task_binding does not match the exact task descriptor"
        )
    if (
        task["packet_status"] == "frozen"
        and task_binding["public_packet_sha256"] is None
    ):
        issues.append(
            "frozen task submission must bind a frozen public packet digest"
        )
    checks["document_ids"] = not any(
        "task_id" in issue for issue in issues
    )
    checks["document_content_bindings"] = not any(
        "task_binding" in issue or "public packet digest" in issue
        for issue in issues
    )

    public_root_parts = Path(task["public_packet"]["root"]).parts
    if "private" in public_root_parts:
        issues.append("public packet root cannot reference a private path")
    if task["public_packet"]["contains_evaluator_assets"]:
        issues.append("public packet cannot contain evaluator assets")
    if (
        task["public_packet"]["network_access"]
        != task["budget"]["network_access"]
    ):
        issues.append(
            "public packet and budget network access policies disagree"
        )
    if (
        not task["public_packet"]["network_access"]
        and submission["network_access_observed"]
    ):
        issues.append("submission reports network access for an offline task")
    checks["public_private_network_boundary"] = not any(
        "public packet" in issue or "network access" in issue
        for issue in issues
    )

    contract = task["submission_contract"]
    artifact_files = submission["artifact"]["files"]
    artifact_paths = [str(item["path"]) for item in artifact_files]
    if len(artifact_paths) != len(set(artifact_paths)):
        issues.append("submission artifact paths must be unique")
    required_files = set(contract["required_files"])
    editable_paths = set(contract["editable_paths"])
    observed_files = set(artifact_paths)
    if not required_files.issubset(observed_files):
        issues.append("submission is missing required files")
    if not observed_files.issubset(editable_paths):
        issues.append("submission contains files outside editable_paths")
    if len(observed_files) > contract["max_files_changed"]:
        issues.append("submission exceeds max_files_changed")
    if sum(int(item["bytes"]) for item in artifact_files) > contract[
        "max_submission_bytes"
    ]:
        issues.append("submission exceeds max_submission_bytes")
    if bundle_root is not None:
        _check_bundle(
            bundle_root=bundle_root,
            files=artifact_files,
            issues=issues,
        )
    checks["submission_scope_and_hashes"] = not any(
        "submission " in issue for issue in issues
    )

    _check_measurement_nulls(
        owner="submission",
        usage=submission["resource_usage"],
        issues=issues,
    )
    budget = task["budget"]
    submission_usage = submission["resource_usage"]
    if submission_usage["wall_time_seconds"] > budget["wall_time_seconds"]:
        issues.append("submission wall time exceeds the task budget")
    if submission["attempt"]["attempt_index"] > budget["workflow_attempts"]:
        issues.append("submission attempt index exceeds workflow_attempts")
    for field, limit in budget["eda_call_limits"].items():
        if submission_usage["eda_calls"][field] > limit:
            issues.append(
                f"submission {field} EDA calls exceed the task budget"
            )
    for field, budget_field in (
        ("llm_calls", "llm_calls"),
        ("human_interventions", "human_interventions"),
    ):
        limit = budget[budget_field]["maximum"]
        if limit is not None and submission_usage[field] > limit:
            issues.append(f"submission {field} exceed the task budget")
    token_policy = budget["tokens"]["accounting_policy"]
    if token_policy == "enforced_limits":
        for field, limit_field in (
            ("input_tokens", "maximum_input_tokens"),
            ("output_tokens", "maximum_output_tokens"),
        ):
            value = submission_usage[field]
            if value is None:
                issues.append(
                    f"submission {field} is required by the frozen token budget"
                )
            elif value > budget["tokens"][limit_field]:
                issues.append(f"submission {field} exceed the task budget")
    checks["resource_accounting"] = not any(
        "measurement" in issue
        or "budget" in issue
        or "workflow_attempts" in issue
        for issue in issues
    )
    return checks, issues


def validate_submission(
    *,
    task: dict[str, Any],
    submission: dict[str, Any],
    bundle_root: Path | None = None,
) -> dict[str, Any]:
    """Validate a workflow-produced submission before private evaluation."""

    issues = [
        issue
        for name, payload in (
            ("task", task),
            ("submission", submission),
        )
        for issue in _schema_issues(name, payload)
    ]
    if issues:
        return {
            "schema_version": "rtlflowbench.submission_conformance.v1",
            "status": "fail",
            "checks": {"schemas": False},
            "issues": issues,
        }
    checks, semantic_issues = _submission_semantics(
        task=task,
        submission=submission,
        bundle_root=bundle_root,
    )
    issues.extend(semantic_issues)
    return {
        "schema_version": "rtlflowbench.submission_conformance.v1",
        "status": "pass" if not issues else "fail",
        "checks": {"schemas": True, **checks},
        "issues": issues,
        "summary": {
            "task_id": task["task_id"],
            "submission_id": submission["submission_id"],
            "artifact_files": len(submission["artifact"]["files"]),
            "token_accounting_cohort": _token_accounting_cohort(
                task=task,
                usage=submission["resource_usage"],
            ),
        },
    }


def validate_documents(
    *,
    task: dict[str, Any],
    submission: dict[str, Any],
    result: dict[str, Any],
    bundle_root: Path | None = None,
    evidence_root: Path | None = None,
) -> dict[str, Any]:
    """Validate schemas plus cross-document and evidence semantics."""

    issues = [
        issue
        for name, payload in (
            ("task", task),
            ("submission", submission),
            ("result", result),
        )
        for issue in _schema_issues(name, payload)
    ]
    if issues:
        return {
            "schema_version": "rtlflowbench.conformance.v1",
            "status": "fail",
            "checks": {"schemas": False},
            "issues": issues,
        }

    submission_checks, submission_issues = _submission_semantics(
        task=task,
        submission=submission,
        bundle_root=bundle_root,
    )
    checks: dict[str, bool] = {"schemas": True, **submission_checks}
    issues.extend(submission_issues)
    task_id = task["task_id"]
    if result["task_id"] != task_id:
        issues.append("task_id must agree across task, submission, and result")
    if result["submission_id"] != submission["submission_id"]:
        issues.append("result submission_id does not match the submission")
    expected_result_bindings = {
        "task_descriptor_sha256": _canonical_json_sha256(task),
        "submission_sha256": _canonical_json_sha256(submission),
    }
    if result["document_bindings"] != expected_result_bindings:
        issues.append(
            "result document_bindings do not match the exact task and submission"
        )
    checks["document_ids"] = not any(
        "task_id" in issue or "submission_id" in issue
        for issue in issues
    )
    checks["document_content_bindings"] = checks[
        "document_content_bindings"
    ] and not any("document_bindings" in issue for issue in issues)
    _check_measurement_nulls(
        owner="result",
        usage=result["resource_usage"],
        issues=issues,
    )
    submission_usage = submission["resource_usage"]
    result_usage = result["resource_usage"]
    if (
        result_usage["wall_time_seconds"]
        < submission_usage["wall_time_seconds"]
    ):
        issues.append("result wall time cannot be less than submission time")
    for field in ("compile_or_lint", "simulation", "formal", "synthesis"):
        if (
            result_usage["eda_calls"][field]
            < submission_usage["eda_calls"][field]
        ):
            issues.append(
                f"result {field} EDA calls cannot be less than submission"
            )
    for field in (
        "input_tokens",
        "output_tokens",
        "llm_calls",
        "human_interventions",
    ):
        if result_usage[field] != submission_usage[field]:
            issues.append(
                f"result {field} must preserve submission accounting"
            )
    checks["resource_accounting"] = checks["resource_accounting"] and not any(
        "measurement" in issue
        or "accounting" in issue
        or "cannot be less" in issue
        for issue in issues
    )

    artifact_files = submission["artifact"]["files"]
    manifest_paths = {
        str(item["path"]) for item in result["evidence_manifest"]
    }
    if len(manifest_paths) != len(result["evidence_manifest"]):
        issues.append("result evidence paths must be unique")
    evidence_refs = [
        str(reference)
        for oracle in result["oracle_results"]
        for reference in oracle["evidence_refs"]
    ]
    evidence_refs.extend(
        str(reference)
        for metric in result["raw_metrics"]
        for reference in metric["evidence_refs"]
    )
    evidence_refs.extend(
        str(reference)
        for event in result["trust_events"]
        for reference in event["evidence_refs"]
    )
    missing_evidence = sorted(set(evidence_refs) - manifest_paths)
    if missing_evidence:
        issues.append(
            "evidence references are absent from evidence_manifest: "
            + ", ".join(missing_evidence)
        )
    if any("private" in Path(path).parts for path in manifest_paths):
        issues.append("result evidence manifest exposes a private path")
    if evidence_root is not None:
        _check_evidence_bundle(
            evidence_root=evidence_root,
            files=result["evidence_manifest"],
            issues=issues,
        )
    checks["evidence_references"] = not any(
        "evidence" in issue for issue in issues
    )

    metric_ids = [str(item["metric_id"]) for item in result["raw_metrics"]]
    if len(metric_ids) != len(set(metric_ids)):
        issues.append("raw metric ids must be unique")
    required_metrics = set(task["scoring_contract"]["raw_metric_ids"])
    if not required_metrics.issubset(metric_ids):
        issues.append("result is missing required raw metrics")
    metric_by_id = {
        str(item["metric_id"]): item for item in result["raw_metrics"]
    }
    usage_metric_values = {
        "wall_time_seconds": result_usage["wall_time_seconds"],
        "input_tokens": result_usage["input_tokens"],
        "output_tokens": result_usage["output_tokens"],
        "llm_calls": result_usage["llm_calls"],
        "eda_calls": sum(result_usage["eda_calls"].values()),
        "human_interventions": result_usage["human_interventions"],
        "scope_violation_count": result["scope"]["violation_count"],
        "trust_event_count": len(result["trust_events"]),
    }
    for metric_id, expected in usage_metric_values.items():
        metric = metric_by_id.get(metric_id)
        if metric is None:
            continue
        if expected is None:
            if metric["status"] == "measured":
                issues.append(
                    f"raw metric {metric_id} cannot be measured when usage is null"
                )
        elif (
            metric["status"] != "measured"
            or metric["value"] != expected
        ):
            issues.append(
                f"raw metric {metric_id} disagrees with result accounting"
            )
    checks["raw_metrics"] = not any(
        "metric" in issue for issue in issues
    )

    scope = result["scope"]
    if scope["violation_count"] != len(scope["violations"]):
        issues.append("scope violation_count disagrees with violations")
    if scope["status"] == "pass" and (
        scope["violation_count"] != 0 or scope["violations"]
    ):
        issues.append("passing scope receipt cannot contain violations")
    if scope["status"] == "violation" and scope["violation_count"] == 0:
        issues.append("scope violation status requires at least one violation")

    verdict_issue_start = len(issues)
    oracle_ids = [str(item["oracle_id"]) for item in result["oracle_results"]]
    if len(oracle_ids) != len(set(oracle_ids)):
        issues.append("oracle ids must be unique")
    oracle_failures = [
        str(item["failure_verdict"])
        for item in result["oracle_results"]
        if item["failure_verdict"] is not None
    ]
    scope_oracles = [
        item
        for item in result["oracle_results"]
        if item["oracle_class"] == "scope"
    ]
    if scope["status"] == "violation" and not any(
        item["status"] == "fail"
        and item["failure_verdict"] == "scope_violation"
        for item in scope_oracles
    ):
        issues.append(
            "scope violation requires a matching failing scope oracle"
        )
    if scope["status"] == "pass" and any(
        item["status"] != "pass" for item in scope_oracles
    ):
        issues.append("passing scope receipt disagrees with the scope oracle")

    verdict = result["verdict"]
    if verdict in ORACLE_EVIDENCE_REQUIRED_VERDICTS and (
        verdict not in oracle_failures
    ):
        issues.append(
            f"result verdict requires matching oracle evidence: {verdict}"
        )
    if oracle_failures:
        priority = {name: index for index, name in enumerate(VERDICT_PRIORITY)}
        highest_oracle_failure = min(
            oracle_failures,
            key=lambda item: priority[item],
        )
        if priority[verdict] > priority[highest_oracle_failure]:
            issues.append(
                "result verdict has lower priority than observed oracle "
                f"failure: {highest_oracle_failure}"
            )
    if verdict == "blocked":
        if any(
            item["status"] not in {"pass", "not_run"}
            or item["failure_verdict"] is not None
            for item in result["oracle_results"]
        ):
            issues.append(
                "BLOCKED cannot mask a failing, timeout, or infrastructure "
                "oracle"
            )
        if task["family"] == "trust_block":
            trust_oracles = [
                item
                for item in result["oracle_results"]
                if item["oracle_class"] == "trust"
            ]
            if not trust_oracles or any(
                item["status"] != "pass" for item in trust_oracles
            ):
                issues.append("BLOCKED requires a passing trust oracle")
        if scope["status"] != "pass":
            issues.append("BLOCKED requires a passing scope receipt")

    if verdict == "pass":
        if scope["status"] != "pass":
            issues.append("PASS requires a passing scope receipt")
        if any(
            item["status"] not in {"pass", "not_run"}
            for item in result["oracle_results"]
        ):
            issues.append("PASS cannot contain a failing oracle result")
        if any(
            event["severity"] == "error"
            for event in result["trust_events"]
        ):
            issues.append("PASS cannot contain error-severity trust events")
        required_oracles = set(
            task["evaluation_contract"]["required_oracle_classes"]
        )
        for oracle_class in sorted(required_oracles):
            class_results = [
                item
                for item in result["oracle_results"]
                if item["oracle_class"] == oracle_class
            ]
            if not class_results or any(
                item["status"] != "pass" for item in class_results
            ):
                issues.append(
                    f"PASS requires passing oracle class: {oracle_class}"
                )
            if (
                oracle_class
                in {"simulation", "formal", "differential", "coverage"}
                and class_results
                and any(
                    item["pass_sentinel_observed"] is not True
                    for item in class_results
                )
            ):
                issues.append(
                    "PASS requires an explicit success sentinel for oracle "
                    f"class: {oracle_class}"
                )
        functional_metric = metric_by_id.get("functional_correctness")
        if (
            functional_metric is None
            or functional_metric["status"] != "measured"
            or not isinstance(
                functional_metric["value"],
                (bool, int, float),
            )
            or functional_metric["value"] != 1
        ):
            issues.append(
                "PASS requires measured functional_correctness equal to 1"
            )
    if (
        verdict
        not in task["evaluation_contract"]["canonical_verdicts"]
    ):
        issues.append("result verdict is not enabled by the task contract")
    score = result["score"]
    if score["status"] == "scored":
        successful_verdicts = {"pass"}
        if task["family"] == "trust_block":
            successful_verdicts.add("blocked")
        if verdict not in successful_verdicts:
            issues.append("failed/infra results cannot receive a score")
        if not score["dimensions"]:
            issues.append("scored result requires at least one score dimension")
        if abs(sum(score["dimensions"].values()) - score["total"]) > 1e-9:
            issues.append("score total must equal the dimension sum")
    checks["strict_verdict_and_score"] = len(issues) == verdict_issue_start

    return {
        "schema_version": "rtlflowbench.conformance.v1",
        "status": "pass" if not issues else "fail",
        "checks": checks,
        "issues": issues,
        "summary": {
            "task_id": task_id,
            "submission_id": submission["submission_id"],
            "result_id": result["result_id"],
            "verdict": result["verdict"],
            "artifact_files": len(artifact_files),
            "oracle_results": len(result["oracle_results"]),
            "raw_metrics": len(result["raw_metrics"]),
            "evidence_files": len(result["evidence_manifest"]),
            "token_accounting_cohort": _token_accounting_cohort(
                task=task,
                usage=result["resource_usage"],
            ),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--task", type=Path, required=True)
    parser.add_argument("--submission", type=Path, required=True)
    parser.add_argument("--result", type=Path)
    parser.add_argument("--bundle-root", type=Path)
    parser.add_argument("--evidence-root", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    task = _load_json(args.task)
    submission = _load_json(args.submission)
    if args.result is None:
        if args.evidence_root is not None:
            parser.error("--evidence-root requires --result")
        payload = validate_submission(
            task=task,
            submission=submission,
            bundle_root=args.bundle_root,
        )
    else:
        payload = validate_documents(
            task=task,
            submission=submission,
            result=_load_json(args.result),
            bundle_root=args.bundle_root,
            evidence_root=args.evidence_root,
        )
    rendered = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0 if payload["status"] == "pass" else 2


if __name__ == "__main__":
    raise SystemExit(main())
