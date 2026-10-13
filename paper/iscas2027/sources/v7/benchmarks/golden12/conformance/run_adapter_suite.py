#!/usr/bin/env python3
"""Run the workflow-neutral, submission-only adapter conformance suite."""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import tempfile
from typing import Any


HERE = Path(__file__).resolve().parent


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ValueError(f"could not load module: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _load(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain one JSON object")
    return payload


def _canonical_sha256(payload: dict[str, Any]) -> str:
    rendered = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(rendered).hexdigest()


def _copy_bundle_without(
    *,
    source_root: Path,
    destination_root: Path,
    excluded_relative: str | None,
) -> None:
    destination_root.mkdir()
    for source in sorted(source_root.rglob("*")):
        relative = source.relative_to(source_root)
        if str(relative) == excluded_relative:
            continue
        destination = destination_root / relative
        if source.is_symlink():
            raise ValueError(
                f"input bundle contains symlink: {relative}"
            )
        if source.is_dir():
            destination.mkdir(parents=True, exist_ok=True)
        elif source.is_file():
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)


def _check(
    check_id: str,
    passed: bool,
    reason: str,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "check_id": check_id,
        "status": "pass" if passed else "fail",
        "reason": reason,
        "details": details or {},
    }


def _expect_packager_rejection(
    packager,
    *,
    task: dict[str, Any],
    metadata: dict[str, Any],
    bundle_root: Path,
    expected: str,
) -> tuple[bool, str]:
    try:
        packager.package_submission(
            task=task,
            metadata=metadata,
            bundle_root=bundle_root,
        )
    except (ValueError, OSError) as exc:
        return expected in str(exc), str(exc)
    return False, "invalid resource usage was accepted"


def run_adapter_suite(
    *,
    task: dict[str, Any],
    metadata: dict[str, Any],
    bundle_root: Path,
    output_dir: Path,
    observed_at: str,
) -> dict[str, Any]:
    if output_dir.exists():
        raise FileExistsError(f"refusing to overwrite output: {output_dir}")
    packager = _load_module(
        "rtlflowbench_adapter_suite_packager",
        HERE / "package_submission.py",
    )
    validator = _load_module(
        "rtlflowbench_adapter_suite_validator",
        HERE / "validate.py",
    )
    submission = packager.package_submission(
        task=task,
        metadata=metadata,
        bundle_root=bundle_root,
    )
    repeated_submission = packager.package_submission(
        task=task,
        metadata=metadata,
        bundle_root=bundle_root,
    )
    conformance = validator.validate_submission(
        task=task,
        submission=submission,
        bundle_root=bundle_root,
    )
    checks = [
        _check(
            "positive_submission",
            conformance["status"] == "pass",
            "The adapter output satisfies schema, scope, hash, and budget checks.",
            {"issues": conformance["issues"]},
        ),
        _check(
            "deterministic_receipt",
            _canonical_sha256(submission)
            == _canonical_sha256(repeated_submission),
            "Repeated packaging produces the same canonical submission digest.",
        ),
    ]

    with tempfile.TemporaryDirectory(
        prefix="rtlflowbench-adapter-suite-"
    ) as temp:
        workspace = Path(temp)
        required = task["submission_contract"]["required_files"]
        missing_root = workspace / "missing-required"
        _copy_bundle_without(
            source_root=bundle_root,
            destination_root=missing_root,
            excluded_relative=required[0],
        )
        try:
            packager.package_submission(
                task=task,
                metadata=metadata,
                bundle_root=missing_root,
            )
        except ValueError as exc:
            missing_rejected = "missing required files" in str(exc)
            missing_reason = str(exc)
        else:
            missing_rejected = False
            missing_reason = "missing required file was accepted"
        checks.append(
            _check(
                "reject_missing_required",
                missing_rejected,
                missing_reason,
            )
        )

        outside_root = workspace / "outside-scope"
        _copy_bundle_without(
            source_root=bundle_root,
            destination_root=outside_root,
            excluded_relative=None,
        )
        probe = outside_root / "__rtlflowbench_probe__/outside.txt"
        probe.parent.mkdir()
        probe.write_text("scope rejection probe\n", encoding="utf-8")
        try:
            packager.package_submission(
                task=task,
                metadata=metadata,
                bundle_root=outside_root,
            )
        except ValueError as exc:
            outside_rejected = "outside editable_paths" in str(exc)
            outside_reason = str(exc)
        else:
            outside_rejected = False
            outside_reason = "out-of-scope file was accepted"
        checks.append(
            _check(
                "reject_out_of_scope",
                outside_rejected,
                outside_reason,
            )
        )

        tampered = copy.deepcopy(submission)
        tampered["artifact"]["files"][0]["sha256"] = "0" * 64
        tamper_audit = validator.validate_submission(
            task=task,
            submission=tampered,
            bundle_root=bundle_root,
        )
        checks.append(
            _check(
                "reject_hash_drift",
                tamper_audit["status"] == "fail"
                and any(
                    "SHA256 mismatch" in issue
                    for issue in tamper_audit["issues"]
                ),
                "A manifest/file hash mismatch must fail closed.",
                {"issues": tamper_audit["issues"]},
            )
        )

        stale_binding = copy.deepcopy(submission)
        stale_binding["task_binding"]["benchmark_version"] += "-stale"
        binding_audit = validator.validate_submission(
            task=task,
            submission=stale_binding,
            bundle_root=bundle_root,
        )
        checks.append(
            _check(
                "reject_task_content_binding_drift",
                binding_audit["status"] == "fail"
                and any(
                    "task_binding does not match" in issue
                    for issue in binding_audit["issues"]
                ),
                "A stale task-content binding must fail even when task_id is unchanged.",
                {"issues": binding_audit["issues"]},
            )
        )

        over_budget = copy.deepcopy(submission)
        over_budget["resource_usage"]["wall_time_seconds"] = (
            task["budget"]["wall_time_seconds"] + 1
        )
        budget_audit = validator.validate_submission(
            task=task,
            submission=over_budget,
            bundle_root=bundle_root,
        )
        checks.append(
            _check(
                "reject_workflow_budget_overrun",
                budget_audit["status"] == "fail"
                and any(
                    "wall time exceeds" in issue
                    for issue in budget_audit["issues"]
                ),
                "A workflow budget overrun must fail closed.",
                {"issues": budget_audit["issues"]},
            )
        )

        frozen_count_task = copy.deepcopy(task)
        frozen_count_task["budget"].update(
            {
                "status": "frozen",
                "llm_calls": {
                    "maximum": metadata["resource_usage"]["llm_calls"]
                },
                "human_interventions": {
                    "maximum": metadata["resource_usage"][
                        "human_interventions"
                    ]
                },
                "tokens": {
                    "accounting_policy": "report_only_separate_cohort",
                    "maximum_input_tokens": None,
                    "maximum_output_tokens": None,
                    "missing_measurement_policy": (
                        "separate_noncomparable_cohort"
                    ),
                },
            }
        )
        for field, check_id in (
            ("llm_calls", "reject_llm_call_budget_overrun"),
            (
                "human_interventions",
                "reject_human_intervention_budget_overrun",
            ),
        ):
            over_count = copy.deepcopy(metadata)
            over_count["resource_usage"][field] += 1
            passed, reason = _expect_packager_rejection(
                packager,
                task=frozen_count_task,
                metadata=over_count,
                bundle_root=bundle_root,
                expected=f"submission {field} exceed workflow budget",
            )
            checks.append(_check(check_id, passed, reason))

        frozen_token_task = copy.deepcopy(frozen_count_task)
        frozen_token_task["budget"]["tokens"] = {
            "accounting_policy": "enforced_limits",
            "maximum_input_tokens": 0,
            "maximum_output_tokens": 0,
            "missing_measurement_policy": "reject",
        }
        missing_tokens = copy.deepcopy(metadata)
        missing_tokens["resource_usage"].update(
            {
                "input_tokens": None,
                "output_tokens": 0,
                "missing_measurements": ["input_tokens"],
            }
        )
        passed, reason = _expect_packager_rejection(
            packager,
            task=frozen_token_task,
            metadata=missing_tokens,
            bundle_root=bundle_root,
            expected="input_tokens is required by workflow budget",
        )
        checks.append(
            _check("reject_missing_frozen_token_measurement", passed, reason)
        )
        over_tokens = copy.deepcopy(metadata)
        over_tokens["resource_usage"].update(
            {
                "input_tokens": 1,
                "output_tokens": 0,
                "missing_measurements": [],
            }
        )
        passed, reason = _expect_packager_rejection(
            packager,
            task=frozen_token_task,
            metadata=over_tokens,
            bundle_root=bundle_root,
            expected="input_tokens exceed workflow budget",
        )
        checks.append(
            _check("reject_frozen_token_budget_overrun", passed, reason)
        )

        if task["public_packet"]["network_access"]:
            checks.append(
                _check(
                    "reject_offline_network_violation",
                    True,
                    "Not applicable because this task permits network access.",
                    {"not_applicable": True},
                )
            )
        else:
            networked = copy.deepcopy(submission)
            networked["network_access_observed"] = True
            network_audit = validator.validate_submission(
                task=task,
                submission=networked,
                bundle_root=bundle_root,
            )
            checks.append(
                _check(
                    "reject_offline_network_violation",
                    network_audit["status"] == "fail"
                    and any(
                        "network access" in issue
                        for issue in network_audit["issues"]
                    ),
                    "Observed network access on an offline task must fail closed.",
                    {"issues": network_audit["issues"]},
                )
            )

        linked_root = workspace / "linked-bundle"
        try:
            linked_root.symlink_to(bundle_root, target_is_directory=True)
            symlink_audit = validator.validate_submission(
                task=task,
                submission=submission,
                bundle_root=linked_root,
            )
            symlink_rejected = (
                symlink_audit["status"] == "fail"
                and any(
                    "non-symlink directory" in issue
                    for issue in symlink_audit["issues"]
                )
            )
            symlink_details = {"issues": symlink_audit["issues"]}
        except OSError as exc:
            symlink_rejected = False
            symlink_details = {"error": f"{type(exc).__name__}: {exc}"}
        checks.append(
            _check(
                "reject_symlink_bundle_root",
                symlink_rejected,
                "A symlink bundle root must fail closed.",
                symlink_details,
            )
        )

    status = "conformant_submission_only" if all(
        item["status"] == "pass" for item in checks
    ) else "fail"
    result = {
        "schema_version": "rtlflowbench.adapter_conformance.v1",
        "task_id": task["task_id"],
        "submission_id": submission["submission_id"],
        "observed_at": observed_at,
        "status": status,
        "submission_sha256": _canonical_sha256(submission),
        "checks": checks,
        "summary": {
            "check_count": len(checks),
            "pass_count": sum(
                item["status"] == "pass" for item in checks
            ),
            "fail_count": sum(
                item["status"] == "fail" for item in checks
            ),
        },
        "admission_impact": {
            "submission_adapter_conformant": status
            == "conformant_submission_only",
            "hidden_evaluator_run": False,
            "rtl_verdict_produced": False,
            "benchmark_ready": False,
        },
        "excluded_claims": [
            "Submission conformance is not RTL correctness.",
            "This suite does not invoke or expose the hidden evaluator.",
            "This suite does not produce PASS, PPA, QoR, or benchmark admission.",
        ],
    }
    output_dir.mkdir(parents=True)
    (output_dir / "submission.json").write_text(
        json.dumps(submission, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (output_dir / "adapter_conformance.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--task", type=Path, required=True)
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--bundle-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--observed-at", required=True)
    args = parser.parse_args()
    try:
        result = run_adapter_suite(
            task=_load(args.task),
            metadata=_load(args.metadata),
            bundle_root=args.bundle_root.expanduser().absolute(),
            output_dir=args.output_dir.expanduser().absolute(),
            observed_at=args.observed_at,
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
    return 0 if result["status"] == "conformant_submission_only" else 2


if __name__ == "__main__":
    raise SystemExit(main())
