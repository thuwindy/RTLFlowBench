#!/usr/bin/env python3
"""Calibrate two independently implemented neutral submission adapters."""

from __future__ import annotations

import argparse
import ast
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
PRIMARY = HERE / "package_submission.py"
SECONDARY = HERE / "adapters/scan_submission_adapter.py"


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
    data = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _source_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _does_not_import_primary(path: Path) -> bool:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imported = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.append(node.module or "")
    return not any(
        name == "package_submission"
        or name.endswith(".package_submission")
        for name in imported
    )


def _copy_bundle(source: Path, destination: Path) -> None:
    destination.mkdir()
    for item in sorted(source.rglob("*")):
        relative = item.relative_to(source)
        target = destination / relative
        if item.is_symlink():
            raise ValueError(f"input bundle contains symlink: {relative}")
        if item.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        elif item.is_file():
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(item, target)


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


def _expect_rejection(
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
    return False, "invalid submission was accepted"


def run_multi_adapter_suite(
    *,
    task: dict[str, Any],
    metadata: dict[str, Any],
    bundle_root: Path,
    output_dir: Path,
    observed_at: str,
) -> dict[str, Any]:
    if output_dir.exists():
        raise FileExistsError(f"refusing to overwrite output: {output_dir}")
    primary = _load_module("rtlflowbench_primary_adapter", PRIMARY)
    secondary = _load_module("rtlflowbench_scan_adapter", SECONDARY)
    validator = _load_module(
        "rtlflowbench_multi_adapter_validator",
        HERE / "validate.py",
    )
    first = primary.package_submission(
        task=task,
        metadata=metadata,
        bundle_root=bundle_root,
    )
    second = secondary.package_submission(
        task=task,
        metadata=metadata,
        bundle_root=bundle_root,
    )
    repeated = secondary.package_submission(
        task=task,
        metadata=metadata,
        bundle_root=bundle_root,
    )
    first_audit = validator.validate_submission(
        task=task,
        submission=first,
        bundle_root=bundle_root,
    )
    second_audit = validator.validate_submission(
        task=task,
        submission=second,
        bundle_root=bundle_root,
    )
    checks = [
        _check(
            "primary_conformant",
            first_audit["status"] == "pass",
            "The canonical adapter passes the neutral validator.",
            {"issues": first_audit["issues"]},
        ),
        _check(
            "secondary_conformant",
            second_audit["status"] == "pass",
            "The scan adapter passes the neutral validator.",
            {"issues": second_audit["issues"]},
        ),
        _check(
            "cross_adapter_equivalence",
            first == second,
            "Both implementations emit the same submission object.",
        ),
        _check(
            "cross_adapter_task_binding_equivalence",
            first["task_binding"] == second["task_binding"],
            "Independent adapters bind the exact same task descriptor and public packet.",
        ),
        _check(
            "secondary_deterministic",
            second == repeated,
            "Repeated scan-adapter packaging is deterministic.",
        ),
        _check(
            "implementation_independence",
            _source_sha256(PRIMARY) != _source_sha256(SECONDARY)
            and _does_not_import_primary(SECONDARY),
            "The scan adapter has distinct source and does not import the canonical packager.",
            {
                "primary_source_sha256": _source_sha256(PRIMARY),
                "secondary_source_sha256": _source_sha256(SECONDARY),
            },
        ),
    ]

    with tempfile.TemporaryDirectory(
        prefix="rtlflowbench-multi-adapter-"
    ) as temp:
        workspace = Path(temp)
        missing = workspace / "missing"
        _copy_bundle(bundle_root, missing)
        (missing / task["submission_contract"]["required_files"][0]).unlink()
        passed, reason = _expect_rejection(
            secondary,
            task=task,
            metadata=metadata,
            bundle_root=missing,
            expected="missing required files",
        )
        checks.append(_check("secondary_rejects_missing", passed, reason))

        outside = workspace / "outside"
        _copy_bundle(bundle_root, outside)
        probe = outside / "__rtlflowbench_probe__/outside.txt"
        probe.parent.mkdir()
        probe.write_text("scope probe\n", encoding="utf-8")
        passed, reason = _expect_rejection(
            secondary,
            task=task,
            metadata=metadata,
            bundle_root=outside,
            expected="outside editable_paths",
        )
        checks.append(_check("secondary_rejects_scope", passed, reason))

        over_budget = copy.deepcopy(metadata)
        over_budget["resource_usage"]["wall_time_seconds"] = (
            task["budget"]["wall_time_seconds"] + 1
        )
        passed, reason = _expect_rejection(
            secondary,
            task=task,
            metadata=over_budget,
            bundle_root=bundle_root,
            expected="wall time exceeds",
        )
        checks.append(_check("secondary_rejects_budget", passed, reason))

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
            ("llm_calls", "secondary_rejects_llm_call_budget"),
            (
                "human_interventions",
                "secondary_rejects_human_intervention_budget",
            ),
        ):
            over_count = copy.deepcopy(metadata)
            over_count["resource_usage"][field] += 1
            passed, reason = _expect_rejection(
                secondary,
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
        passed, reason = _expect_rejection(
            secondary,
            task=frozen_token_task,
            metadata=missing_tokens,
            bundle_root=bundle_root,
            expected="input_tokens is required by workflow budget",
        )
        checks.append(
            _check("secondary_rejects_missing_token_measurement", passed, reason)
        )
        over_tokens = copy.deepcopy(metadata)
        over_tokens["resource_usage"].update(
            {
                "input_tokens": 1,
                "output_tokens": 0,
                "missing_measurements": [],
            }
        )
        passed, reason = _expect_rejection(
            secondary,
            task=frozen_token_task,
            metadata=over_tokens,
            bundle_root=bundle_root,
            expected="input_tokens exceed workflow budget",
        )
        checks.append(
            _check("secondary_rejects_token_budget", passed, reason)
        )

        networked = copy.deepcopy(metadata)
        networked["network_access_observed"] = True
        passed, reason = _expect_rejection(
            secondary,
            task=task,
            metadata=networked,
            bundle_root=bundle_root,
            expected="network access",
        )
        checks.append(_check("secondary_rejects_network", passed, reason))

        linked = workspace / "linked"
        try:
            linked.symlink_to(bundle_root, target_is_directory=True)
            passed, reason = _expect_rejection(
                secondary,
                task=task,
                metadata=metadata,
                bundle_root=linked,
                expected="regular directory",
            )
        except OSError as exc:
            passed, reason = False, f"{type(exc).__name__}: {exc}"
        checks.append(_check("secondary_rejects_symlink", passed, reason))

    status = (
        "multi_adapter_conformant_submission_only"
        if all(check["status"] == "pass" for check in checks)
        else "fail"
    )
    result = {
        "schema_version": "rtlflowbench.multi_adapter_conformance.v1",
        "task_id": task["task_id"],
        "observed_at": observed_at,
        "status": status,
        "adapters": [
            {
                "adapter_id": "canonical-packager-v1",
                "source": str(PRIMARY.relative_to(HERE.parent.parent.parent)),
                "source_sha256": _source_sha256(PRIMARY),
            },
            {
                "adapter_id": "scan-adapter-v1",
                "source": str(SECONDARY.relative_to(HERE.parent.parent.parent)),
                "source_sha256": _source_sha256(SECONDARY),
            },
        ],
        "submission_sha256": _canonical_sha256(first),
        "checks": checks,
        "summary": {
            "adapter_count": 2,
            "check_count": len(checks),
            "pass_count": sum(
                check["status"] == "pass" for check in checks
            ),
            "fail_count": sum(
                check["status"] == "fail" for check in checks
            ),
        },
        "admission_impact": {
            "multi_adapter_calibration_candidate": status
            == "multi_adapter_conformant_submission_only",
            "hidden_evaluator_run": False,
            "rtl_verdict_produced": False,
            "protocol_ready": False,
        },
        "excluded_claims": [
            "Two adapter implementations do not freeze the protocol.",
            "Submission conformance is not RTL correctness.",
            "This suite does not invoke or expose a hidden evaluator.",
            "This suite does not produce benchmark PASS, QoR, or PPA.",
        ],
    }
    output_dir.mkdir(parents=True)
    (output_dir / "primary-submission.json").write_text(
        json.dumps(first, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (output_dir / "secondary-submission.json").write_text(
        json.dumps(second, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (output_dir / "multi-adapter-conformance.json").write_text(
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
        result = run_multi_adapter_suite(
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
    return (
        0
        if result["status"]
        == "multi_adapter_conformant_submission_only"
        else 2
    )


if __name__ == "__main__":
    raise SystemExit(main())
