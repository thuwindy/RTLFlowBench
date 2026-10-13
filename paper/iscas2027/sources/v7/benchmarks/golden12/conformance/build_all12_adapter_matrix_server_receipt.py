#!/usr/bin/env python3
"""Build a source-bound SERVER26 receipt for the all-12 adapter matrix."""

from __future__ import annotations

import argparse
import hashlib
from importlib.metadata import version
import json
from pathlib import Path
import platform
import re
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


REPO_ROOT = Path(__file__).resolve().parents[3]
CONFORMANCE = Path(__file__).resolve().parent
SCHEMA = REPO_ROOT / (
    "docs/chipflow/research/golden12/"
    "protocol_all12_adapter_matrix_server_receipt.schema.json"
)


def _sha256(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"expected regular non-symlink file: {path}")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def _elapsed_seconds(value: str) -> float:
    parts = value.strip().split(":")
    if len(parts) == 2:
        return int(parts[0]) * 60 + float(parts[1])
    if len(parts) == 3:
        return int(parts[0]) * 3600 + int(parts[1]) * 60 + float(parts[2])
    raise ValueError("unrecognized GNU time elapsed value")


def _resource_metrics(path: Path) -> tuple[int, float]:
    text = path.read_text(encoding="utf-8")
    rss = re.search(r"Maximum resident set size \(kbytes\):\s*(\d+)", text)
    elapsed = re.search(r"Elapsed \(wall clock\) time .*?:\s*([0-9:.]+)", text)
    if not rss or not elapsed:
        raise ValueError("GNU time resource log is incomplete")
    return int(rss.group(1)), _elapsed_seconds(elapsed.group(1))


def _authority(path: Path) -> tuple[str, str, str, int]:
    text = path.read_text(encoding="utf-8")
    return "codex/chipflow-native-trunk", "", hashlib.sha256(path.read_bytes()).hexdigest(), len(text.splitlines())


def build_receipt(
    *,
    repo_root: Path,
    matrix_path: Path,
    raw_log_path: Path,
    resource_log_path: Path,
    evidence_root: str,
    authority_status_before: Path,
    authority_status_after: Path,
    authority_head: str,
    observed_at: str,
) -> dict[str, Any]:
    root = repo_root.resolve(strict=True)
    if "/home/" in evidence_root or "/Users/" in evidence_root:
        raise ValueError("evidence root must not expose a private absolute path")
    if authority_status_before.read_bytes() != authority_status_after.read_bytes():
        raise ValueError("authority status changed during matrix execution")
    _, _, status_sha256, status_count = _authority(authority_status_before)
    matrix = _load(matrix_path)
    summary = matrix.get("summary", {})
    if matrix.get("status") != "all12_multi_adapter_conformant_submission_only":
        raise ValueError("all-12 adapter matrix did not pass")
    expected_summary = {
        "task_count": 12,
        "candidate_bound_task_count": 12,
        "adapter_count_per_task": 2,
        "check_count": 180,
        "pass_count": 180,
        "fail_count": 0,
    }
    if summary != expected_summary:
        raise ValueError("all-12 adapter matrix summary is unexpected")
    bindings = []
    for item in matrix["tasks"]:
        bindings.append({
            "task_id": item["task_id"],
            "task_descriptor_sha256": item["task_descriptor_sha256"],
            "candidate_lock_sha256": item["candidate_lock_sha256"],
            "submission_sha256": item["submission_sha256"],
        })
    rss, elapsed = _resource_metrics(resource_log_path)
    result = {
        "schema_version": "rtlflowbench.protocol_all12_adapter_matrix_server_receipt.v1",
        "candidate_release": "rtlflowbench-protocol-v1",
        "observed_at": observed_at,
        "status": "server_all12_submission_protocol_calibrated_not_frozen",
        "source": {
            "receipt_builder_sha256": _sha256(Path(__file__).resolve()),
            "matrix_runner_sha256": _sha256(CONFORMANCE / "run_all12_adapter_matrix.py"),
            "matrix_schema_sha256": _sha256(CONFORMANCE / "all12_adapter_matrix.schema.json"),
            "multi_adapter_suite_sha256": _sha256(CONFORMANCE / "run_multi_adapter_suite.py"),
            "primary_adapter_sha256": _sha256(CONFORMANCE / "package_submission.py"),
            "secondary_adapter_sha256": _sha256(CONFORMANCE / "adapters/scan_submission_adapter.py"),
            "validator_sha256": _sha256(CONFORMANCE / "validate.py"),
            "task_schema_sha256": _sha256(root / "benchmarks/golden12/schemas/task.schema.json"),
        },
        "environment": {
            "host": "SERVER26",
            "python_version": platform.python_version(),
            "jsonschema_version": version("jsonschema"),
            "resource_max_rss_kib": rss,
            "elapsed_wall_seconds": elapsed,
            "environment_frozen": False,
        },
        "matrix": {
            "evidence_root": evidence_root,
            "result_sha256": _sha256(matrix_path),
            "raw_log_sha256": _sha256(raw_log_path),
            "resource_log_sha256": _sha256(resource_log_path),
            "exit_code": 0,
            "status": matrix["status"],
            **summary,
        },
        "binding_semantics": {
            "task_descriptor_sha256": "must_match_current_descriptor_and_current_task_candidate_binding",
            "candidate_lock_sha256": "execution_time_identity_not_protocol_release_dependency",
            "post_run_candidate_relock_rule": "permitted_only_when_current_task_candidate_binds_the_same_descriptor_sha256",
        },
        "task_bindings": bindings,
        "isolation": {
            "fixture_classification": "synthetic_submission_protocol_only",
            "network_access_observed": False,
            "hidden_evaluator_run": False,
            "rtl_verdict_produced": False,
            "workflow_workspace_private_assets_exposed": False,
        },
        "authority_guard": {
            "branch": "codex/chipflow-native-trunk",
            "head": authority_head,
            "porcelain_entry_count": status_count,
            "porcelain_sha256": status_sha256,
            "unchanged": True,
        },
        "readiness": {
            "all12_external_submission_coverage_candidate": True,
            "independent_protocol_review_complete": False,
            "schema_frozen": False,
            "container_cli_frozen": False,
            "protocol_ready": False,
            "benchmark_ready": False,
            "chipflow_adapter_ready": False,
        },
        "excluded_claims": [
            "The twelve fixtures are protocol calibration inputs, not AIRTL workflow runs.",
            "No hidden evaluator, EDA, RTL verdict, score, QoR, PPA, or performance measurement was produced.",
            "Candidate-lock hashes identify execution-time task candidates and do not admit them.",
            "This same-host observation is not cross-host or independent review.",
        ],
    }
    schema = _load(root / SCHEMA.relative_to(REPO_ROOT))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--matrix", type=Path, required=True)
    parser.add_argument("--raw-log", type=Path, required=True)
    parser.add_argument("--resource-log", type=Path, required=True)
    parser.add_argument("--evidence-root", required=True)
    parser.add_argument("--authority-status-before", type=Path, required=True)
    parser.add_argument("--authority-status-after", type=Path, required=True)
    parser.add_argument("--authority-head", required=True)
    parser.add_argument("--observed-at", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists() or args.output.is_symlink():
        raise FileExistsError(f"refusing to overwrite output: {args.output}")
    value = build_receipt(
        repo_root=args.repo_root,
        matrix_path=args.matrix,
        raw_log_path=args.raw_log,
        resource_log_path=args.resource_log,
        evidence_root=args.evidence_root,
        authority_status_before=args.authority_status_before,
        authority_status_after=args.authority_status_after,
        authority_head=args.authority_head,
        observed_at=args.observed_at,
    )
    args.output.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(value["matrix"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
