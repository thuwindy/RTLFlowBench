#!/usr/bin/env python3
"""Classify current Golden-6 freeze blockers without changing release state."""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


TASK_IDS = (
    "G01-common-fifo-spec",
    "G03-axis-fifo-backpressure",
    "G05-picorv32-missing-irq",
    "G08-common-fifo-dv",
    "G10-serv-area-qor",
    "G12-common-cdc-missing-contract",
)
EXPECTED_ORDERED_BLOCKERS = {
    "candidate_relock_and_supersession_pending",
    "environment_release_freeze_missing",
    "final_independent_admission_missing",
    "independent_rights_receipt_missing",
    "new_post_relock_signatures_missing",
    "public_digest_must_be_recomputed_after_rights_and_budget_materialization",
    "release_freeze_policy_pending_independent_review",
    "runner_release_freeze_missing",
    "scoring_release_freeze_missing",
}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load(path: Path, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a regular non-symlink file")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise TypeError(f"{label} must contain one JSON object")
    return value


def _validate(value: dict[str, Any], schema_path: Path, label: str) -> None:
    schema = _load(schema_path, f"{label} schema")
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(value)


def _parse_observed_at(value: str) -> None:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("--observed-at must include a timezone")


def _external_file(repo_root: Path, path: Path, label: str) -> Path:
    expanded = path.expanduser()
    if expanded.is_symlink() or not expanded.is_file():
        raise ValueError(f"{label} must be a regular non-symlink file")
    resolved = expanded.resolve(strict=True)
    if resolved.is_relative_to(repo_root):
        raise ValueError(f"{label} must remain outside the repository")
    return resolved


def _external_output(repo_root: Path, path: Path) -> Path:
    expanded = path.expanduser()
    if expanded.is_symlink():
        raise ValueError("freeze blocker output cannot be a symlink")
    resolved = expanded.resolve()
    if resolved.is_relative_to(repo_root):
        raise ValueError("freeze blocker output must remain outside the repository")
    if resolved.exists():
        raise FileExistsError(f"refusing to overwrite output: {resolved}")
    return resolved


def _instructions() -> str:
    return """# Golden-6 freeze readiness blocker receipt

This release-authority-private receipt separates already-passing automatic
gates from human governance and ordered post-review materialization. It does
not approve rights, nominate a reviewer, sign an attestation, freeze bytes,
admit a task, or authorize formal workflow experiments.

Next order is mandatory: obtain real nominations and governed reviewer keys;
complete rights and all 54 review items; approve the freeze policy; materialize
environment, scoring, budget, and public-digest transitions; relock; obtain new
post-relock signatures; finalize admission; then run formal repeated AIRTL
experiments. Reviewer-only evidence must never enter a workflow workspace.
"""


def build_golden6_freeze_readiness_blocker(
    *,
    repo_root: Path,
    freeze_preflight_path: Path,
    expected_freeze_preflight_sha256: str,
    technical_control_path: Path,
    expected_technical_control_sha256: str,
    reviewer_distribution_path: Path,
    expected_reviewer_distribution_sha256: str,
    output_dir: Path,
    observed_at: str,
) -> dict[str, Any]:
    _parse_observed_at(observed_at)
    for label, digest in (
        ("freeze preflight", expected_freeze_preflight_sha256),
        ("technical control", expected_technical_control_sha256),
        ("reviewer distribution", expected_reviewer_distribution_sha256),
    ):
        if SHA256_RE.fullmatch(digest) is None:
            raise ValueError(f"expected {label} SHA256 must be lowercase")
    repo_root = repo_root.expanduser().resolve(strict=True)
    freeze_preflight_path = _external_file(
        repo_root, freeze_preflight_path, "Golden-12 freeze preflight"
    )
    technical_control_path = _external_file(
        repo_root, technical_control_path, "Golden-6 technical control"
    )
    reviewer_distribution_path = _external_file(
        repo_root, reviewer_distribution_path, "Golden-6 reviewer distribution"
    )
    output_dir = _external_output(repo_root, output_dir)

    admission = repo_root / "benchmarks/golden12/admission"
    golden6 = repo_root / "benchmarks/golden12/golden6"
    preflight_schema = admission / "release_freeze_preflight.schema.json"
    technical_schema = golden6 / "alpha_technical_control_receipt.schema.json"
    distribution_schema = admission / "golden6_reviewer_distribution.schema.json"
    output_schema = admission / "golden6_freeze_readiness_blocker.schema.json"
    preflight = _load(freeze_preflight_path, "Golden-12 freeze preflight")
    technical = _load(technical_control_path, "Golden-6 technical control")
    distribution = _load(reviewer_distribution_path, "Golden-6 reviewer distribution")
    if _sha256(freeze_preflight_path) != expected_freeze_preflight_sha256:
        raise ValueError("freeze preflight differs from its out-of-band trust anchor")
    if _sha256(technical_control_path) != expected_technical_control_sha256:
        raise ValueError("technical control differs from its out-of-band trust anchor")
    if _sha256(reviewer_distribution_path) != expected_reviewer_distribution_sha256:
        raise ValueError("reviewer distribution differs from its out-of-band trust anchor")
    _validate(preflight, preflight_schema, "Golden-12 freeze preflight")
    _validate(technical, technical_schema, "Golden-6 technical control")
    _validate(distribution, distribution_schema, "Golden-6 reviewer distribution")

    if (
        preflight["status"] != "blocked_pending_independent_freeze"
        or preflight["task_count"] != 12
        or preflight["exact_budget_proposal_count"] != 12
        or preflight["candidate_bound_material_count"] != 12
        or preflight["freeze_transition_eligible_count"] != 0
        or preflight["independent_review_complete"] is not False
        or preflight["benchmark_ready"] is not False
        or preflight["chipflow_adapter_ready"] is not False
    ):
        raise ValueError("Golden-12 freeze preflight is not current and fail closed")
    if (
        technical["status"] != "current_technical_controls_reprojected_not_admitted"
        or technical["readiness"]["integrity_checks_passed"] is not True
        or technical["protocol"]["failed_automatic_gate_count"] != 0
        or technical["task_control_summary"]["component_mismatch_count"] != 0
        or technical["task_control_summary"]["approved_review_item_count"] != 0
        or technical["public_transport"]["private_file_count"] != 0
        or technical["public_transport"]["technically_reproduced"] is not True
        or technical["offline_evaluator_v11"]["case_count"] != 6
        or technical["offline_evaluator_v11"]["source_integrity_pass_count"] != 6
        or technical["alpha_ready"] is not False
    ):
        raise ValueError("Golden-6 technical control has an automatic gate failure")
    if (
        distribution["status"]
        != "verified_unsigned_distribution_pending_real_reviewer_nomination"
        or distribution["review_item_count"] != 54
        or distribution["governance"]["human_nomination_response_supplied"] is not False
        or distribution["governance"]["approvals_recorded"] != 0
        or distribution["readiness"]["golden6_alpha_ready"] is not False
        or distribution["workflow_workspace_exposure_permitted"] is not False
    ):
        raise ValueError("Golden-6 reviewer distribution is not safe and pending")

    preflight_rows = {row["task_id"]: row for row in preflight["tasks"]}
    technical_rows = {row["task_id"]: row for row in technical["tasks"]}
    distribution_rows = {
        row["task_id"]: row
        for row in distribution["subjects"]
        if row["task_id"] is not None
    }
    if not all(set(rows) >= set(TASK_IDS) for rows in (preflight_rows, technical_rows)):
        raise ValueError("Golden-6 task coverage is incomplete")
    if set(distribution_rows) != set(TASK_IDS):
        raise ValueError("reviewer distribution task coverage drifted")

    tasks = []
    for task_id in TASK_IDS:
        preflight_row = preflight_rows[task_id]
        technical_row = technical_rows[task_id]
        distribution_row = distribution_rows[task_id]
        blockers = set(preflight_row["blockers"])
        if blockers != EXPECTED_ORDERED_BLOCKERS:
            raise ValueError(f"freeze blocker classification drifted: {task_id}")
        if (
            preflight_row["candidate_lock_sha256"]
            != technical_row["candidate_lock_sha256"]
            or technical_row["candidate_lock_sha256"]
            != distribution_row["candidate_lock_sha256"]
            or technical_row["review_packet_sha256"]
            != distribution_row["review_packet_sha256"]
            or preflight_row["exact_budget_proposal_complete"] is not True
            or preflight_row["all_selected_materials_candidate_bound"] is not True
            or distribution_row["archive_safety_verified"] is not True
            or preflight_row["public_rights_ready"] is not False
            or preflight_row["materials"]["environment_lock"]
            ["current_release_freeze_verified"] is not False
            or preflight_row["materials"]["scoring_profile"]
            ["current_release_freeze_verified"] is not False
            or preflight_row["freeze_transition_eligible"] is not False
        ):
            raise ValueError(f"Golden-6 task freeze anchors or gates drifted: {task_id}")
        tasks.append(
            {
                "task_id": task_id,
                "subject_id": task_id[:3],
                "candidate_lock_sha256": technical_row["candidate_lock_sha256"],
                "review_packet_sha256": technical_row["review_packet_sha256"],
                "review_item_count": technical_row["review_item_count"],
                "automatic_gate_status": "pass",
                "exact_budget_proposal_complete": True,
                "all_selected_materials_candidate_bound": True,
                "review_bundle_safety_verified": True,
                "public_rights_ready": False,
                "environment_release_frozen": False,
                "scoring_release_frozen": False,
                "freeze_transition_eligible": False,
                "ordered_blockers": sorted(blockers),
            }
        )

    builder_path = Path(__file__).resolve(strict=True)
    sources = {
        builder_path.relative_to(repo_root).as_posix(): builder_path,
        preflight_schema.relative_to(repo_root).as_posix(): preflight_schema,
        technical_schema.relative_to(repo_root).as_posix(): technical_schema,
        distribution_schema.relative_to(repo_root).as_posix(): distribution_schema,
        output_schema.relative_to(repo_root).as_posix(): output_schema,
    }
    result = {
        "schema_version": "rtlflowbench.golden6_freeze_readiness_blocker.v1",
        "observed_at": observed_at,
        "status": "automatic_preflight_pass_human_review_and_freeze_pending",
        "classification": "release_authority_private",
        "release_target": "golden6_alpha",
        "task_count": 6,
        "review_item_count": 54,
        "anchors": {
            "golden12_freeze_preflight_sha256": _sha256(freeze_preflight_path),
            "golden6_technical_control_sha256": _sha256(technical_control_path),
            "golden6_reviewer_distribution_sha256": _sha256(
                reviewer_distribution_path
            ),
        },
        "machine_gates": {
            "integrity_checks_passed": True,
            "protocol_automatic_gate_failure_count": 0,
            "task_component_mismatch_count": 0,
            "candidate_bound_task_count": 6,
            "exact_budget_task_count": 6,
            "safe_reviewer_bundle_task_count": 6,
            "public_transport_private_file_count": 0,
            "offline_evaluator_source_integrity_task_count": 6,
            "pre_review_automatic_blocker_count": 0,
        },
        "tasks": tasks,
        "human_governance": {
            "nomination_response_supplied": False,
            "trusted_reviewer_registry_supplied": False,
            "registry_governance_complete": False,
            "independent_rights_ready_task_count": 0,
            "approved_review_item_count": 0,
            "independent_review_complete": False,
            "freeze_policy_approved": False,
            "final_admission_complete": False,
        },
        "post_review_materialization": {
            "environment_release_frozen_task_count": 0,
            "scoring_release_frozen_task_count": 0,
            "public_digest_recomputed_task_count": 0,
            "candidate_relock_complete_task_count": 0,
            "post_relock_signature_complete_task_count": 0,
            "freeze_materialized": False,
        },
        "downstream_experiments": {
            "formal_experiments_permitted": False,
            "formal_results_admissible": False,
        },
        "readiness": {
            "benchmark_ready_task_count": 0,
            "chipflow_adapter_ready_task_count": 0,
            "golden6_alpha_ready": False,
            "golden12_v1_ready": False,
        },
        "workflow_workspace_exposure_permitted": False,
        "source_sha256": {
            relative: _sha256(path) for relative, path in sorted(sources.items())
        },
        "excluded_claims": [
            "Automatic preflight PASS is not independent review or rights approval.",
            "Candidate-bound development environment and scoring files are not frozen release bytes.",
            "This receipt creates no reviewer identity, registry, signature, approval, relock, admission, or freeze.",
            "Formal workflow experiments remain prohibited and inadmissible before the ordered gates complete.",
            "Golden-6 alpha and Golden-12 v1 remain not ready.",
            "No benchmark PASS, score, QoR, PPA, performance, human-level, or superhuman claim is made.",
        ],
    }
    _validate(result, output_schema, "Golden-6 freeze readiness blocker")
    rendered = json.dumps(result, sort_keys=True) + _instructions()
    if "/home/" in rendered or "/Users/" in rendered:
        raise ValueError("freeze blocker receipt exposes a private host path")
    output_dir.mkdir(parents=True)
    (output_dir / "golden6_freeze_readiness_blocker.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (output_dir / "GOLDEN6_FREEZE_READINESS_NEXT_STEPS.md").write_text(
        _instructions(), encoding="utf-8"
    )
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--freeze-preflight", type=Path, required=True)
    parser.add_argument("--expected-freeze-preflight-sha256", required=True)
    parser.add_argument("--technical-control", type=Path, required=True)
    parser.add_argument("--expected-technical-control-sha256", required=True)
    parser.add_argument("--reviewer-distribution", type=Path, required=True)
    parser.add_argument("--expected-reviewer-distribution-sha256", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--observed-at", required=True)
    args = parser.parse_args()
    try:
        result = build_golden6_freeze_readiness_blocker(
            repo_root=args.repo_root,
            freeze_preflight_path=args.freeze_preflight,
            expected_freeze_preflight_sha256=args.expected_freeze_preflight_sha256,
            technical_control_path=args.technical_control,
            expected_technical_control_sha256=args.expected_technical_control_sha256,
            reviewer_distribution_path=args.reviewer_distribution,
            expected_reviewer_distribution_sha256=args.expected_reviewer_distribution_sha256,
            output_dir=args.output_dir,
            observed_at=args.observed_at,
        )
    except Exception as exc:
        print(
            json.dumps(
                {"status": "invalid_evidence", "error": f"{type(exc).__name__}: {exc}"},
                indent=2,
                sort_keys=True,
            )
        )
        return 2
    print(
        json.dumps(
            {
                "status": result["status"],
                "task_count": result["task_count"],
                "pre_review_automatic_blocker_count": 0,
                "approved_review_item_count": 0,
                "golden6_alpha_ready": False,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
