#!/usr/bin/env python3
"""Build a non-independent author review of Golden-12 rights/admission state.

The review checks provenance consistency and fail-closed admission projections.
It never converts pending rights decisions into legal approval and never marks a
task benchmark-ready.
"""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
from typing import Any


MANIFEST = Path("docs/chipflow/research/golden12/manifest.json")
TASK_ROOT = Path("benchmarks/golden12/tasks")


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def review_task(
    *,
    task_id: str,
    rights: dict[str, Any],
    admission: dict[str, Any],
    source: dict[str, Any],
    material: dict[str, Any],
    candidate_lock_sha256: str,
    rights_sha256: str,
    admission_sha256: str,
) -> dict[str, Any]:
    provenance_issues: list[str] = []
    repository = source.get("repository", {})
    expected = {
        "task_id": task_id,
        "source_id": source.get("source_id"),
        "license_spdx": repository.get("license_spdx"),
        "license_evidence_url": source.get("license_evidence_url"),
    }
    for key, value in expected.items():
        if rights.get(key) != value:
            provenance_issues.append(f"rights/manifest mismatch: {key}")
    if rights.get("rights_review_complete") is not False:
        provenance_issues.append("rights review must remain pending without independent signature")
    if rights.get("independent_reviewer") is not None or rights.get("signed_at") is not None:
        provenance_issues.append("unsigned rights receipt contains reviewer/signature claim")
    admission_issues: list[str] = []
    gaps = admission.get("benchmark_readiness_gaps")
    if admission.get("task_id") != task_id:
        admission_issues.append("admission task identity mismatch")
    if admission.get("benchmark_status") != "not_ready":
        admission_issues.append("pending task does not fail closed as not_ready")
    if admission.get("rights_review_complete") is not False:
        admission_issues.append("admission incorrectly claims rights complete")
    if admission.get("independent_review_complete") is not False:
        admission_issues.append("admission incorrectly claims independent review")
    if not isinstance(gaps, list) or not gaps or not all(
        isinstance(item, str) and item.strip() for item in gaps
    ):
        admission_issues.append("non-ready admission lacks concrete readiness gaps")
    expected_material = {
        "public_task_archive": "verified",
        "evaluator_private_archive": "verified",
        "environment_lock": "verified",
        "scoring_profile": "verified",
        "runner_lock": "not_available",
        "protocol_release": "not_available",
    }
    if material.get("task_id") != task_id:
        admission_issues.append("release material task identity mismatch")
    if material.get("candidate_lock_sha256") != candidate_lock_sha256:
        admission_issues.append("release material candidate lock mismatch")
    if material.get("material_status") != expected_material:
        admission_issues.append("release material role status drift")
    return {
        "task_id": task_id,
        "source_id": source.get("source_id"),
        "license_spdx": repository.get("license_spdx"),
        "candidate_lock_sha256": candidate_lock_sha256,
        "rights_receipt_sha256": rights_sha256,
        "admission_receipt_sha256": admission_sha256,
        "rights_provenance_review": (
            "PASS" if not provenance_issues else "FAIL"
        ),
        "admission_fail_closed_review": (
            "PASS" if not admission_issues else "FAIL"
        ),
        "provenance_issues": provenance_issues,
        "admission_issues": admission_issues,
        "readiness_gap_count": len(gaps) if isinstance(gaps, list) else 0,
        "rights_review_complete": False,
        "independent_admission_complete": False,
        "benchmark_ready": False,
        "legal_opinion_provided": False,
    }


def build_receipt(
    *, repo_root: Path, release_material_handoff: Path, observed_at: str
) -> dict[str, Any]:
    parsed = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("observed_at must include timezone")
    repo_root = repo_root.resolve(strict=True)
    manifest_path = repo_root / MANIFEST
    manifest = _load(manifest_path)
    materials = _load(release_material_handoff.resolve(strict=True))
    sources = {row["source_id"]: row for row in manifest["sources"]}
    material_rows = {row["task_id"]: row for row in materials["tasks"]}
    task_ids = [row["task_id"] for row in manifest["tasks"]]
    if len(task_ids) != 12 or len(set(task_ids)) != 12:
        raise ValueError("manifest does not contain twelve unique tasks")
    if set(material_rows) != set(task_ids):
        raise ValueError("release material handoff task set mismatch")
    reviews: list[dict[str, Any]] = []
    for task_id in task_ids:
        public = repo_root / TASK_ROOT / task_id / "public"
        rights_path = public / "rights_review.json"
        admission_path = public / "admission.json"
        candidate_path = (
            repo_root / TASK_ROOT / task_id / "private/admission/candidate.lock.json"
        )
        rights = _load(rights_path)
        admission = _load(admission_path)
        source_id = rights.get("source_id")
        if source_id not in sources:
            raise ValueError(f"unknown source for {task_id}: {source_id}")
        reviews.append(
            review_task(
                task_id=task_id,
                rights=rights,
                admission=admission,
                source=sources[source_id],
                material=material_rows[task_id],
                candidate_lock_sha256=_sha256(candidate_path),
                rights_sha256=_sha256(rights_path),
                admission_sha256=_sha256(admission_path),
            )
        )
    failed = [
        row for row in reviews
        if row["rights_provenance_review"] != "PASS"
        or row["admission_fail_closed_review"] != "PASS"
    ]
    result = {
        "schema_version": "rtlflowbench.author_rights_admission_review.v1",
        "observed_at": observed_at,
        "status": (
            "AUTHOR_TECHNICAL_REVIEW_PASS_RELEASE_BLOCKED"
            if not failed else "AUTHOR_TECHNICAL_REVIEW_FAIL"
        ),
        "reviewer_classification": "author_ai_assisted_technical_review",
        "independent_human_reviewer": False,
        "cryptographic_independent_signature_present": False,
        "manifest_sha256": _sha256(manifest_path),
        "release_material_handoff_sha256": _sha256(release_material_handoff),
        "tasks": reviews,
        "summary": {
            "task_count": len(reviews),
            "rights_provenance_pass_count": sum(
                row["rights_provenance_review"] == "PASS" for row in reviews
            ),
            "admission_fail_closed_pass_count": sum(
                row["admission_fail_closed_review"] == "PASS" for row in reviews
            ),
            "author_review_failure_count": len(failed),
            "rights_review_complete_count": 0,
            "independent_admission_complete_count": 0,
            "benchmark_ready_count": 0,
        },
        "release_decision": "BLOCK",
        "blockers": [
            "Author technical provenance review is not independent legal approval.",
            "No task has an independent rights/admission signature.",
            "Protocol RELEASE and runner RELEASE locks remain unavailable.",
        ],
        "excluded_claims": [
            "This receipt is not legal advice or permission to redistribute upstream material.",
            "Author/AI-assisted review is not human-independent admission.",
            "A PASS in this receipt applies only to provenance consistency and fail-closed readiness projection.",
            "No task is benchmark-ready and no RTL PASS, score, QoR, PPA, or publication result is created."
        ],
    }
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--release-material-handoff", type=Path, required=True)
    parser.add_argument("--observed-at", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists() or args.output.is_symlink():
        raise FileExistsError("refusing to overwrite author review receipt")
    result = build_receipt(
        repo_root=args.repo_root,
        release_material_handoff=args.release_material_handoff,
        observed_at=args.observed_at,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"status": result["status"], **result["summary"]}, sort_keys=True))
    return 0 if result["status"] == "AUTHOR_TECHNICAL_REVIEW_PASS_RELEASE_BLOCKED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
