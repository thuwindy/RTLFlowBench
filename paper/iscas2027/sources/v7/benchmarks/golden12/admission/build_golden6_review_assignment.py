#!/usr/bin/env python3
"""Derive the Golden-6 alpha review queue from a locked Golden-12 queue.

This is a workload projection only. It cannot nominate reviewers, approve an
item, freeze a task, admit a workflow, or substitute for the full Golden-12
review assignment.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


SUBJECTS = ("protocol", "G01", "G03", "G05", "G08", "G10", "G12")
TASK_IDS = (
    "G01-common-fifo-spec",
    "G03-axis-fifo-backpressure",
    "G05-picorv32-missing-irq",
    "G08-common-fifo-dv",
    "G10-serv-area-qor",
    "G12-common-cdc-missing-contract",
)
SUBJECT_ITEM_COUNTS = {
    "protocol": 3,
    "G01": 8,
    "G03": 8,
    "G05": 8,
    "G08": 8,
    "G10": 9,
    "G12": 10,
}
TRACK_ITEM_COUNTS = {
    "rights_governance": 13,
    "protocol_schema_freeze": 2,
    "public_contract_projection": 5,
    "evaluator_calibration": 9,
    "environment_scoring_freeze": 19,
    "technical_admission": 0,
    "final_admission": 6,
}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load(path: Path, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a regular non-symlink file: {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{label} must contain one JSON object")
    return value


def _validate(value: dict[str, Any], schema_path: Path, label: str) -> None:
    schema = _load(schema_path, f"{label} schema")
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(value)


def _external(repo_root: Path, path: Path, label: str) -> Path:
    resolved = path.expanduser().resolve()
    try:
        resolved.relative_to(repo_root)
    except ValueError:
        return resolved
    raise ValueError(f"{label} must remain outside the repository")


def _instructions() -> str:
    return """# Golden-6 alpha independent review assignment

This directory is evaluator-private and reviewer-only. Keep it outside the
repository and every evaluated workflow workspace.

The queue contains the protocol plus G01, G03, G05, G08, G10, and G12: 54
pending items projected without modification from the content-bound Golden-12
assignment. The projection is only a smaller review workload. It creates no
reviewer identity, conflict-of-interest decision, signature, approval, freeze,
benchmark readiness, adapter readiness, score, or release.

Reviewers must use each item's verified workspace, exact candidate-lock digest,
documented signature namespace, and out-of-band trusted reviewer registry.
Every item remains pending until a real independent reviewer completes the
documented review and detached-signature flow. A change to reviewed content
requires a new lock, packet, projection, and review. The remaining six Golden-12
tasks are still covered by the original 102-item assignment and are not waived.
"""


def build_golden6_review_assignment(
    *,
    repo_root: Path,
    full_assignment_path: Path,
    expected_full_assignment_sha256: str,
    output_dir: Path,
) -> dict[str, Any]:
    if SHA256_RE.fullmatch(expected_full_assignment_sha256) is None:
        raise ValueError("expected full assignment SHA256 must be a lowercase digest")
    repo_root = repo_root.expanduser().resolve(strict=True)
    full_assignment_path = _external(
        repo_root, full_assignment_path, "full assignment"
    ).resolve(strict=True)
    output_dir = _external(repo_root, output_dir, "Golden-6 assignment output")
    if output_dir.exists() or output_dir.is_symlink():
        raise FileExistsError(f"refusing to overwrite output: {output_dir}")

    admission_root = repo_root / "benchmarks/golden12/admission"
    full_schema_path = admission_root / "review_assignment_handoff.schema.json"
    schema_path = admission_root / "golden6_review_assignment.schema.json"
    full = _load(full_assignment_path, "full Golden-12 review assignment")
    full_sha256 = _sha256(full_assignment_path)
    if full_sha256 != expected_full_assignment_sha256:
        raise ValueError("full assignment differs from its out-of-band trust anchor")
    _validate(full, full_schema_path, "full Golden-12 review assignment")
    if (
        full.get("status") != "verified_unassigned_pending_independent_review"
        or full.get("subject_count") != 13
        or full.get("task_count") != 12
        or full.get("total_review_item_count") != 102
        or full.get("pending_review_item_count") != 102
        or full.get("assigned_review_item_count") != 0
        or full.get("approved_review_item_count") != 0
        or full.get("trusted_reviewer_registry_supplied") is not False
        or full.get("registry_governance_complete") is not False
        or full.get("independent_review_complete") is not False
        or full.get("suite_ready") is not False
        or full.get("workflow_workspace_exposure_permitted") is not False
    ):
        raise ValueError("full assignment is not a safe unsigned Golden-12 queue")

    full_items = full["items"]
    full_keys = [item["item_key"] for item in full_items]
    if len(full_keys) != len(set(full_keys)):
        raise ValueError("full assignment contains duplicate item keys")
    routed_keys = [key for track in full["tracks"] for key in track["item_keys"]]
    if len(routed_keys) != len(set(routed_keys)) or set(routed_keys) != set(full_keys):
        raise ValueError("full assignment track routing is not an exact partition")

    items = [item for item in full_items if item["subject_id"] in SUBJECTS]
    if len(items) != 54 or len({item["item_key"] for item in items}) != 54:
        raise ValueError("Golden-6 projection must contain exactly 54 unique items")
    observed_subject_counts = {
        subject: sum(item["subject_id"] == subject for item in items)
        for subject in SUBJECTS
    }
    if observed_subject_counts != SUBJECT_ITEM_COUNTS:
        raise ValueError("Golden-6 subject review counts drifted")
    if {
        item["task_id"] for item in items if item["task_id"] is not None
    } != set(TASK_IDS):
        raise ValueError("Golden-6 task projection drifted")
    if any(
        item["assignment_status"] != "unassigned"
        or item["reviewer_identity"] is not None
        or item["approval_status"] != "pending"
        or item["conflict_of_interest_declaration_required"] is not True
        or item["detached_signature_required"] is not True
        for item in items
    ):
        raise ValueError("Golden-6 projection contains assigned or approved material")

    item_keys = {item["item_key"] for item in items}
    tracks = []
    for source_track in full["tracks"]:
        keys = [key for key in source_track["item_keys"] if key in item_keys]
        tracks.append(
            {
                "track_id": source_track["track_id"],
                "description": source_track["description"],
                "item_count": len(keys),
                "item_keys": keys,
            }
        )
    track_counts = {track["track_id"]: track["item_count"] for track in tracks}
    if track_counts != TRACK_ITEM_COUNTS:
        raise ValueError("Golden-6 review track counts drifted")
    projected_routing = [key for track in tracks for key in track["item_keys"]]
    if (
        len(projected_routing) != len(set(projected_routing))
        or set(projected_routing) != item_keys
    ):
        raise ValueError("Golden-6 track routing is not an exact partition")

    candidate_digests = {
        subject: full["source"]["candidate_lock_sha256"][subject]
        for subject in SUBJECTS
    }
    packet_digests = {
        subject: full["source"]["review_packet_sha256"][subject]
        for subject in SUBJECTS
    }
    result = {
        "schema_version": "rtlflowbench.golden6_review_assignment.v1",
        "observed_at": full["observed_at"],
        "status": "verified_unassigned_pending_independent_review",
        "classification": "evaluator_private_reviewer_only",
        "release_target": "golden6_alpha",
        "subjects": list(SUBJECTS),
        "task_ids": list(TASK_IDS),
        "subject_count": 7,
        "task_count": 6,
        "total_review_item_count": 54,
        "assigned_review_item_count": 0,
        "approved_review_item_count": 0,
        "pending_review_item_count": 54,
        "assignment_ready": True,
        "trusted_reviewer_registry_supplied": False,
        "registry_governance_complete": False,
        "independent_review_complete": False,
        "protocol_ready": False,
        "benchmark_ready_task_count": 0,
        "chipflow_adapter_ready_task_count": 0,
        "golden6_alpha_ready": False,
        "golden12_v1_ready": False,
        "workflow_workspace_exposure_permitted": False,
        "full_assignment": {
            "schema_version": full["schema_version"],
            "receipt_sha256": full_sha256,
            "expected_receipt_sha256": expected_full_assignment_sha256,
            "trust_anchor_digest_match": True,
            "subject_count": full["subject_count"],
            "task_count": full["task_count"],
            "total_review_item_count": full["total_review_item_count"],
        },
        "tracks": tracks,
        "items": items,
        "source": {
            "builder_sha256": _sha256(Path(__file__).resolve(strict=True)),
            "schema_sha256": _sha256(schema_path),
            "full_assignment_sha256": full_sha256,
            "full_assignment_schema_sha256": _sha256(full_schema_path),
            "candidate_lock_sha256": candidate_digests,
            "review_packet_sha256": packet_digests,
        },
        "excluded_claims": [
            "This projection does not appoint or qualify any reviewer.",
            "This projection creates no registry, signature, decision, freeze, admission, or release.",
            "Golden-6 alpha is not ready because this queue was built.",
            "The other six Golden-12 tasks are not reviewed, waived, frozen, or released by this projection.",
            "No benchmark, task, ChipFlow adapter, vanilla adapter, MAGE adapter, or suite is ready.",
            "No AIRTL PASS, score, QoR, PPA, performance, human-level, or superhuman result is claimed.",
        ],
    }
    _validate(result, schema_path, "Golden-6 review assignment")
    output_dir.mkdir(parents=True)
    (output_dir / "golden6_review_assignment.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (output_dir / "GOLDEN6_REVIEW_ASSIGNMENT_INSTRUCTIONS.md").write_text(
        _instructions(),
        encoding="utf-8",
    )
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--full-assignment-path", type=Path, required=True)
    parser.add_argument("--expected-full-assignment-sha256", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = build_golden6_review_assignment(
            repo_root=args.repo_root,
            full_assignment_path=args.full_assignment_path,
            expected_full_assignment_sha256=args.expected_full_assignment_sha256,
            output_dir=args.output_dir,
        )
    except Exception as exc:
        print(
            json.dumps(
                {
                    "status": "invalid_evidence",
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
