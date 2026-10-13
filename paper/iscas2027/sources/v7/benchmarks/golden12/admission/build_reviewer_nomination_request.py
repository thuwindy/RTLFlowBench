#!/usr/bin/env python3
"""Build a fail-closed request for real Golden-12 reviewer nominations."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
TASK_IDS = (
    "G01-common-fifo-spec",
    "G02-common-rr-arbiter-spec",
    "G03-axis-fifo-backpressure",
    "G04-wb2axip-split-bridge",
    "G05-picorv32-missing-irq",
    "G06-ibex-debug-csr-exception",
    "G07-ibex-ifetch-error-timing",
    "G08-common-fifo-dv",
    "G09-axis-fifo-dv",
    "G10-serv-area-qor",
    "G11-picorv32-qor",
    "G12-common-cdc-missing-contract",
)
SUBJECT_TASK_IDS = {
    "protocol": None,
    **{task_id[:3]: task_id for task_id in TASK_IDS},
}
TRACK_COMPETENCIES = {
    "rights_governance": [
        "open-source licensing and redistribution",
        "benchmark provenance and attribution",
    ],
    "protocol_schema_freeze": [
        "workflow-neutral evaluation protocols",
        "JSON schema, CLI, container, and security review",
    ],
    "public_contract_projection": [
        "RTL specifications and hardware interfaces",
        "public repository projection and leakage review",
    ],
    "evaluator_calibration": [
        "RTL design verification, simulation, and formal methods",
        "mutation, alternate-solution, and anti-overfitting calibration",
    ],
    "environment_scoring_freeze": [
        "EDA toolchains, containers, and reproducibility",
        "QoR measurement, scoring, budgets, and statistical reporting",
    ],
    "technical_admission": [
        "independent RTL engineering and benchmark audit",
    ],
    "final_admission": [
        "independent benchmark governance and evidence-chain audit",
        "conflict-of-interest and release admission review",
    ],
}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load(path: Path, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a regular non-symlink file: {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise TypeError(f"{label} must contain one JSON object")
    return value


def _validate(value: dict[str, Any], schema_path: Path, label: str) -> None:
    schema = _load(schema_path, f"{label} schema")
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(
        schema,
        format_checker=FormatChecker(),
    ).validate(value)


def _parse_observed_at(value: str) -> None:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("--observed-at must include a timezone")


def _external(repo_root: Path, path: Path, label: str) -> Path:
    resolved = path.expanduser().resolve()
    try:
        resolved.relative_to(repo_root)
    except ValueError:
        return resolved
    raise ValueError(f"{label} must remain outside the repository")


def _current_review_material_sha256(
    repo_root: Path,
) -> tuple[dict[str, str], dict[str, str]]:
    candidate_lock_sha256: dict[str, str] = {}
    review_packet_sha256: dict[str, str] = {}
    for subject_id, task_id in SUBJECT_TASK_IDS.items():
        if task_id is None:
            material_root = repo_root / "benchmarks/golden12/protocol"
        else:
            material_root = (
                repo_root
                / "benchmarks/golden12/tasks"
                / task_id
                / "private/admission"
            )
        lock_path = material_root / "candidate.lock.json"
        packet_path = material_root / "review_packet.json"
        _load(lock_path, f"current {subject_id} candidate lock")
        packet = _load(packet_path, f"current {subject_id} review packet")
        lock_digest = _sha256(lock_path)
        packet_digest = _sha256(packet_path)
        if (
            packet.get("status") != "pending_independent_review"
            or packet.get("self_approval_forbidden") is not True
            or packet.get("candidate_lock_sha256") != lock_digest
        ):
            raise ValueError(
                f"current review material is not a safe pending packet: {subject_id}"
            )
        candidate_lock_sha256[subject_id] = lock_digest
        review_packet_sha256[subject_id] = packet_digest
    return candidate_lock_sha256, review_packet_sha256


def _validate_current_assignment_sources(
    repo_root: Path,
    assignment: dict[str, Any],
) -> None:
    source = assignment.get("source")
    if not isinstance(source, dict):
        raise ValueError("review assignment has no source binding")
    assigned_locks = source.get("candidate_lock_sha256")
    assigned_packets = source.get("review_packet_sha256")
    if not isinstance(assigned_locks, dict) or not isinstance(
        assigned_packets, dict
    ):
        raise ValueError("review assignment source binding is incomplete")
    expected_subjects = set(SUBJECT_TASK_IDS)
    if set(assigned_locks) != expected_subjects or set(assigned_packets) != expected_subjects:
        raise ValueError("review assignment source subjects are incomplete")

    current_locks, current_packets = _current_review_material_sha256(repo_root)
    if assigned_locks != current_locks:
        raise ValueError(
            "review assignment candidate locks are stale relative to current repository"
        )
    if assigned_packets != current_packets:
        raise ValueError(
            "review assignment packets are stale relative to current repository"
        )

    items = assignment.get("items")
    if not isinstance(items, list) or not items:
        raise ValueError("review assignment has no items")
    observed_subjects: set[str] = set()
    for item in items:
        if not isinstance(item, dict):
            raise ValueError("review assignment contains a non-object item")
        subject_id = item.get("subject_id")
        if subject_id not in SUBJECT_TASK_IDS:
            raise ValueError("review assignment item has an unknown subject")
        observed_subjects.add(subject_id)
        if item.get("task_id") != SUBJECT_TASK_IDS[subject_id]:
            raise ValueError(
                f"review assignment item task drift: {subject_id}"
            )
        if item.get("candidate_lock_sha256") != current_locks[subject_id]:
            raise ValueError(
                "review assignment item candidate lock is stale relative to "
                f"current repository: {subject_id}"
            )
        if item.get("review_packet_sha256") != current_packets[subject_id]:
            raise ValueError(
                "review assignment item packet is stale relative to current "
                f"repository: {subject_id}"
            )
    if observed_subjects != expected_subjects:
        raise ValueError("review assignment items do not cover every subject")


def _instructions() -> str:
    return """# Golden-12 reviewer nomination intake

This directory is reviewer-only and must remain outside the repository and all
evaluated workflow workspaces. The request is not an approval, reviewer
registry, assignment, signature, freeze, admission, or benchmark result.

Release-authority steps:

1. Verify the SHA256 of `reviewer_nomination_request.json` out of band.
2. Ask real people to provide identity, organization, OpenSSH public key and
   fingerprint, relevant tracks, qualifications, and a conflict declaration.
3. Record only those human-provided fields in a response conforming to
   `reviewer_nomination_response.schema.json`. Do not invent identities or keys.
4. A separate governance authority reviews the nominations and creates the
   governed trusted-reviewer registries and allowed-signers files.
5. Re-run the registry governance verifier before assigning any review item.
6. Reviewer attestations must target the exact candidate-lock digest in the
   verified reviewer workspace. A content relock invalidates prior signatures.

The response schema is deliberately pending-only: it cannot record an approval,
completed review, or ready suite. Private evaluator evidence must never be
copied into an evaluated workflow workspace.
"""


def build_reviewer_nomination_request(
    *,
    repo_root: Path,
    assignment_handoff_path: Path,
    expected_assignment_sha256: str,
    output_dir: Path,
    observed_at: str,
) -> dict[str, Any]:
    _parse_observed_at(observed_at)
    if SHA256_RE.fullmatch(expected_assignment_sha256) is None:
        raise ValueError("expected assignment SHA256 must be a lowercase digest")
    repo_root = repo_root.expanduser().resolve(strict=True)
    assignment_handoff_path = _external(
        repo_root,
        assignment_handoff_path,
        "assignment handoff",
    ).resolve(strict=True)
    output_dir = _external(repo_root, output_dir, "nomination output")
    if output_dir.exists() or output_dir.is_symlink():
        raise FileExistsError(f"refusing to overwrite output: {output_dir}")

    admission = repo_root / "benchmarks/golden12/admission"
    assignment_schema = admission / "review_assignment_handoff.schema.json"
    request_schema = admission / "reviewer_nomination_request.schema.json"
    response_schema = admission / "reviewer_nomination_response.schema.json"
    assignment = _load(assignment_handoff_path, "review assignment handoff")
    assignment_sha256 = _sha256(assignment_handoff_path)
    if assignment_sha256 != expected_assignment_sha256:
        raise ValueError("review assignment differs from its out-of-band trust anchor")
    _validate(assignment, assignment_schema, "review assignment handoff")
    if (
        assignment.get("status")
        != "verified_unassigned_pending_independent_review"
        or assignment.get("assignment_ready") is not True
        or assignment.get("assigned_review_item_count") != 0
        or assignment.get("approved_review_item_count") != 0
        or assignment.get("trusted_reviewer_registry_supplied") is not False
        or assignment.get("registry_governance_complete") is not False
        or assignment.get("independent_review_complete") is not False
        or assignment.get("suite_ready") is not False
        or assignment.get("workflow_workspace_exposure_permitted") is not False
    ):
        raise ValueError("review assignment is not a safe unassigned handoff")

    items = assignment.get("items")
    tracks = assignment.get("tracks")
    if not isinstance(items, list) or not items:
        raise ValueError("review assignment has no items")
    if not isinstance(tracks, list) or len(tracks) != len(TRACK_COMPETENCIES):
        raise ValueError("review assignment has an unexpected track set")
    item_keys = {item.get("item_key") for item in items}
    if None in item_keys or len(item_keys) != len(items):
        raise ValueError("review assignment contains invalid or duplicate item keys")
    if any(
        item.get("assignment_status") != "unassigned"
        or item.get("reviewer_identity") is not None
        or item.get("approval_status") != "pending"
        for item in items
    ):
        raise ValueError("review assignment contains identity or approval material")

    track_ids = {track.get("track_id") for track in tracks}
    if track_ids != set(TRACK_COMPETENCIES):
        raise ValueError("review assignment track ids are incomplete")
    routed_keys = [key for track in tracks for key in track.get("item_keys", [])]
    if len(routed_keys) != len(set(routed_keys)) or set(routed_keys) != item_keys:
        raise ValueError("review assignment tracks do not cover each item exactly once")
    if any(track.get("item_count") != len(track.get("item_keys", [])) for track in tracks):
        raise ValueError("review assignment track count drift")
    _validate_current_assignment_sources(repo_root, assignment)

    builder_path = Path(__file__).resolve(strict=True)
    source_paths = {
        builder_path.relative_to(repo_root).as_posix(): builder_path,
        assignment_schema.relative_to(repo_root).as_posix(): assignment_schema,
        request_schema.relative_to(repo_root).as_posix(): request_schema,
        response_schema.relative_to(repo_root).as_posix(): response_schema,
    }
    result = {
        "schema_version": "rtlflowbench.reviewer_nomination_request.v1",
        "observed_at": observed_at,
        "status": "awaiting_real_reviewer_nominations",
        "classification": "reviewer_only_not_workflow_input",
        "assignment_anchor": {
            "sha256": assignment_sha256,
            "schema_version": assignment["schema_version"],
            "observed_at": assignment["observed_at"],
            "subject_count": assignment["subject_count"],
            "review_item_count": assignment["total_review_item_count"],
        },
        "tracks": [
            {
                "track_id": track["track_id"],
                "description": track["description"],
                "item_count": track["item_count"],
                "item_keys": track["item_keys"],
                "required_competencies": TRACK_COMPETENCIES[track["track_id"]],
                "nomination_status": "pending",
                "nominated_reviewer_count": 0,
            }
            for track in tracks
        ],
        "nomination_response_schema": {
            "relative_path": response_schema.relative_to(repo_root).as_posix(),
            "sha256": _sha256(response_schema),
        },
        "governance": {
            "real_reviewer_identity_required": True,
            "public_key_required": True,
            "public_key_fingerprint_required": True,
            "conflict_of_interest_declaration_required": True,
            "separate_registry_governance_authority_required": True,
            "trusted_reviewer_registry_supplied": False,
            "registry_governance_complete": False,
        },
        "readiness": {
            "independent_review_complete": False,
            "protocol_ready": False,
            "benchmark_ready_task_count": 0,
            "chipflow_adapter_ready_task_count": 0,
            "suite_ready": False,
        },
        "workflow_workspace_exposure_permitted": False,
        "source_sha256": {
            relative: _sha256(path)
            for relative, path in sorted(source_paths.items())
        },
        "excluded_claims": [
            "No reviewer identity, qualification, or public key is supplied by this request.",
            "No reviewer registry, assignment, attestation, signature, or approval is created.",
            "No independent review, protocol freeze, task admission, or suite release is complete.",
            "No benchmark result, score, RTL verdict, PPA claim, or workflow ranking is reported.",
        ],
    }
    _validate(result, request_schema, "reviewer nomination request")
    rendered = json.dumps(result, sort_keys=True)
    instructions = _instructions()
    if "/home/" in rendered + instructions or "/Users/" in rendered + instructions:
        raise ValueError("reviewer nomination request exposes a private host path")
    output_dir.mkdir(parents=True, exist_ok=False)
    (output_dir / "reviewer_nomination_request.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (output_dir / "REVIEWER_NOMINATION_INSTRUCTIONS.md").write_text(
        instructions,
        encoding="utf-8",
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--assignment-handoff", type=Path, required=True)
    parser.add_argument("--expected-assignment-sha256", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--observed-at", required=True)
    args = parser.parse_args()
    build_reviewer_nomination_request(
        repo_root=args.repo_root,
        assignment_handoff_path=args.assignment_handoff,
        expected_assignment_sha256=args.expected_assignment_sha256,
        output_dir=args.output_dir,
        observed_at=args.observed_at,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
