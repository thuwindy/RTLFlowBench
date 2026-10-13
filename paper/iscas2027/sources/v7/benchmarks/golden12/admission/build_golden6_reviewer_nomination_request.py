#!/usr/bin/env python3
"""Build a pending-only reviewer nomination request for Golden-6 alpha."""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
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
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(value)


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


def _instructions() -> str:
    return """# Golden-6 alpha reviewer nomination intake

This directory is reviewer-only and must remain outside the repository and all
evaluated workflow workspaces. It contains no reviewer identity, key, approval,
signature, freeze, score, or benchmark result.

Give a prospective reviewer only this request, the Golden-6 review assignment,
and the verified workspaces referenced by the assigned item keys. Ask the real
person to return: identity; organization; OpenSSH public key and SHA256
fingerprint; selected track IDs; a short qualification statement; and an
explicit conflict-of-interest declaration listing affected item keys, if any.

Record those human-provided fields in a response conforming to
`benchmarks/golden12/admission/reviewer_nomination_response.schema.json`, bound
to the exact request and assignment SHA256 values. Do not invent identities,
keys, qualifications, or COI declarations. A separate governance authority
must approve the trusted reviewer registry before any item can be assigned.

The 54-item queue is an alpha workload projection only. It does not waive the
remaining 48 items in the full Golden-12 queue. Content changes require a new
candidate lock, review packet, assignment projection, and nomination request.
"""


def build_golden6_reviewer_nomination_request(
    *,
    repo_root: Path,
    assignment_path: Path,
    expected_assignment_sha256: str,
    output_dir: Path,
    observed_at: str,
) -> dict[str, Any]:
    _parse_observed_at(observed_at)
    if SHA256_RE.fullmatch(expected_assignment_sha256) is None:
        raise ValueError("expected assignment SHA256 must be a lowercase digest")
    repo_root = repo_root.expanduser().resolve(strict=True)
    assignment_path = _external(
        repo_root, assignment_path, "Golden-6 assignment"
    ).resolve(strict=True)
    output_dir = _external(repo_root, output_dir, "nomination output")
    if output_dir.exists() or output_dir.is_symlink():
        raise FileExistsError(f"refusing to overwrite output: {output_dir}")

    admission = repo_root / "benchmarks/golden12/admission"
    assignment_schema = admission / "golden6_review_assignment.schema.json"
    request_schema = admission / "golden6_reviewer_nomination_request.schema.json"
    response_schema = admission / "reviewer_nomination_response.schema.json"
    assignment = _load(assignment_path, "Golden-6 review assignment")
    assignment_sha256 = _sha256(assignment_path)
    if assignment_sha256 != expected_assignment_sha256:
        raise ValueError("Golden-6 assignment differs from its out-of-band trust anchor")
    _validate(assignment, assignment_schema, "Golden-6 review assignment")
    if (
        assignment.get("status")
        != "verified_unassigned_pending_independent_review"
        or assignment.get("release_target") != "golden6_alpha"
        or assignment.get("assignment_ready") is not True
        or assignment.get("total_review_item_count") != 54
        or assignment.get("assigned_review_item_count") != 0
        or assignment.get("approved_review_item_count") != 0
        or assignment.get("trusted_reviewer_registry_supplied") is not False
        or assignment.get("registry_governance_complete") is not False
        or assignment.get("independent_review_complete") is not False
        or assignment.get("golden6_alpha_ready") is not False
        or assignment.get("golden12_v1_ready") is not False
        or assignment.get("workflow_workspace_exposure_permitted") is not False
    ):
        raise ValueError("Golden-6 assignment is not a safe unassigned handoff")

    items = assignment["items"]
    tracks = assignment["tracks"]
    item_keys = {item.get("item_key") for item in items}
    if None in item_keys or len(item_keys) != len(items) or len(items) != 54:
        raise ValueError("Golden-6 assignment item set is invalid")
    if any(
        item.get("assignment_status") != "unassigned"
        or item.get("reviewer_identity") is not None
        or item.get("approval_status") != "pending"
        for item in items
    ):
        raise ValueError("Golden-6 assignment contains identity or approval material")
    if {track.get("track_id") for track in tracks} != set(TRACK_COMPETENCIES):
        raise ValueError("Golden-6 assignment track ids are incomplete")
    routed = [key for track in tracks for key in track.get("item_keys", [])]
    if len(routed) != len(set(routed)) or set(routed) != item_keys:
        raise ValueError("Golden-6 assignment tracks are not an exact partition")
    if any(track.get("item_count") != len(track.get("item_keys", [])) for track in tracks):
        raise ValueError("Golden-6 assignment track count drift")

    builder_path = Path(__file__).resolve(strict=True)
    sources = {
        builder_path.relative_to(repo_root).as_posix(): builder_path,
        assignment_schema.relative_to(repo_root).as_posix(): assignment_schema,
        request_schema.relative_to(repo_root).as_posix(): request_schema,
        response_schema.relative_to(repo_root).as_posix(): response_schema,
    }
    result = {
        "schema_version": "rtlflowbench.golden6_reviewer_nomination_request.v1",
        "observed_at": observed_at,
        "status": "awaiting_real_reviewer_nominations",
        "classification": "reviewer_only_not_workflow_input",
        "release_target": "golden6_alpha",
        "assignment_anchor": {
            "sha256": assignment_sha256,
            "schema_version": assignment["schema_version"],
            "observed_at": assignment["observed_at"],
            "subject_count": assignment["subject_count"],
            "task_count": assignment["task_count"],
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
            "golden6_alpha_ready": False,
            "golden12_v1_ready": False,
        },
        "workflow_workspace_exposure_permitted": False,
        "source_sha256": {
            relative: _sha256(path) for relative, path in sorted(sources.items())
        },
        "excluded_claims": [
            "No reviewer identity, qualification, public key, or COI statement is supplied by this request.",
            "No reviewer registry, assignment, attestation, signature, approval, freeze, admission, or release is created.",
            "Golden-6 alpha and Golden-12 v1 remain not ready.",
            "The remaining Golden-12 review items are not waived or completed.",
            "No benchmark result, score, RTL verdict, QoR, PPA, performance, or workflow ranking is reported.",
        ],
    }
    _validate(result, request_schema, "Golden-6 reviewer nomination request")
    rendered = json.dumps(result, sort_keys=True) + _instructions()
    if "/home/" in rendered or "/Users/" in rendered:
        raise ValueError("Golden-6 nomination request exposes a private host path")
    output_dir.mkdir(parents=True, exist_ok=False)
    (output_dir / "golden6_reviewer_nomination_request.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (output_dir / "GOLDEN6_REVIEWER_NOMINATION_INSTRUCTIONS.md").write_text(
        _instructions(), encoding="utf-8"
    )
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--assignment", type=Path, required=True)
    parser.add_argument("--expected-assignment-sha256", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--observed-at", required=True)
    args = parser.parse_args()
    try:
        result = build_golden6_reviewer_nomination_request(
            repo_root=args.repo_root,
            assignment_path=args.assignment,
            expected_assignment_sha256=args.expected_assignment_sha256,
            output_dir=args.output_dir,
            observed_at=args.observed_at,
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
