#!/usr/bin/env python3
"""Validate reviewer nominations and build pending registry candidates."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

ADMISSION = Path("benchmarks/golden12/admission")
PROTOCOL = Path("benchmarks/golden12/protocol")
ASSIGNMENT_SCHEMA = ADMISSION / "review_assignment_handoff.schema.json"
REQUEST_SCHEMA = ADMISSION / "reviewer_nomination_request.schema.json"
RESPONSE_SCHEMA = ADMISSION / "reviewer_nomination_response.schema.json"
INTAKE_SCHEMA = ADMISSION / "reviewer_nomination_intake.schema.json"
COMMON_REGISTRY_SCHEMA = ADMISSION / "trusted_reviewers.schema.json"
PROTOCOL_REGISTRY_SCHEMA = PROTOCOL / "trusted_reviewers.schema.json"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
IDENTITY_RE = re.compile(r"^[A-Za-z0-9_.@+-]+$")


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _sha256(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _load(path: Path, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a regular non-symlink file")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise TypeError(f"{label} must contain one JSON object")
    return value


def _validate(
    value: dict[str, Any],
    schema_path: Path,
    label: str,
) -> None:
    schema = _load(schema_path, f"{label} schema")
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(
        schema,
        format_checker=FormatChecker(),
    ).validate(value)


def _external_file(
    repo_root: Path,
    path: Path,
    label: str,
) -> Path:
    expanded = path.expanduser()
    if expanded.is_symlink() or not expanded.is_file():
        raise ValueError(f"{label} must be a regular non-symlink file")
    resolved = expanded.resolve()
    if resolved.is_relative_to(repo_root):
        raise ValueError(f"{label} must remain outside the repository")
    return resolved


def _external_output(repo_root: Path, path: Path) -> Path:
    expanded = path.expanduser()
    if expanded.is_symlink():
        raise ValueError("nomination intake output cannot be a symlink")
    resolved = expanded.resolve()
    if resolved.is_relative_to(repo_root):
        raise ValueError("nomination intake output must remain outside the repository")
    if resolved.exists():
        raise FileExistsError(f"refusing to overwrite output: {resolved}")
    return resolved


def _parse_observed_at(value: str) -> None:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("--observed-at must include a timezone")


def _normalized_public_key(value: str) -> tuple[str, str]:
    if "\r" in value or "\n" in value:
        raise ValueError("reviewer public key must occupy one line")
    fields = value.strip().split()
    if len(fields) not in (2, 3):
        raise ValueError("reviewer public key must use OpenSSH public-key format")
    key_type, key_body = fields[:2]
    if not (
        key_type.startswith(("ssh-", "ecdsa-", "sk-"))
    ):
        raise ValueError(f"unsupported reviewer key type: {key_type}")
    normalized = f"{key_type} {key_body}"
    with tempfile.TemporaryDirectory(
        prefix="rtlflowbench-reviewer-intake-key-"
    ) as temp:
        key_path = Path(temp) / "reviewer.pub"
        key_path.write_text(normalized + "\n", encoding="utf-8")
        completed = subprocess.run(
            ["ssh-keygen", "-lf", str(key_path), "-E", "sha256"],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    if completed.returncode != 0:
        raise ValueError("reviewer public key cannot be fingerprinted")
    output = completed.stdout.split()
    if len(output) < 2 or not output[1].startswith("SHA256:"):
        raise ValueError("ssh-keygen returned an invalid reviewer fingerprint")
    return normalized, output[1]


def _registry_schema_relative(
    repo_root: Path,
    subject_id: str,
    task_id: str | None,
) -> Path:
    if subject_id == "protocol":
        return PROTOCOL_REGISTRY_SCHEMA
    if task_id is None:
        raise ValueError(f"{subject_id} is missing its task id")
    custom = (
        Path("benchmarks/golden12/tasks")
        / task_id
        / "private/admission/trusted_reviewers.schema.json"
    )
    if (repo_root / custom).is_file():
        return custom
    return COMMON_REGISTRY_SCHEMA


def _json_payload(value: dict[str, Any]) -> bytes:
    return (
        json.dumps(value, indent=2, sort_keys=True) + "\n"
    ).encode()


def _instructions() -> str:
    return """# Reviewer registry governance next steps

This reviewer-only output must remain outside the repository and every
evaluated workflow workspace. It contains pending registry candidates and
reviewer public keys, but no governance trust anchor, approval, signature,
review attestation, task admission, benchmark result, or ready claim.

Independent governance steps:

1. Verify the three content anchors in reviewer_nomination_intake.json.
2. Inspect the original nomination response, real identities, qualifications,
   public keys, organizations, and every conflict declaration out of band.
3. Reject or amend any candidate with insufficient independence or competence.
4. For an approved final registry, set its authority and governance claim only
   through the separately controlled governance process.
5. Build and sign the registry-governance request with an out-of-band
   governance key and trust-anchor digest.
6. Pin the governed registry digest, relock affected candidates, and obtain new
   reviewer signatures over those exact post-relock bytes.

Generation of this directory is not governance approval. A content relock
invalidates prior review signatures.
"""


def build_reviewer_nomination_intake(
    *,
    repo_root: Path,
    assignment_handoff_path: Path,
    expected_assignment_sha256: str,
    nomination_request_path: Path,
    expected_request_sha256: str,
    nomination_response_path: Path,
    output_dir: Path,
    observed_at: str,
) -> dict[str, Any]:
    _parse_observed_at(observed_at)
    for label, digest in (
        ("assignment", expected_assignment_sha256),
        ("request", expected_request_sha256),
    ):
        if SHA256_RE.fullmatch(digest) is None:
            raise ValueError(f"expected {label} SHA256 must be lowercase")
    repo_root = repo_root.expanduser().resolve(strict=True)
    assignment_path = _external_file(
        repo_root,
        assignment_handoff_path,
        "review assignment handoff",
    )
    request_path = _external_file(
        repo_root,
        nomination_request_path,
        "reviewer nomination request",
    )
    response_path = _external_file(
        repo_root,
        nomination_response_path,
        "reviewer nomination response",
    )
    output_dir = _external_output(repo_root, output_dir)

    assignment_schema = repo_root / ASSIGNMENT_SCHEMA
    request_schema = repo_root / REQUEST_SCHEMA
    response_schema = repo_root / RESPONSE_SCHEMA
    intake_schema = repo_root / INTAKE_SCHEMA
    assignment = _load(assignment_path, "review assignment handoff")
    request = _load(request_path, "reviewer nomination request")
    response = _load(response_path, "reviewer nomination response")
    _validate(assignment, assignment_schema, "review assignment handoff")
    _validate(request, request_schema, "reviewer nomination request")
    _validate(response, response_schema, "reviewer nomination response")

    assignment_sha = _sha256(assignment_path)
    request_sha = _sha256(request_path)
    response_sha = _sha256(response_path)
    if assignment_sha != expected_assignment_sha256:
        raise ValueError("assignment differs from its out-of-band trust anchor")
    if request_sha != expected_request_sha256:
        raise ValueError("request differs from its out-of-band trust anchor")
    if request["assignment_anchor"]["sha256"] != assignment_sha:
        raise ValueError("request is not bound to the supplied assignment")
    if response["assignment_handoff_sha256"] != assignment_sha:
        raise ValueError("response is not bound to the supplied assignment")
    if response["request_sha256"] != request_sha:
        raise ValueError("response is not bound to the supplied request")
    if (
        request["nomination_response_schema"]["sha256"]
        != _sha256(response_schema)
    ):
        raise ValueError("request binds a different nomination response schema")
    if (
        assignment["status"]
        != "verified_unassigned_pending_independent_review"
        or not assignment["assignment_ready"]
        or assignment["assigned_review_item_count"] != 0
        or assignment["approved_review_item_count"] != 0
        or assignment["registry_governance_complete"]
        or assignment["independent_review_complete"]
        or assignment["suite_ready"]
    ):
        raise ValueError("assignment is not a safe unassigned review handoff")

    assignment_tracks = {
        item["track_id"]: item for item in assignment["tracks"]
    }
    request_tracks = {item["track_id"]: item for item in request["tracks"]}
    if set(assignment_tracks) != set(request_tracks):
        raise ValueError("request track set differs from assignment")
    for track_id, assignment_track in assignment_tracks.items():
        request_track = request_tracks[track_id]
        if (
            request_track["item_count"] != assignment_track["item_count"]
            or request_track["item_keys"] != assignment_track["item_keys"]
        ):
            raise ValueError(f"request track drift: {track_id}")

    items = assignment["items"]
    item_keys = {item["item_key"] for item in items}
    if len(items) != 102 or len(item_keys) != 102:
        raise ValueError("assignment must contain 102 unique review items")

    nominees: dict[str, dict[str, Any]] = {}
    fingerprints: set[str] = set()
    release_authority = response["release_authority"]
    for nomination in response["nominations"]:
        identity = nomination["identity"]
        if IDENTITY_RE.fullmatch(identity) is None:
            raise ValueError(
                "reviewer identity must be a single allowed-signers principal"
            )
        if identity == release_authority:
            raise ValueError(
                "release authority and reviewer identities must be distinct"
            )
        if identity in nominees:
            raise ValueError(f"duplicate reviewer identity: {identity}")
        public_key, observed_fingerprint = _normalized_public_key(
            nomination["public_key"]
        )
        if observed_fingerprint != nomination["key_fingerprint"]:
            raise ValueError(
                f"reviewer key fingerprint mismatch: {identity}"
            )
        if observed_fingerprint in fingerprints:
            raise ValueError("distinct reviewers cannot share one key")
        fingerprints.add(observed_fingerprint)
        conflicts = set(
            nomination["conflict_of_interest"]["affected_item_keys"]
        )
        unknown_conflicts = conflicts - item_keys
        if unknown_conflicts:
            raise ValueError(
                "conflict declaration names unknown review items: "
                + ", ".join(sorted(unknown_conflicts))
            )
        nominees[identity] = {
            **nomination,
            "normalized_public_key": public_key,
            "conflict_item_keys": conflicts,
        }

    item_results: list[dict[str, Any]] = []
    uncovered: list[str] = []
    for item in items:
        eligible = sorted(
            identity
            for identity, nominee in nominees.items()
            if item["primary_track"] in nominee["track_ids"]
            and item["item_key"] not in nominee["conflict_item_keys"]
        )
        excluded = sorted(
            identity
            for identity, nominee in nominees.items()
            if item["primary_track"] in nominee["track_ids"]
            and item["item_key"] in nominee["conflict_item_keys"]
        )
        if not eligible:
            uncovered.append(item["item_key"])
        item_results.append(
            {
                "item_key": item["item_key"],
                "subject_id": item["subject_id"],
                "review_id": item["review_id"],
                "primary_track": item["primary_track"],
                "eligible_reviewer_identities": eligible,
                "excluded_for_declared_conflict": excluded,
                "assignment_status": "pending_registry_governance",
                "approval_status": "pending",
            }
        )
    if uncovered:
        preview = ", ".join(sorted(uncovered)[:8])
        raise ValueError(f"uncovered review items: {preview}")

    track_results = []
    for track_id, track in sorted(assignment_tracks.items()):
        eligible_count = sum(
            track_id in nominee["track_ids"]
            for nominee in nominees.values()
        )
        track_results.append(
            {
                "track_id": track_id,
                "item_count": track["item_count"],
                "eligible_reviewer_count": eligible_count,
                "coverage_status": (
                    "no_items" if track["item_count"] == 0 else "covered"
                ),
            }
        )

    by_subject: dict[str, list[tuple[dict[str, Any], dict[str, Any]]]] = {}
    item_result_by_key = {
        item["item_key"]: item for item in item_results
    }
    for item in items:
        by_subject.setdefault(item["subject_id"], []).append(
            (item, item_result_by_key[item["item_key"]])
        )
    if set(by_subject) != {
        "protocol",
        *(f"G{index:02d}" for index in range(1, 13)),
    }:
        raise ValueError("review subjects are incomplete")

    pending_files: dict[str, bytes] = {}
    subjects = []
    used_registry_schemas: set[Path] = set()
    for subject_id, subject_items in sorted(by_subject.items()):
        task_ids = {item["task_id"] for item, _ in subject_items}
        if len(task_ids) != 1:
            raise ValueError(f"{subject_id} has inconsistent task ids")
        task_id = next(iter(task_ids))
        namespaces = {
            item["signature_namespace"] for item, _ in subject_items
        }
        candidate_locks = {
            item["candidate_lock_sha256"] for item, _ in subject_items
        }
        review_packets = {
            item["review_packet_sha256"] for item, _ in subject_items
        }
        if not (
            len(namespaces) == len(candidate_locks) == len(review_packets) == 1
        ):
            raise ValueError(f"{subject_id} has inconsistent review anchors")
        namespace = next(iter(namespaces))
        registry_schema_relative = _registry_schema_relative(
            repo_root,
            subject_id,
            task_id,
        )
        registry_schema_path = repo_root / registry_schema_relative
        registry_schema = _load(
            registry_schema_path,
            f"{subject_id} trusted reviewer registry schema",
        )
        Draft202012Validator.check_schema(registry_schema)
        used_registry_schemas.add(registry_schema_relative)
        schema_version = registry_schema["properties"]["schema_version"][
            "const"
        ]

        reviewers = []
        for identity, nominee in sorted(nominees.items()):
            allowed_ids = sorted(
                {
                    item["review_id"]
                    for item, result in subject_items
                    if identity in result["eligible_reviewer_identities"]
                }
            )
            if not allowed_ids:
                continue
            reviewers.append(
                {
                    "identity": identity,
                    "organization": nominee["organization"],
                    "key_fingerprint": nominee["key_fingerprint"],
                    "allowed_review_ids": allowed_ids,
                }
            )
        if not reviewers:
            raise ValueError(f"{subject_id} has no eligible reviewers")
        registry = {
            "schema_version": schema_version,
            "signature_namespace": namespace,
            "registry_authority": release_authority,
            "governance_status": "pending_independent_approval",
            "prohibited_identities": sorted(
                {release_authority, "chipflow-workflow-agent"}
            ),
            "reviewers": reviewers,
        }
        Draft202012Validator(
            registry_schema,
            format_checker=FormatChecker(),
        ).validate(registry)
        registry_payload = _json_payload(registry)
        signers_payload = "".join(
            f"{reviewer['identity']} "
            f"{nominees[reviewer['identity']]['normalized_public_key']}\n"
            for reviewer in reviewers
        ).encode()
        subject_root = f"subjects/{subject_id}"
        registry_relative = (
            f"{subject_root}/trusted_reviewers.pending.json"
        )
        signers_relative = f"{subject_root}/reviewer_allowed_signers"
        pending_files[registry_relative] = registry_payload
        pending_files[signers_relative] = signers_payload
        subjects.append(
            {
                "subject_id": subject_id,
                "task_id": task_id,
                "signature_namespace": namespace,
                "candidate_lock_sha256": next(iter(candidate_locks)),
                "review_packet_sha256": next(iter(review_packets)),
                "registry_relative_path": registry_relative,
                "registry_schema_relative_path": (
                    registry_schema_relative.as_posix()
                ),
                "registry_sha256": _sha256_bytes(registry_payload),
                "allowed_signers_relative_path": signers_relative,
                "allowed_signers_sha256": _sha256_bytes(signers_payload),
                "reviewer_count": len(reviewers),
                "allowed_review_id_count": len(
                    {
                        review_id
                        for reviewer in reviewers
                        for review_id in reviewer["allowed_review_ids"]
                    }
                ),
            }
        )

    builder_path = Path(__file__).resolve(strict=True)
    source_relatives = {
        builder_path.relative_to(repo_root),
        ASSIGNMENT_SCHEMA,
        REQUEST_SCHEMA,
        RESPONSE_SCHEMA,
        INTAKE_SCHEMA,
        *used_registry_schemas,
    }
    result = {
        "schema_version": "rtlflowbench.reviewer_nomination_intake.v1",
        "observed_at": observed_at,
        "status": "pending_independent_registry_governance",
        "classification": "reviewer_only_registry_candidates",
        "anchors": {
            "assignment_handoff_sha256": assignment_sha,
            "nomination_request_sha256": request_sha,
            "nomination_response_sha256": response_sha,
        },
        "release_authority": release_authority,
        "nomination_count": len(response["nominations"]),
        "distinct_reviewer_count": len(nominees),
        "subject_count": len(subjects),
        "review_item_count": len(item_results),
        "eligible_review_item_count": sum(
            bool(item["eligible_reviewer_identities"])
            for item in item_results
        ),
        "uncovered_review_item_count": 0,
        "conflict_exclusion_count": sum(
            len(item["excluded_for_declared_conflict"])
            for item in item_results
        ),
        "tracks": track_results,
        "subjects": subjects,
        "items": sorted(item_results, key=lambda item: item["item_key"]),
        "governance": {
            "trusted_reviewer_registries_generated": True,
            "registry_governance_complete": False,
            "governance_authority": None,
            "approvals_recorded": 0,
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
            relative.as_posix(): _sha256(repo_root / relative)
            for relative in sorted(source_relatives)
        },
        "excluded_claims": [
            "Nomination intake is not registry governance approval.",
            "Pending registries are not trusted reviewer registries.",
            "No review item is assigned, signed, approved, or admitted.",
            "No protocol, task, adapter, or suite is ready.",
            "No benchmark result, workflow score, PPA, or ranking is claimed.",
        ],
    }
    _validate(result, intake_schema, "reviewer nomination intake")

    output_dir.mkdir(parents=True)
    for relative, payload in sorted(pending_files.items()):
        target = output_dir / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
    (output_dir / "REVIEWER_REGISTRY_GOVERNANCE_NEXT_STEPS.md").write_text(
        _instructions(),
        encoding="utf-8",
    )
    (output_dir / "reviewer_nomination_intake.json").write_bytes(
        _json_payload(result)
    )
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--assignment-handoff", type=Path, required=True)
    parser.add_argument("--expected-assignment-sha256", required=True)
    parser.add_argument("--nomination-request", type=Path, required=True)
    parser.add_argument("--expected-request-sha256", required=True)
    parser.add_argument("--nomination-response", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--observed-at", required=True)
    args = parser.parse_args()
    try:
        result = build_reviewer_nomination_intake(
            repo_root=args.repo_root,
            assignment_handoff_path=args.assignment_handoff,
            expected_assignment_sha256=args.expected_assignment_sha256,
            nomination_request_path=args.nomination_request,
            expected_request_sha256=args.expected_request_sha256,
            nomination_response_path=args.nomination_response,
            output_dir=args.output_dir,
            observed_at=args.observed_at,
        )
    except Exception as exc:  # noqa: BLE001 - CLI must fail closed as JSON
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
    receipt_path = args.output_dir.expanduser().resolve() / (
        "reviewer_nomination_intake.json"
    )
    print(
        json.dumps(
            {
                "status": result["status"],
                "subject_count": result["subject_count"],
                "review_item_count": result["review_item_count"],
                "distinct_reviewer_count": result[
                    "distinct_reviewer_count"
                ],
                "receipt_sha256": _sha256(receipt_path),
                "registry_governance_complete": False,
                "suite_ready": False,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
