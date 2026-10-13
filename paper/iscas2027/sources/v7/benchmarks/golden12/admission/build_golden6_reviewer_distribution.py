#!/usr/bin/env python3
"""Build a content-bound reviewer-only Golden-6 bundle distribution."""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import tarfile
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


SUBJECT_TASKS = {
    "protocol": None,
    "G01": "G01-common-fifo-spec",
    "G03": "G03-axis-fifo-backpressure",
    "G05": "G05-picorv32-missing-irq",
    "G08": "G08-common-fifo-dv",
    "G10": "G10-serv-area-qor",
    "G12": "G12-common-cdc-missing-contract",
}
SUBJECT_ITEM_COUNTS = {
    "protocol": 3,
    "G01": 8,
    "G03": 8,
    "G05": 8,
    "G08": 8,
    "G10": 9,
    "G12": 10,
}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


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


def _external_file(repo_root: Path, path: Path, label: str) -> Path:
    expanded = path.expanduser()
    if expanded.is_symlink() or not expanded.is_file():
        raise ValueError(f"{label} must be a regular non-symlink file")
    resolved = _external(repo_root, expanded, label).resolve(strict=True)
    return resolved


def _root_file(root: Path, relative: str, label: str) -> Path:
    pure = PurePosixPath(relative)
    if pure.is_absolute() or ".." in pure.parts:
        raise ValueError(f"unsafe {label} relative path")
    candidate = root.joinpath(*pure.parts)
    resolved = candidate.resolve(strict=True)
    if not resolved.is_relative_to(root) or candidate.is_symlink() or not candidate.is_file():
        raise ValueError(f"unsafe {label}: {relative}")
    return candidate


def _archive_member_count(path: Path) -> int:
    try:
        with tarfile.open(path, "r:gz") as archive:
            members = archive.getmembers()
    except tarfile.TarError as exc:
        raise ValueError(f"review archive is invalid: {path.name}") from exc
    if not members:
        raise ValueError(f"review archive is empty: {path.name}")
    for member in members:
        pure = PurePosixPath(member.name)
        if (
            pure.is_absolute()
            or ".." in pure.parts
            or member.issym()
            or member.islnk()
            or member.isdev()
            or member.isfifo()
        ):
            raise ValueError(f"unsafe review archive member: {path.name}")
    return len(members)


def _instructions() -> str:
    return """# Golden-6 alpha reviewer bundle distribution

This directory is evaluator-private and reviewer-only. Never copy it, an
archive extracted from it, or any reviewer evidence into an evaluated workflow
workspace. The archives contain the protocol and six Golden-6 candidate review
bundles exactly as recorded by the content-bound Golden-12 handoff.

Before review, verify every SHA256 in `golden6_reviewer_distribution.json` and
verify the nomination package separately. Extract archives only in a dedicated
reviewer workspace. Reviewers must inspect the exact candidate lock and review
packet, declare conflicts of interest, and follow the signature namespace and
commands inside each bundle. No detached signature or decision may be reused
after any content relock.

This distribution does not nominate a reviewer, create a trusted registry,
approve a review item, freeze a task, admit a workflow, or report a benchmark
result. The other six Golden-12 tasks remain governed by the full handoff.
"""


def build_golden6_reviewer_distribution(
    *,
    repo_root: Path,
    review_handoff_root: Path,
    expected_review_handoff_sha256: str,
    assignment_path: Path,
    expected_assignment_sha256: str,
    nomination_request_path: Path,
    expected_nomination_request_sha256: str,
    output_dir: Path,
    observed_at: str,
) -> dict[str, Any]:
    _parse_observed_at(observed_at)
    for label, digest in (
        ("review handoff", expected_review_handoff_sha256),
        ("assignment", expected_assignment_sha256),
        ("nomination request", expected_nomination_request_sha256),
    ):
        if SHA256_RE.fullmatch(digest) is None:
            raise ValueError(f"expected {label} SHA256 must be lowercase")
    repo_root = repo_root.expanduser().resolve(strict=True)
    expanded_handoff = review_handoff_root.expanduser()
    if expanded_handoff.is_symlink() or not expanded_handoff.is_dir():
        raise ValueError("review handoff root must be a regular directory")
    review_handoff_root = _external(
        repo_root, expanded_handoff, "review handoff root"
    ).resolve(strict=True)
    assignment_path = _external_file(repo_root, assignment_path, "Golden-6 assignment")
    nomination_request_path = _external_file(
        repo_root, nomination_request_path, "Golden-6 nomination request"
    )
    expanded_output = output_dir.expanduser()
    if expanded_output.is_symlink():
        raise ValueError("reviewer distribution output cannot be a symlink")
    output_dir = _external(
        repo_root, expanded_output, "reviewer distribution output"
    )
    if output_dir.exists():
        raise FileExistsError(f"refusing to overwrite output: {output_dir}")

    admission = repo_root / "benchmarks/golden12/admission"
    handoff_schema = admission / "review_handoff.schema.json"
    assignment_schema = admission / "golden6_review_assignment.schema.json"
    request_schema = admission / "golden6_reviewer_nomination_request.schema.json"
    distribution_schema = admission / "golden6_reviewer_distribution.schema.json"
    handoff_path = review_handoff_root / "golden12_review_handoff_receipt.json"
    handoff = _load(handoff_path, "Golden-12 review handoff")
    assignment = _load(assignment_path, "Golden-6 review assignment")
    request = _load(nomination_request_path, "Golden-6 nomination request")
    handoff_sha = _sha256(handoff_path)
    assignment_sha = _sha256(assignment_path)
    request_sha = _sha256(nomination_request_path)
    if handoff_sha != expected_review_handoff_sha256:
        raise ValueError("review handoff differs from its out-of-band trust anchor")
    if assignment_sha != expected_assignment_sha256:
        raise ValueError("assignment differs from its out-of-band trust anchor")
    if request_sha != expected_nomination_request_sha256:
        raise ValueError("nomination request differs from its out-of-band trust anchor")
    _validate(handoff, handoff_schema, "Golden-12 review handoff")
    _validate(assignment, assignment_schema, "Golden-6 review assignment")
    _validate(request, request_schema, "Golden-6 nomination request")
    if (
        handoff["status"] != "verified_unsigned_handoff_pending_independent_review"
        or handoff["approved_review_item_count"] != 0
        or handoff["independent_review_complete"] is not False
        or handoff["workflow_workspace_exposure_permitted"] is not False
    ):
        raise ValueError("review handoff is not a safe unsigned handoff")
    if (
        assignment["status"] != "verified_unassigned_pending_independent_review"
        or assignment["total_review_item_count"] != 54
        or assignment["approved_review_item_count"] != 0
        or assignment["independent_review_complete"] is not False
        or assignment["golden6_alpha_ready"] is not False
        or assignment["workflow_workspace_exposure_permitted"] is not False
    ):
        raise ValueError("Golden-6 assignment is not a safe pending assignment")
    if (
        request["status"] != "awaiting_real_reviewer_nominations"
        or request["assignment_anchor"]["sha256"] != assignment_sha
        or request["assignment_anchor"]["review_item_count"] != 54
        or any(track["nominated_reviewer_count"] != 0 for track in request["tracks"])
        or request["readiness"]["golden6_alpha_ready"] is not False
        or request["workflow_workspace_exposure_permitted"] is not False
    ):
        raise ValueError("Golden-6 nomination request is not safe and pending")

    task_records = {row["task_id"]: row for row in handoff["tasks"]}
    if set(task_records) != {
        f"G{index:02d}-{suffix}"
        for index, suffix in (
            (1, "common-fifo-spec"),
            (2, "common-rr-arbiter-spec"),
            (3, "axis-fifo-backpressure"),
            (4, "wb2axip-split-bridge"),
            (5, "picorv32-missing-irq"),
            (6, "ibex-debug-csr-exception"),
            (7, "ibex-ifetch-error-timing"),
            (8, "common-fifo-dv"),
            (9, "axis-fifo-dv"),
            (10, "serv-area-qor"),
            (11, "picorv32-qor"),
            (12, "common-cdc-missing-contract"),
        )
    }:
        raise ValueError("review handoff task census drifted")
    assignment_items = assignment["items"]
    records: list[dict[str, Any]] = []
    copy_rows: list[tuple[Path, str]] = []
    for subject_id, task_id in SUBJECT_TASKS.items():
        handoff_record = handoff["protocol"] if task_id is None else task_records[task_id]
        subject_items = [
            item for item in assignment_items if item["subject_id"] == subject_id
        ]
        if len(subject_items) != SUBJECT_ITEM_COUNTS[subject_id]:
            raise ValueError(f"assignment item count drift: {subject_id}")
        if (
            handoff_record["status"] != "verified_unsigned_review_workspace"
            or handoff_record["review_item_count"] != len(subject_items)
            or handoff_record["approved_review_item_count"] != 0
            or handoff_record["independent_review_complete"] is not False
            or handoff_record["workflow_workspace_exposure_permitted"] is not False
        ):
            raise ValueError(f"unsafe review handoff subject: {subject_id}")
        if task_id is None:
            if handoff_record["protocol_ready"] is not False:
                raise ValueError("protocol is unexpectedly ready")
        elif (
            handoff_record["bundle_build_status"] != "pending_independent_review"
            or handoff_record["benchmark_ready"] is not False
            or handoff_record["chipflow_adapter_ready"] is not False
        ):
            raise ValueError(f"task is unexpectedly ready: {subject_id}")
        candidate_digests = {item["candidate_lock_sha256"] for item in subject_items}
        packet_digests = {item["review_packet_sha256"] for item in subject_items}
        if candidate_digests != {handoff_record["candidate_lock_sha256"]}:
            raise ValueError(f"candidate-lock anchor drift: {subject_id}")
        if packet_digests != {handoff_record["review_packet_sha256"]}:
            raise ValueError(f"review-packet anchor drift: {subject_id}")

        archive = _root_file(
            review_handoff_root,
            handoff_record["bundle_archive_path"],
            f"{subject_id} bundle archive",
        )
        manifest = _root_file(
            review_handoff_root,
            str(PurePosixPath(handoff_record["bundle_archive_path"]).parent / "bundle_manifest.json"),
            f"{subject_id} bundle manifest",
        )
        receipt = _root_file(
            review_handoff_root,
            str(PurePosixPath(handoff_record["bundle_archive_path"]).parent / "bundle_receipt.json"),
            f"{subject_id} bundle receipt",
        )
        manifest_value = _load(manifest, f"{subject_id} bundle manifest")
        receipt_value = _load(receipt, f"{subject_id} bundle receipt")
        if (
            _sha256(archive) != handoff_record["bundle_archive_sha256"]
            or archive.stat().st_size != handoff_record["bundle_archive_bytes"]
            or _sha256(manifest) != handoff_record["bundle_manifest_sha256"]
            or _sha256(receipt) != handoff_record["bundle_receipt_sha256"]
        ):
            raise ValueError(f"review bundle content drift: {subject_id}")
        if (
            manifest_value.get("status") != "pending_independent_review"
            or receipt_value.get("status") != "pending_independent_review"
            or receipt_value.get("approved_review_item_count") != 0
            or manifest_value.get("candidate_lock_sha256")
            != handoff_record["candidate_lock_sha256"]
            or receipt_value.get("candidate_lock_sha256")
            != handoff_record["candidate_lock_sha256"]
            or manifest_value.get("review_packet_sha256")
            != handoff_record["review_packet_sha256"]
            or receipt_value.get("review_packet_sha256")
            != handoff_record["review_packet_sha256"]
        ):
            raise ValueError(f"review bundle pending-state drift: {subject_id}")
        member_count = _archive_member_count(archive)
        output_root = f"subjects/{subject_id}"
        archive_relative = f"{output_root}/{archive.name}"
        manifest_relative = f"{output_root}/bundle_manifest.json"
        receipt_relative = f"{output_root}/bundle_receipt.json"
        copy_rows.extend(
            (
                (archive, archive_relative),
                (manifest, manifest_relative),
                (receipt, receipt_relative),
            )
        )
        records.append(
            {
                "subject_id": subject_id,
                "task_id": task_id,
                "review_item_count": len(subject_items),
                "status": "pending_independent_review",
                "candidate_lock_sha256": handoff_record["candidate_lock_sha256"],
                "review_packet_sha256": handoff_record["review_packet_sha256"],
                "bundle_archive_relative_path": archive_relative,
                "bundle_archive_sha256": handoff_record["bundle_archive_sha256"],
                "bundle_archive_bytes": handoff_record["bundle_archive_bytes"],
                "bundle_manifest_relative_path": manifest_relative,
                "bundle_manifest_sha256": handoff_record["bundle_manifest_sha256"],
                "bundle_receipt_relative_path": receipt_relative,
                "bundle_receipt_sha256": handoff_record["bundle_receipt_sha256"],
                "archive_member_count": member_count,
                "archive_safety_verified": True,
                "approved_review_item_count": 0,
                "independent_review_complete": False,
                "subject_ready": False,
                "chipflow_adapter_ready": False,
                "workflow_workspace_exposure_permitted": False,
            }
        )

    builder_path = Path(__file__).resolve(strict=True)
    sources = {
        builder_path.relative_to(repo_root).as_posix(): builder_path,
        handoff_schema.relative_to(repo_root).as_posix(): handoff_schema,
        assignment_schema.relative_to(repo_root).as_posix(): assignment_schema,
        request_schema.relative_to(repo_root).as_posix(): request_schema,
        distribution_schema.relative_to(repo_root).as_posix(): distribution_schema,
    }
    result = {
        "schema_version": "rtlflowbench.golden6_reviewer_distribution.v1",
        "observed_at": observed_at,
        "status": "verified_unsigned_distribution_pending_real_reviewer_nomination",
        "classification": "evaluator_private_reviewer_only",
        "release_target": "golden6_alpha",
        "subject_count": 7,
        "task_count": 6,
        "review_item_count": 54,
        "payload_file_count": len(copy_rows),
        "anchors": {
            "golden12_review_handoff_sha256": handoff_sha,
            "golden6_review_assignment_sha256": assignment_sha,
            "golden6_nomination_request_sha256": request_sha,
        },
        "subjects": records,
        "governance": {
            "human_nomination_response_supplied": False,
            "trusted_reviewer_registry_supplied": False,
            "registry_governance_complete": False,
            "approvals_recorded": 0,
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
            "Distribution does not nominate, qualify, or assign a reviewer.",
            "Distribution creates no trusted registry, signature, approval, freeze, admission, or release.",
            "Reviewer-only private evidence is not workflow input and must remain isolated.",
            "Golden-6 alpha and Golden-12 v1 remain not ready.",
            "The other six Golden-12 tasks are not waived, reviewed, or released.",
            "No benchmark PASS, score, QoR, PPA, performance, human-level, or superhuman claim is made.",
        ],
    }
    _validate(result, distribution_schema, "Golden-6 reviewer distribution")
    rendered = json.dumps(result, sort_keys=True) + _instructions()
    if "/home/" in rendered or "/Users/" in rendered:
        raise ValueError("reviewer distribution exposes a private host path")

    output_dir.mkdir(parents=True)
    for source, relative in copy_rows:
        target = output_dir / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source.read_bytes())
    (output_dir / "golden6_reviewer_distribution.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (output_dir / "GOLDEN6_REVIEWER_DISTRIBUTION_INSTRUCTIONS.md").write_text(
        _instructions(), encoding="utf-8"
    )
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--review-handoff-root", type=Path, required=True)
    parser.add_argument("--expected-review-handoff-sha256", required=True)
    parser.add_argument("--assignment", type=Path, required=True)
    parser.add_argument("--expected-assignment-sha256", required=True)
    parser.add_argument("--nomination-request", type=Path, required=True)
    parser.add_argument("--expected-nomination-request-sha256", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--observed-at", required=True)
    args = parser.parse_args()
    try:
        result = build_golden6_reviewer_distribution(
            repo_root=args.repo_root,
            review_handoff_root=args.review_handoff_root,
            expected_review_handoff_sha256=args.expected_review_handoff_sha256,
            assignment_path=args.assignment,
            expected_assignment_sha256=args.expected_assignment_sha256,
            nomination_request_path=args.nomination_request,
            expected_nomination_request_sha256=args.expected_nomination_request_sha256,
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
                "subject_count": result["subject_count"],
                "review_item_count": result["review_item_count"],
                "payload_file_count": result["payload_file_count"],
                "human_nomination_response_supplied": False,
                "golden6_alpha_ready": False,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
