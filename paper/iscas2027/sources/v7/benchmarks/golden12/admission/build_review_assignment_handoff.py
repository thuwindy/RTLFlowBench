#!/usr/bin/env python3
"""Build a content-bound, unsigned assignment plan for Golden-12 review.

The handoff normalizes all protocol and task review items into one queue.  It
does not create reviewer identities, registries, signatures, decisions,
freezes, or admissions.  The output is reviewer-only evidence and must remain
outside the repository and every evaluated workflow workspace.
"""

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
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
TRACKS = {
    "rights_governance": (
        "Rights, provenance, attribution, redistribution, and benchmark-use review."
    ),
    "protocol_schema_freeze": (
        "Workflow-neutral protocol, schema, CLI, and container freeze review."
    ),
    "public_contract_projection": (
        "Public specification, packet, repository projection, and interface freeze review."
    ),
    "evaluator_calibration": (
        "Hidden evaluator, formal, mutation, alternate, coverage, and calibration review."
    ),
    "environment_scoring_freeze": (
        "Runner, environment, resource budget, scoring, repeatability, and QoR freeze review."
    ),
    "technical_admission": (
        "Task-specific technical evidence that does not fit another review track."
    ),
    "final_admission": (
        "Final independent admission after every preceding review is approved."
    ),
}


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


def _track(review_id: str, scope: str, *, protocol: bool) -> str:
    text = f"{review_id} {scope}".lower()
    if "final_admission" in text or "final_benchmark_admission" in text:
        return "final_admission"
    if any(
        token in text
        for token in (
            "rights",
            "redistribut",
            "provenance",
            "attribution",
            "license",
            "benchmark-use",
        )
    ):
        return "rights_governance"
    if protocol or any(
        token in text for token in ("protocol", "schema_freeze", "container_cli")
    ):
        return "protocol_schema_freeze"
    if any(
        token in text
        for token in (
            "environment",
            "scoring",
            "budget",
            "runner",
            "repeatability",
            "resource",
            "physical",
            "qor",
        )
    ):
        return "environment_scoring_freeze"
    if any(
        token in text
        for token in (
            "hidden",
            "oracle",
            "mutation",
            "formal",
            "coverage",
            "vacuity",
            "alternate",
            "alternative",
            "reference",
            "calibration",
            "equivalence",
            "workload",
        )
    ):
        return "evaluator_calibration"
    if any(
        token in text
        for token in (
            "spec",
            "public",
            "projection",
            "manifest",
            "interface",
            "repository",
            "contract",
        )
    ):
        return "public_contract_projection"
    return "technical_admission"


def _pending_item(item: dict[str, Any], subject_id: str) -> None:
    if item.get("status") != "pending":
        raise ValueError(f"review item is not pending: {subject_id}")
    if item.get("independent_reviewer") is not None:
        raise ValueError(f"review item already has a reviewer: {subject_id}")
    if item.get("signed_candidate_lock_sha256") is not None:
        raise ValueError(f"review item already has a signed lock: {subject_id}")
    for field in (
        "signature_sha256",
        "attestation_sha256",
        "signature_path",
        "attestation_path",
        "verification_receipt_path",
        "trusted_key_id",
    ):
        if item.get(field) is not None:
            raise ValueError(
                f"review item contains approval material: {subject_id}.{field}"
            )


def _instructions() -> str:
    return """# Golden-12 independent review assignment handoff

This directory is reviewer-only. It must stay outside the repository and every
evaluated workflow workspace.

`review_assignment_handoff.json` lists every pending protocol and task review
item. Suggested tracks are workload triage only; they do not appoint a
reviewer, establish qualifications, or approve a decision.

Critical path:

1. A release authority obtains real reviewer identities and public keys.
2. A separate governance authority approves the trusted reviewer registry
   using the out-of-band governance signing procedure.
3. Protocol review and task evidence review may proceed in parallel, but the
   protocol must be released before task release materials can become complete.
4. A first-round approval of rights, public packet, environment, scoring, or
   budget evidence does not survive a content change. If those approvals are
   used to materialize a frozen public descriptor or frozen release document,
   rebuild the candidate lock and review packet and preserve a supersession
   receipt. Never reuse a detached signature across the relock.
5. Each final reviewer uses the rebuilt verified workspace, checks the exact
   candidate-lock digest, declares conflicts of interest, builds an unsigned
   attestation, and signs it with the namespace documented in that workspace.
6. Run the live verifier and release finalizer. The finalizer rejects a public
   task descriptor whose version, rights, public digest, or budget remains
   draft/provisional. Never edit the packet to turn a
   pending item into an approval.
7. Only after protocol and all task finalizers return RELEASE may the suite
   finalizer be run with `--require-release`.

The required commands and signature namespaces are in each verified review
workspace. No private evaluator asset may be copied to a workflow workspace.
"""


def build_review_assignment_handoff(
    *,
    repo_root: Path,
    review_handoff_root: Path,
    expected_review_handoff_sha256: str,
    output_dir: Path,
    observed_at: str,
) -> dict[str, Any]:
    _parse_observed_at(observed_at)
    if SHA256_RE.fullmatch(expected_review_handoff_sha256) is None:
        raise ValueError("expected review handoff SHA256 must be a lowercase digest")
    repo_root = repo_root.expanduser().resolve(strict=True)
    review_handoff_root = _external(
        repo_root, review_handoff_root, "review handoff root"
    ).resolve(strict=True)
    output_dir = _external(repo_root, output_dir, "assignment output")
    if review_handoff_root.is_symlink() or not review_handoff_root.is_dir():
        raise ValueError("review handoff root must be a regular directory")
    if output_dir.exists() or output_dir.is_symlink():
        raise FileExistsError(f"refusing to overwrite output: {output_dir}")

    admission_root = repo_root / "benchmarks/golden12/admission"
    handoff_path = review_handoff_root / "golden12_review_handoff_receipt.json"
    handoff = _load(handoff_path, "review handoff receipt")
    handoff_sha256 = _sha256(handoff_path)
    if handoff_sha256 != expected_review_handoff_sha256:
        raise ValueError("review handoff differs from its out-of-band trust anchor")
    _validate(
        handoff,
        admission_root / "review_handoff.schema.json",
        "review handoff receipt",
    )
    if handoff.get("observed_at") != observed_at:
        raise ValueError("review handoff and assignment observation timestamps differ")
    if (
        handoff.get("status")
        != "verified_unsigned_handoff_pending_independent_review"
        or handoff.get("approved_review_item_count") != 0
        or handoff.get("independent_review_complete") is not False
        or handoff.get("workflow_workspace_exposure_permitted") is not False
    ):
        raise ValueError("review handoff is not a safe unsigned handoff")

    records: list[dict[str, Any]] = []
    packet_sha256: dict[str, str] = {}
    lock_sha256: dict[str, str] = {}
    subject_rows: list[tuple[str, str | None, dict[str, Any], dict[str, Any], Path]] = []
    protocol_record = handoff["protocol"]
    subject_rows.append(
        (
            "protocol",
            None,
            protocol_record,
            _load(
                repo_root / "benchmarks/golden12/protocol/review_packet.json",
                "protocol review packet",
            ),
            repo_root / "benchmarks/golden12/protocol/candidate.lock.json",
        )
    )
    task_handoff = {item["task_id"]: item for item in handoff["tasks"]}
    if set(task_handoff) != set(TASK_IDS):
        raise ValueError("review handoff does not cover exactly Golden-12")
    for task_id in TASK_IDS:
        admission = (
            repo_root
            / "benchmarks/golden12/tasks"
            / task_id
            / "private/admission"
        )
        subject_rows.append(
            (
                task_id[:3],
                task_id,
                task_handoff[task_id],
                _load(admission / "review_packet.json", f"{task_id} review packet"),
                admission / "candidate.lock.json",
            )
        )

    for subject_id, task_id, handoff_record, packet, lock_path in subject_rows:
        protocol = task_id is None
        packet_path = (
            repo_root / "benchmarks/golden12/protocol/review_packet.json"
            if protocol
            else repo_root
            / "benchmarks/golden12/tasks"
            / task_id
            / "private/admission/review_packet.json"
        )
        packet_digest = _sha256(packet_path)
        lock_digest = _sha256(lock_path)
        if packet.get("status") != "pending_independent_review":
            raise ValueError(f"review packet is not pending: {subject_id}")
        if packet.get("self_approval_forbidden") is not True:
            raise ValueError(f"review packet permits self-approval: {subject_id}")
        if packet.get("candidate_lock_sha256") != lock_digest:
            raise ValueError(f"review packet candidate drift: {subject_id}")
        if handoff_record.get("review_packet_sha256") != packet_digest:
            raise ValueError(f"review handoff packet drift: {subject_id}")
        if handoff_record.get("candidate_lock_sha256") != lock_digest:
            raise ValueError(f"review handoff candidate drift: {subject_id}")
        items = packet.get("review_items")
        if not isinstance(items, list) or not items:
            raise ValueError(f"review packet has no review items: {subject_id}")
        if handoff_record.get("review_item_count") != len(items):
            raise ValueError(f"review item count drift: {subject_id}")
        workspace_relative = handoff_record["review_workspace_path"]
        workspace = (review_handoff_root / workspace_relative).resolve(strict=True)
        if (
            not workspace.is_relative_to(review_handoff_root)
            or workspace.is_symlink()
            or not workspace.is_dir()
        ):
            raise ValueError(f"unsafe review workspace: {subject_id}")
        signature_namespace = (
            "rtlflowbench-protocol-review"
            if protocol
            else f"rtlflowbench-{subject_id.lower()}-review"
        )
        for item in items:
            review_id = item.get("review_id")
            scope = item.get("scope")
            if not isinstance(review_id, str) or not review_id:
                raise ValueError(f"invalid review id: {subject_id}")
            if not isinstance(scope, str) or not scope:
                raise ValueError(f"invalid review scope: {subject_id}:{review_id}")
            _pending_item(item, f"{subject_id}:{review_id}")
            records.append(
                {
                    "item_key": f"{subject_id}:{review_id}",
                    "subject_id": subject_id,
                    "task_id": task_id,
                    "review_id": review_id,
                    "scope": scope,
                    "primary_track": _track(review_id, scope, protocol=protocol),
                    "candidate_lock_sha256": lock_digest,
                    "review_packet_sha256": packet_digest,
                    "verified_workspace_relative_path": workspace_relative,
                    "signature_namespace": signature_namespace,
                    "assignment_status": "unassigned",
                    "reviewer_identity": None,
                    "conflict_of_interest_declaration_required": True,
                    "detached_signature_required": True,
                    "approval_status": "pending",
                }
            )
        packet_sha256[subject_id] = packet_digest
        lock_sha256[subject_id] = lock_digest

    if len({item["item_key"] for item in records}) != len(records):
        raise ValueError("review assignment contains duplicate item keys")
    track_rows = [
        {
            "track_id": track_id,
            "description": description,
            "item_count": sum(
                item["primary_track"] == track_id for item in records
            ),
            "item_keys": [
                item["item_key"]
                for item in records
                if item["primary_track"] == track_id
            ],
        }
        for track_id, description in TRACKS.items()
    ]
    schema_path = admission_root / "review_assignment_handoff.schema.json"
    builder_path = Path(__file__).resolve(strict=True)
    result = {
        "schema_version": "rtlflowbench.review_assignment_handoff.v1",
        "observed_at": observed_at,
        "status": "verified_unassigned_pending_independent_review",
        "classification": "evaluator_private_reviewer_only",
        "subject_count": 13,
        "task_count": 12,
        "total_review_item_count": len(records),
        "assigned_review_item_count": 0,
        "approved_review_item_count": 0,
        "pending_review_item_count": len(records),
        "minimum_distinct_reviewer_count": None,
        "minimum_distinct_reviewer_count_reason": (
            "Reviewer identities, qualifications, conflicts, and governance are external inputs."
        ),
        "assignment_ready": True,
        "trusted_reviewer_registry_supplied": False,
        "registry_governance_complete": False,
        "independent_review_complete": False,
        "protocol_ready": False,
        "benchmark_ready_task_count": 0,
        "chipflow_adapter_ready_task_count": 0,
        "suite_ready": False,
        "workflow_workspace_exposure_permitted": False,
        "review_handoff": {
            "receipt_sha256": handoff_sha256,
            "expected_receipt_sha256": expected_review_handoff_sha256,
            "trust_anchor_digest_match": True,
        },
        "tracks": track_rows,
        "items": records,
        "source": {
            "builder_sha256": _sha256(builder_path),
            "schema_sha256": _sha256(schema_path),
            "review_handoff_schema_sha256": _sha256(
                admission_root / "review_handoff.schema.json"
            ),
            "candidate_lock_sha256": lock_sha256,
            "review_packet_sha256": packet_sha256,
        },
        "excluded_claims": [
            "Suggested tracks do not appoint or qualify a reviewer.",
            "This handoff creates no registry, signature, decision, freeze, or admission.",
            "No task, protocol, adapter, or suite is ready because this queue was built.",
            "No AIRTL PASS, QoR, PPA, performance, human-level, or superhuman result is claimed.",
        ],
    }
    _validate(result, schema_path, "review assignment handoff")
    output_dir.mkdir(parents=True)
    (output_dir / "review_assignment_handoff.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (output_dir / "REVIEW_ASSIGNMENT_INSTRUCTIONS.md").write_text(
        _instructions(),
        encoding="utf-8",
    )
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--review-handoff-root", type=Path, required=True)
    parser.add_argument("--expected-review-handoff-sha256", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--observed-at", required=True)
    args = parser.parse_args()
    try:
        result = build_review_assignment_handoff(
            repo_root=args.repo_root,
            review_handoff_root=args.review_handoff_root,
            expected_review_handoff_sha256=args.expected_review_handoff_sha256,
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
