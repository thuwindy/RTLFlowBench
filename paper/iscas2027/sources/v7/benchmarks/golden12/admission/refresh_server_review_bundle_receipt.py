#!/usr/bin/env python3
"""Refresh a pending server review-bundle receipt from two checked builds."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


SERVER_ONLY_SCHEMAS = {
    "rtlflowbench.g03_review_bundle_server_reproduction_receipt.v1",
    "rtlflowbench.g05_review_bundle_server_reproduction_receipt.v1",
    "rtlflowbench.g08_review_bundle_server_reproduction_receipt.v1",
    "rtlflowbench.g10_review_bundle_server_reproduction_receipt.v1",
    "rtlflowbench.g12_review_bundle_server_reproduction_receipt.v1",
}
G01_SCHEMA = "rtlflowbench.g01_review_bundle_server_reproduction_receipt.v1"


def _sha256(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"expected regular non-symlink file: {path}")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected one JSON object: {path}")
    return value


def _authority_guard(path: Path) -> dict[str, str]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"authority guard must be a regular file: {path}")
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        key, separator, value = line.partition("=")
        if not separator or key in values:
            raise ValueError("invalid authority guard evidence")
        values[key] = value
    if set(values) != {"head", "branch", "status_sha256"}:
        raise ValueError("authority guard keys are incomplete")
    if len(values["head"]) != 40 or any(
        character not in "0123456789abcdef" for character in values["head"]
    ):
        raise ValueError("authority guard HEAD is invalid")
    if len(values["status_sha256"]) != 64 or any(
        character not in "0123456789abcdef"
        for character in values["status_sha256"]
    ):
        raise ValueError("authority guard status digest is invalid")
    return values


def _run(root: Path, evidence_root: str) -> tuple[dict[str, Any], dict[str, Any]]:
    root = root.resolve(strict=True)
    if root.is_symlink() or not root.is_dir():
        raise ValueError(f"review build root is not a regular directory: {root}")
    receipt_path = root / "bundle_receipt.json"
    manifest_path = root / "bundle_manifest.json"
    receipt = _load(receipt_path)
    archive_paths = list(root.glob("*.tar.gz"))
    if len(archive_paths) != 1:
        raise ValueError(f"expected exactly one review archive: {root}")
    archive = archive_paths[0]
    observed = {
        "archive_bytes": archive.stat().st_size,
        "archive_sha256": _sha256(archive),
        "bundle_receipt_sha256": _sha256(receipt_path),
        "evidence_root": evidence_root,
        "manifest_sha256": _sha256(manifest_path),
    }
    for key in ("archive_bytes", "archive_sha256", "manifest_sha256"):
        if receipt.get(key) != observed[key]:
            raise ValueError(f"bundle receipt {key} mismatch: {root}")
    if receipt.get("status") != "pending_independent_review":
        raise ValueError("bundle receipt must remain pending independent review")
    if receipt.get("workflow_workspace_exposed") is not False:
        raise ValueError("review bundle must remain outside workflow workspaces")
    if receipt.get("approved_review_item_count") != 0:
        raise ValueError("unsigned review bundle cannot contain approvals")
    return observed, receipt


def refresh(
    *,
    repo_root: Path,
    prior_receipt_path: Path,
    run_a_root: Path,
    run_b_root: Path,
    run_a_evidence_root: str,
    run_b_evidence_root: str,
    prior_receipt_evidence_root: str,
    observed_at: str,
    authority_before_path: Path | None = None,
    authority_after_path: Path | None = None,
    authority_status_entry_count: int | None = None,
) -> dict[str, Any]:
    repo_root = repo_root.resolve(strict=True)
    prior_receipt_path = prior_receipt_path.resolve(strict=True)
    for evidence_root in (
        run_a_evidence_root,
        run_b_evidence_root,
        prior_receipt_evidence_root,
    ):
        if "/home/" in evidence_root or "/Users/" in evidence_root:
            raise ValueError(
                "receipt evidence roots must not expose private host paths"
            )
    prior = _load(prior_receipt_path)
    schema_version = prior.get("schema_version")
    if schema_version not in SERVER_ONLY_SCHEMAS | {G01_SCHEMA}:
        raise ValueError(f"unsupported server review receipt: {schema_version}")

    guard_values = (
        authority_before_path,
        authority_after_path,
        authority_status_entry_count,
    )
    if any(value is not None for value in guard_values):
        if any(value is None for value in guard_values):
            raise ValueError("authority guard inputs must be provided together")
        assert authority_before_path is not None
        assert authority_after_path is not None
        assert authority_status_entry_count is not None
        if authority_status_entry_count < 0:
            raise ValueError("authority status entry count cannot be negative")
        authority_before = _authority_guard(authority_before_path.resolve(strict=True))
        authority_after = _authority_guard(authority_after_path.resolve(strict=True))
        if authority_before != authority_after:
            raise ValueError("authority HEAD/status changed during review bundle builds")
    else:
        authority_before = None

    run_a, bundle_a = _run(run_a_root, run_a_evidence_root)
    run_b, bundle_b = _run(run_b_root, run_b_evidence_root)
    task_id = bundle_a.get("task_id")
    if task_id != bundle_b.get("task_id") or task_id != prior.get("task_id"):
        raise ValueError("review builds and prior receipt target different tasks")
    comparable_keys = (
        "archive_bytes",
        "archive_sha256",
        "bundle_receipt_sha256",
        "manifest_sha256",
    )
    if any(run_a[key] != run_b[key] for key in comparable_keys):
        raise ValueError("review bundle builds are not byte-identical")
    for key in (
        "candidate_lock_sha256",
        "review_packet_sha256",
        "locked_component_count",
        "review_item_count",
    ):
        if bundle_a.get(key) != bundle_b.get(key):
            raise ValueError(f"review bundle control mismatch: {key}")

    task_root = repo_root / "benchmarks/golden12/tasks" / str(task_id)
    admission = task_root / "private/admission"
    lock_path = admission / "candidate.lock.json"
    packet_path = admission / "review_packet.json"
    builder_path = admission / "build_review_bundle.py"
    candidate_builder_path = admission / "build_candidate_lock.py"
    lock = _load(lock_path)
    packet = _load(packet_path)
    lock_sha256 = _sha256(lock_path)
    packet_sha256 = _sha256(packet_path)
    if bundle_a.get("candidate_lock_sha256") != lock_sha256:
        raise ValueError("review bundle does not target the current candidate lock")
    if bundle_a.get("review_packet_sha256") != packet_sha256:
        raise ValueError("review bundle does not target the current review packet")
    if packet.get("candidate_lock_sha256") != lock_sha256:
        raise ValueError("review packet does not target the current candidate lock")
    review_items = packet.get("review_items")
    if not isinstance(review_items, list) or any(
        item.get("status") != "pending"
        or item.get("independent_reviewer") is not None
        or item.get("signature_sha256") is not None
        for item in review_items
    ):
        raise ValueError("review packet must remain fully unsigned and pending")

    receipt = json.loads(json.dumps(prior))
    receipt["observed_at"] = observed_at
    receipt["candidate_lock_sha256"] = lock_sha256
    receipt["review_packet_sha256"] = packet_sha256
    receipt["builder_source_sha256"] = _sha256(builder_path)
    receipt["locked_component_count"] = len(lock["component_sha256"])
    receipt["review_item_count"] = len(review_items)
    receipt["approved_review_item_count"] = 0
    receipt["workflow_workspace_exposed"] = False
    receipt["independent_review_complete"] = False
    receipt["refresh_builder_source_sha256"] = _sha256(Path(__file__).resolve())
    if authority_before is not None:
        assert authority_status_entry_count is not None
        receipt["server_authority_guard"] = {
            "status": "pass",
            "head": authority_before["head"],
            "head_before_after": authority_before["head"],
            "branch": authority_before["branch"],
            "branch_before_after": authority_before["branch"],
            "porcelain_entry_count_before_after": authority_status_entry_count,
            "dirty_entry_count": authority_status_entry_count,
            "porcelain_sha256_before_after": authority_before["status_sha256"],
            "porcelain_v1_sha256_before_and_after": authority_before[
                "status_sha256"
            ],
        }

    if "candidate_builder_source_sha256" in receipt:
        receipt["candidate_builder_source_sha256"] = _sha256(candidate_builder_path)

    prior_sha256 = _sha256(prior_receipt_path)
    if schema_version == G01_SCHEMA:
        evidence_map = admission / "review_evidence_map.json"
        receipt["review_evidence_map_sha256"] = _sha256(evidence_map)
        previous_run = prior["local"]
        receipt["local"] = {
            **run_a,
            "host": "SERVER26",
            "role": "same_server_run_a_compatibility_slot",
        }
        receipt["server"] = {**run_b, "role": "server_run_b"}
        receipt["cross_host_reproduced"] = False
        receipt["reproduction_scope"] = "same_server_two_builds"
        receipt["supersedes"] = {
            "archive_sha256": previous_run["archive_sha256"],
            "bundle_receipt_sha256": previous_run["bundle_receipt_sha256"],
            "candidate_lock_sha256": prior["candidate_lock_sha256"],
            "historical_supersession_chain_preserved_in_previous_receipt": True,
            "locked_component_count": prior["locked_component_count"],
            "manifest_sha256": previous_run["manifest_sha256"],
            "reason": (
                "The previous unsigned server receipt remains preserved. The "
                "replacement binds the current candidate and approves no review item."
            ),
            "receipt_evidence_root": prior_receipt_evidence_root,
            "receipt_sha256": prior_sha256,
        }
    else:
        previous = {
            "adopted_for_current_candidate": False,
            "archive_bytes": prior["server_run_a"]["archive_bytes"],
            "archive_sha256": prior["server_run_a"]["archive_sha256"],
            "bundle_receipt_sha256": prior["server_run_a"]["bundle_receipt_sha256"],
            "candidate_lock_sha256": prior["candidate_lock_sha256"],
            "evidence_root": prior["server_run_a"]["evidence_root"],
            "manifest_sha256": prior["server_run_a"]["manifest_sha256"],
            "reason": (
                "Preserved for the preceding pending candidate. The replacement "
                "binds current technical controls, approves no review item, and "
                "does not relabel workflow, EDA, score, PPA, or readiness evidence."
            ),
            "receipt_sha256": prior_sha256,
            "review_packet_sha256": prior["review_packet_sha256"],
        }
        receipt["previous_server_reproductions"] = [
            previous,
            *prior.get("previous_server_reproductions", []),
        ]
        receipt["server_run_a"] = run_a
        receipt["server_run_b"] = run_b
        receipt["server_reproduction"] = {
            "copies": 2,
            "artifacts_byte_identical": True,
        }

    if receipt.get("benchmark_ready") not in (None, False):
        raise ValueError("server review receipt cannot claim benchmark readiness")
    if receipt.get("chipflow_adapter_ready") not in (None, False):
        raise ValueError("server review receipt cannot claim adapter readiness")
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--prior-receipt", type=Path, required=True)
    parser.add_argument("--run-a-root", type=Path, required=True)
    parser.add_argument("--run-b-root", type=Path, required=True)
    parser.add_argument("--run-a-evidence-root", required=True)
    parser.add_argument("--run-b-evidence-root", required=True)
    parser.add_argument("--prior-receipt-evidence-root", required=True)
    parser.add_argument("--observed-at", required=True)
    parser.add_argument("--authority-before", type=Path)
    parser.add_argument("--authority-after", type=Path)
    parser.add_argument("--authority-status-entry-count", type=int)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists() or args.output.is_symlink():
        raise FileExistsError(f"refusing existing output: {args.output}")
    receipt = refresh(
        repo_root=args.repo_root,
        prior_receipt_path=args.prior_receipt,
        run_a_root=args.run_a_root,
        run_b_root=args.run_b_root,
        run_a_evidence_root=args.run_a_evidence_root,
        run_b_evidence_root=args.run_b_evidence_root,
        prior_receipt_evidence_root=args.prior_receipt_evidence_root,
        observed_at=args.observed_at,
        authority_before_path=args.authority_before,
        authority_after_path=args.authority_after,
        authority_status_entry_count=args.authority_status_entry_count,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
