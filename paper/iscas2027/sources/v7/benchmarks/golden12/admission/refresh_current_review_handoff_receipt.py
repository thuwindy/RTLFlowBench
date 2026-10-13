#!/usr/bin/env python3
"""Refresh a pending task review handoff from current server evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


SUPPORTED_TASKS = {
    "G01-common-fifo-spec",
    "G02-common-rr-arbiter-spec",
    "G04-wb2axip-split-bridge",
    "G09-axis-fifo-dv",
}


def _sha256(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"expected regular non-symlink file: {path}")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected one JSON object: {path}")
    return value


def _bundle(root: Path) -> tuple[dict[str, Any], Path, Path]:
    root = root.resolve(strict=True)
    receipt_path = root / "bundle_receipt.json"
    manifest_path = root / "bundle_manifest.json"
    receipt = _load(receipt_path)
    archives = list(root.glob("*.tar.gz"))
    if len(archives) != 1:
        raise ValueError(f"expected exactly one review archive: {root}")
    archive = archives[0]
    if receipt.get("archive_sha256") != _sha256(archive):
        raise ValueError("review archive does not match bundle receipt")
    if receipt.get("manifest_sha256") != _sha256(manifest_path):
        raise ValueError("review manifest does not match bundle receipt")
    if receipt.get("approved_review_item_count") != 0:
        raise ValueError("review bundle cannot contain approvals")
    return receipt, receipt_path, archive


def _sanitized(value: str) -> str:
    if "/home/" in value or "/Users/" in value:
        raise ValueError("handoff evidence paths must not expose private host paths")
    return value


def _redact_legacy_server_evidence_root(value: str) -> str:
    marker = "/rtlflowbench/"
    if value.startswith("SERVER26:/") and marker in value:
        return "SERVER26:rtlflowbench/" + value.split(marker, 1)[1]
    return value


def _redact_legacy_server_paths(value: Any) -> Any:
    """Remove private host prefixes from nested, historical SERVER26 paths.

    Only the established ``SERVER26:.../rtlflowbench/`` namespace is
    rewritten.  Other absolute host paths remain untouched so the final
    serialized-path guard still rejects unexpected leaks.
    """

    if isinstance(value, str):
        return _redact_legacy_server_evidence_root(value)
    if isinstance(value, list):
        return [_redact_legacy_server_paths(item) for item in value]
    if isinstance(value, dict):
        return {
            key: _redact_legacy_server_paths(item)
            for key, item in value.items()
        }
    return value


def _gate_counts(rows: Any, *, label: str) -> dict[str, int]:
    if not isinstance(rows, list):
        raise ValueError(f"{label} must be a list")
    counts = {"pass": 0, "pending": 0, "fail": 0}
    for row in rows:
        if not isinstance(row, dict) or row.get("status") not in counts:
            raise ValueError(f"{label} contains an invalid gate status")
        counts[row["status"]] += 1
    return counts


def _current_g02_admission_recheck(
    *,
    admission_result_path: Path | None,
    normal_exit_code: int | None,
    require_ready_result_path: Path | None,
    require_ready_exit_code: int | None,
    audit_result_path: Path | None,
    audit_exit_code: int | None,
    evidence_root: str | None,
    candidate_lock_sha256: str,
) -> dict[str, Any] | None:
    supplied = (
        admission_result_path,
        normal_exit_code,
        require_ready_result_path,
        require_ready_exit_code,
        audit_result_path,
        audit_exit_code,
        evidence_root,
    )
    if all(value is None for value in supplied):
        return None
    if any(value is None for value in supplied):
        raise ValueError("G02 admission refresh arguments must be supplied together")
    assert admission_result_path is not None
    assert require_ready_result_path is not None
    assert audit_result_path is not None
    assert evidence_root is not None
    evidence_root = _sanitized(evidence_root)
    normal = _load(admission_result_path.resolve(strict=True))
    require_ready = _load(require_ready_result_path.resolve(strict=True))
    audit = _load(audit_result_path.resolve(strict=True))
    if _sha256(admission_result_path) != _sha256(require_ready_result_path):
        raise ValueError("normal and require-ready G02 results are not byte-identical")
    automatic = _gate_counts(normal.get("automatic_gates"), label="automatic gates")
    independent = _gate_counts(normal.get("independent_gates"), label="independent gates")
    adapter = _gate_counts(normal.get("adapter_gates"), label="adapter gates")
    if not (
        normal_exit_code == 0
        and require_ready_exit_code == 2
        and audit_exit_code == 0
        and normal.get("task_id") == "G02-common-rr-arbiter-spec"
        and normal.get("candidate_lock_sha256") == candidate_lock_sha256
        and normal.get("status") == "development_candidate_pending"
        and normal.get("benchmark_ready") is False
        and normal.get("chipflow_adapter_ready") is False
        and automatic == {"pass": 17, "pending": 0, "fail": 0}
        and independent == {"pass": 0, "pending": 8, "fail": 0}
        and adapter == {"pass": 0, "pending": 3, "fail": 0}
        and audit.get("task_id") == "G02-common-rr-arbiter-spec"
        and audit.get("status") == "pass"
        and audit.get("technical_candidate_evidence_complete") is True
        and audit.get("automatic_gate_counts") == automatic
        and audit.get("independent_pending_count") == 8
        and audit.get("adapter_pending_count") == 3
        and audit.get("benchmark_ready") is False
        and audit.get("chipflow_adapter_ready") is False
    ):
        raise ValueError("G02 admission/audit evidence is not the expected current pending state")
    return {
        "adapter_gate_counts": adapter,
        "audit_exit_code": audit_exit_code,
        "audit_result_sha256": _sha256(audit_result_path),
        "automatic_gate_counts": automatic,
        "evidence_root": evidence_root,
        "independent_gate_counts": independent,
        "job_metadata_sha256": None,
        "normal_exit_code": normal_exit_code,
        "require_ready_exit_code": require_ready_exit_code,
        "require_ready_result_sha256": _sha256(require_ready_result_path),
        "result_sha256": _sha256(admission_result_path),
        "status": normal["status"],
    }


def refresh(
    *,
    repo_root: Path,
    prior_receipt_path: Path,
    run_a_root: Path,
    run_b_root: Path,
    workspace_root: Path,
    bundle_evidence_root: str,
    workspace_evidence_root: str,
    observed_at: str,
    admission_result_path: Path | None = None,
    normal_exit_code: int | None = None,
    require_ready_result_path: Path | None = None,
    require_ready_exit_code: int | None = None,
    audit_result_path: Path | None = None,
    audit_exit_code: int | None = None,
    admission_evidence_root: str | None = None,
) -> dict[str, Any]:
    repo_root = repo_root.resolve(strict=True)
    prior = _load(prior_receipt_path.resolve(strict=True))
    task_id = prior.get("task_id")
    if task_id not in SUPPORTED_TASKS:
        raise ValueError(f"unsupported task handoff: {task_id}")
    bundle_evidence_root = _sanitized(bundle_evidence_root)
    workspace_evidence_root = _sanitized(workspace_evidence_root)

    run_a, run_a_receipt_path, archive_a = _bundle(run_a_root)
    run_b, run_b_receipt_path, archive_b = _bundle(run_b_root)
    comparable = (
        "archive_sha256",
        "archive_bytes",
        "manifest_sha256",
        "candidate_lock_sha256",
        "review_packet_sha256",
        "review_evidence_map_sha256",
        "locked_component_count",
        "review_item_count",
        "approved_review_item_count",
    )
    if any(run_a.get(key) != run_b.get(key) for key in comparable):
        raise ValueError("review bundle runs are not byte-identical")
    if _sha256(archive_a) != _sha256(archive_b):
        raise ValueError("review archives are not byte-identical")

    workspace_root = workspace_root.resolve(strict=True)
    workspace_receipt_path = workspace_root / "review_workspace_receipt.json"
    checklist_path = workspace_root / "review_checklist.json"
    workspace = _load(workspace_receipt_path)
    if workspace.get("status") != "verified_unsigned_review_workspace":
        raise ValueError("review workspace is not a verified unsigned workspace")
    if workspace.get("approved_review_item_count") != 0:
        raise ValueError("review workspace cannot contain approvals")
    if workspace.get("source_archive_sha256") != run_a["archive_sha256"]:
        raise ValueError("review workspace does not consume the current archive")

    task_root = repo_root / "benchmarks/golden12/tasks" / str(task_id)
    admission = task_root / "private/admission"
    protocol = repo_root / "benchmarks/golden12/protocol"
    lock_path = admission / "candidate.lock.json"
    packet_path = admission / "review_packet.json"
    lock = _load(lock_path)
    packet = _load(packet_path)
    lock_sha = _sha256(lock_path)
    packet_sha = _sha256(packet_path)
    if run_a["candidate_lock_sha256"] != lock_sha:
        raise ValueError("review bundle does not bind the current candidate")
    if run_a["review_packet_sha256"] != packet_sha:
        raise ValueError("review bundle does not bind the current review packet")
    if workspace["candidate_lock_sha256"] != lock_sha:
        raise ValueError("review workspace does not bind the current candidate")
    if packet.get("candidate_lock_sha256") != lock_sha:
        raise ValueError("review packet does not bind the current candidate")
    review_items = packet.get("review_items")
    if not isinstance(review_items, list) or any(
        item.get("status") != "pending"
        or item.get("independent_reviewer") is not None
        or item.get("signature_sha256") is not None
        for item in review_items
    ):
        raise ValueError("review packet must remain fully unsigned")

    receipt = json.loads(json.dumps(prior))
    receipt["observed_at"] = observed_at
    receipt["benchmark_ready"] = False
    receipt["chipflow_adapter_ready"] = False
    receipt["independent_review_complete"] = False
    receipt["workflow_workspace_exposed"] = False
    receipt["refresh_builder_source_sha256"] = _sha256(Path(__file__).resolve())
    admission_recheck = receipt.get("admission_recheck")
    if isinstance(admission_recheck, dict):
        evidence_root = admission_recheck.get("evidence_root")
        if isinstance(evidence_root, str):
            admission_recheck["evidence_root"] = (
                _redact_legacy_server_evidence_root(evidence_root)
            )
    authority_guard = receipt.get("server_authority_guard")
    if isinstance(authority_guard, dict) and "repository" in authority_guard:
        authority_guard["repository"] = "SERVER26:authority-repository"
    workspace_projection = {
        "approved_review_item_count": 0,
        "benchmark_ready": False,
        "candidate_lock_sha256": lock_sha,
        "checklist_sha256": _sha256(checklist_path),
        "path": workspace_evidence_root,
        "preparer_exit_code": 0,
        "protocol_ready": False,
        "receipt_sha256": _sha256(workspace_receipt_path),
        "review_item_count": len(review_items),
        "status": "verified_unsigned_review_workspace",
        "workflow_workspace_exposure_permitted": False,
    }
    reproduction = {
        "approved_review_item_count": 0,
        "archive_bytes": archive_a.stat().st_size,
        "byte_identical": True,
        "contains_hidden_evaluator_assets": bool(
            run_a.get("contains_hidden_evaluator_assets", True)
        ),
        "cross_host_reproduced": False,
        "evidence_root": bundle_evidence_root,
        "job_metadata_sha256": None,
        "job_metadata_status": "not_generated_direct_builder_invocation",
        "locked_component_count": len(lock["component_sha256"]),
        "reproduction_scope": "same_server_two_builds",
        "review_item_count": len(review_items),
        "run_a_archive_sha256": run_a["archive_sha256"],
        "run_a_exit_code": 0,
        "run_a_manifest_sha256": run_a["manifest_sha256"],
        "run_a_receipt_sha256": _sha256(run_a_receipt_path),
        "run_b_archive_sha256": run_b["archive_sha256"],
        "run_b_exit_code": 0,
        "run_b_manifest_sha256": run_b["manifest_sha256"],
        "run_b_receipt_sha256": _sha256(run_b_receipt_path),
        "workflow_workspace_exposed": False,
    }

    if task_id in {"G01-common-fifo-spec", "G02-common-rr-arbiter-spec"}:
        evidence_map_sha = _sha256(admission / "review_evidence_map.json")
        receipt["candidate"] = {
            **receipt["candidate"],
            "approved_review_item_count": 0,
            "candidate_lock_sha256": lock_sha,
            "locked_component_count": len(lock["component_sha256"]),
            "review_evidence_map_sha256": evidence_map_sha,
            "review_item_count": len(review_items),
            "review_packet_sha256": packet_sha,
        }
        receipt["sources"]["bundle_builder_sha256"] = _sha256(
            admission / "build_review_bundle.py"
        )
        receipt["sources"]["review_workspace_preparer_sha256"] = _sha256(
            protocol / "prepare_review_workspace.py"
        )
        if task_id == "G02-common-rr-arbiter-spec":
            receipt["sources"]["admission_checker_sha256"] = _sha256(
                admission / "check.py"
            )
            receipt["sources"]["candidate_lock_builder_sha256"] = _sha256(
                admission / "build_candidate_lock.py"
            )
            receipt["sources"]["standalone_audit_sha256"] = _sha256(
                repo_root / "scripts/audit_chipflow_golden12_g02.py"
            )
            receipt["reviewer_workspace"] = workspace_projection
            receipt["server_reproduction"] = reproduction
            current_admission = _current_g02_admission_recheck(
                admission_result_path=admission_result_path,
                normal_exit_code=normal_exit_code,
                require_ready_result_path=require_ready_result_path,
                require_ready_exit_code=require_ready_exit_code,
                audit_result_path=audit_result_path,
                audit_exit_code=audit_exit_code,
                evidence_root=admission_evidence_root,
                candidate_lock_sha256=lock_sha,
            )
            if current_admission is not None:
                receipt["admission_recheck"] = current_admission
        else:
            receipt["reviewer_workspace"] = {
                "approved_review_item_count": 0,
                "benchmark_ready": False,
                "evidence_root": workspace_evidence_root,
                "prepare_exit_code": 0,
                "protocol_ready": False,
                "review_checklist_sha256": _sha256(checklist_path),
                "review_workspace_receipt_sha256": _sha256(workspace_receipt_path),
                "status": "verified_unsigned_review_workspace",
                "workflow_workspace_exposure_permitted": False,
            }
            receipt["server_reproduction"] = {
                "archive_bytes": archive_a.stat().st_size,
                "archive_sha256": run_a["archive_sha256"],
                "bundle_receipt_sha256": _sha256(run_a_receipt_path),
                "byte_identical": True,
                "cross_host_reproduced": False,
                "evidence_root": bundle_evidence_root,
                "manifest_sha256": run_a["manifest_sha256"],
                "reproduction_scope": "same_server_two_builds",
                "run_a_exit_code": 0,
                "run_b_exit_code": 0,
            }
    else:
        receipt["candidate_lock_sha256"] = lock_sha
        receipt["review_packet_sha256"] = packet_sha
        receipt["bundle_builder_sha256"] = _sha256(admission / "build_review_bundle.py")
        receipt["review_workspace_preparer_sha256"] = _sha256(
            protocol / "prepare_review_workspace.py"
        )
        receipt["reviewer_workspace"] = workspace_projection
        receipt["server_reproduction"] = reproduction
        if task_id == "G09-axis-fifo-dv":
            receipt["review_bundle_receipt_sha256"] = _sha256(
                admission / "review_bundle_receipt.json"
            )
        supersession = receipt.get("supersession")
        if isinstance(supersession, dict):
            previous_path = supersession.get("previous_handoff_evidence_path")
            if isinstance(previous_path, str) and "/evidence/" in previous_path:
                supersession["previous_handoff_evidence_path"] = (
                    "SERVER26:rtlflowbench/evidence/"
                    + previous_path.split("/evidence/", 1)[1]
                )
    receipt = _redact_legacy_server_paths(receipt)
    serialized = json.dumps(receipt, sort_keys=True)
    if "/home/" in serialized or "/Users/" in serialized:
        raise ValueError("refreshed handoff exposes a private host path")
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--prior-receipt", type=Path, required=True)
    parser.add_argument("--run-a-root", type=Path, required=True)
    parser.add_argument("--run-b-root", type=Path, required=True)
    parser.add_argument("--workspace-root", type=Path, required=True)
    parser.add_argument("--bundle-evidence-root", required=True)
    parser.add_argument("--workspace-evidence-root", required=True)
    parser.add_argument("--observed-at", required=True)
    parser.add_argument("--admission-result", type=Path)
    parser.add_argument("--normal-exit-code", type=int)
    parser.add_argument("--require-ready-result", type=Path)
    parser.add_argument("--require-ready-exit-code", type=int)
    parser.add_argument("--audit-result", type=Path)
    parser.add_argument("--audit-exit-code", type=int)
    parser.add_argument("--admission-evidence-root")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists() or args.output.is_symlink():
        raise FileExistsError(f"refusing existing output: {args.output}")
    receipt = refresh(
        repo_root=args.repo_root,
        prior_receipt_path=args.prior_receipt,
        run_a_root=args.run_a_root,
        run_b_root=args.run_b_root,
        workspace_root=args.workspace_root,
        bundle_evidence_root=args.bundle_evidence_root,
        workspace_evidence_root=args.workspace_evidence_root,
        observed_at=args.observed_at,
        admission_result_path=args.admission_result,
        normal_exit_code=args.normal_exit_code,
        require_ready_result_path=args.require_ready_result,
        require_ready_exit_code=args.require_ready_exit_code,
        audit_result_path=args.audit_result,
        audit_exit_code=args.audit_exit_code,
        admission_evidence_root=args.admission_evidence_root,
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
