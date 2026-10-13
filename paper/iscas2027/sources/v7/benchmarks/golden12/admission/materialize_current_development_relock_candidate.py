#!/usr/bin/env python3
"""Materialize a verified all-task development relock candidate.

This is a development-only transition.  It preserves every prior lock and
unsigned review packet under a content-addressed name, atomically installs the
external candidate, and leaves all release/admission gates closed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
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
ADMISSION = Path("benchmarks/golden12/admission")
CANDIDATE_SCHEMA = ADMISSION / "current_development_relock_candidate.schema.json"
MATERIALIZATION_SCHEMA = (
    ADMISSION / "current_development_relock_materialization.schema.json"
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _load(path: Path, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a regular non-symlink file: {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{label} must contain one JSON object")
    return value


def _write_json_new(path: Path, value: dict[str, Any]) -> None:
    if path.exists() or path.is_symlink():
        raise FileExistsError(f"refusing to overwrite output: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _external(repo_root: Path, path: Path, label: str) -> Path:
    resolved = path.expanduser().resolve()
    try:
        resolved.relative_to(repo_root)
    except ValueError:
        return resolved
    raise ValueError(f"{label} must remain outside the repository")


def _git_output(root: Path, *args: str) -> bytes:
    completed = subprocess.run(
        ["git", "-C", str(root), *args],
        check=False,
        capture_output=True,
    )
    if completed.returncode != 0:
        raise ValueError(
            f"git {' '.join(args)} failed with exit {completed.returncode}"
        )
    return completed.stdout


def authority_fingerprint(root: Path) -> dict[str, Any]:
    resolved = root.expanduser().resolve(strict=True)
    status = _git_output(
        resolved,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
    )
    return {
        "root": str(resolved),
        "branch": _git_output(
            resolved, "rev-parse", "--abbrev-ref", "HEAD"
        ).decode().strip(),
        "head": _git_output(resolved, "rev-parse", "HEAD").decode().strip(),
        "status_item_count": len(status.splitlines()),
        "status_sha256": _sha256_bytes(status),
    }


def _archive_path(path: Path, digest: str) -> Path:
    stem = path.name.removesuffix(".json")
    return path.with_name(
        f"{stem}.pre-visible-runner-contract-{digest[:12]}.json"
    )


def _validate_existing_archive(path: Path, expected_sha256: str) -> bool:
    """Accept only an exact content-addressed archive from an earlier attempt."""

    if path.is_symlink():
        raise FileExistsError(f"refusing symlink archive: {path}")
    if not path.exists():
        return False
    if not path.is_file() or _sha256(path) != expected_sha256:
        raise FileExistsError(f"refusing mismatched existing archive: {path}")
    return True


def _assert_pending(packet: dict[str, Any], task_id: str) -> None:
    lists = [packet.get("review_items")]
    if "reviews" in packet:
        lists.append(packet.get("reviews"))
    for items in lists:
        if not isinstance(items, list) or not items:
            raise ValueError(f"review packet has no items: {task_id}")
        for item in items:
            if not isinstance(item, dict) or item.get("status") != "pending":
                raise ValueError(f"review decision is not pending: {task_id}")
            for field in (
                "reviewer",
                "independent_reviewer",
                "signed_at",
                "signed_candidate_lock_sha256",
                "signature_sha256",
            ):
                if item.get(field) is not None:
                    raise ValueError(
                        f"review packet contains signed state: {task_id}:{field}"
                    )


def preflight_materialization(
    *,
    repo_root: Path,
    candidate_root: Path,
    expected_candidate_receipt_sha256: str,
    authority_root: Path,
    expected_authority_head: str,
    expected_authority_status_sha256: str,
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    repo_root = repo_root.expanduser().resolve(strict=True)
    candidate_root = _external(
        repo_root, candidate_root, "candidate root"
    ).resolve(strict=True)
    receipt_path = candidate_root / "candidate-receipt.json"
    if _sha256(receipt_path) != expected_candidate_receipt_sha256:
        raise ValueError("candidate receipt differs from its trust anchor")
    receipt = _load(receipt_path, "candidate receipt")
    candidate_schema = _load(repo_root / CANDIDATE_SCHEMA, "candidate schema")
    Draft202012Validator.check_schema(candidate_schema)
    Draft202012Validator(
        candidate_schema,
        format_checker=FormatChecker(),
    ).validate(receipt)
    if (
        receipt.get("status")
        != "verified_development_relock_candidate_pending_apply"
        or receipt.get("apply_permitted") is not False
        or receipt.get("pretransition_signature_reuse_permitted") is not False
        or receipt.get("task_count") != 12
    ):
        raise ValueError("candidate receipt weakens development boundaries")
    source = receipt["source"]
    if (
        source.get("builder_sha256")
        != _sha256(
            repo_root
            / ADMISSION
            / "build_current_development_relock_candidate.py"
        )
        or source.get("schema_sha256") != _sha256(repo_root / CANDIDATE_SCHEMA)
    ):
        raise ValueError("candidate builder/schema source drift")

    authority = authority_fingerprint(authority_root)
    if authority["head"] != expected_authority_head:
        raise ValueError("authority HEAD drift")
    if authority["status_sha256"] != expected_authority_status_sha256:
        raise ValueError("authority status drift")

    rows = {item["task_id"]: item for item in receipt["tasks"]}
    if tuple(rows) != TASK_IDS:
        raise ValueError("candidate task coverage/order drift")
    operations: list[dict[str, Any]] = []
    for task_id in TASK_IDS:
        row = rows[task_id]
        admission = (
            repo_root
            / "benchmarks/golden12/tasks"
            / task_id
            / "private/admission"
        )
        current_lock = admission / "candidate.lock.json"
        current_packet = admission / "review_packet.json"
        candidate_lock = candidate_root / "files" / task_id / "candidate.lock.json"
        candidate_packet = candidate_root / "files" / task_id / "review_packet.json"
        current_lock_sha256 = _sha256(current_lock)
        current_packet_sha256 = _sha256(current_packet)
        pretransition_lock_sha256 = row[
            "pretransition_candidate_lock_sha256"
        ]
        pretransition_packet_sha256 = row[
            "pretransition_review_packet_sha256"
        ]
        candidate_lock_sha256 = row["candidate_lock_sha256"]
        candidate_packet_sha256 = row["review_packet_sha256"]
        if (
            current_lock_sha256
            not in {pretransition_lock_sha256, candidate_lock_sha256}
            or current_packet_sha256
            not in {pretransition_packet_sha256, candidate_packet_sha256}
        ):
            raise ValueError(f"pretransition source drift: {task_id}")
        if (
            _sha256(candidate_lock) != row["candidate_lock_sha256"]
            or _sha256(candidate_packet) != row["review_packet_sha256"]
        ):
            raise ValueError(f"candidate file drift: {task_id}")
        lock = _load(candidate_lock, f"{task_id} candidate lock")
        packet = _load(candidate_packet, f"{task_id} candidate review packet")
        if lock.get("benchmark_ready") is not False:
            raise ValueError(f"candidate claims benchmark readiness: {task_id}")
        if lock.get("chipflow_adapter_ready") not in (None, False):
            raise ValueError(f"candidate claims adapter readiness: {task_id}")
        if packet.get("candidate_lock_sha256") != _sha256(candidate_lock):
            raise ValueError(f"candidate review packet drift: {task_id}")
        _assert_pending(packet, task_id)
        lock_archive = _archive_path(
            current_lock, pretransition_lock_sha256
        )
        packet_archive = _archive_path(
            current_packet, pretransition_packet_sha256
        )
        lock_archive_exists = _validate_existing_archive(
            lock_archive, pretransition_lock_sha256
        )
        packet_archive_exists = _validate_existing_archive(
            packet_archive, pretransition_packet_sha256
        )
        if (
            current_lock_sha256 == candidate_lock_sha256
            and current_lock_sha256 != pretransition_lock_sha256
            and not lock_archive_exists
        ):
            raise ValueError(
                "missing pretransition lock archive for applied candidate: "
                f"{task_id}"
            )
        if (
            current_packet_sha256 == candidate_packet_sha256
            and current_packet_sha256 != pretransition_packet_sha256
            and not packet_archive_exists
        ):
            raise ValueError(
                "missing pretransition packet archive for applied candidate: "
                f"{task_id}"
            )
        operations.append(
            {
                "task_id": task_id,
                "current_lock": current_lock,
                "current_packet": current_packet,
                "candidate_lock": candidate_lock,
                "candidate_packet": candidate_packet,
                "lock_archive": lock_archive,
                "packet_archive": packet_archive,
                "lock_archive_exists": lock_archive_exists,
                "packet_archive_exists": packet_archive_exists,
                "replace_lock": current_lock_sha256 != candidate_lock_sha256,
                "replace_packet": (
                    current_packet_sha256 != candidate_packet_sha256
                ),
            }
        )
    return receipt, operations, authority


def _write_bytes_new(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as output:
        output.write(payload)
        output.flush()
        os.fsync(output.fileno())


def _atomic_replace(path: Path, payload: bytes) -> None:
    temporary = path.with_name(
        f".{path.name}.tmp-{_sha256_bytes(payload)[:12]}"
    )
    if temporary.exists() or temporary.is_symlink():
        raise FileExistsError(f"refusing existing temporary file: {temporary}")
    try:
        _write_bytes_new(temporary, payload)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def materialize_current_development_relock_candidate(
    *,
    repo_root: Path,
    candidate_root: Path,
    expected_candidate_receipt_sha256: str,
    authority_root: Path,
    expected_authority_head: str,
    expected_authority_status_sha256: str,
    output: Path,
    observed_at: str,
    preflight_only: bool = False,
) -> dict[str, Any]:
    repo_root = repo_root.expanduser().resolve(strict=True)
    output = _external(repo_root, output, "materialization receipt")
    if output.exists() or output.is_symlink():
        raise FileExistsError(f"refusing to overwrite output: {output}")
    candidate, operations, authority = preflight_materialization(
        repo_root=repo_root,
        candidate_root=candidate_root,
        expected_candidate_receipt_sha256=expected_candidate_receipt_sha256,
        authority_root=authority_root,
        expected_authority_head=expected_authority_head,
        expected_authority_status_sha256=expected_authority_status_sha256,
    )
    if preflight_only:
        return {
            "status": "preflight_passed_not_applied",
            "task_count": len(operations),
            "authority": authority,
        }

    archived: list[dict[str, Any]] = []
    replaced: list[tuple[Path, Path]] = []
    try:
        for operation in operations:
            if not operation["lock_archive_exists"]:
                _write_bytes_new(
                    operation["lock_archive"],
                    operation["current_lock"].read_bytes(),
                )
            if not operation["packet_archive_exists"]:
                _write_bytes_new(
                    operation["packet_archive"],
                    operation["current_packet"].read_bytes(),
                )
            archived.append(operation)
        for operation in operations:
            if operation["replace_lock"]:
                _atomic_replace(
                    operation["current_lock"],
                    operation["candidate_lock"].read_bytes(),
                )
                replaced.append(
                    (operation["current_lock"], operation["lock_archive"])
                )
            if operation["replace_packet"]:
                _atomic_replace(
                    operation["current_packet"],
                    operation["candidate_packet"].read_bytes(),
                )
                replaced.append(
                    (
                        operation["current_packet"],
                        operation["packet_archive"],
                    )
                )
    except Exception:
        for current_path, archive_path in reversed(replaced):
            _atomic_replace(
                current_path,
                archive_path.read_bytes(),
            )
        raise

    rows = {item["task_id"]: item for item in candidate["tasks"]}
    task_receipts: list[dict[str, Any]] = []
    for operation in operations:
        task_id = operation["task_id"]
        row = rows[task_id]
        if (
            _sha256(operation["current_lock"]) != row["candidate_lock_sha256"]
            or _sha256(operation["current_packet"]) != row["review_packet_sha256"]
            or _sha256(operation["lock_archive"])
            != row["pretransition_candidate_lock_sha256"]
            or _sha256(operation["packet_archive"])
            != row["pretransition_review_packet_sha256"]
        ):
            raise ValueError(f"post-materialization digest drift: {task_id}")
        task_receipts.append(
            {
                "task_id": task_id,
                "pretransition_candidate_lock_sha256": row[
                    "pretransition_candidate_lock_sha256"
                ],
                "pretransition_review_packet_sha256": row[
                    "pretransition_review_packet_sha256"
                ],
                "candidate_lock_sha256": row["candidate_lock_sha256"],
                "review_packet_sha256": row["review_packet_sha256"],
                "candidate_lock_archive": operation["lock_archive"].relative_to(
                    repo_root
                ).as_posix(),
                "review_packet_archive": operation[
                    "packet_archive"
                ].relative_to(repo_root).as_posix(),
                "all_review_items_pending": True,
                "benchmark_ready": False,
                "chipflow_adapter_ready": False,
            }
        )

    result = {
        "schema_version": (
            "rtlflowbench.current_development_relock_materialization.v1"
        ),
        "observed_at": observed_at,
        "status": "development_locks_applied_pending_review_bundle_rebuild",
        "classification": "release_authority_only",
        "candidate_receipt_sha256": expected_candidate_receipt_sha256,
        "authority": authority,
        "task_count": len(task_receipts),
        "benchmark_ready_task_count": 0,
        "chipflow_adapter_ready_task_count": 0,
        "pretransition_signature_reuse_permitted": False,
        "review_bundle_rebuild_required": True,
        "census_permitted": False,
        "workflow_workspace_exposure_permitted": False,
        "source": {
            "materializer_sha256": _sha256(Path(__file__).resolve()),
            "schema_sha256": _sha256(repo_root / MATERIALIZATION_SCHEMA),
        },
        "tasks": task_receipts,
        "excluded_claims": [
            "Development relock materialization is not release freeze or admission.",
            "All independent review items remain pending and prior signatures are invalid.",
            "Review bundles must be rebuilt before an admission census may run.",
            "No AIRTL, EDA, QoR, PPA, performance, or benchmark PASS is claimed.",
        ],
    }
    schema = _load(repo_root / MATERIALIZATION_SCHEMA, "materialization schema")
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(
        schema,
        format_checker=FormatChecker(),
    ).validate(result)
    _write_json_new(output, result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--candidate-root", type=Path, required=True)
    parser.add_argument("--expected-candidate-receipt-sha256", required=True)
    parser.add_argument("--authority-root", type=Path, required=True)
    parser.add_argument("--expected-authority-head", required=True)
    parser.add_argument("--expected-authority-status-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--observed-at", required=True)
    parser.add_argument("--preflight-only", action="store_true")
    args = parser.parse_args()
    try:
        result = materialize_current_development_relock_candidate(
            repo_root=args.repo_root,
            candidate_root=args.candidate_root,
            expected_candidate_receipt_sha256=(
                args.expected_candidate_receipt_sha256
            ),
            authority_root=args.authority_root,
            expected_authority_head=args.expected_authority_head,
            expected_authority_status_sha256=(
                args.expected_authority_status_sha256
            ),
            output=args.output,
            observed_at=args.observed_at,
            preflight_only=args.preflight_only,
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
