#!/usr/bin/env python3
"""Verify and bind all twelve public-only Golden-12 trial workspaces."""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import tarfile
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
WORKSPACE_SCHEMA_RELATIVE = (
    "benchmarks/golden12/admission/public_trial_workspace_receipt.schema.json"
)
SET_SCHEMA_RELATIVE = (
    "benchmarks/golden12/admission/public_trial_workspace_set_receipt.schema.json"
)
MATERIALIZER_RELATIVE = (
    "benchmarks/golden12/admission/prepare_public_trial_workspace.py"
)
VERIFIER_RELATIVE = (
    "benchmarks/golden12/admission/verify_public_suite_candidate.py"
)
SUITE_RECEIPT_RELATIVE = (
    "docs/chipflow/research/golden12/"
    "protocol_public_suite_candidate_server_receipt.json"
)


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _sha256(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"expected regular non-symlink file: {path}")
    return _sha256_bytes(path.read_bytes())


def _load(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"expected regular non-symlink JSON file: {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected one JSON object: {path}")
    return value


def _validate_observed_at(value: str) -> None:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("--observed-at must include a timezone")


def _canonical_digest(entries: list[dict[str, Any]]) -> str:
    return _sha256_bytes(
        json.dumps(entries, separators=(",", ":"), sort_keys=True).encode()
    )


def _release_binding(
    *,
    suite_archive_sha256: str,
    release_archive_path: Path,
    expected_release_archive_sha256: str,
    release_lock_path: Path,
    expected_release_lock_sha256: str,
) -> dict[str, str]:
    release_archive_path = release_archive_path.expanduser().resolve(strict=True)
    release_lock_path = release_lock_path.expanduser().resolve(strict=True)
    if (
        release_archive_path.is_symlink()
        or not release_archive_path.is_file()
        or release_lock_path.is_symlink()
        or not release_lock_path.is_file()
    ):
        raise ValueError("release inputs must be regular non-symlink files")
    if (
        len(expected_release_archive_sha256) != 64
        or len(expected_release_lock_sha256) != 64
        or _sha256(release_archive_path) != expected_release_archive_sha256
        or _sha256(release_lock_path) != expected_release_lock_sha256
    ):
        raise ValueError("AI-reviewed release trust anchor mismatch")
    lock = _load(release_lock_path)
    if not (
        lock.get("schema_version")
        == "rtlflowbench.golden12_ai_reviewed_v1_global_release_lock.v1"
        and lock.get("status") == "RELEASE_AI_REVIEWED_V1"
        and lock.get("release_class") == "Golden-12 AI-reviewed v1"
        and lock.get("human_independent_review_present") is False
        and lock.get("legal_review_complete") is False
        and lock.get("public_archive", {}).get("sha256")
        == expected_release_archive_sha256
        and lock.get("public_archive", {}).get("private_file_count") == 0
    ):
        raise ValueError("AI-reviewed release lock semantics drifted")

    overlay_name = "rtlflowbench-golden12-ai-reviewed-v1/release.json"
    overlay_payload: bytes | None = None
    with tarfile.open(release_archive_path, "r:gz") as archive:
        seen: set[str] = set()
        for member in archive.getmembers():
            pure = PurePosixPath(member.name)
            if (
                pure.is_absolute()
                or ".." in pure.parts
                or member.issym()
                or member.islnk()
                or (not member.isdir() and not member.isfile())
                or member.name in seen
            ):
                raise ValueError("AI-reviewed release archive has an unsafe member")
            seen.add(member.name)
            if member.name == overlay_name:
                if not member.isfile() or member.size > 1024 * 1024:
                    raise ValueError("AI-reviewed release overlay is unsafe")
                stream = archive.extractfile(member)
                if stream is None:
                    raise ValueError("AI-reviewed release overlay is unreadable")
                overlay_payload = stream.read(member.size + 1)
                if len(overlay_payload) != member.size:
                    raise ValueError("AI-reviewed release overlay size drifted")
    if overlay_payload is None:
        raise ValueError("AI-reviewed release overlay is missing")
    overlay = json.loads(overlay_payload.decode("utf-8"))
    if not (
        isinstance(overlay, dict)
        and overlay.get("schema_version")
        == "rtlflowbench.golden12_ai_reviewed_release_overlay.v1"
        and overlay.get("status") == "RELEASE"
        and overlay.get("release_class") == "Golden-12 AI-reviewed v1"
        and overlay.get("public_candidate_archive_sha256")
        == suite_archive_sha256
        and overlay.get("readiness", {}).get(
            "ai_reviewed_research_artifact_release"
        )
        is True
        and overlay.get("readiness", {}).get(
            "human_independent_admission_complete"
        )
        is False
        and overlay.get("readiness", {}).get("legal_review_complete") is False
    ):
        raise ValueError("AI-reviewed release overlay does not bind this public suite")
    return {
        "release_archive_sha256": expected_release_archive_sha256,
        "release_lock_sha256": expected_release_lock_sha256,
        "release_class": "Golden-12 AI-reviewed v1",
        "trust_receipt_kind": "ai_reviewed_v1_global_release_lock",
    }


def _safe_relative(path: Path, *, label: str) -> str:
    value = path.as_posix()
    pure = PurePosixPath(value)
    lowered = {part.lower() for part in pure.parts}
    if (
        pure.is_absolute()
        or not pure.parts
        or any(part in {"", ".", ".."} for part in pure.parts)
        or "private" in lowered
        or "oracle" in lowered
    ):
        raise ValueError(f"unsafe {label} path: {value}")
    return value


def _tree_entries(root: Path, *, label: str) -> list[dict[str, Any]]:
    if root.is_symlink() or not root.is_dir():
        raise ValueError(f"{label} root must be a regular directory")
    entries: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        value = _safe_relative(relative, label=label)
        if path.is_symlink():
            raise ValueError(f"{label} contains a symlink: {value}")
        if path.is_dir():
            continue
        if not path.is_file():
            raise ValueError(f"{label} contains a non-regular entry: {value}")
        payload = path.read_bytes()
        entries.append(
            {"path": value, "bytes": len(payload), "sha256": _sha256_bytes(payload)}
        )
    return entries


def _require_public_permissions(root: Path) -> None:
    for path in [root, *sorted(root.rglob("*"))]:
        if path.is_symlink():
            raise ValueError("public workspace contains a symlink")
        mode = path.stat().st_mode & 0o777
        expected = 0o555 if path.is_dir() else 0o444
        if mode != expected:
            raise ValueError(
                f"public workspace mode drift: {path.relative_to(root)}:{mode:o}"
            )


def _projection_contract(lock: dict[str, Any]) -> list[dict[str, Any]]:
    raw = lock.get("repository_projection_files")
    if raw is None:
        return []
    if not isinstance(raw, list) or not raw:
        raise ValueError("repository_projection_files must be non-empty")
    entries: list[dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            raise ValueError("invalid repository projection contract")
        path = item.get("path")
        mode = item.get("mode")
        digest = item.get("sha256")
        byte_count = item.get("bytes")
        if not isinstance(path, str):
            raise ValueError("projection path must be a string")
        _safe_relative(Path(path), label="projection")
        if mode not in {"editable", "read_only"}:
            raise ValueError("projection mode must be editable or read_only")
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or not isinstance(byte_count, int)
            or isinstance(byte_count, bool)
            or byte_count < 0
        ):
            raise ValueError("invalid projection digest or byte count")
        entries.append(
            {
                "path": path,
                "mode": mode,
                "sha256": digest,
                "bytes": byte_count,
            }
        )
    if len(entries) != len({item["path"] for item in entries}):
        raise ValueError("duplicate repository projection path")
    return entries


def _validate_worktree(
    *,
    worktree: Path,
    lock: dict[str, Any],
    scope: dict[str, Any],
    projection_summary: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    actual = _tree_entries(worktree, label="worktree")
    contract = _projection_contract(lock)
    editable = set(scope.get("editable_paths", []))
    read_only = set(scope.get("read_only_repository_paths", []))
    if contract:
        expected = [
            {
                "path": item["path"],
                "bytes": item["bytes"],
                "sha256": item["sha256"],
            }
            for item in contract
        ]
        if actual != sorted(expected, key=lambda item: item["path"]):
            raise ValueError("workspace worktree differs from the public projection lock")
        if editable != {
            item["path"] for item in contract if item["mode"] == "editable"
        }:
            raise ValueError("editable path contract differs from projection lock")
        modes = {item["path"]: item["mode"] for item in contract}
    else:
        allowlist = lock.get("repository_projection_allowlist", [])
        if not isinstance(allowlist, list) or not all(
            isinstance(item, str) for item in allowlist
        ):
            raise ValueError("invalid repository projection allowlist")
        if len(allowlist) != len(set(allowlist)):
            raise ValueError("duplicate repository projection allowlist path")
        for item in allowlist:
            _safe_relative(Path(item), label="projection")
        if [item["path"] for item in actual] != sorted(allowlist):
            raise ValueError("workspace worktree differs from the public projection allowlist")
        if not set(allowlist).issubset(editable | read_only):
            raise ValueError("projection allowlist escapes editable/read-only scope")
        locked_digests = lock.get("repository_projection_sha256", {})
        if not isinstance(locked_digests, dict) or not set(locked_digests).issubset(
            set(allowlist)
        ):
            raise ValueError("invalid repository projection digest map")
        actual_by_path = {item["path"]: item for item in actual}
        if any(
            actual_by_path[path]["sha256"] != digest
            for path, digest in locked_digests.items()
        ):
            raise ValueError("workspace worktree digest differs from public lock")
        modes = {
            path: "editable" if path in editable else "read_only"
            for path in allowlist
        }
    if projection_summary is not None and projection_summary.get(
        "projected_paths"
    ) != [item["path"] for item in actual]:
        raise ValueError("workspace projection summary path closure drift")
    for path, projection_mode in modes.items():
        target = worktree / path
        mode = target.stat().st_mode & 0o777
        expected_mode = 0o644 if projection_mode == "editable" else 0o444
        if mode != expected_mode:
            raise ValueError(f"worktree file mode drift: {path}:{mode:o}")
    return actual


def build_public_trial_workspace_set(
    *,
    repo_root: Path,
    workspace_root: Path,
    expected_suite_archive_sha256: str,
    observed_at: str,
    release_archive_path: Path | None = None,
    expected_release_archive_sha256: str | None = None,
    release_lock_path: Path | None = None,
    expected_release_lock_sha256: str | None = None,
) -> dict[str, Any]:
    repo_root = repo_root.expanduser().resolve(strict=True)
    workspace_root = workspace_root.expanduser().resolve(strict=True)
    _validate_observed_at(observed_at)
    if len(expected_suite_archive_sha256) != 64:
        raise ValueError("invalid expected suite archive sha256")
    if workspace_root.is_symlink() or not workspace_root.is_dir():
        raise ValueError("workspace root must be a regular directory")
    children = sorted(path.name for path in workspace_root.iterdir())
    if children != sorted(TASK_IDS):
        raise ValueError("workspace root must contain exactly the twelve task directories")

    workspace_schema_path = repo_root / WORKSPACE_SCHEMA_RELATIVE
    set_schema_path = repo_root / SET_SCHEMA_RELATIVE
    materializer_path = repo_root / MATERIALIZER_RELATIVE
    verifier_path = repo_root / VERIFIER_RELATIVE
    suite_receipt_path = repo_root / SUITE_RECEIPT_RELATIVE
    workspace_schema = _load(workspace_schema_path)
    set_schema = _load(set_schema_path)
    release_values = (
        release_archive_path,
        expected_release_archive_sha256,
        release_lock_path,
        expected_release_lock_sha256,
    )
    release_mode = all(value is not None for value in release_values)
    if any(value is not None for value in release_values) and not release_mode:
        raise ValueError("all AI-reviewed release binding inputs are required together")
    suite_receipt = None if release_mode else _load(suite_receipt_path)
    Draft202012Validator.check_schema(workspace_schema)
    Draft202012Validator.check_schema(set_schema)
    if not release_mode and (
        suite_receipt is None
        or suite_receipt.get("status")
        != "server_byte_reproducible_public_only_not_released"
        or suite_receipt.get("reproduction", {}).get("archive_sha256")
        != expected_suite_archive_sha256
        or suite_receipt.get("suite", {}).get("task_count") != 12
        or suite_receipt.get("suite", {}).get("private_file_count") != 0
    ):
        raise ValueError("public suite server receipt is stale or unsafe")
    release_binding = None
    if release_mode:
        assert release_archive_path is not None
        assert expected_release_archive_sha256 is not None
        assert release_lock_path is not None
        assert expected_release_lock_sha256 is not None
        release_binding = _release_binding(
            suite_archive_sha256=expected_suite_archive_sha256,
            release_archive_path=release_archive_path,
            expected_release_archive_sha256=expected_release_archive_sha256,
            release_lock_path=release_lock_path,
            expected_release_lock_sha256=expected_release_lock_sha256,
        )

    materializer_sha256 = _sha256(materializer_path)
    verifier_sha256 = _sha256(verifier_path)
    workspace_schema_sha256 = _sha256(workspace_schema_path)
    task_rows: list[dict[str, Any]] = []
    total_public = 0
    total_repository = 0
    projection_count = 0
    receipt_observed_at: str | None = None
    for task_id in TASK_IDS:
        workspace = workspace_root / task_id
        if workspace.is_symlink() or not workspace.is_dir():
            raise ValueError(f"invalid workspace directory: {task_id}")
        public = workspace / "public"
        worktree = workspace / "worktree"
        receipt_path = workspace / "workspace_receipt.json"
        receipt = _load(receipt_path)
        Draft202012Validator(
            workspace_schema, format_checker=FormatChecker()
        ).validate(receipt)
        if receipt_observed_at is None:
            receipt_observed_at = receipt["observed_at"]
        elif receipt["observed_at"] != receipt_observed_at:
            raise ValueError("workspace receipts were not materialized as one cohort")
        if (
            receipt["task_id"] != task_id
            or receipt["public_suite"]["archive_sha256"]
            != expected_suite_archive_sha256
            or receipt["layout"]["private_file_count"] != 0
            or receipt["materializer_sha256"] != materializer_sha256
            or receipt["public_suite_verifier_sha256"] != verifier_sha256
            or receipt["receipt_schema_sha256"] != workspace_schema_sha256
            or any(receipt["readiness"].values())
        ):
            raise ValueError(f"workspace receipt is stale or unsafe: {task_id}")

        source_public = repo_root / "benchmarks/golden12/tasks" / task_id / "public"
        source_entries = _tree_entries(source_public, label="source public")
        public_entries = _tree_entries(public, label="workspace public")
        if source_entries != public_entries:
            raise ValueError(f"workspace public packet drift: {task_id}")
        public_digest = _canonical_digest(public_entries)
        if receipt["public_suite"]["task_public_tree_sha256"] != public_digest:
            raise ValueError(f"workspace public tree receipt drift: {task_id}")
        _require_public_permissions(public)

        lock = _load(public / "repo.lock")
        scope = _load(public / "allowed_scope.json")
        external_task = _load(public / "external_task.json")
        if (
            lock.get("task_id") != task_id
            or scope.get("task_id") != task_id
            or external_task.get("task_id") != task_id
            or external_task.get("submission_contract", {}).get("editable_paths")
            != scope.get("editable_paths")
        ):
            raise ValueError(f"public task contract drift: {task_id}")
        worktree_entries = _validate_worktree(
            worktree=worktree,
            lock=lock,
            scope=scope,
            projection_summary=receipt["repository_projection"],
        )
        projection_required = lock.get("source_snapshot_exposed_to_workflow") is True
        if projection_required != (receipt["repository_projection"] is not None):
            raise ValueError(f"workspace projection receipt drift: {task_id}")
        projection_count += int(projection_required)
        if (
            receipt["layout"]["public_file_count"] != len(public_entries)
            or receipt["layout"]["repository_file_count"] != len(worktree_entries)
        ):
            raise ValueError(f"workspace layout count drift: {task_id}")
        payload_entries = [
            {**item, "path": f"public/{item['path']}"} for item in public_entries
        ] + [
            {**item, "path": f"worktree/{item['path']}"}
            for item in worktree_entries
        ]
        total_public += len(public_entries)
        total_repository += len(worktree_entries)
        task_rows.append(
            {
                "task_id": task_id,
                "workspace_receipt_sha256": _sha256(receipt_path),
                "public_tree_sha256": public_digest,
                "workspace_payload_sha256": _canonical_digest(payload_entries),
                "public_file_count": len(public_entries),
                "repository_file_count": len(worktree_entries),
                "projection_required": projection_required,
                "private_file_count": 0,
            }
        )
    if projection_count != 10:
        raise ValueError("expected ten repository-projection workspaces")

    result = {
        "schema_version": (
            "rtlflowbench.golden12_public_trial_workspace_set_receipt.v1"
        ),
        "observed_at": observed_at,
        "status": (
            "development_public_trial_workspace_set_materialized_not_admitted"
        ),
        "public_suite": {
            "archive_sha256": expected_suite_archive_sha256,
            "server_receipt_sha256": (
                release_binding["release_lock_sha256"]
                if release_binding is not None
                else _sha256(suite_receipt_path)
            ),
            "task_count": 12,
            "public_only": True,
            **(release_binding or {}),
        },
        "summary": {
            "task_count": 12,
            "workspace_count": 12,
            "projection_workspace_count": projection_count,
            "blank_workspace_count": 12 - projection_count,
            "public_file_count": total_public,
            "repository_file_count": total_repository,
            "private_file_count": 0,
        },
        "tasks": task_rows,
        "source_sha256": {
            "workspace_set_builder": _sha256(Path(__file__).resolve()),
            "workspace_materializer": materializer_sha256,
            "workspace_receipt_schema": workspace_schema_sha256,
            "public_suite_verifier": verifier_sha256,
        },
        "readiness": {
            "all_public_workspaces_materialized": True,
            "public_private_path_isolation_verified": True,
            "controller_measurement_envelope_bound": False,
            "rights_review_complete": False,
            "suite_frozen": False,
            "official_attempts_permitted": False,
            "publishable_score_permitted": False,
        },
        "attempt_accounting": {
            "official_attempts_started": 0,
            "semantic_attempts_consumed": 0,
            "provider_calls": 0,
            "eda_calls": 0,
            "private_evaluator_calls": 0,
            "benchmark_results_created": 0,
        },
        "blockers": [
            "controller_aware_measurement_envelope_not_bound",
            "common_provider_preflight_not_passed",
            "release_freeze_not_complete",
            "independent_rights_and_admission_review_pending",
        ],
        "excluded_claims": [
            "Workspace materialization is not a workflow attempt or benchmark verdict.",
            "No private evaluator, reference solution, hidden oracle, score, QoR, or PPA result is included.",
            "The development public suite remains unfrozen and is not publishable.",
        ],
    }
    Draft202012Validator(
        set_schema, format_checker=FormatChecker()
    ).validate(result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--workspace-root", type=Path, required=True)
    parser.add_argument("--expected-suite-archive-sha256", required=True)
    parser.add_argument("--observed-at", required=True)
    parser.add_argument("--release-archive", type=Path)
    parser.add_argument("--expected-release-archive-sha256")
    parser.add_argument("--release-lock", type=Path)
    parser.add_argument("--expected-release-lock-sha256")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists() or args.output.is_symlink():
        raise FileExistsError(f"refusing to overwrite output: {args.output}")
    value = build_public_trial_workspace_set(
        repo_root=args.repo_root,
        workspace_root=args.workspace_root,
        expected_suite_archive_sha256=args.expected_suite_archive_sha256,
        observed_at=args.observed_at,
        release_archive_path=args.release_archive,
        expected_release_archive_sha256=args.expected_release_archive_sha256,
        release_lock_path=args.release_lock,
        expected_release_lock_sha256=args.expected_release_lock_sha256,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(value, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
