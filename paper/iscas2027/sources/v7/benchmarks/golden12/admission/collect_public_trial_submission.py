#!/usr/bin/env python3
"""Collect a Golden-12 public trial worktree without running evaluation."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import sys
import tempfile
from typing import Any

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parent
WORKSPACE_MATERIALIZER = ROOT / "prepare_public_trial_workspace.py"
WORKSPACE_RECEIPT_SCHEMA = ROOT / "public_trial_workspace_receipt.schema.json"
COLLECTION_RECEIPT_SCHEMA = (
    ROOT / "public_trial_submission_collection_receipt.schema.json"
)
PUBLIC_SUITE_VERIFIER = ROOT / "verify_public_suite_candidate.py"
PACKAGE_SUBMISSION = ROOT.parent / "conformance/package_submission.py"


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _sha256(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _load(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"required JSON is not a regular file: {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain one JSON object")
    return value


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load required module: {path.name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _safe_relative(value: str) -> Path:
    pure = PurePosixPath(value)
    if (
        pure.is_absolute()
        or not pure.parts
        or any(part in {"", ".", ".."} for part in pure.parts)
        or "\\" in value
        or value != pure.as_posix()
        or "private" in {part.lower() for part in pure.parts}
    ):
        raise ValueError(f"unsafe trial path: {value}")
    return Path(*pure.parts)


def _scan_tree(root: Path) -> tuple[dict[str, Path], dict[str, Path], list[str]]:
    files: dict[str, Path] = {}
    directories: dict[str, Path] = {}
    issues: list[str] = []
    if root.is_symlink() or not root.is_dir():
        return files, directories, ["root is missing, non-directory, or symlink"]
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        try:
            _safe_relative(relative)
        except ValueError:
            issues.append(f"unsafe path: {relative}")
            continue
        if path.is_symlink():
            issues.append(f"symlink path: {relative}")
        elif path.is_dir():
            directories[relative] = path
        elif path.is_file():
            files[relative] = path
        else:
            issues.append(f"non-regular path: {relative}")
    return files, directories, issues


def _tree_digest(files: dict[str, Path]) -> str:
    entries = [
        {"path": relative, "bytes": path.stat().st_size, "sha256": _sha256(path)}
        for relative, path in sorted(files.items())
    ]
    return _sha256_bytes(
        json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()
    )


def _expected_directories(paths: set[str]) -> set[str]:
    directories: set[str] = set()
    for value in paths:
        parent = PurePosixPath(value).parent
        while parent.parts:
            directories.add(parent.as_posix())
            parent = parent.parent
    return directories


def _write_receipt_output(
    *, output_dir: Path, receipt: dict[str, Any], staging: Path
) -> None:
    schema = _load(COLLECTION_RECEIPT_SCHEMA)
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(receipt)
    (staging / "collection_receipt.json").write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    staging.replace(output_dir)


def collect_public_trial_submission(
    *,
    workspace_root: Path,
    workspace_receipt_path: Path,
    expected_workspace_receipt_sha256: str,
    metadata_path: Path,
    output_dir: Path,
    observed_at: str,
    projection_archive: Path | None = None,
    projection_receipt: Path | None = None,
) -> dict[str, Any]:
    workspace_root = workspace_root.expanduser().resolve(strict=True)
    workspace_receipt_path = workspace_receipt_path.expanduser().resolve(strict=True)
    metadata_path = metadata_path.expanduser().resolve(strict=True)
    output_dir = output_dir.expanduser().resolve()
    if output_dir.exists() or output_dir.is_symlink():
        raise FileExistsError(f"refusing to overwrite output: {output_dir}")
    if output_dir.is_relative_to(workspace_root):
        raise ValueError("collection output must be outside the trial workspace")
    if len(expected_workspace_receipt_sha256) != 64 or any(
        char not in "0123456789abcdef" for char in expected_workspace_receipt_sha256
    ):
        raise ValueError("expected workspace receipt SHA256 is invalid")
    if _sha256(workspace_receipt_path) != expected_workspace_receipt_sha256:
        raise ValueError("workspace receipt disagrees with caller-provided trust anchor")

    workspace_receipt = _load(workspace_receipt_path)
    workspace_schema = _load(WORKSPACE_RECEIPT_SCHEMA)
    Draft202012Validator.check_schema(workspace_schema)
    Draft202012Validator(workspace_schema).validate(workspace_receipt)
    if (
        workspace_receipt.get("materializer_sha256") != _sha256(WORKSPACE_MATERIALIZER)
        or workspace_receipt.get("public_suite_verifier_sha256")
        != _sha256(PUBLIC_SUITE_VERIFIER)
        or workspace_receipt.get("receipt_schema_sha256")
        != _sha256(WORKSPACE_RECEIPT_SCHEMA)
    ):
        raise ValueError("workspace receipt source binding is stale")

    public_root = workspace_root / workspace_receipt["layout"]["public_root"]
    worktree_root = workspace_root / workspace_receipt["layout"]["worktree_root"]
    task = _load(public_root / "external_task.json")
    lock_path = public_root / "repo.lock"
    scope_path = public_root / "allowed_scope.json"
    lock = _load(lock_path)
    scope = _load(scope_path)
    task_id = workspace_receipt["task_id"]
    if (
        task.get("task_id") != task_id
        or lock.get("task_id") != task_id
        or scope.get("task_id") != task_id
        or task["submission_contract"]["editable_paths"]
        != workspace_receipt["layout"]["editable_paths"]
    ):
        raise ValueError("workspace receipt and public task contract disagree")

    projection_summary = workspace_receipt["repository_projection"]
    baseline: dict[str, bytes] = {}
    if projection_summary is None:
        if projection_archive is not None or projection_receipt is not None:
            raise ValueError("blank task must not receive a repository projection")
    else:
        if projection_archive is None or projection_receipt is None:
            raise ValueError("repository task requires its projection archive and receipt")
        workspace_module = _load_module(
            WORKSPACE_MATERIALIZER,
            "rtlflowbench_golden12_trial_workspace_for_collection",
        )
        baseline, projection_value = workspace_module._read_projection(
            archive_path=projection_archive,
            receipt_path=projection_receipt,
            repo_lock_path=lock_path,
            allowed_scope_path=scope_path,
        )
        if (
            projection_summary["archive_sha256"] != projection_value["archive_sha256"]
            or projection_summary["projection_digest"]
            != projection_value["projection_digest"]
            or projection_summary["receipt_sha256"] != _sha256(projection_receipt)
            or projection_summary["receipt_schema_version"]
            != projection_value["schema_version"]
            or projection_summary["projected_paths"] != sorted(baseline)
        ):
            raise ValueError("workspace and operator projection receipts disagree")

    public_files, public_dirs, public_issues = _scan_tree(public_root)
    scope_issues = [f"public {issue}" for issue in public_issues]
    public_digest = _tree_digest(public_files) if not public_issues else None
    expected_public_digest = workspace_receipt["public_suite"][
        "task_public_tree_sha256"
    ]
    if public_digest != expected_public_digest:
        scope_issues.append("public packet tree digest changed")
    expected_public_dirs = _expected_directories(set(public_files))
    if set(public_dirs) != expected_public_dirs:
        scope_issues.append("public packet directory set changed")
    for relative, path in public_files.items():
        if stat.S_IMODE(path.stat().st_mode) != 0o444:
            scope_issues.append(f"public file mode changed: {relative}")
    for relative, path in public_dirs.items():
        if stat.S_IMODE(path.stat().st_mode) != 0o555:
            scope_issues.append(f"public directory mode changed: {relative}")
    if stat.S_IMODE(public_root.stat().st_mode) != 0o555:
        scope_issues.append("public root mode changed")

    worktree_files, worktree_dirs, worktree_issues = _scan_tree(worktree_root)
    scope_issues.extend(f"worktree {issue}" for issue in worktree_issues)
    editable = set(task["submission_contract"]["editable_paths"])
    allowed_files = set(baseline) | editable
    unexpected_files = sorted(set(worktree_files) - allowed_files)
    if unexpected_files:
        scope_issues.append(
            "worktree contains files outside editable/baseline paths: "
            + ", ".join(unexpected_files)
        )
    missing_baseline = sorted(set(baseline) - set(worktree_files))
    if missing_baseline:
        scope_issues.append("worktree deleted baseline files: " + ", ".join(missing_baseline))
    expected_worktree_dirs = _expected_directories(allowed_files)
    unexpected_dirs = sorted(set(worktree_dirs) - expected_worktree_dirs)
    missing_dirs = sorted(expected_worktree_dirs - set(worktree_dirs))
    if unexpected_dirs:
        scope_issues.append(
            "worktree contains unexpected directories: " + ", ".join(unexpected_dirs)
        )
    if missing_dirs:
        scope_issues.append(
            "worktree deleted required directories: " + ", ".join(missing_dirs)
        )
    for relative, payload in sorted(baseline.items()):
        current = worktree_files.get(relative)
        if current is None:
            continue
        if relative not in editable and _sha256_bytes(payload) != _sha256(current):
            scope_issues.append(f"read-only repository file changed: {relative}")
    for relative, current in sorted(worktree_files.items()):
        if relative not in editable and stat.S_IMODE(current.stat().st_mode) != 0o444:
            scope_issues.append(f"read-only worktree file mode changed: {relative}")

    issues = sorted(set(scope_issues))
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{output_dir.name}-", dir=output_dir.parent))
    staging = temporary / "collection"
    staging.mkdir()
    base_receipt: dict[str, Any] = {
        "schema_version": "rtlflowbench.golden12_public_trial_submission_collection_receipt.v1",
        "observed_at": observed_at,
        "task_id": task_id,
        "workspace_receipt_sha256": expected_workspace_receipt_sha256,
        "public_tree_expected_sha256": expected_public_digest,
        "public_tree_observed_sha256": public_digest,
        "projection_archive_sha256": (
            projection_summary["archive_sha256"] if projection_summary is not None else None
        ),
        "scope": {
            "baseline_repository_file_count": len(baseline),
            "observed_worktree_file_count": len(worktree_files),
            "editable_path_count": len(editable),
            "issue_count": len(issues),
            "issues": issues,
        },
        "submission": None,
        "private_file_count": 0,
        "evaluation_performed": False,
        "readiness": {
            "benchmark_ready": False,
            "chipflow_adapter_ready": False,
            "publishable_score_permitted": False,
        },
        "collector_sha256": _sha256(Path(__file__)),
        "workspace_materializer_sha256": _sha256(WORKSPACE_MATERIALIZER),
        "neutral_submission_packager_sha256": _sha256(PACKAGE_SUBMISSION),
        "collection_receipt_schema_sha256": _sha256(COLLECTION_RECEIPT_SCHEMA),
        "excluded_claims": [
            "Submission collection and schema conformance are not RTL correctness or benchmark PASS.",
            "No private evaluator or hidden oracle ran during collection.",
            "This development trial is not admitted, scored, or publishable.",
        ],
    }
    try:
        if issues:
            receipt = {
                **base_receipt,
                "status": "scope_violation",
                "canonical_verdict": "scope_violation",
            }
            _write_receipt_output(output_dir=output_dir, receipt=receipt, staging=staging)
            return receipt

        bundle = staging / "bundle"
        bundle.mkdir()
        for relative in sorted(editable.intersection(worktree_files)):
            source = worktree_files[relative]
            target = bundle / _safe_relative(relative)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(source.read_bytes())
        metadata = _load(metadata_path)
        packager = _load_module(
            PACKAGE_SUBMISSION,
            "rtlflowbench_package_submission_for_golden12_trial_collection",
        )
        try:
            submission = packager.package_submission(
                task=task, metadata=metadata, bundle_root=bundle
            )
        except Exception as exc:
            shutil.rmtree(bundle)
            invalid_issue = f"submission contract rejected: {type(exc).__name__}: {exc}"
            receipt = {
                **base_receipt,
                "status": "invalid_submission",
                "canonical_verdict": "invalid_submission",
                "scope": {
                    **base_receipt["scope"],
                    "issue_count": 1,
                    "issues": [invalid_issue],
                },
            }
            _write_receipt_output(output_dir=output_dir, receipt=receipt, staging=staging)
            return receipt
        submission_path = staging / "submission.json"
        submission_path.write_text(
            json.dumps(submission, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        bundle_files, _, bundle_issues = _scan_tree(bundle)
        if bundle_issues:
            raise ValueError("collector produced an unsafe submission bundle")
        receipt = {
            **base_receipt,
            "status": "collected_not_evaluated",
            "canonical_verdict": None,
            "submission": {
                "submission_id": submission["submission_id"],
                "submission_sha256": _sha256(submission_path),
                "bundle_tree_sha256": _tree_digest(bundle_files),
                "artifact_file_count": len(bundle_files),
                "artifact_bytes": sum(path.stat().st_size for path in bundle_files.values()),
            },
        }
        _write_receipt_output(output_dir=output_dir, receipt=receipt, staging=staging)
        return receipt
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace-root", type=Path, required=True)
    parser.add_argument("--workspace-receipt", type=Path, required=True)
    parser.add_argument("--expected-workspace-receipt-sha256", required=True)
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--projection-archive", type=Path)
    parser.add_argument("--projection-receipt", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--observed-at", required=True)
    args = parser.parse_args()
    try:
        receipt = collect_public_trial_submission(
            workspace_root=args.workspace_root,
            workspace_receipt_path=args.workspace_receipt,
            expected_workspace_receipt_sha256=args.expected_workspace_receipt_sha256,
            metadata_path=args.metadata,
            projection_archive=args.projection_archive,
            projection_receipt=args.projection_receipt,
            output_dir=args.output_dir,
            observed_at=args.observed_at,
        )
    except Exception as exc:
        print(json.dumps({"status": "fail", "error": f"{type(exc).__name__}: {exc}"}, indent=2, sort_keys=True))
        return 2
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0 if receipt["status"] == "collected_not_evaluated" else 2


if __name__ == "__main__":
    raise SystemExit(main())
