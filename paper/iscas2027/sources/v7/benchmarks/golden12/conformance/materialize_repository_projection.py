#!/usr/bin/env python3
"""Materialize a deterministic, allowlisted repository-base projection."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import shutil
import tarfile
import tempfile
from typing import Any


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _sha256(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _load(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain one JSON object")
    return payload


def _safe_relative(value: str) -> Path:
    pure = PurePosixPath(value)
    if pure.is_absolute() or not pure.parts or ".." in pure.parts:
        raise ValueError(f"unsafe repository projection path: {value}")
    return Path(*pure.parts)


def _under_prefix(path: str, prefix: str) -> bool:
    normalized = prefix.rstrip("/")
    return path == normalized or path.startswith(normalized + "/")


def _deterministic_archive(members: dict[str, bytes]) -> bytes:
    tar_stream = io.BytesIO()
    with tarfile.open(
        fileobj=tar_stream,
        mode="w",
        format=tarfile.PAX_FORMAT,
    ) as archive:
        for name, payload in sorted(members.items()):
            info = tarfile.TarInfo(name=name)
            info.size = len(payload)
            info.mode = 0o444
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            info.mtime = 0
            archive.addfile(info, io.BytesIO(payload))
    compressed = io.BytesIO()
    with gzip.GzipFile(
        filename="",
        mode="wb",
        fileobj=compressed,
        compresslevel=9,
        mtime=0,
    ) as output:
        output.write(tar_stream.getvalue())
    return compressed.getvalue()


def materialize_projection(
    *,
    repo_lock_path: Path,
    source_tree: Path,
    source_intake_path: Path,
    output_dir: Path,
    observed_at: str,
) -> dict[str, Any]:
    repo_lock_path = repo_lock_path.expanduser().resolve()
    source_tree = source_tree.expanduser().resolve()
    source_intake_path = source_intake_path.expanduser().resolve()
    output_dir = output_dir.expanduser().resolve()
    if output_dir.exists():
        raise FileExistsError(f"refusing to overwrite output: {output_dir}")

    lock = _load(repo_lock_path)
    intake = _load(source_intake_path)
    if lock.get("agent_source_mode") != "repository_base":
        raise ValueError("repository projection requires repository_base mode")
    if lock.get("repository_projection_status") not in {
        "planned_not_materialized",
        "development_materialized_not_frozen",
    }:
        raise ValueError(
            "repository projection status is not a development state"
        )
    if intake != {
        "schema": "chipflow.golden12.source_intake.v1",
        "source_id": lock["source_id"],
        "archive_sha256": lock["source_archive_sha256"],
        "archive_file": "archive.tar.gz",
        "source_tree": "source",
        "hidden_evaluator_materialized": False,
    }:
        raise ValueError("source intake does not match the repository lock")
    if source_intake_path.parent / intake["source_tree"] != source_tree:
        raise ValueError("source tree is not the tree bound by source intake")
    archive_path = source_intake_path.parent / intake["archive_file"]
    if (
        archive_path.is_symlink()
        or not archive_path.is_file()
        or _sha256(archive_path) != lock["source_archive_sha256"]
    ):
        raise ValueError("content-addressed source archive is missing or drifted")
    if source_tree.is_symlink() or not source_tree.is_dir():
        raise ValueError("source tree must be a regular directory")

    allowlist = lock.get("repository_projection_allowlist")
    notices = lock.get("required_notice_paths")
    excluded = lock.get("excluded_repository_paths", [])
    if (
        not isinstance(allowlist, list)
        or not allowlist
        or len(allowlist) != len(set(allowlist))
    ):
        raise ValueError("repository projection allowlist must be non-empty and unique")
    if (
        not isinstance(notices, list)
        or not notices
        or not set(notices).issubset(allowlist)
    ):
        raise ValueError("required license notices must be present in the allowlist")

    members: dict[str, bytes] = {}
    entries = []
    for relative in sorted(allowlist):
        safe = _safe_relative(relative)
        if any(_under_prefix(relative, prefix) for prefix in excluded):
            raise ValueError(
                f"allowlisted path overlaps an excluded path: {relative}"
            )
        source = source_tree / safe
        if source.is_symlink() or not source.is_file():
            raise ValueError(
                f"allowlisted source is not a regular file: {relative}"
            )
        if source.stat().st_mode & 0o222:
            raise ValueError(
                f"content-addressed source is writable: {relative}"
            )
        payload = source.read_bytes()
        members[relative] = payload
        entries.append(
            {
                "path": relative,
                "bytes": len(payload),
                "sha256": _sha256_bytes(payload),
                "role": (
                    "license_notice"
                    if relative in notices
                    else "read_only_repository_dependency"
                ),
            }
        )

    archive_payload = _deterministic_archive(members)
    manifest = {
        "schema_version": "rtlflowbench.repository_projection_manifest.v1",
        "task_id": lock["task_id"],
        "source_id": lock["source_id"],
        "source_archive_sha256": lock["source_archive_sha256"],
        "status": "development_projection_not_frozen",
        "entries": entries,
        "excluded_repository_paths": excluded,
        "contains_evaluator_assets": False,
        "workflow_files_writable": False,
    }
    manifest_payload = (
        json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    ).encode()
    projection_digest = _sha256_bytes(
        json.dumps(entries, separators=(",", ":"), sort_keys=True).encode()
    )
    receipt = {
        "schema_version": "rtlflowbench.repository_projection_receipt.v1",
        "task_id": lock["task_id"],
        "observed_at": observed_at,
        "status": "development_projection_not_frozen",
        "source_id": lock["source_id"],
        "source_archive_sha256": lock["source_archive_sha256"],
        "repo_lock_sha256": _sha256(repo_lock_path),
        "archive_sha256": _sha256_bytes(archive_payload),
        "archive_bytes": len(archive_payload),
        "manifest_sha256": _sha256_bytes(manifest_payload),
        "projection_digest": projection_digest,
        "projected_file_count": len(entries),
        "projected_paths": [entry["path"] for entry in entries],
        "required_notice_paths": notices,
        "contains_evaluator_assets": False,
        "workflow_files_writable": False,
        "redistribution_review_complete": False,
        "excluded_claims": [
            "Projection construction is not an independent rights review.",
            "This development archive is not a frozen public release.",
            "No RTL workflow, simulation, coverage, performance, or PPA result is claimed.",
        ],
    }

    output_dir.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(
        tempfile.mkdtemp(
            prefix=f".{output_dir.name}-",
            dir=output_dir.parent,
        )
    )
    try:
        (temporary / "repository-projection.tar.gz").write_bytes(
            archive_payload
        )
        (temporary / "projection_manifest.json").write_bytes(
            manifest_payload
        )
        (temporary / "projection_receipt.json").write_text(
            json.dumps(receipt, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        temporary.replace(output_dir)
    except Exception:
        if temporary.exists():
            shutil.rmtree(temporary)
        raise
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-lock", type=Path, required=True)
    parser.add_argument("--source-tree", type=Path, required=True)
    parser.add_argument("--source-intake", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--observed-at", required=True)
    args = parser.parse_args()
    try:
        receipt = materialize_projection(
            repo_lock_path=args.repo_lock,
            source_tree=args.source_tree,
            source_intake_path=args.source_intake,
            output_dir=args.output_dir,
            observed_at=args.observed_at,
        )
    except Exception as exc:
        print(
            json.dumps(
                {
                    "status": "fail",
                    "error": f"{type(exc).__name__}: {exc}",
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 2
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
