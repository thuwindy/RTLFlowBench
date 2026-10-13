#!/usr/bin/env python3
"""Bind an external workflow source tree to a reviewed Git or snapshot identity."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
from typing import Any


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _snapshot_entries(source: Path) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for path in sorted(source.rglob("*"), key=lambda item: item.relative_to(source).as_posix()):
        if path.is_dir() and not path.is_symlink():
            continue
        relative = path.relative_to(source).as_posix()
        if path.is_symlink():
            target = os.readlink(path)
            entries.append(
                {
                    "path": relative,
                    "type": "symlink",
                    "target": target,
                    "sha256": _sha256_bytes(target.encode("utf-8")),
                }
            )
        elif path.is_file():
            entries.append(
                {
                    "path": relative,
                    "type": "file",
                    "bytes": path.stat().st_size,
                    "sha256": _sha256_bytes(path.read_bytes()),
                }
            )
        else:
            raise ValueError(f"unsupported source snapshot entry: {relative}")
    return entries


def _tracked_manifest_sha256(entries: list[dict[str, Any]]) -> str:
    digest = hashlib.sha256()
    for item in entries:
        digest.update(
            f"{item['sha256']}  {item['type']}  {item['path']}\n".encode("utf-8")
        )
    return digest.hexdigest()


def _bind_snapshot(
    source: Path,
    *,
    expected_commit: str,
    expected_manifest_sha256: str,
    manifest_path: Path,
) -> None:
    unresolved = manifest_path.expanduser().absolute()
    if unresolved.is_symlink() or not unresolved.is_file():
        raise ValueError("source snapshot manifest must be a regular file")
    manifest = json.loads(unresolved.read_text(encoding="utf-8"))
    if manifest.get("schema_version") != "rtlflowbench.source_snapshot.v1":
        raise ValueError("source snapshot manifest schema is unsupported")
    if manifest.get("commit") != expected_commit:
        raise ValueError("source snapshot commit drift")
    if manifest.get("tracked_manifest_sha256") != expected_manifest_sha256:
        raise ValueError("source snapshot tracked manifest drift")
    entries = _snapshot_entries(source)
    if manifest.get("entries") != entries:
        raise ValueError("source snapshot file set or content drift")
    if _tracked_manifest_sha256(entries) != expected_manifest_sha256:
        raise ValueError("source snapshot aggregate digest drift")


def bind_source(
    source_root: Path,
    *,
    expected_commit: str,
    expected_manifest_sha256: str,
    snapshot_manifest: Path | None,
) -> Path:
    """Return the resolved source only after one exact source identity passes."""
    if not COMMIT_RE.fullmatch(expected_commit):
        raise ValueError("reviewed source commit is invalid")
    if not SHA256_RE.fullmatch(expected_manifest_sha256):
        raise ValueError("reviewed source manifest digest is invalid")
    unresolved = source_root.expanduser().absolute()
    if unresolved.is_symlink() or not unresolved.is_dir():
        raise ValueError("workflow source must be a regular directory")
    source = unresolved.resolve(strict=True)
    git = shutil.which("git")
    if (source / ".git").exists() and git is not None:
        head = subprocess.run(
            [git, "rev-parse", "HEAD"],
            cwd=source,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        status = subprocess.run(
            [git, "status", "--porcelain=v1", "--untracked-files=all"],
            cwd=source,
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        if head != expected_commit or status:
            raise ValueError("workflow source HEAD or clean status drift")
        return source
    if snapshot_manifest is None:
        raise ValueError("content-only workflow source requires a snapshot manifest")
    _bind_snapshot(
        source,
        expected_commit=expected_commit,
        expected_manifest_sha256=expected_manifest_sha256,
        manifest_path=snapshot_manifest,
    )
    return source
