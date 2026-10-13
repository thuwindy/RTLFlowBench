#!/usr/bin/env python3
"""Export one clean reviewed Git commit as a content-addressed runtime snapshot."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile

from source_snapshot_binding import _snapshot_entries, _tracked_manifest_sha256


def _extract_git_archive(archive: Path, output: Path) -> None:
    """Extract only archive-relative members while preserving reviewed links."""
    with tarfile.open(archive, "r:") as handle:
        for member in handle.getmembers():
            relative = Path(member.name)
            if relative.is_absolute() or ".." in relative.parts:
                raise ValueError("Git archive contains an unsafe member path")
            target = output / relative
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            elif member.isfile():
                target.parent.mkdir(parents=True, exist_ok=True)
                source = handle.extractfile(member)
                if source is None:
                    raise ValueError("Git archive regular file has no payload")
                target.write_bytes(source.read())
                target.chmod(member.mode & 0o777)
            elif member.issym():
                target.parent.mkdir(parents=True, exist_ok=True)
                target.symlink_to(member.linkname)
            else:
                raise ValueError("Git archive contains an unsupported entry type")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--expected-manifest-sha256", required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    source = args.source_root.expanduser().resolve(strict=True)
    output = args.output_root.expanduser().absolute()
    if output.exists() or output.is_symlink():
        raise FileExistsError("refusing to overwrite runtime source snapshot")
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=source, check=True, capture_output=True, text=True
    ).stdout.strip()
    status = subprocess.run(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=source,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    if head != args.expected_commit or status:
        raise ValueError("source HEAD or clean status drift")
    output.mkdir(parents=True)
    exported = output / "source"
    exported.mkdir()
    with tempfile.TemporaryDirectory(dir=output.parent) as temporary:
        archive = Path(temporary) / "source.tar"
        subprocess.run(
            ["git", "archive", "--format=tar", "-o", str(archive), "HEAD"],
            cwd=source,
            check=True,
        )
        _extract_git_archive(archive, exported)
    entries = _snapshot_entries(exported)
    observed = _tracked_manifest_sha256(entries)
    if observed != args.expected_manifest_sha256:
        raise ValueError("exported source manifest disagrees with reviewed source")
    manifest = {
        "schema_version": "rtlflowbench.source_snapshot.v1",
        "commit": args.expected_commit,
        "tracked_manifest_sha256": observed,
        "entry_count": len(entries),
        "entries": entries,
    }
    (output / "source_snapshot.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps({"commit": head, "manifest_sha256": observed, "entry_count": len(entries)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
