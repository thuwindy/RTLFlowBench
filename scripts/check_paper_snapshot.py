#!/usr/bin/env python3
"""Offline guard for the published paper tree; requires only Python and local Git.

Develop outside paper/iscas2027. A future paper revision needs a new directory
and explicit provenance; do not move the published tag or silently relock it.
This checks source integrity, not runtime replay or RTL correctness.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import sys

BASE_COMMIT = "007f75a750bba155f90b976b5ed03293c7cf09d3"
BASE_TAG = "paper-source-20261013"
FROZEN_PATH = "paper/iscas2027"
GUIDANCE = (
    "Develop outside paper/iscas2027. Put a future paper revision in a new "
    "directory with explicit provenance; never silently relock this snapshot "
    "or move paper-source-20261013. Missing history/tag must be restored "
    "separately; this guard never fetches."
)


def git(root: Path, *args: str) -> bytes:
    # No shell, hooks, filters, replacement objects, inherited Git overrides,
    # credentials, or lazy partial-clone fetches are needed for these reads.
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update(
        GIT_CONFIG_NOSYSTEM="1",
        GIT_CONFIG_GLOBAL=os.devnull,
        GIT_NO_LAZY_FETCH="1",
        GIT_ALLOW_PROTOCOL="",
        GIT_TERMINAL_PROMPT="0",
    )
    result = subprocess.run(
        ["git", "--no-replace-objects", "-c", "core.fsmonitor=false", "-C", str(root), *args],
        env=env, capture_output=True, check=False, timeout=30,
    )
    if result.returncode:
        raise ValueError(f"local Git read failed: {args[0]} (required history/tag may be missing)")
    return result.stdout


def read_entries(data: bytes, *, index: bool = False) -> dict[str, tuple[str, str]]:
    entries = {}
    for entry in data.split(b"\0"):
        if not entry:
            continue
        metadata, raw_path = entry.split(b"\t", 1)
        first, second, third = metadata.decode("ascii").split()
        mode, oid = (first, second) if index else (first, third)
        path = os.fsdecode(raw_path)
        relative = PurePosixPath(path)
        if relative.is_absolute() or ".." in relative.parts or not path.startswith(FROZEN_PATH + "/"):
            raise ValueError("unsafe path in Git snapshot")
        if (index and third != "0") or (not index and second != "blob"):
            raise ValueError(f"unmerged or non-blob entry: {path}")
        if mode not in {"100644", "100755"}:
            raise ValueError(f"symlink or unsupported Git mode: {path}")
        if path in entries:
            raise ValueError(f"duplicate Git entry: {path}")
        entries[path] = (mode, oid)
    return entries


def incidental_file(path: Path) -> bool:
    """Only untracked OS metadata and bytecode are harmless additions."""
    return path.name == ".DS_Store" or (
        path.parent.name == "__pycache__" and path.suffix in {".pyc", ".pyo"}
    )


def check_snapshot(root: Path) -> dict:
    root = root.resolve()
    if Path(os.fsdecode(git(root, "rev-parse", "--show-toplevel")).strip()).resolve() != root:
        raise ValueError("run the guard against the repository root")
    commit = git(root, "rev-parse", "--verify", BASE_COMMIT + "^{commit}").decode().strip()
    tag = git(root, "rev-parse", "--verify", "refs/tags/" + BASE_TAG + "^{commit}").decode().strip()
    if commit != BASE_COMMIT or tag != BASE_COMMIT:
        raise ValueError("published tag does not resolve to the exact pinned commit")
    expected = read_entries(git(root, "ls-tree", "-rz", "--full-tree", BASE_COMMIT, "--", FROZEN_PATH))
    if not expected:
        raise ValueError("published commit has no frozen paper files")
    indexed = read_entries(git(root, "ls-files", "--stage", "-z", "--", FROZEN_PATH), index=True)
    errors = []
    for name in sorted(expected.keys() | indexed.keys()):
        if expected.get(name) != indexed.get(name):
            errors.append(f"index differs from published snapshot: {name}")

    # Inspect both ancestors before walking, so an intermediate symlink cannot
    # redirect the scan outside the checkout. Never follow directory symlinks.
    frozen = root
    for part in PurePosixPath(FROZEN_PATH).parts:
        frozen /= part
        if frozen.is_symlink() or not frozen.is_dir():
            raise ValueError("frozen directory is missing, a symlink, or not a directory")
    seen = set()
    pending = [frozen]
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as children:
            for child in children:
                path = Path(child.path)
                name = path.relative_to(root).as_posix()
                mode = child.stat(follow_symlinks=False).st_mode
                if stat.S_ISLNK(mode):
                    errors.append(f"symlink is forbidden: {name}")
                elif stat.S_ISDIR(mode):
                    pending.append(path)
                elif not stat.S_ISREG(mode):
                    errors.append(f"non-regular file is forbidden: {name}")
                elif name not in expected:
                    if not incidental_file(path):
                        errors.append(f"unexpected file: {name}")
                else:
                    seen.add(name)
                    data = path.read_bytes()
                    # Hash raw bytes, without applying Git clean/smudge filters.
                    oid = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data, usedforsecurity=False).hexdigest()
                    file_mode = "100755" if mode & 0o111 else "100644"
                    if (file_mode, oid) != expected[name]:
                        errors.append(f"bytes or executable mode changed: {name}")
    errors.extend(f"missing published file: {name}" for name in sorted(expected.keys() - seen))
    return {
        "status": "FAIL" if errors else "PASS",
        "scope": "published paper source integrity only; no model, EDA, or runtime replay",
        "base_commit": BASE_COMMIT,
        "base_tag": BASE_TAG,
        "frozen_path": FROZEN_PATH,
        "files_checked": len(seen),
        "error_count": len(errors),
        "errors": sorted(errors)[:20],
        "guidance": GUIDANCE,
    }


def main() -> int:
    try:
        report = check_snapshot(Path(__file__).resolve().parents[1])
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        report = {"status": "FAIL", "errors": [str(exc)], "guidance": GUIDANCE}
    print(json.dumps(report, indent=2))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
