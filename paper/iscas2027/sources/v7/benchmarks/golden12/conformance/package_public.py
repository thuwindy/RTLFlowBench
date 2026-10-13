#!/usr/bin/env python3
"""Build a deterministic public-only task archive.

The packager refuses symlinks, generated caches, non-regular entries and any
path outside the task's public directory.  It never traverses the sibling
private evaluator directory.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import tarfile
from pathlib import Path
from typing import Any


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_json_sha256(value: Any) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _content_manifest(
    public_root: Path,
    files: list[Path],
) -> list[dict[str, Any]]:
    return [
        {
            "path": path.relative_to(public_root).as_posix(),
            "bytes": path.stat().st_size,
            "sha256": _sha256(path),
        }
        for path in files
        if path.relative_to(public_root).as_posix() != "external_task.json"
    ]


def _public_files(task_root: Path) -> tuple[Path, list[Path]]:
    public_root = (task_root / "public").resolve()
    if not public_root.is_dir() or public_root.is_symlink():
        raise ValueError("task root must contain a regular public directory")
    files: list[Path] = []
    for path in sorted(public_root.rglob("*")):
        if path.is_symlink():
            raise ValueError(
                "public packet contains symlink: "
                f"{path.relative_to(public_root)}"
            )
        if path.is_dir():
            continue
        if not path.is_file():
            raise ValueError(
                "public packet contains a non-regular entry: "
                f"{path.relative_to(public_root)}"
            )
        if "__pycache__" in path.parts or path.suffix == ".pyc":
            raise ValueError(
                "public packet contains generated Python cache: "
                f"{path.relative_to(public_root)}"
            )
        if not path.resolve().is_relative_to(public_root):
            raise ValueError("public packet path escapes the public root")
        files.append(path)
    if not files:
        raise ValueError("public packet is empty")
    return public_root, files


def canonical_public_archive(
    task_root: Path,
) -> tuple[bytes, Path, list[Path]]:
    """Return the deterministic public packet bytes without writing a file."""

    task_root = task_root.expanduser().resolve()
    public_root, files = _public_files(task_root)
    task_id = json.loads(
        (public_root / "task.json").read_text(encoding="utf-8")
    )["task_id"]
    payload = io.BytesIO()
    with gzip.GzipFile(
        filename="",
        mode="wb",
        fileobj=payload,
        mtime=0,
    ) as gzip_stream:
        with tarfile.open(
            fileobj=gzip_stream,
            mode="w",
            format=tarfile.PAX_FORMAT,
        ) as archive:
            for path in files:
                relative = path.relative_to(public_root)
                archive_name = Path(task_id) / "public" / relative
                info = archive.gettarinfo(
                    str(path),
                    arcname=str(archive_name),
                )
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                info.mtime = 0
                info.mode = 0o644
                with path.open("rb") as source:
                    archive.addfile(info, source)
    return payload.getvalue(), public_root, files


def public_archive_sha256(task_root: Path) -> str:
    payload, _, _ = canonical_public_archive(task_root)
    return hashlib.sha256(payload).hexdigest()


def package_public_task(
    *,
    task_root: Path,
    archive_path: Path,
    receipt_path: Path | None = None,
) -> dict[str, Any]:
    task_root = task_root.expanduser().resolve()
    archive_payload, public_root, files = canonical_public_archive(task_root)
    task_id = json.loads(
        (public_root / "task.json").read_text(encoding="utf-8")
    )["task_id"]
    archive_path = archive_path.expanduser().resolve()
    if archive_path.exists():
        raise FileExistsError(f"refusing to overwrite archive: {archive_path}")
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    content_manifest = _content_manifest(public_root, files)

    with archive_path.open("xb") as raw_stream:
        raw_stream.write(archive_payload)

    receipt = {
        "schema_version": "rtlflowbench.public_packet_receipt.v1",
        "task_id": task_id,
        "status": "development_not_frozen",
        "archive_path": str(archive_path),
        "archive_sha256": _sha256(archive_path),
        "archive_bytes": archive_path.stat().st_size,
        "public_content_manifest_sha256": _canonical_json_sha256(
            content_manifest
        ),
        "public_content_manifest_excludes": ["external_task.json"],
        "public_files": [
            {
                "path": str(path.relative_to(public_root)),
                "bytes": path.stat().st_size,
                "sha256": _sha256(path),
            }
            for path in files
        ],
        "private_files_in_archive": 0,
        "excluded_claims": [
            "This development archive is not a frozen benchmark release.",
            "The task rights review and admission are still open.",
        ],
    }
    if receipt_path is not None:
        receipt_path = receipt_path.expanduser().resolve()
        if receipt_path.exists():
            raise FileExistsError(
                f"refusing to overwrite receipt: {receipt_path}"
            )
        receipt_path.parent.mkdir(parents=True, exist_ok=True)
        receipt_path.write_text(
            json.dumps(receipt, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--task-root", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--receipt", type=Path)
    args = parser.parse_args()
    try:
        receipt = package_public_task(
            task_root=args.task_root,
            archive_path=args.archive,
            receipt_path=args.receipt,
        )
    except Exception as exc:
        print(
            json.dumps(
                {
                    "schema_version": (
                        "rtlflowbench.public_packet_receipt.v1"
                    ),
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
