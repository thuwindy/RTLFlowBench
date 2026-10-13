#!/usr/bin/env python3
"""Build and verify deterministic public archives from candidate-bound files."""

from __future__ import annotations

import argparse
from datetime import datetime
import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


SCHEMA_RELATIVE = (
    "benchmarks/golden12/admission/public_release_archive_receipt.schema.json"
)


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _load(path: Path, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a regular non-symlink file: {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{label} must contain one JSON object")
    return value


def _parse_observed_at(value: str) -> None:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("--observed-at must include a timezone")


def _public_payload(
    *, repo_root: Path, task_id: str
) -> tuple[bytes, list[dict[str, Any]], dict[str, Any], str]:
    task_root = repo_root / "benchmarks/golden12/tasks" / task_id
    public_root = task_root / "public"
    lock_path = task_root / "private/admission/candidate.lock.json"
    lock = _load(lock_path, "candidate lock")
    if lock.get("task_id") != task_id:
        raise ValueError("candidate lock task id mismatch")
    components = lock.get("component_sha256")
    if not isinstance(components, dict) or not components:
        raise ValueError("candidate lock has no component digest map")
    if not public_root.is_dir() or public_root.is_symlink():
        raise ValueError("public task root must be a regular directory")
    all_entries = sorted(public_root.rglob("*"))
    if any(path.is_symlink() for path in all_entries):
        raise ValueError("public input packet contains a symlink")
    files = [path for path in all_entries if path.is_file()]
    if not files:
        raise ValueError("public input packet is empty")
    prefix = public_root.relative_to(repo_root).as_posix() + "/"
    locked_public = {
        relative: digest
        for relative, digest in components.items()
        if relative.startswith(prefix)
    }
    observed_paths = {path.relative_to(repo_root).as_posix() for path in files}
    if set(locked_public) != observed_paths:
        missing = sorted(observed_paths - set(locked_public))
        stale = sorted(set(locked_public) - observed_paths)
        raise ValueError(
            "candidate public component closure differs from the public tree: "
            f"missing={missing}, stale={stale}"
        )
    members: list[dict[str, Any]] = []
    archive_members: dict[str, bytes] = {}
    for path in files:
        component_path = path.relative_to(repo_root).as_posix()
        payload = path.read_bytes()
        digest = _sha256_bytes(payload)
        if locked_public[component_path] != digest:
            raise ValueError(f"candidate public component drift: {component_path}")
        member_path = "public/" + path.relative_to(public_root).as_posix()
        archive_members[member_path] = payload
        members.append({
            "path": member_path,
            "bytes": len(payload),
            "sha256": digest,
            "candidate_component_path": component_path,
        })
    plain = io.BytesIO()
    with tarfile.open(fileobj=plain, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name, payload in sorted(archive_members.items()):
            info = tarfile.TarInfo(name=name)
            info.size = len(payload)
            info.mode = 0o644
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mtime = 0
            archive.addfile(info, io.BytesIO(payload))
    compressed = io.BytesIO()
    with gzip.GzipFile(
        filename="", mode="wb", fileobj=compressed, mtime=0, compresslevel=9
    ) as output:
        output.write(plain.getvalue())
    return compressed.getvalue(), members, lock, _sha256(lock_path)


def verify_public_archive(
    *, repo_root: Path, task_id: str, archive_path: Path
) -> dict[str, Any]:
    repo_root = repo_root.expanduser().resolve(strict=True)
    archive_path = archive_path.expanduser().resolve(strict=True)
    if archive_path.is_symlink() or not archive_path.is_file():
        raise ValueError("public archive must be a regular non-symlink file")
    try:
        archive_path.relative_to(repo_root)
    except ValueError:
        pass
    else:
        raise ValueError("public archive must remain outside the repository")
    expected, members, lock, lock_sha256 = _public_payload(
        repo_root=repo_root, task_id=task_id
    )
    observed = archive_path.read_bytes()
    if observed != expected:
        raise ValueError("public archive is not the canonical candidate-bound payload")
    return {
        "archive_sha256": _sha256_bytes(observed),
        "archive_bytes": len(observed),
        "members": members,
        "candidate_release": lock["candidate_release"],
        "candidate_lock_sha256": lock_sha256,
    }


def build_public_release_archive(
    *, repo_root: Path, task_id: str, output_dir: Path, observed_at: str
) -> dict[str, Any]:
    _parse_observed_at(observed_at)
    repo_root = repo_root.expanduser().resolve(strict=True)
    output_dir = output_dir.expanduser().resolve()
    if output_dir.exists() or output_dir.is_symlink():
        raise FileExistsError(f"refusing to overwrite output: {output_dir}")
    try:
        output_dir.relative_to(repo_root)
    except ValueError:
        pass
    else:
        raise ValueError("public release archive output must remain outside the repository")
    payload, members, lock, lock_sha256 = _public_payload(
        repo_root=repo_root, task_id=task_id
    )
    output_dir.mkdir(parents=True)
    archive_path = output_dir / f"{task_id[:3].lower()}-public-input.tar.gz"
    archive_path.write_bytes(payload)
    builder_path = Path(__file__).resolve(strict=True)
    schema_path = repo_root / SCHEMA_RELATIVE
    receipt = {
        "schema_version": "rtlflowbench.public_release_archive_receipt.v1",
        "observed_at": observed_at,
        "task_id": task_id,
        "candidate_release": lock["candidate_release"],
        "candidate_lock_sha256": lock_sha256,
        "status": "candidate_component_closure_verified_not_released",
        "classification": "public_input_packet",
        "archive_format": "canonical_tar_gzip_v1",
        "archive_sha256": _sha256_bytes(payload),
        "archive_bytes": len(payload),
        "member_count": len(members),
        "members": members,
        "candidate_component_closure_complete": True,
        "contains_private_paths": False,
        "contains_symlinks": False,
        "benchmark_ready": False,
        "chipflow_adapter_ready": False,
        "source": {
            "builder_sha256": _sha256(builder_path),
            "schema_sha256": _sha256(schema_path),
        },
        "excluded_claims": [
            "A candidate-bound public archive is not independent benchmark admission.",
            "Public packaging does not expose evaluator-private assets.",
            "Public packaging does not establish ChipFlow adapter readiness.",
            "No AIRTL result, PPA, performance, human-level, or superhuman claim is made.",
        ],
    }
    schema = _load(schema_path, "public release archive receipt schema")
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(
        schema, format_checker=FormatChecker()
    ).validate(receipt)
    (output_dir / "receipt.json").write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--task-id", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--observed-at", required=True)
    args = parser.parse_args()
    try:
        result = build_public_release_archive(
            repo_root=args.repo_root,
            task_id=args.task_id,
            output_dir=args.output_dir,
            observed_at=args.observed_at,
        )
    except Exception as exc:
        print(json.dumps({"status": "invalid_evidence", "error": f"{type(exc).__name__}: {exc}"}, indent=2, sort_keys=True))
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
