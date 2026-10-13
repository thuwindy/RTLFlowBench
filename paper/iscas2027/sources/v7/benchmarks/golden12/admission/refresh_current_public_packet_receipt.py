#!/usr/bin/env python3
"""Refresh G01/G02 public-packet reproduction receipts without freezing them."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


SUPPORTED = {
    "G01-common-fifo-spec": {
        "schema_version": "rtlflowbench.public_packet_cross_environment_receipt.v1",
        "status": "development_reproducible_not_frozen",
    },
    "G02-common-rr-arbiter-spec": {
        "schema_version": "rtlflowbench.g02_public_package_receipt.v1",
        "status": "server_byte_reproducible_not_frozen",
    },
}


def _sha256(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"expected regular non-symlink file: {path}")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load(path: Path, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a regular non-symlink file: {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{label} must contain one JSON object")
    return value


def _sanitized(value: str) -> str:
    if "/home/" in value or "/Users/" in value:
        raise ValueError("evidence root exposes a private host path")
    return value


def _git_output(root: Path, *args: str) -> bytes:
    completed = subprocess.run(
        ["git", "-C", str(root), *args],
        check=False,
        capture_output=True,
    )
    if completed.returncode != 0:
        raise ValueError(f"git {' '.join(args)} failed")
    return completed.stdout


def _authority(root: Path) -> dict[str, Any]:
    root = root.resolve(strict=True)
    status = _git_output(
        root, "status", "--porcelain=v1", "--untracked-files=all"
    )
    return {
        "head": _git_output(root, "rev-parse", "HEAD").decode().strip(),
        "status_sha256": hashlib.sha256(status).hexdigest(),
        "status_item_count": len(status.splitlines()),
    }


def _run(root: Path, task_id: str) -> tuple[dict[str, Any], Path]:
    root = root.resolve(strict=True)
    receipt_path = root / "public_receipt.json"
    receipt = _load(receipt_path, "public packet build receipt")
    archives = list(root.glob("*.tar.gz"))
    if len(archives) != 1:
        raise ValueError(f"expected exactly one public archive: {root}")
    archive = archives[0]
    if (
        receipt.get("schema_version") != "rtlflowbench.public_packet_receipt.v1"
        or receipt.get("task_id") != task_id
        or receipt.get("status") != "development_not_frozen"
        or receipt.get("archive_sha256") != _sha256(archive)
        or receipt.get("archive_bytes") != archive.stat().st_size
        or receipt.get("private_files_in_archive") != 0
    ):
        raise ValueError("public packet build receipt is inconsistent")
    return receipt, archive


def refresh(
    *,
    repo_root: Path,
    task_id: str,
    prior_receipt_path: Path,
    run_a_root: Path,
    run_b_root: Path,
    run_a_evidence_root: str,
    run_b_evidence_root: str,
    prior_receipt_evidence_root: str,
    authority_root: Path,
    expected_authority_head: str,
    expected_authority_status_sha256: str,
    observed_at: str,
) -> dict[str, Any]:
    if task_id not in SUPPORTED:
        raise ValueError(f"unsupported public packet task: {task_id}")
    repo_root = repo_root.resolve(strict=True)
    run_a_evidence_root = _sanitized(run_a_evidence_root)
    run_b_evidence_root = _sanitized(run_b_evidence_root)
    prior_receipt_evidence_root = _sanitized(prior_receipt_evidence_root)
    prior = _load(prior_receipt_path.resolve(strict=True), "prior receipt")
    config = SUPPORTED[task_id]
    if (
        prior.get("task_id") != task_id
        or prior.get("schema_version") != config["schema_version"]
        or prior.get("status") != config["status"]
    ):
        raise ValueError("prior public packet receipt is incompatible")
    run_a, archive_a = _run(run_a_root, task_id)
    run_b, archive_b = _run(run_b_root, task_id)
    comparable = (
        "archive_sha256",
        "archive_bytes",
        "public_content_manifest_sha256",
        "public_files",
        "private_files_in_archive",
    )
    if any(run_a.get(key) != run_b.get(key) for key in comparable):
        raise ValueError("public packet builds are not semantically identical")
    if archive_a.read_bytes() != archive_b.read_bytes():
        raise ValueError("public packet archives are not byte-identical")
    authority = _authority(authority_root)
    if authority["head"] != expected_authority_head:
        raise ValueError("authority HEAD drift")
    if authority["status_sha256"] != expected_authority_status_sha256:
        raise ValueError("authority status drift")

    if task_id == "G01-common-fifo-spec":
        previous = {
            "archive_bytes": prior["archive_bytes"],
            "archive_sha256": prior["archive_sha256"],
            "observed_at": prior["observed_at"],
            "reason": (
                "Preserved before adding the workflow-neutral visible runner "
                "contract to the public packet."
            ),
            "receipt_sha256": _sha256(prior_receipt_path),
            "receipt_evidence_root": prior_receipt_evidence_root,
        }
        history = [previous, *prior.get("superseded_archives", [])]
        seen: set[str] = set()
        history = [
            item
            for item in history
            if isinstance(item.get("archive_sha256"), str)
            and not (
                item["archive_sha256"] in seen
                or seen.add(item["archive_sha256"])
            )
        ]
        result = {
            "schema_version": config["schema_version"],
            "task_id": task_id,
            "observed_at": observed_at,
            "status": config["status"],
            "archive_sha256": run_a["archive_sha256"],
            "archive_bytes": run_a["archive_bytes"],
            "public_file_count": len(run_a["public_files"]),
            "private_files_in_archive": 0,
            "observations": [
                {
                    "environment_id": "server26-development-a",
                    "evidence_root": run_a_evidence_root,
                    "receipt_sha256": _sha256(
                        run_a_root / "public_receipt.json"
                    ),
                },
                {
                    "environment_id": "server26-development-b",
                    "evidence_root": run_b_evidence_root,
                    "receipt_sha256": _sha256(
                        run_b_root / "public_receipt.json"
                    ),
                },
            ],
            "admission_impact": {
                "public_private_packaging_verified": True,
                "packet_frozen": False,
                "benchmark_ready": False,
            },
            "remaining_blockers": [
                "Independent rights and specification review are unsigned.",
                "The current public packet digest is reproducible but not independently frozen.",
                "Runner, environment, budget, scoring, and final admission remain pending.",
            ],
            "superseded_archive": previous,
            "superseded_archives": history,
        }
    else:
        previous = {
            "archive_bytes": prior["archive_bytes"],
            "archive_sha256": prior["archive_sha256"],
            "reason": (
                "Preserved before adding the workflow-neutral visible runner "
                "contract to the public packet."
            ),
            "receipt_sha256": _sha256(prior_receipt_path),
            "receipt_evidence_root": prior_receipt_evidence_root,
        }
        result = json.loads(json.dumps(prior))
        result.update(
            {
                "observed_at": observed_at,
                "archive_sha256": run_a["archive_sha256"],
                "archive_bytes": run_a["archive_bytes"],
                "archive_bytes_identical": True,
                "public_file_count": len(run_a["public_files"]),
                "private_files_in_archive": 0,
                "packager_source_sha256": _sha256(
                    repo_root
                    / "benchmarks/golden12/conformance/package_public.py"
                ),
                "authority_guard": {
                    "status": "pass",
                    "head_before_after": authority["head"],
                    "porcelain_sha256_before_after": authority[
                        "status_sha256"
                    ],
                },
                "runs": [
                    {
                        "run_id": "server-a",
                        "environment_id": "server26-development",
                        "evidence_root": run_a_evidence_root,
                        "receipt_sha256": _sha256(
                            run_a_root / "public_receipt.json"
                        ),
                    },
                    {
                        "run_id": "server-b",
                        "environment_id": "server26-development",
                        "evidence_root": run_b_evidence_root,
                        "receipt_sha256": _sha256(
                            run_b_root / "public_receipt.json"
                        ),
                    },
                ],
                "superseded_packages": [
                    previous,
                    *prior.get("superseded_packages", []),
                ],
            }
        )
        schema_path = prior_receipt_path.with_suffix(".schema.json")
        if schema_path.exists():
            schema = _load(schema_path, "G02 public package schema")
            Draft202012Validator.check_schema(schema)
            Draft202012Validator(
                schema,
                format_checker=FormatChecker(),
            ).validate(result)
    serialized = json.dumps(result, sort_keys=True)
    if "/home/" in serialized or "/Users/" in serialized:
        raise ValueError("refreshed public receipt exposes a private host path")
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--task-id", required=True)
    parser.add_argument("--prior-receipt", type=Path, required=True)
    parser.add_argument("--run-a-root", type=Path, required=True)
    parser.add_argument("--run-b-root", type=Path, required=True)
    parser.add_argument("--run-a-evidence-root", required=True)
    parser.add_argument("--run-b-evidence-root", required=True)
    parser.add_argument("--prior-receipt-evidence-root", required=True)
    parser.add_argument("--authority-root", type=Path, required=True)
    parser.add_argument("--expected-authority-head", required=True)
    parser.add_argument("--expected-authority-status-sha256", required=True)
    parser.add_argument("--observed-at", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists() or args.output.is_symlink():
        raise FileExistsError(f"refusing existing output: {args.output}")
    result = refresh(
        repo_root=args.repo_root,
        task_id=args.task_id,
        prior_receipt_path=args.prior_receipt,
        run_a_root=args.run_a_root,
        run_b_root=args.run_b_root,
        run_a_evidence_root=args.run_a_evidence_root,
        run_b_evidence_root=args.run_b_evidence_root,
        prior_receipt_evidence_root=args.prior_receipt_evidence_root,
        authority_root=args.authority_root,
        expected_authority_head=args.expected_authority_head,
        expected_authority_status_sha256=(
            args.expected_authority_status_sha256
        ),
        observed_at=args.observed_at,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
