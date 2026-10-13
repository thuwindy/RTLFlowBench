#!/usr/bin/env python3
"""Build a source-bound SERVER26 receipt for two public-suite reproductions."""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
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
ADMISSION_ROOT = Path("benchmarks/golden12/admission")
SOURCE_PATHS = {
    "builder": ADMISSION_ROOT / "build_public_suite_candidate.py",
    "verifier": ADMISSION_ROOT / "verify_public_suite_candidate.py",
    "candidate_receipt_schema": (
        ADMISSION_ROOT / "public_suite_candidate_receipt.schema.json"
    ),
    "verification_receipt_schema": (
        ADMISSION_ROOT / "public_suite_verification_receipt.schema.json"
    ),
    "suite_schema": ADMISSION_ROOT / "public_suite_descriptor.schema.json",
    "manifest_schema": ADMISSION_ROOT / "public_suite_manifest.schema.json",
    "targeted_test": (
        Path("backend/tests")
        / "test_chipflow_golden12_public_suite_candidate.py"
    ),
}
SERVER_SCHEMA_PATH = (
    Path("docs/chipflow/research/golden12")
    / "protocol_public_suite_candidate_server_receipt.schema.json"
)
ARCHIVE_NAME = "rtlflowbench-golden12-public-candidate.tar.gz"
EVIDENCE_ID_RE = re.compile(
    r"^golden12-public-suite-server-reproduction-[a-z0-9-]+$"
)


def _sha256(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"expected regular non-symlink file: {path}")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical_json(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def _load(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"expected regular non-symlink JSON file: {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected one JSON object: {path}")
    return value


def _parse_observed_at(value: str) -> None:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("--observed-at must include a timezone")


def _read_exit_code(path: Path, label: str) -> int:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"missing {label} exit-code evidence: {path}")
    value = int(path.read_text(encoding="utf-8").strip())
    if value != 0:
        raise ValueError(f"{label} did not complete successfully: exit {value}")
    return value


def _validate_external(repo_root: Path, path: Path, label: str) -> Path:
    resolved = path.expanduser().resolve(strict=True)
    if resolved.is_symlink() or not resolved.is_dir():
        raise ValueError(f"{label} must be a regular directory")
    if resolved.is_relative_to(repo_root):
        raise ValueError(f"{label} must remain outside the repository")
    return resolved


def _schemas(repo_root: Path) -> tuple[dict[str, Any], ...]:
    paths = (
        SOURCE_PATHS["candidate_receipt_schema"],
        SOURCE_PATHS["verification_receipt_schema"],
        SOURCE_PATHS["suite_schema"],
        SOURCE_PATHS["manifest_schema"],
        SERVER_SCHEMA_PATH,
    )
    schemas = tuple(_load(repo_root / path) for path in paths)
    for schema in schemas:
        Draft202012Validator.check_schema(schema)
    return schemas


def _candidate_lock_sha256(repo_root: Path) -> dict[str, str]:
    return {
        task_id: _sha256(
            repo_root
            / "benchmarks/golden12/tasks"
            / task_id
            / "private/admission/candidate.lock.json"
        )
        for task_id in TASK_IDS
    }


def _build_run(
    *,
    root: Path,
    candidate_schema: dict[str, Any],
    suite_schema: dict[str, Any],
    manifest_schema: dict[str, Any],
    current_locks: dict[str, str],
) -> dict[str, Any]:
    archive = root / ARCHIVE_NAME
    receipt_path = root / "receipt.json"
    suite_path = root / "suite.json"
    manifest_path = root / "manifest.json"
    receipt = _load(receipt_path)
    suite = _load(suite_path)
    manifest = _load(manifest_path)
    Draft202012Validator(
        candidate_schema, format_checker=FormatChecker()
    ).validate(receipt)
    Draft202012Validator(suite_schema, format_checker=FormatChecker()).validate(
        suite
    )
    Draft202012Validator(
        manifest_schema, format_checker=FormatChecker()
    ).validate(manifest)
    observed = {
        "archive_sha256": _sha256(archive),
        "builder_receipt_sha256": _sha256(receipt_path),
        "manifest_sha256": _sha256(manifest_path),
        "suite_descriptor_sha256": _sha256(suite_path),
    }
    for receipt_key, observed_key in (
        ("archive_sha256", "archive_sha256"),
        ("manifest_sha256", "manifest_sha256"),
        ("suite_descriptor_sha256", "suite_descriptor_sha256"),
    ):
        if receipt.get(receipt_key) != observed[observed_key]:
            raise ValueError(f"public-suite builder receipt drift: {receipt_key}")
    if (
        receipt.get("status")
        != "development_public_suite_candidate_not_released"
        or receipt.get("candidate_lock_sha256") != current_locks
        or receipt.get("task_count") != 12
        or receipt.get("private_file_count") != 0
        or receipt.get("benchmark_ready_task_count") != 0
        or receipt.get("chipflow_adapter_ready_task_count") != 0
        or receipt.get("protocol_ready") is not False
        or receipt.get("suite_ready") is not False
        or receipt.get("publishable_score_permitted") is not False
    ):
        raise ValueError("public-suite builder receipt is unsafe or stale")
    return {**observed, "receipt": receipt}


def _verification_run(
    *,
    root: Path,
    verification_schema: dict[str, Any],
    build: dict[str, Any],
    current_locks: dict[str, str],
) -> dict[str, Any]:
    receipt_path = root / "verification_receipt.json"
    receipt = _load(receipt_path)
    Draft202012Validator(
        verification_schema, format_checker=FormatChecker()
    ).validate(receipt)
    observed_sha256 = _sha256(receipt_path)
    if (
        receipt.get("status") != "verified_development_candidate_not_released"
        or receipt.get("archive_sha256") != build["archive_sha256"]
        or receipt.get("manifest_sha256") != build["manifest_sha256"]
        or receipt.get("suite_descriptor_sha256")
        != build["suite_descriptor_sha256"]
        or receipt.get("candidate_lock_sha256") != current_locks
        or receipt.get("private_file_count") != 0
        or receipt.get("benchmark_ready_task_count") != 0
        or receipt.get("chipflow_adapter_ready_task_count") != 0
        or receipt.get("protocol_ready") is not False
        or receipt.get("suite_ready") is not False
        or receipt.get("publishable_score_permitted") is not False
        or receipt.get("extraction_performed") is not True
    ):
        raise ValueError("public-suite verification receipt is unsafe or stale")
    return {"verification_receipt_sha256": observed_sha256, "receipt": receipt}


def build_server_receipt(
    *,
    repo_root: Path,
    build_a_root: Path,
    build_b_root: Path,
    verify_a_root: Path,
    verify_b_root: Path,
    build_a_exit_code: Path,
    build_b_exit_code: Path,
    verify_a_exit_code: Path,
    verify_b_exit_code: Path,
    evidence_id: str,
    observed_at: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    repo_root = repo_root.expanduser().resolve(strict=True)
    _parse_observed_at(observed_at)
    if not EVIDENCE_ID_RE.fullmatch(evidence_id):
        raise ValueError("invalid public-suite server evidence id")
    build_a_root = _validate_external(repo_root, build_a_root, "build A root")
    build_b_root = _validate_external(repo_root, build_b_root, "build B root")
    verify_a_root = _validate_external(repo_root, verify_a_root, "verify A root")
    verify_b_root = _validate_external(repo_root, verify_b_root, "verify B root")
    exit_codes = {
        "run_a_exit_code": _read_exit_code(build_a_exit_code, "build A"),
        "run_b_exit_code": _read_exit_code(build_b_exit_code, "build B"),
        "verification_a_exit_code": _read_exit_code(
            verify_a_exit_code, "verification A"
        ),
        "verification_b_exit_code": _read_exit_code(
            verify_b_exit_code, "verification B"
        ),
    }
    (
        candidate_schema,
        verification_schema,
        suite_schema,
        manifest_schema,
        server_schema,
    ) = _schemas(repo_root)
    current_locks = _candidate_lock_sha256(repo_root)
    build_a = _build_run(
        root=build_a_root,
        candidate_schema=candidate_schema,
        suite_schema=suite_schema,
        manifest_schema=manifest_schema,
        current_locks=current_locks,
    )
    build_b = _build_run(
        root=build_b_root,
        candidate_schema=candidate_schema,
        suite_schema=suite_schema,
        manifest_schema=manifest_schema,
        current_locks=current_locks,
    )
    verify_a = _verification_run(
        root=verify_a_root,
        verification_schema=verification_schema,
        build=build_a,
        current_locks=current_locks,
    )
    verify_b = _verification_run(
        root=verify_b_root,
        verification_schema=verification_schema,
        build=build_b,
        current_locks=current_locks,
    )
    for key in (
        "archive_sha256",
        "builder_receipt_sha256",
        "manifest_sha256",
        "suite_descriptor_sha256",
    ):
        if build_a[key] != build_b[key]:
            raise ValueError(f"public-suite builds are not byte-identical: {key}")
    if (
        verify_a["verification_receipt_sha256"]
        != verify_b["verification_receipt_sha256"]
    ):
        raise ValueError("public-suite verification receipts are not byte-identical")

    evidence_summary = {
        "schema_version": (
            "rtlflowbench.protocol_public_suite_server_evidence_summary.v1"
        ),
        "observed_at": observed_at,
        "status": "server_reproduction_verified_not_released",
        "evidence_id": evidence_id,
        "exit_codes": exit_codes,
        "build": {
            key: build_a[key]
            for key in (
                "archive_sha256",
                "builder_receipt_sha256",
                "manifest_sha256",
                "suite_descriptor_sha256",
            )
        },
        "verification_receipt_sha256": verify_a[
            "verification_receipt_sha256"
        ],
        "receipt_builder_sha256": _sha256(Path(__file__).resolve()),
        "candidate_lock_sha256": current_locks,
        "authority_tree_written": False,
        "workflow_workspace_exposed": False,
        "excluded_claims": [
            "This evidence summary is deterministic transport evidence, not benchmark admission.",
            "The public archive contains no evaluator-private oracle.",
            "No AIRTL workflow score or RTL PASS is represented here.",
        ],
    }
    evidence_summary_sha256 = hashlib.sha256(
        _canonical_json(evidence_summary)
    ).hexdigest()
    receipt = {
        "schema_version": (
            "rtlflowbench.protocol_public_suite_candidate_server_receipt.v1"
        ),
        "observed_at": observed_at,
        "status": "server_byte_reproducible_public_only_not_released",
        "evidence_id": evidence_id,
        "evidence_summary_sha256": evidence_summary_sha256,
        "source_sha256": {
            label: _sha256(repo_root / path)
            for label, path in SOURCE_PATHS.items()
        },
        "candidate_lock_sha256": current_locks,
        "reproduction": {
            **exit_codes,
            "archive_sha256": build_a["archive_sha256"],
            "builder_receipt_sha256": build_a["builder_receipt_sha256"],
            "verification_receipt_sha256": verify_a[
                "verification_receipt_sha256"
            ],
            "archives_byte_identical": True,
            "builder_receipts_byte_identical": True,
            "verification_receipts_byte_identical": True,
        },
        "suite": {
            "task_count": 12,
            "private_file_count": 0,
            "benchmark_ready_task_count": 0,
            "chipflow_adapter_ready_task_count": 0,
            "protocol_ready": False,
            "suite_ready": False,
            "publishable_score_permitted": False,
        },
        "admission_impact": {
            "public_transport_candidate_complete": True,
            "private_evaluator_exposed": False,
            "independent_review_complete": False,
            "protocol_ready": False,
            "benchmark_ready_task_count": 0,
            "chipflow_adapter_ready_task_count": 0,
            "published_score_permitted": False,
        },
        "excluded_claims": [
            "SERVER26 byte reproduction establishes deterministic public transport only, not independent benchmark admission.",
            "The archive contains no evaluator-private asset or hidden oracle.",
            "No workflow PASS, official score, PPA, QoR, performance, human-level, or superhuman result is claimed.",
        ],
    }
    Draft202012Validator(
        server_schema, format_checker=FormatChecker()
    ).validate(receipt)
    return receipt, evidence_summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--build-a-root", type=Path, required=True)
    parser.add_argument("--build-b-root", type=Path, required=True)
    parser.add_argument("--verify-a-root", type=Path, required=True)
    parser.add_argument("--verify-b-root", type=Path, required=True)
    parser.add_argument("--build-a-exit-code", type=Path, required=True)
    parser.add_argument("--build-b-exit-code", type=Path, required=True)
    parser.add_argument("--verify-a-exit-code", type=Path, required=True)
    parser.add_argument("--verify-b-exit-code", type=Path, required=True)
    parser.add_argument("--evidence-id", required=True)
    parser.add_argument("--observed-at", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--evidence-summary-output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.expanduser().resolve()
    summary_output = args.evidence_summary_output.expanduser().resolve()
    for path in (output, summary_output):
        if path.exists() or path.is_symlink():
            raise FileExistsError(f"refusing to overwrite output: {path}")
    receipt, summary = build_server_receipt(
        repo_root=args.repo_root,
        build_a_root=args.build_a_root,
        build_b_root=args.build_b_root,
        verify_a_root=args.verify_a_root,
        verify_b_root=args.verify_b_root,
        build_a_exit_code=args.build_a_exit_code,
        build_b_exit_code=args.build_b_exit_code,
        verify_a_exit_code=args.verify_a_exit_code,
        verify_b_exit_code=args.verify_b_exit_code,
        evidence_id=args.evidence_id,
        observed_at=args.observed_at,
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    summary_output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(_canonical_json(receipt))
    summary_output.write_bytes(_canonical_json(summary))
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
