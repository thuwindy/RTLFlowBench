#!/usr/bin/env python3
"""Build one deterministic, public-only Golden-12 development candidate.

The outer archive transports twelve candidate-bound public task archives and
the workflow-neutral schemas.  It never copies evaluator-private assets and
it deliberately keeps every release/readiness claim false.
"""

from __future__ import annotations

import argparse
from datetime import datetime
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path, PurePosixPath
import sys
import tarfile
import tempfile
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
ARCHIVE_ROOT = PurePosixPath("rtlflowbench-golden12-development-candidate")
ARCHIVE_NAME = "rtlflowbench-golden12-public-candidate.tar.gz"
ADMISSION_ROOT = Path("benchmarks/golden12/admission")
README_RELATIVE = ADMISSION_ROOT / "public_suite_README.md"
RECEIPT_SCHEMA_RELATIVE = (
    ADMISSION_ROOT / "public_suite_candidate_receipt.schema.json"
)
SUITE_SCHEMA_RELATIVE = ADMISSION_ROOT / "public_suite_descriptor.schema.json"
MANIFEST_SCHEMA_RELATIVE = ADMISSION_ROOT / "public_suite_manifest.schema.json"
TASK_ARCHIVE_SCHEMA_RELATIVE = (
    ADMISSION_ROOT / "public_release_archive_receipt.schema.json"
)
TASK_ARCHIVE_BUILDER_RELATIVE = (
    ADMISSION_ROOT / "build_public_release_archive.py"
)
WORKFLOW_SCHEMAS = {
    "task": Path("benchmarks/golden12/schemas/task.schema.json"),
    "submission": Path("benchmarks/golden12/schemas/submission.schema.json"),
    "result": Path("benchmarks/golden12/schemas/result.schema.json"),
}
FORBIDDEN_PARTS = {
    "private",
    "outputs",
    "logs",
    "node_modules",
    "__pycache__",
    ".git",
    ".deer-flow",
}
FORBIDDEN_SUFFIXES = {".pyc", ".vcd", ".fst", ".log"}


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _sha256(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _canonical_json(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


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


def _validate_archive_name(name: PurePosixPath) -> None:
    rendered = name.as_posix()
    lowered_parts = {part.lower() for part in name.parts}
    if (
        name.is_absolute()
        or not name.parts
        or name.parts[0] != ARCHIVE_ROOT.as_posix()
        or ".." in name.parts
        or "\\" in rendered
        or lowered_parts.intersection(FORBIDDEN_PARTS)
        or name.suffix.lower() in FORBIDDEN_SUFFIXES
        or name.name.lower().startswith(".env")
        or name.name.lower() == "config.yaml"
    ):
        raise ValueError(f"forbidden public-suite archive path: {rendered}")


def _tar_payload(members: dict[str, bytes]) -> bytes:
    plain = io.BytesIO()
    with tarfile.open(fileobj=plain, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name, payload in sorted(members.items()):
            _validate_archive_name(PurePosixPath(name))
            info = tarfile.TarInfo(name=name)
            info.size = len(payload)
            info.mode = 0o644
            info.uid = info.gid = 0
            info.uname = info.gname = ""
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
        output.write(plain.getvalue())
    return compressed.getvalue()


def _load_task_archive_builder(repo_root: Path):
    path = repo_root / TASK_ARCHIVE_BUILDER_RELATIVE
    spec = importlib.util.spec_from_file_location(
        "rtlflowbench_golden12_public_suite_task_archive", path
    )
    if spec is None or spec.loader is None:
        raise ValueError("could not load task public-archive builder")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _source_paths(repo_root: Path) -> dict[str, Path]:
    paths = {
        "builder": Path(__file__).resolve(strict=True),
        "readme": repo_root / README_RELATIVE,
        "receipt_schema": repo_root / RECEIPT_SCHEMA_RELATIVE,
        "suite_schema": repo_root / SUITE_SCHEMA_RELATIVE,
        "manifest_schema": repo_root / MANIFEST_SCHEMA_RELATIVE,
        "task_archive_builder": repo_root / TASK_ARCHIVE_BUILDER_RELATIVE,
        "task_archive_receipt_schema": repo_root / TASK_ARCHIVE_SCHEMA_RELATIVE,
    }
    paths.update(
        {
            f"{name}_schema": repo_root / relative
            for name, relative in WORKFLOW_SCHEMAS.items()
        }
    )
    return paths


def build_public_suite_candidate(
    *, repo_root: Path, output_dir: Path, observed_at: str
) -> dict[str, Any]:
    _parse_observed_at(observed_at)
    repo_root = repo_root.expanduser().resolve(strict=True)
    output_dir = output_dir.expanduser().resolve()
    if output_dir.exists() or output_dir.is_symlink():
        raise FileExistsError(f"refusing to overwrite output: {output_dir}")
    if output_dir.is_relative_to(repo_root):
        raise ValueError("public suite output must remain outside the repository")

    receipt_schema = _load(
        repo_root / RECEIPT_SCHEMA_RELATIVE, "public suite receipt schema"
    )
    suite_schema = _load(
        repo_root / SUITE_SCHEMA_RELATIVE, "public suite descriptor schema"
    )
    manifest_schema = _load(
        repo_root / MANIFEST_SCHEMA_RELATIVE, "public suite manifest schema"
    )
    task_schema = _load(repo_root / WORKFLOW_SCHEMAS["task"], "task schema")
    task_receipt_schema = _load(
        repo_root / TASK_ARCHIVE_SCHEMA_RELATIVE,
        "task public-archive receipt schema",
    )
    for schema in (
        receipt_schema,
        suite_schema,
        manifest_schema,
        task_schema,
        task_receipt_schema,
    ):
        Draft202012Validator.check_schema(schema)
    task_validator = Draft202012Validator(task_schema)
    task_receipt_validator = Draft202012Validator(
        task_receipt_schema, format_checker=FormatChecker()
    )
    task_builder = _load_task_archive_builder(repo_root)

    members: dict[str, bytes] = {}
    entries: list[dict[str, Any]] = []

    def add_member(name: PurePosixPath, payload: bytes, role: str) -> None:
        _validate_archive_name(name)
        rendered = name.as_posix()
        if rendered in members:
            raise ValueError(f"duplicate public-suite member: {rendered}")
        members[rendered] = payload
        entries.append(
            {
                "path": rendered,
                "bytes": len(payload),
                "sha256": _sha256_bytes(payload),
                "role": role,
            }
        )

    add_member(
        ARCHIVE_ROOT / "README.md",
        (repo_root / README_RELATIVE).read_bytes(),
        "public_suite_readme",
    )
    bundled_schemas = {
        **WORKFLOW_SCHEMAS,
        "public_suite_descriptor": SUITE_SCHEMA_RELATIVE,
        "public_suite_manifest": MANIFEST_SCHEMA_RELATIVE,
        "task_public_archive_receipt": TASK_ARCHIVE_SCHEMA_RELATIVE,
    }
    for name, relative in sorted(bundled_schemas.items()):
        add_member(
            ARCHIVE_ROOT / f"shared/schemas/{name}.schema.json",
            (repo_root / relative).read_bytes(),
            "public_schema",
        )

    task_records: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="rtlflowbench-golden12-public-") as tmp:
        temporary_root = Path(tmp)
        for task_id in TASK_IDS:
            task_output = temporary_root / task_id
            task_receipt = task_builder.build_public_release_archive(
                repo_root=repo_root,
                task_id=task_id,
                output_dir=task_output,
                observed_at=observed_at,
            )
            task_receipt_validator.validate(task_receipt)
            task_archive = task_output / f"{task_id[:3].lower()}-public-input.tar.gz"
            archive_payload = task_archive.read_bytes()
            if _sha256_bytes(archive_payload) != task_receipt["archive_sha256"]:
                raise ValueError(f"task public archive digest drift: {task_id}")

            public_root = (
                repo_root / "benchmarks/golden12/tasks" / task_id / "public"
            )
            external_task = _load(
                public_root / "external_task.json", f"{task_id} external task"
            )
            task_errors = list(task_validator.iter_errors(external_task))
            if task_errors:
                raise ValueError(
                    f"{task_id} external task schema error: "
                    f"{task_errors[0].message}"
                )
            admission = _load(
                public_root / "admission.json", f"{task_id} public admission"
            )
            rights = _load(
                public_root / "rights_review.json", f"{task_id} rights review"
            )
            if (
                external_task.get("task_id") != task_id
                or external_task.get("packet_status") != "draft"
                or admission.get("benchmark_status") != "not_ready"
                or admission.get("rights_review_complete") is not False
                or rights.get("rights_review_complete") is not False
                or task_receipt.get("benchmark_ready") is not False
                or task_receipt.get("chipflow_adapter_ready") is not False
                or task_receipt.get("contains_private_paths") is not False
            ):
                raise ValueError(f"{task_id} public readiness/rights projection is unsafe")

            archive_relative = f"tasks/{task_id}/{task_id[:3].lower()}-public-input.tar.gz"
            receipt_relative = f"tasks/{task_id}/receipt.json"
            add_member(
                ARCHIVE_ROOT / archive_relative,
                archive_payload,
                "candidate_bound_task_public_archive",
            )
            receipt_payload = _canonical_json(task_receipt)
            add_member(
                ARCHIVE_ROOT / receipt_relative,
                receipt_payload,
                "task_public_archive_receipt",
            )
            task_records.append(
                {
                    "task_id": task_id,
                    "capability_family": external_task["family"],
                    "candidate_release": task_receipt["candidate_release"],
                    "candidate_lock_sha256": task_receipt[
                        "candidate_lock_sha256"
                    ],
                    "public_archive_path": archive_relative,
                    "public_archive_sha256": task_receipt["archive_sha256"],
                    "public_archive_bytes": task_receipt["archive_bytes"],
                    "public_archive_member_count": task_receipt["member_count"],
                    "public_archive_receipt_path": receipt_relative,
                    "packet_status": "draft",
                    "rights_review_complete": False,
                    "benchmark_ready": False,
                    "chipflow_adapter_ready": False,
                }
            )

    suite = {
        "schema_version": "rtlflowbench.golden12_public_suite.v1",
        "suite_id": "Golden-12-v1-development-candidate",
        "observed_at": observed_at,
        "status": "development_candidate_not_released",
        "task_count": 12,
        "tasks": task_records,
        "workflow_contract": {
            "task_schema": "shared/schemas/task.schema.json",
            "submission_schema": "shared/schemas/submission.schema.json",
            "result_schema": "shared/schemas/result.schema.json",
            "task_archives_candidate_bound": True,
            "private_evaluator_exposed": False,
            "offline_evaluation_required": True,
            "protocol_release_included": False,
            "publishable_score_permitted": False,
            "required_result_label": "development-trial-not-admitted",
        },
        "readiness": {
            "rights_review_complete_task_count": 0,
            "benchmark_ready_task_count": 0,
            "chipflow_adapter_ready_task_count": 0,
            "protocol_ready": False,
            "suite_ready": False,
        },
        "excluded_claims": [
            "This archive is a development transport candidate, not Golden-12-v1 release.",
            "No evaluator-private asset or hidden oracle is included.",
            "No workflow PASS, official score, PPA, QoR, performance, human-level, or superhuman result is claimed.",
        ],
    }
    Draft202012Validator(
        suite_schema, format_checker=FormatChecker()
    ).validate(suite)
    suite_payload = _canonical_json(suite)
    add_member(ARCHIVE_ROOT / "suite.json", suite_payload, "suite_descriptor")

    manifest = {
        "schema_version": "rtlflowbench.golden12_public_suite_manifest.v1",
        "suite_id": suite["suite_id"],
        "observed_at": observed_at,
        "status": "development_candidate_not_frozen",
        "archive_root": ARCHIVE_ROOT.as_posix(),
        "entry_count": len(entries),
        "private_file_count": 0,
        "entries": sorted(entries, key=lambda item: item["path"]),
    }
    Draft202012Validator(
        manifest_schema, format_checker=FormatChecker()
    ).validate(manifest)
    manifest_payload = _canonical_json(manifest)
    manifest_name = ARCHIVE_ROOT / "manifest.json"
    _validate_archive_name(manifest_name)
    members[manifest_name.as_posix()] = manifest_payload
    archive_payload = _tar_payload(members)

    output_dir.mkdir(parents=True)
    archive_path = output_dir / ARCHIVE_NAME
    suite_path = output_dir / "suite.json"
    manifest_path = output_dir / "manifest.json"
    receipt_path = output_dir / "receipt.json"
    archive_path.write_bytes(archive_payload)
    suite_path.write_bytes(suite_payload)
    manifest_path.write_bytes(manifest_payload)
    source_sha256 = {
        key: _sha256(path)
        for key, path in sorted(_source_paths(repo_root).items())
    }
    receipt = {
        "schema_version": "rtlflowbench.golden12_public_suite_candidate_receipt.v1",
        "observed_at": observed_at,
        "status": "development_public_suite_candidate_not_released",
        "suite_id": suite["suite_id"],
        "archive_sha256": _sha256_bytes(archive_payload),
        "archive_bytes": len(archive_payload),
        "archive_member_count": len(members),
        "manifest_sha256": _sha256_bytes(manifest_payload),
        "suite_descriptor_sha256": _sha256_bytes(suite_payload),
        "task_count": 12,
        "task_ids": list(TASK_IDS),
        "candidate_lock_sha256": {
            task["task_id"]: task["candidate_lock_sha256"]
            for task in task_records
        },
        "task_public_archive_sha256": {
            task["task_id"]: task["public_archive_sha256"]
            for task in task_records
        },
        "private_file_count": 0,
        "rights_review_complete_task_count": 0,
        "benchmark_ready_task_count": 0,
        "chipflow_adapter_ready_task_count": 0,
        "protocol_ready": False,
        "suite_ready": False,
        "publishable_score_permitted": False,
        "source_sha256": source_sha256,
        "excluded_claims": suite["excluded_claims"],
    }
    Draft202012Validator(
        receipt_schema, format_checker=FormatChecker()
    ).validate(receipt)
    receipt_path.write_bytes(_canonical_json(receipt))
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--observed-at", required=True)
    args = parser.parse_args()
    try:
        result = build_public_suite_candidate(
            repo_root=args.repo_root,
            output_dir=args.output_dir,
            observed_at=args.observed_at,
        )
    except Exception as exc:
        print(
            json.dumps(
                {
                    "status": "invalid_evidence",
                    "error": f"{type(exc).__name__}: {exc}",
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
