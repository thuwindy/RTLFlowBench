#!/usr/bin/env python3
"""Fail-closed offline verifier for a Golden-12 public suite candidate."""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import tarfile
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker, ValidationError


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
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_OUTER_MEMBER_BYTES = 32 * 1024 * 1024
MAX_OUTER_UNPACKED_BYTES = 128 * 1024 * 1024
MAX_OUTER_MEMBERS = 128
MAX_TASK_ARCHIVE_BYTES = 16 * 1024 * 1024
MAX_TASK_MEMBER_BYTES = 16 * 1024 * 1024
MAX_TASK_UNPACKED_BYTES = 64 * 1024 * 1024
MAX_TASK_MEMBERS = 512
ROOT = Path(__file__).resolve().parent
RECEIPT_SCHEMA = ROOT / "public_suite_verification_receipt.schema.json"
SUITE_SCHEMA = ROOT / "public_suite_descriptor.schema.json"
MANIFEST_SCHEMA = ROOT / "public_suite_manifest.schema.json"
TASK_ARCHIVE_RECEIPT_SCHEMA = ROOT / "public_release_archive_receipt.schema.json"
BUNDLED_SCHEMA_FILES = {
    "task": ROOT.parent / "schemas/task.schema.json",
    "submission": ROOT.parent / "schemas/submission.schema.json",
    "result": ROOT.parent / "schemas/result.schema.json",
    "public_suite_descriptor": SUITE_SCHEMA,
    "public_suite_manifest": MANIFEST_SCHEMA,
    "task_public_archive_receipt": TASK_ARCHIVE_RECEIPT_SCHEMA,
}


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _load_json_bytes(payload: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is not valid UTF-8 JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must contain one JSON object")
    return value


def _load_json(path: Path, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a regular non-symlink file")
    return _load_json_bytes(path.read_bytes(), label)


def _validate_schema(
    schema: dict[str, Any], instance: dict[str, Any], label: str
) -> None:
    try:
        Draft202012Validator(
            schema, format_checker=FormatChecker()
        ).validate(instance)
    except ValidationError as exc:
        location = "/".join(str(item) for item in exc.absolute_path)
        raise ValueError(
            f"{label} schema validation failed at {location or '<root>'}: "
            f"{exc.message}"
        ) from exc


def _parse_observed_at(value: str) -> None:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("--observed-at must include a timezone")


def _require_sha256(value: str) -> None:
    if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise ValueError("expected archive SHA256 must be 64 lowercase hex characters")


def _validate_outer_name(raw_name: str) -> PurePosixPath:
    name = PurePosixPath(raw_name)
    lowered_parts = {part.lower() for part in name.parts}
    if (
        raw_name != name.as_posix()
        or name.is_absolute()
        or not name.parts
        or name.parts[0] != ARCHIVE_ROOT.as_posix()
        or ".." in name.parts
        or "\\" in raw_name
        or lowered_parts.intersection(FORBIDDEN_PARTS)
        or name.suffix.lower() in FORBIDDEN_SUFFIXES
        or name.name.lower().startswith(".env")
        or name.name.lower() == "config.yaml"
    ):
        raise ValueError(f"unsafe public-suite member path: {raw_name}")
    return name


def _validate_task_name(raw_name: str) -> PurePosixPath:
    name = PurePosixPath(raw_name)
    lowered_parts = {part.lower() for part in name.parts}
    if (
        raw_name != name.as_posix()
        or name.is_absolute()
        or not name.parts
        or name.parts[0] != "public"
        or ".." in name.parts
        or "\\" in raw_name
        or lowered_parts.intersection(FORBIDDEN_PARTS)
        or name.suffix.lower() in FORBIDDEN_SUFFIXES
        or name.name.lower().startswith(".env")
        or name.name.lower() == "config.yaml"
    ):
        raise ValueError(f"unsafe task public-archive member path: {raw_name}")
    return name


def _read_tar_members(
    *,
    payload: bytes,
    label: str,
    name_validator,
    max_members: int,
    max_member_bytes: int,
    max_unpacked_bytes: int,
) -> dict[str, bytes]:
    members: dict[str, bytes] = {}
    total_size = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
            infos = archive.getmembers()
            if not infos or len(infos) > max_members:
                raise ValueError(
                    f"{label} member count outside safety limit: {len(infos)}"
                )
            for info in infos:
                name = name_validator(info.name).as_posix()
                if name in members:
                    raise ValueError(f"duplicate {label} member: {name}")
                if not info.isfile():
                    raise ValueError(f"non-regular {label} member: {name}")
                if (
                    info.size < 0
                    or info.size > max_member_bytes
                    or info.uid != 0
                    or info.gid != 0
                    or info.uname != ""
                    or info.gname != ""
                    or info.mtime != 0
                    or info.mode != 0o644
                ):
                    raise ValueError(f"non-canonical {label} member metadata: {name}")
                total_size += info.size
                if total_size > max_unpacked_bytes:
                    raise ValueError(f"{label} exceeds uncompressed safety limit")
                stream = archive.extractfile(info)
                if stream is None:
                    raise ValueError(f"{label} member cannot be read: {name}")
                member_payload = stream.read(max_member_bytes + 1)
                if len(member_payload) != info.size:
                    raise ValueError(f"{label} member size mismatch: {name}")
                members[name] = member_payload
    except (tarfile.TarError, OSError) as exc:
        raise ValueError(f"{label} cannot be decoded: {exc}") from exc
    return members


def _require_member(members: dict[str, bytes], relative: str) -> bytes:
    name = (ARCHIVE_ROOT / relative).as_posix()
    if name not in members:
        raise ValueError(f"required public-suite member is missing: {name}")
    return members[name]


def _validate_manifest(
    *, members: dict[str, bytes], manifest: dict[str, Any]
) -> dict[str, dict[str, Any]]:
    entries = manifest["entries"]
    if manifest["entry_count"] != len(entries):
        raise ValueError("manifest entry count is inconsistent")
    indexed: dict[str, dict[str, Any]] = {}
    for entry in entries:
        path = _validate_outer_name(entry["path"]).as_posix()
        if path in indexed:
            raise ValueError(f"duplicate manifest path: {path}")
        payload = members.get(path)
        if payload is None:
            raise ValueError(f"manifest references a missing member: {path}")
        if entry["bytes"] != len(payload) or entry["sha256"] != _sha256_bytes(
            payload
        ):
            raise ValueError(f"manifest digest/size mismatch: {path}")
        indexed[path] = entry
    manifest_path = (ARCHIVE_ROOT / "manifest.json").as_posix()
    expected = set(members) - {manifest_path}
    if set(indexed) != expected:
        missing = sorted(expected - set(indexed))
        extra = sorted(set(indexed) - expected)
        raise ValueError(
            f"manifest/member closure mismatch: missing={missing}, extra={extra}"
        )
    return indexed


def _validate_task_archive(
    *,
    task: dict[str, Any],
    archive_payload: bytes,
    receipt: dict[str, Any],
    task_validator: Draft202012Validator,
) -> None:
    task_id = task["task_id"]
    if len(archive_payload) > MAX_TASK_ARCHIVE_BYTES:
        raise ValueError(f"{task_id} public archive exceeds safety limit")
    if (
        receipt["task_id"] != task_id
        or receipt["candidate_release"] != task["candidate_release"]
        or receipt["candidate_lock_sha256"] != task["candidate_lock_sha256"]
        or receipt["archive_sha256"] != task["public_archive_sha256"]
        or receipt["archive_sha256"] != _sha256_bytes(archive_payload)
        or receipt["archive_bytes"] != task["public_archive_bytes"]
        or receipt["archive_bytes"] != len(archive_payload)
        or receipt["member_count"] != task["public_archive_member_count"]
        or receipt["contains_private_paths"] is not False
        or receipt["contains_symlinks"] is not False
        or receipt["benchmark_ready"] is not False
        or receipt["chipflow_adapter_ready"] is not False
    ):
        raise ValueError(f"{task_id} public archive receipt projection is invalid")
    nested = _read_tar_members(
        payload=archive_payload,
        label=f"{task_id} task archive",
        name_validator=_validate_task_name,
        max_members=MAX_TASK_MEMBERS,
        max_member_bytes=MAX_TASK_MEMBER_BYTES,
        max_unpacked_bytes=MAX_TASK_UNPACKED_BYTES,
    )
    receipt_entries = {entry["path"]: entry for entry in receipt["members"]}
    if len(receipt_entries) != len(receipt["members"]) or set(receipt_entries) != set(
        nested
    ):
        raise ValueError(f"{task_id} task archive member closure is invalid")
    for name, payload in nested.items():
        entry = receipt_entries[name]
        if entry["bytes"] != len(payload) or entry["sha256"] != _sha256_bytes(
            payload
        ):
            raise ValueError(f"{task_id} task archive member drift: {name}")
        if b"/home/" in payload or b"/Users/" in payload:
            raise ValueError(f"{task_id} public packet contains a developer-host path")

    external = _load_json_bytes(
        nested.get("public/external_task.json", b""),
        f"{task_id} external task",
    )
    task_errors = list(task_validator.iter_errors(external))
    if task_errors:
        raise ValueError(
            f"{task_id} external task schema error: {task_errors[0].message}"
        )
    admission = _load_json_bytes(
        nested.get("public/admission.json", b""),
        f"{task_id} public admission",
    )
    rights = _load_json_bytes(
        nested.get("public/rights_review.json", b""),
        f"{task_id} rights review",
    )
    if (
        external.get("task_id") != task_id
        or external.get("family") != task["capability_family"]
        or external.get("packet_status") != "draft"
        or admission.get("benchmark_status") != "not_ready"
        or admission.get("rights_review_complete") is not False
        or rights.get("rights_review_complete") is not False
        or task["packet_status"] != "draft"
        or task["rights_review_complete"] is not False
        or task["benchmark_ready"] is not False
        or task["chipflow_adapter_ready"] is not False
    ):
        raise ValueError(f"{task_id} readiness/rights claim is unsafe")


def _extract_members(members: dict[str, bytes], output_dir: Path) -> None:
    if output_dir.exists() or output_dir.is_symlink():
        raise FileExistsError(f"refusing to overwrite output: {output_dir}")
    resolved_output = output_dir.expanduser().resolve()
    resolved_output.mkdir(parents=True)
    for name, payload in sorted(members.items()):
        target = resolved_output.joinpath(*PurePosixPath(name).parts)
        target.resolve().relative_to(resolved_output)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)


def verify_public_suite_candidate(
    *,
    archive_path: Path,
    expected_archive_sha256: str,
    output_dir: Path,
    observed_at: str,
) -> dict[str, Any]:
    _parse_observed_at(observed_at)
    _require_sha256(expected_archive_sha256)
    archive_input = archive_path.expanduser()
    if archive_input.is_symlink() or not archive_input.is_file():
        raise ValueError("archive must be a regular non-symlink file")
    archive_path = archive_input.resolve(strict=True)
    outer_archive_payload = archive_path.read_bytes()
    if not outer_archive_payload or len(outer_archive_payload) > MAX_ARCHIVE_BYTES:
        raise ValueError("archive size is outside the safety limit")
    archive_sha256 = _sha256_bytes(outer_archive_payload)
    if archive_sha256 != expected_archive_sha256:
        raise ValueError("archive SHA256 does not match the caller trust anchor")
    members = _read_tar_members(
        payload=outer_archive_payload,
        label="public suite archive",
        name_validator=_validate_outer_name,
        max_members=MAX_OUTER_MEMBERS,
        max_member_bytes=MAX_OUTER_MEMBER_BYTES,
        max_unpacked_bytes=MAX_OUTER_UNPACKED_BYTES,
    )

    manifest_payload = _require_member(members, "manifest.json")
    suite_payload = _require_member(members, "suite.json")
    manifest = _load_json_bytes(manifest_payload, "public suite manifest")
    suite = _load_json_bytes(suite_payload, "public suite descriptor")
    manifest_schema = _load_json(MANIFEST_SCHEMA, "manifest schema")
    suite_schema = _load_json(SUITE_SCHEMA, "suite descriptor schema")
    task_receipt_schema = _load_json(
        TASK_ARCHIVE_RECEIPT_SCHEMA, "task public-archive receipt schema"
    )
    receipt_schema = _load_json(RECEIPT_SCHEMA, "verification receipt schema")
    for schema in (
        manifest_schema,
        suite_schema,
        task_receipt_schema,
        receipt_schema,
    ):
        Draft202012Validator.check_schema(schema)
    _validate_schema(manifest_schema, manifest, "public suite manifest")
    _validate_schema(suite_schema, suite, "public suite descriptor")
    indexed = _validate_manifest(members=members, manifest=manifest)

    for name, local_path in BUNDLED_SCHEMA_FILES.items():
        bundled = _require_member(members, f"shared/schemas/{name}.schema.json")
        if bundled != local_path.read_bytes():
            raise ValueError(f"bundled schema differs from verifier source: {name}")
    task_schema = _load_json_bytes(
        _require_member(members, "shared/schemas/task.schema.json"),
        "bundled task schema",
    )
    Draft202012Validator.check_schema(task_schema)
    task_validator = Draft202012Validator(task_schema)
    task_receipt_validator = Draft202012Validator(
        task_receipt_schema, format_checker=FormatChecker()
    )

    tasks = suite["tasks"]
    if tuple(task["task_id"] for task in tasks) != TASK_IDS:
        raise ValueError("suite task order/coverage differs from Golden-12")
    candidate_locks: dict[str, str] = {}
    task_archive_digests: dict[str, str] = {}
    for task in tasks:
        task_id = task["task_id"]
        archive_relative = task["public_archive_path"]
        receipt_relative = task["public_archive_receipt_path"]
        task_archive_payload = _require_member(members, archive_relative)
        receipt = _load_json_bytes(
            _require_member(members, receipt_relative),
            f"{task_id} public archive receipt",
        )
        try:
            task_receipt_validator.validate(receipt)
        except ValidationError as exc:
            raise ValueError(
                f"{task_id} public archive receipt schema validation failed: "
                f"{exc.message}"
            ) from exc
        _validate_task_archive(
            task=task,
            archive_payload=task_archive_payload,
            receipt=receipt,
            task_validator=task_validator,
        )
        if indexed[(ARCHIVE_ROOT / archive_relative).as_posix()]["role"] != (
            "candidate_bound_task_public_archive"
        ):
            raise ValueError(f"{task_id} public archive manifest role is invalid")
        if indexed[(ARCHIVE_ROOT / receipt_relative).as_posix()]["role"] != (
            "task_public_archive_receipt"
        ):
            raise ValueError(f"{task_id} receipt manifest role is invalid")
        candidate_locks[task_id] = task["candidate_lock_sha256"]
        task_archive_digests[task_id] = task["public_archive_sha256"]

    workflow = suite["workflow_contract"]
    readiness = suite["readiness"]
    if (
        workflow["task_archives_candidate_bound"] is not True
        or workflow["private_evaluator_exposed"] is not False
        or workflow["protocol_release_included"] is not False
        or workflow["publishable_score_permitted"] is not False
        or readiness
        != {
            "rights_review_complete_task_count": 0,
            "benchmark_ready_task_count": 0,
            "chipflow_adapter_ready_task_count": 0,
            "protocol_ready": False,
            "suite_ready": False,
        }
        or manifest["private_file_count"] != 0
    ):
        raise ValueError("suite readiness/private projection is unsafe")

    receipt = {
        "schema_version": "rtlflowbench.golden12_public_suite_verification_receipt.v1",
        "observed_at": observed_at,
        "status": "verified_development_candidate_not_released",
        "suite_id": suite["suite_id"],
        "archive_sha256": archive_sha256,
        "archive_bytes": len(outer_archive_payload),
        "archive_member_count": len(members),
        "manifest_entry_count": len(indexed),
        "manifest_sha256": _sha256_bytes(manifest_payload),
        "suite_descriptor_sha256": _sha256_bytes(suite_payload),
        "task_count": 12,
        "task_ids": list(TASK_IDS),
        "candidate_lock_sha256": candidate_locks,
        "task_public_archive_sha256": task_archive_digests,
        "private_file_count": 0,
        "benchmark_ready_task_count": 0,
        "chipflow_adapter_ready_task_count": 0,
        "protocol_ready": False,
        "suite_ready": False,
        "publishable_score_permitted": False,
        "extraction_performed": True,
        "verifier_sha256": _sha256_bytes(Path(__file__).read_bytes()),
        "receipt_schema_sha256": _sha256_bytes(RECEIPT_SCHEMA.read_bytes()),
        "excluded_claims": [
            "Verification authenticates a caller-pinned development archive; it is not independent release admission.",
            "No evaluator-private asset, hidden oracle, workflow PASS, official score, PPA, QoR, or performance result is established.",
            "All rights, protocol governance, task admissions, and frozen multi-workflow evaluations remain external gates.",
        ],
    }
    _validate_schema(receipt_schema, receipt, "verification receipt")
    _extract_members(members, output_dir)
    (output_dir.expanduser().resolve() / "verification_receipt.json").write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--expected-archive-sha256", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--observed-at", required=True)
    args = parser.parse_args()
    try:
        result = verify_public_suite_candidate(
            archive_path=args.archive,
            expected_archive_sha256=args.expected_archive_sha256,
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
