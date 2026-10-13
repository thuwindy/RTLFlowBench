#!/usr/bin/env python3
"""Build a fail-closed, candidate-bound task release-material receipt.

This builder verifies packaging inputs only.  It never admits a benchmark and
never changes ChipFlow adapter readiness.  Private archives and protocol trust
receipts must be supplied from outside the repository.
"""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import sys
import tarfile
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


SCHEMA_RELATIVE = "benchmarks/golden12/admission/release_materials.schema.json"
PUBLIC_ARCHIVE_BUILDER_RELATIVE = (
    "benchmarks/golden12/admission/build_public_release_archive.py"
)
PUBLIC_ARCHIVE_SCHEMA_RELATIVE = (
    "benchmarks/golden12/admission/public_release_archive_receipt.schema.json"
)
RELEASE_FREEZE_DECLARATION_SCHEMA_RELATIVE = (
    "benchmarks/golden12/admission/release_freeze_declaration.schema.json"
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


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


def _external_file(repo_root: Path, path: Path, label: str) -> Path:
    resolved = path.expanduser().resolve(strict=True)
    if resolved.is_symlink() or not resolved.is_file():
        raise ValueError(f"{label} must be a regular non-symlink file")
    try:
        resolved.relative_to(repo_root)
    except ValueError:
        return resolved
    raise ValueError(f"{label} must remain outside the repository")


def _relative_component(repo_root: Path, relative: str, label: str) -> tuple[str, Path]:
    pure = PurePosixPath(relative)
    if pure.is_absolute() or ".." in pure.parts or not pure.parts:
        raise ValueError(f"{label} is not a safe repository-relative path")
    path = (repo_root / Path(*pure.parts)).resolve(strict=True)
    if not path.is_relative_to(repo_root) or path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must resolve to a regular repository file")
    return pure.as_posix(), path


def _archive_material(
    *,
    repo_root: Path,
    task_id: str,
    archive: Path | None,
    expected_sha256: str | None,
) -> dict[str, Any]:
    if archive is None:
        return {
            "status": "not_available",
            "sha256": None,
            "bytes": None,
            "candidate_digest_bound": False,
            "binding_method": None,
        }
    path = _external_file(repo_root, archive, "public task archive")
    builder_path = repo_root / PUBLIC_ARCHIVE_BUILDER_RELATIVE
    spec = importlib.util.spec_from_file_location(
        "rtlflowbench_release_public_archive_verifier", builder_path
    )
    if spec is None or spec.loader is None:
        raise ValueError("could not load public archive verifier")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    verified = module.verify_public_archive(
        repo_root=repo_root, task_id=task_id, archive_path=path
    )
    digest = verified["archive_sha256"]
    binding_method = (
        "candidate_archive_sha256"
        if isinstance(expected_sha256, str) and digest == expected_sha256
        else "candidate_public_component_closure"
    )
    return {
        "status": "verified",
        "sha256": digest,
        "bytes": verified["archive_bytes"],
        "candidate_digest_bound": True,
        "binding_method": binding_method,
    }


def _private_archive_material(
    *,
    repo_root: Path,
    task_id: str,
    candidate_lock_sha256: str,
    components: dict[str, str],
    archive: Path | None,
    receipt_path: Path | None,
) -> dict[str, Any]:
    empty = {
        "status": "not_available",
        "sha256": None,
        "bytes": None,
        "candidate_digest_bound": False,
        "receipt_sha256": None,
        "candidate_lock_sha256": None,
        "workflow_workspace_exposed": False,
    }
    if archive is None and receipt_path is None:
        return empty
    if archive is None or receipt_path is None:
        return {**empty, "status": "unbound"}
    archive_path = _external_file(repo_root, archive, "evaluator-private archive")
    receipt_file = _external_file(
        repo_root, receipt_path, "evaluator-private bundle receipt"
    )
    receipt = _load(receipt_file, "evaluator-private bundle receipt")
    digest = _sha256(archive_path)
    member_payloads: dict[str, bytes] = {}
    with tarfile.open(archive_path, mode="r:*") as archive_reader:
        for member in archive_reader.getmembers():
            pure = PurePosixPath(member.name)
            if pure.is_absolute() or ".." in pure.parts:
                raise ValueError("evaluator-private archive contains an unsafe path")
            if not member.isfile():
                raise ValueError("evaluator-private archive contains a non-regular member")
            if member.name in member_payloads:
                raise ValueError("evaluator-private archive contains a duplicate member")
            handle = archive_reader.extractfile(member)
            if handle is None:
                raise ValueError("could not read evaluator-private archive member")
            member_payloads[member.name] = handle.read()
    component_closure_bound = all(
        f"candidate/{relative}" in member_payloads
        and _sha256_bytes(member_payloads[f"candidate/{relative}"]) == expected
        for relative, expected in components.items()
    )
    bound = (
        receipt.get("task_id") == task_id
        and receipt.get("classification") == "evaluator_private"
        and receipt.get("workflow_workspace_exposed") is False
        and receipt.get("candidate_lock_sha256") == candidate_lock_sha256
        and receipt.get("archive_sha256") == digest
        and receipt.get("archive_bytes") == archive_path.stat().st_size
        and component_closure_bound
    )
    return {
        "status": "verified" if bound else "unbound",
        "sha256": digest,
        "bytes": archive_path.stat().st_size,
        "candidate_digest_bound": bound,
        "receipt_sha256": _sha256(receipt_file),
        "candidate_lock_sha256": receipt.get("candidate_lock_sha256"),
        "workflow_workspace_exposed": False,
    }


def _component_material(
    *,
    repo_root: Path,
    components: dict[str, str],
    relative: str | None,
    label: str,
) -> dict[str, Any]:
    if relative is None:
        return {
            "status": "not_available",
            "relative_path": None,
            "sha256": None,
            "candidate_component_bound": False,
            "release_freeze_status": "not_available",
            "release_freeze_verified": False,
            "freeze_evidence": [],
        }
    normalized, path = _relative_component(repo_root, relative, label)
    digest = _sha256(path)
    bound = components.get(normalized) == digest
    value = _load(path, label)
    marker_names = (
        "status",
        "freeze_status",
        "environment_frozen",
        "scoring_frozen",
        "independent_freeze",
        "official_score_eligible",
        "canonical_score_available",
    )
    markers = {
        name: value[name]
        for name in marker_names
        if name in value
    }
    freeze_evidence = [
        f"{name}={json.dumps(markers[name], sort_keys=True)}"
        for name in sorted(markers)
    ]
    negative_text = " ".join(
        str(item).lower() for item in markers.values()
    )
    explicit_negative = any(
        token in negative_text
        for token in (
            "not_frozen",
            "development",
            "pending",
            "not_calibrated",
            "tool_intake",
        )
    ) or any(
        markers.get(name) is False
        for name in (
            "environment_frozen",
            "scoring_frozen",
            "independent_freeze",
            "official_score_eligible",
        )
    )
    frozen_strings = {
        "frozen",
        "independently_frozen",
        "release_frozen",
    }
    explicit_positive = bool(
        markers.get("environment_frozen") is True
        or markers.get("scoring_frozen") is True
        or markers.get("independent_freeze") is True
        or str(markers.get("status", "")).lower() in frozen_strings
        or str(markers.get("freeze_status", "")).lower()
        in frozen_strings
    )
    release_freeze_verified = bool(
        bound and explicit_positive and not explicit_negative
    )
    return {
        "status": "verified" if bound else "unbound",
        "relative_path": normalized,
        "sha256": digest,
        "candidate_component_bound": bound,
        "release_freeze_status": (
            "verified_frozen"
            if release_freeze_verified
            else "not_frozen"
        ),
        "release_freeze_verified": release_freeze_verified,
        "freeze_evidence": freeze_evidence,
    }


def _runner_lock_material(
    *,
    repo_root: Path,
    components: dict[str, str],
    relative: str | None,
) -> dict[str, Any]:
    material = _component_material(
        repo_root=repo_root,
        components=components,
        relative=relative,
        label="runner lock",
    )
    if material["status"] != "verified":
        return material
    path = repo_root / material["relative_path"]
    declaration = _load(path, "runner lock")
    schema_path = repo_root / RELEASE_FREEZE_DECLARATION_SCHEMA_RELATIVE
    schema = _load(schema_path, "release freeze declaration schema")
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(
        schema, format_checker=FormatChecker()
    ).validate(declaration)
    if declaration.get("role") != "runner_lock":
        raise ValueError("runner lock declaration has the wrong role")
    closure = declaration["runner_source_closure"]
    for role in ("entrypoint", "candidate", "candidate_schema", "receipt_schema"):
        observed_relative, observed_path = _relative_component(
            repo_root,
            closure[role]["relative_path"],
            f"runner lock {role}",
        )
        if observed_relative != closure[role]["relative_path"]:
            raise ValueError(f"runner lock {role} path normalization drift")
        if _sha256(observed_path) != closure[role]["sha256"]:
            raise ValueError(f"runner lock source digest drift: {role}")
    candidate = closure["candidate"]
    if (
        declaration["source_material"]["relative_path"]
        != candidate["relative_path"]
        or declaration["source_material"]["sha256"] != candidate["sha256"]
    ):
        raise ValueError("runner lock source material differs from its candidate")
    return material


def _protocol_material(
    *,
    repo_root: Path,
    receipt_path: Path | None,
    expected_receipt_sha256: str | None,
) -> dict[str, Any]:
    empty = {
        "status": "not_available",
        "receipt_sha256": None,
        "expected_receipt_sha256": expected_receipt_sha256,
        "trust_anchor_digest_match": False,
        "protocol_ready": False,
        "independent_review_complete": False,
    }
    if receipt_path is None and expected_receipt_sha256 is None:
        return empty
    if receipt_path is None or expected_receipt_sha256 is None:
        return {**empty, "status": "invalid"}
    receipt_file = _external_file(repo_root, receipt_path, "protocol release receipt")
    receipt = _load(receipt_file, "protocol release receipt")
    digest = _sha256(receipt_file)
    digest_match = digest == expected_receipt_sha256
    protocol_ready = receipt.get("protocol_ready") is True
    independently_reviewed = receipt.get("independent_review_complete") is True
    verified = digest_match and protocol_ready and independently_reviewed
    return {
        "status": "verified" if verified else "invalid",
        "receipt_sha256": digest,
        "expected_receipt_sha256": expected_receipt_sha256,
        "trust_anchor_digest_match": digest_match,
        "protocol_ready": protocol_ready,
        "independent_review_complete": independently_reviewed,
    }


def build_release_materials(
    *,
    repo_root: Path,
    task_id: str,
    observed_at: str,
    public_archive: Path | None = None,
    evaluator_private_archive: Path | None = None,
    evaluator_bundle_receipt: Path | None = None,
    environment_lock_relative: str | None = None,
    scoring_profile_relative: str | None = None,
    runner_lock_relative: str | None = None,
    protocol_release_receipt: Path | None = None,
    expected_protocol_release_sha256: str | None = None,
) -> dict[str, Any]:
    _parse_observed_at(observed_at)
    repo_root = repo_root.expanduser().resolve(strict=True)
    admission_root = (
        repo_root / "benchmarks/golden12/tasks" / task_id / "private/admission"
    )
    lock_path = admission_root / "candidate.lock.json"
    lock = _load(lock_path, "candidate lock")
    if lock.get("task_id") != task_id:
        raise ValueError("candidate lock task id mismatch")
    components = lock.get("component_sha256")
    if not isinstance(components, dict) or not components:
        raise ValueError("candidate lock has no component digest map")
    lock_sha256 = _sha256(lock_path)
    materials = {
        "public_task_archive": _archive_material(
            repo_root=repo_root,
            task_id=task_id,
            archive=public_archive,
            expected_sha256=lock.get("public_archive_sha256"),
        ),
        "evaluator_private_archive": _private_archive_material(
            repo_root=repo_root,
            task_id=task_id,
            candidate_lock_sha256=lock_sha256,
            components=components,
            archive=evaluator_private_archive,
            receipt_path=evaluator_bundle_receipt,
        ),
        "environment_lock": _component_material(
            repo_root=repo_root,
            components=components,
            relative=environment_lock_relative,
            label="environment lock",
        ),
        "scoring_profile": _component_material(
            repo_root=repo_root,
            components=components,
            relative=scoring_profile_relative,
            label="scoring profile",
        ),
        "runner_lock": _runner_lock_material(
            repo_root=repo_root,
            components=components,
            relative=runner_lock_relative,
        ),
        "protocol_release": _protocol_material(
            repo_root=repo_root,
            receipt_path=protocol_release_receipt,
            expected_receipt_sha256=expected_protocol_release_sha256,
        ),
    }
    missing_roles = [
        role for role, material in materials.items()
        if material["status"] != "verified"
    ]
    release_freeze_missing_roles = [
        role
        for role in ("environment_lock", "scoring_profile", "runner_lock")
        if materials[role]["release_freeze_verified"] is not True
    ]
    all_release_freezes_verified = not release_freeze_missing_roles
    schema_path = repo_root / SCHEMA_RELATIVE
    public_archive_builder_path = repo_root / PUBLIC_ARCHIVE_BUILDER_RELATIVE
    public_archive_schema_path = repo_root / PUBLIC_ARCHIVE_SCHEMA_RELATIVE
    declaration_schema_path = (
        repo_root / RELEASE_FREEZE_DECLARATION_SCHEMA_RELATIVE
    )
    builder_path = Path(__file__).resolve(strict=True)
    result = {
        "schema_version": "rtlflowbench.task_release_materials.v1",
        "observed_at": observed_at,
        "task_id": task_id,
        "candidate_release": lock["candidate_release"],
        "candidate_lock_sha256": lock_sha256,
        "status": "complete_candidate_bound" if not missing_roles else "incomplete",
        "materials": materials,
        "missing_roles": missing_roles,
        "all_required_materials_verified": not missing_roles,
        "release_freeze_missing_roles": release_freeze_missing_roles,
        "all_release_freezes_verified": all_release_freezes_verified,
        "benchmark_ready": False,
        "chipflow_adapter_ready": False,
        "source": {
            "builder_sha256": _sha256(builder_path),
            "schema_sha256": _sha256(schema_path),
            "public_archive_builder_sha256": _sha256(
                public_archive_builder_path
            ),
            "public_archive_schema_sha256": _sha256(
                public_archive_schema_path
            ),
            "release_freeze_declaration_schema_sha256": _sha256(
                declaration_schema_path
            ),
        },
        "excluded_claims": [
            "A release-material receipt is not independent benchmark admission.",
            "Evaluator-private assets remain forbidden from workflow workspaces.",
            "Packaging verification does not establish ChipFlow adapter readiness.",
            "Candidate-bound environment, scoring, and runner files remain unusable for release until their explicit freeze markers are verified.",
            "No AIRTL result, PPA, performance, human-level, or superhuman claim is made.",
        ],
    }
    schema = _load(schema_path, "release materials schema")
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--task-id", required=True)
    parser.add_argument("--observed-at", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--public-archive", type=Path)
    parser.add_argument("--evaluator-private-archive", type=Path)
    parser.add_argument("--evaluator-bundle-receipt", type=Path)
    parser.add_argument("--environment-lock-relative")
    parser.add_argument("--scoring-profile-relative")
    parser.add_argument("--runner-lock-relative")
    parser.add_argument("--protocol-release-receipt", type=Path)
    parser.add_argument("--expected-protocol-release-sha256")
    args = parser.parse_args()
    try:
        result = build_release_materials(
            repo_root=args.repo_root,
            task_id=args.task_id,
            observed_at=args.observed_at,
            public_archive=args.public_archive,
            evaluator_private_archive=args.evaluator_private_archive,
            evaluator_bundle_receipt=args.evaluator_bundle_receipt,
            environment_lock_relative=args.environment_lock_relative,
            scoring_profile_relative=args.scoring_profile_relative,
            runner_lock_relative=args.runner_lock_relative,
            protocol_release_receipt=args.protocol_release_receipt,
            expected_protocol_release_sha256=args.expected_protocol_release_sha256,
        )
    except Exception as exc:
        print(json.dumps({"status": "invalid_evidence", "error": f"{type(exc).__name__}: {exc}"}, indent=2, sort_keys=True))
        return 2
    output = args.output.expanduser().resolve()
    if output.exists() or output.is_symlink():
        print("refusing to overwrite output")
        return 2
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
