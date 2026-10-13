#!/usr/bin/env python3
"""Promote one Golden-12 technical candidate only after live trusted review.

The finalizer is post-candidate infrastructure.  A release authority must pin
this finalizer and both derived input receipts out of band.  Review signatures
are always re-verified against the current candidate; a saved review-result
JSON is never accepted as an input.
"""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import re
import sys
from typing import Any, Callable

from jsonschema import Draft202012Validator, FormatChecker


GENERIC_TASKS = {
    "G02-common-rr-arbiter-spec",
    "G03-axis-fifo-backpressure",
    "G04-wb2axip-split-bridge",
    "G05-picorv32-missing-irq",
    "G06-ibex-debug-csr-exception",
    "G07-ibex-ifetch-error-timing",
    "G10-serv-area-qor",
    "G11-picorv32-qor",
}
SPECIAL_TASKS = {
    "G01-common-fifo-spec": "verify_g01_attestations",
    "G08-common-fifo-dv": "verify_g08_attestations",
    "G09-axis-fifo-dv": "verify_g09_attestations",
    "G12-common-cdc-missing-contract": "verify_g12_attestations",
}
ALL_TASKS = GENERIC_TASKS | set(SPECIAL_TASKS)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
MATERIALS_SCHEMA_RELATIVE = (
    "benchmarks/golden12/admission/release_materials.schema.json"
)
RESULT_SCHEMA_RELATIVE = (
    "benchmarks/golden12/admission/release_promotion_result.schema.json"
)
MATURITY_SCHEMA_RELATIVE = "benchmarks/golden12/maturity/result.schema.json"
TASK_SCHEMA_RELATIVE = "benchmarks/golden12/schemas/task.schema.json"
MATERIALS_BUILDER_RELATIVE = (
    "benchmarks/golden12/admission/build_release_materials.py"
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical_sha256(value: dict[str, Any]) -> str:
    payload = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _load(path: Path, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a regular non-symlink file: {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{label} must contain one JSON object")
    return value


def _load_module(name: str, path: Path):
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"review verifier must be a regular file: {path}")
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ValueError(f"could not load review verifier: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _parse_observed_at(value: str) -> None:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("--observed-at must include a timezone")


def _require_sha256(value: str, label: str) -> None:
    if SHA256_RE.fullmatch(value) is None:
        raise ValueError(f"{label} must be a lowercase SHA256 digest")


def _validate_schema(value: dict[str, Any], schema_path: Path, label: str) -> None:
    schema = _load(schema_path, f"{label} schema")
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(
        schema, format_checker=FormatChecker()
    ).validate(value)


def _verify_candidate_components(repo_root: Path, lock: dict[str, Any]) -> None:
    components = lock.get("component_sha256")
    if not isinstance(components, dict) or not components:
        raise ValueError("candidate lock has no component digest map")
    for relative, expected in sorted(components.items()):
        pure = PurePosixPath(relative)
        if pure.is_absolute() or ".." in pure.parts or not pure.parts:
            raise ValueError(f"unsafe candidate component path: {relative}")
        path = (repo_root / Path(*pure.parts)).resolve(strict=True)
        if not path.is_relative_to(repo_root) or path.is_symlink() or not path.is_file():
            raise ValueError(f"candidate component is not a regular file: {relative}")
        if _sha256(path) != expected:
            raise ValueError(f"candidate component digest drift: {relative}")


def _review_verifier(
    repo_root: Path, task_id: str
) -> tuple[Path, Callable[..., dict[str, Any]], bool]:
    if task_id in GENERIC_TASKS:
        path = repo_root / "benchmarks/golden12/admission/verify_task_review_attestations.py"
        module = _load_module("rtlflowbench_release_generic_verifier", path)
        return path, module.verify_task_attestations, True
    path = (
        repo_root / "benchmarks/golden12/tasks" / task_id
        / "private/admission/verify_review_attestations.py"
    )
    module = _load_module(f"rtlflowbench_release_{task_id[:3]}_verifier", path)
    return path, getattr(module, SPECIAL_TASKS[task_id]), False


def _run_live_review(
    *,
    repo_root: Path,
    task_id: str,
    registry_path: Path,
    allowed_signers_path: Path,
    attestations_root: Path,
    observed_at: str,
    governance_attestation_path: Path | None,
    governance_signature_path: Path | None,
    governance_allowed_signers_path: Path | None,
    expected_governance_allowed_signers_sha256: str | None,
) -> tuple[dict[str, Any], Path]:
    verifier_path, verifier, generic = _review_verifier(repo_root, task_id)
    kwargs: dict[str, Any] = {
        "repo_root": repo_root,
        "registry_path": registry_path.expanduser().resolve(),
        "allowed_signers_path": allowed_signers_path.expanduser().resolve(),
        "attestations_root": attestations_root.expanduser().resolve(),
        "observed_at": observed_at,
        "governance_attestation_path": (
            governance_attestation_path.expanduser().resolve()
            if governance_attestation_path else None
        ),
        "governance_signature_path": (
            governance_signature_path.expanduser().resolve()
            if governance_signature_path else None
        ),
        "governance_allowed_signers_path": (
            governance_allowed_signers_path.expanduser().resolve()
            if governance_allowed_signers_path else None
        ),
        "expected_governance_allowed_signers_sha256": (
            expected_governance_allowed_signers_sha256
        ),
    }
    if generic:
        kwargs["task_id"] = task_id
    result = verifier(**kwargs)
    if not isinstance(result, dict):
        raise ValueError("live review verifier returned a non-object")
    if result.get("status") == "invalid_evidence":
        raise ValueError("live review verifier rejected invalid evidence")
    return result, verifier_path


def evaluate_release_promotion(
    *,
    repo_root: Path,
    task_id: str,
    maturity_result_path: Path,
    expected_maturity_result_sha256: str,
    release_materials_path: Path,
    expected_release_materials_sha256: str,
    registry_path: Path,
    allowed_signers_path: Path,
    attestations_root: Path,
    observed_at: str,
    expected_finalizer_sha256: str,
    governance_attestation_path: Path | None = None,
    governance_signature_path: Path | None = None,
    governance_allowed_signers_path: Path | None = None,
    expected_governance_allowed_signers_sha256: str | None = None,
) -> dict[str, Any]:
    if task_id not in ALL_TASKS:
        raise ValueError(f"unsupported Golden-12 task: {task_id}")
    _parse_observed_at(observed_at)
    for value, label in (
        (expected_maturity_result_sha256, "expected maturity result SHA256"),
        (expected_release_materials_sha256, "expected release materials SHA256"),
        (expected_finalizer_sha256, "expected finalizer SHA256"),
    ):
        _require_sha256(value, label)
    repo_root = repo_root.expanduser().resolve(strict=True)
    finalizer_path = Path(__file__).resolve(strict=True)
    finalizer_sha256 = _sha256(finalizer_path)
    if finalizer_sha256 != expected_finalizer_sha256:
        raise ValueError("finalizer source differs from the out-of-band trust anchor")

    lock_path = (
        repo_root / "benchmarks/golden12/tasks" / task_id
        / "private/admission/candidate.lock.json"
    )
    lock = _load(lock_path, "candidate lock")
    if lock.get("task_id") != task_id:
        raise ValueError("candidate lock task id mismatch")
    _verify_candidate_components(repo_root, lock)
    candidate_lock_sha256 = _sha256(lock_path)

    task_descriptor_relative = (
        f"benchmarks/golden12/tasks/{task_id}/public/external_task.json"
    )
    task_descriptor_path = repo_root / task_descriptor_relative
    task_schema_path = repo_root / TASK_SCHEMA_RELATIVE
    task_descriptor = _load(task_descriptor_path, "public task descriptor")
    _validate_schema(task_descriptor, task_schema_path, "public task descriptor")
    task_descriptor_sha256 = _sha256(task_descriptor_path)
    if task_descriptor.get("task_id") != task_id:
        raise ValueError("public task descriptor task id mismatch")
    if (
        lock.get("component_sha256", {}).get(task_descriptor_relative)
        != task_descriptor_sha256
    ):
        raise ValueError(
            "public task descriptor is not bound by the candidate lock"
        )
    rights = task_descriptor["rights"]
    public_packet = task_descriptor["public_packet"]
    budget = task_descriptor["budget"]
    token_policy = budget["tokens"]["accounting_policy"]
    public_task_descriptor_frozen = bool(
        task_descriptor.get("benchmark_version") == "Golden-12-v1"
        and task_descriptor.get("packet_status") == "frozen"
        and rights.get("status") == "approved"
        and rights.get("redistribution_review_complete") is True
        and public_packet.get("digest_status") == "frozen"
        and isinstance(public_packet.get("sha256"), str)
        and SHA256_RE.fullmatch(public_packet["sha256"]) is not None
        and budget.get("status") == "frozen"
        and token_policy in {
            "enforced_limits",
            "report_only_separate_cohort",
        }
    )
    public_task_descriptor = {
        "relative_path": task_descriptor_relative,
        "sha256": task_descriptor_sha256,
        "candidate_component_bound": True,
        "benchmark_version": task_descriptor["benchmark_version"],
        "packet_status": task_descriptor["packet_status"],
        "rights_status": rights["status"],
        "redistribution_review_complete": rights[
            "redistribution_review_complete"
        ],
        "public_packet_digest_status": public_packet["digest_status"],
        "public_packet_sha256": public_packet["sha256"],
        "budget_status": budget["status"],
        "token_accounting_policy": token_policy,
        "frozen": public_task_descriptor_frozen,
    }

    maturity_path = maturity_result_path.expanduser().resolve(strict=True)
    materials_path = release_materials_path.expanduser().resolve(strict=True)
    maturity_sha256 = _sha256(maturity_path)
    materials_sha256 = _sha256(materials_path)
    if maturity_sha256 != expected_maturity_result_sha256:
        raise ValueError("maturity result differs from its out-of-band trust anchor")
    if materials_sha256 != expected_release_materials_sha256:
        raise ValueError("release materials differ from their out-of-band trust anchor")
    maturity = _load(maturity_path, "maturity result")
    materials = _load(materials_path, "release materials")
    maturity_schema_path = repo_root / MATURITY_SCHEMA_RELATIVE
    materials_schema_path = repo_root / MATERIALS_SCHEMA_RELATIVE
    result_schema_path = repo_root / RESULT_SCHEMA_RELATIVE
    _validate_schema(maturity, maturity_schema_path, "maturity result")
    _validate_schema(materials, materials_schema_path, "release materials")

    if any(value.get("task_id") != task_id for value in (maturity, materials)):
        raise ValueError("derived input task drift")
    lock_release = lock.get("candidate_release")
    maturity_release = maturity.get("candidate_release")
    materials_release = materials.get("candidate_release")
    if materials_release != lock_release:
        raise ValueError("release materials candidate release drift")
    if maturity_release == lock_release:
        release_relation = "exact"
    elif (
        isinstance(lock_release, str)
        and lock_release.endswith("-candidate")
        and maturity_release == lock_release.removesuffix("-candidate")
    ):
        release_relation = "legacy_candidate_suffix"
    else:
        raise ValueError("maturity candidate release is not a safe lock projection")
    if maturity["source"]["candidate_lock_sha256"] != candidate_lock_sha256:
        raise ValueError("maturity result targets a different candidate lock")
    if materials["candidate_lock_sha256"] != candidate_lock_sha256:
        raise ValueError("release materials target a different candidate lock")
    maturity_builder_path = repo_root / "benchmarks/golden12/maturity/build_candidate_maturity.py"
    if maturity["source"]["maturity_builder_sha256"] != _sha256(maturity_builder_path):
        raise ValueError("maturity result was not produced by the current builder")
    if maturity["source"]["result_schema_sha256"] != _sha256(maturity_schema_path):
        raise ValueError("maturity result schema digest drift")
    materials_builder_path = repo_root / MATERIALS_BUILDER_RELATIVE
    if materials["source"]["builder_sha256"] != _sha256(materials_builder_path):
        raise ValueError("release materials were not produced by the current builder")
    if materials["source"]["schema_sha256"] != _sha256(materials_schema_path):
        raise ValueError("release materials schema digest drift")
    freeze_declaration_schema_path = (
        repo_root
        / "benchmarks/golden12/admission/"
        "release_freeze_declaration.schema.json"
    )
    if materials["source"][
        "release_freeze_declaration_schema_sha256"
    ] != _sha256(freeze_declaration_schema_path):
        raise ValueError("release freeze declaration schema digest drift")
    public_archive_builder_path = (
        repo_root
        / "benchmarks/golden12/admission/build_public_release_archive.py"
    )
    public_archive_schema_path = (
        repo_root
        / "benchmarks/golden12/admission/public_release_archive_receipt.schema.json"
    )
    if materials["source"]["public_archive_builder_sha256"] != _sha256(
        public_archive_builder_path
    ):
        raise ValueError("public archive builder digest drift")
    if materials["source"]["public_archive_schema_sha256"] != _sha256(
        public_archive_schema_path
    ):
        raise ValueError("public archive receipt schema digest drift")

    review, review_verifier_path = _run_live_review(
        repo_root=repo_root,
        task_id=task_id,
        registry_path=registry_path,
        allowed_signers_path=allowed_signers_path,
        attestations_root=attestations_root,
        observed_at=observed_at,
        governance_attestation_path=governance_attestation_path,
        governance_signature_path=governance_signature_path,
        governance_allowed_signers_path=governance_allowed_signers_path,
        expected_governance_allowed_signers_sha256=(
            expected_governance_allowed_signers_sha256
        ),
    )
    if review.get("candidate_lock_sha256") != candidate_lock_sha256:
        raise ValueError("live review verifier targets a different candidate lock")
    if review.get("candidate_release") != lock.get("candidate_release"):
        raise ValueError("live review verifier targets a different release")
    if review.get("task_id", task_id) != task_id:
        raise ValueError("live review verifier targets a different task")

    technical_ready = bool(
        maturity.get("technical_candidate_ready") is True
        and maturity.get("status") in {"technical_candidate", "independently_admitted"}
        and maturity.get("automated_gates", {}).get("fail") == 0
        and maturity.get("automated_gates", {}).get("pending") == 0
    )
    cryptographic_complete = review.get("cryptographic_verification_complete") is True
    governance_complete = bool(
        review.get("registry_independently_approved") is True
        and review.get("registry_governance_verified_by_external_anchor") is True
    )
    decisions_complete = review.get("all_review_decisions_approved") is True
    final_items = [
        item for item in review.get("items", [])
        if item.get("review_id") in {"final_admission", "final_benchmark_admission"}
    ]
    final_admission = bool(
        len(final_items) == 1
        and final_items[0].get("status") == "approved"
        and final_items[0].get("signature_verified") is True
    )
    review_complete = bool(
        cryptographic_complete
        and governance_complete
        and decisions_complete
        and final_admission
        and review.get("independent_review_complete") is True
    )
    release_material_freezes_complete = bool(
        materials.get("all_release_freezes_verified") is True
        and not materials.get("release_freeze_missing_roles")
    )
    materials_complete = bool(
        materials.get("all_required_materials_verified") is True
        and materials.get("status") == "complete_candidate_bound"
        and not materials.get("missing_roles")
        and release_material_freezes_complete
    )

    blockers: list[str] = []
    if not technical_ready:
        blockers.append("technical_candidate_incomplete")
    if not public_task_descriptor_frozen:
        blockers.append("public_task_descriptor_not_frozen")
    if not cryptographic_complete:
        blockers.append("review_cryptographic_verification_incomplete")
    if not governance_complete:
        blockers.append("review_registry_governance_incomplete")
    if not decisions_complete:
        blockers.append("review_decisions_incomplete")
    if not final_admission:
        blockers.append("final_admission_missing")
    if not materials_complete:
        blockers.append("release_materials_incomplete")
    released = not blockers
    live_review_sha256 = _canonical_sha256(review)
    subject = {
        "task_id": task_id,
        "candidate_release": lock["candidate_release"],
        "release_projection": {
            "candidate_lock_release": lock_release,
            "maturity_release": maturity_release,
            "relation": release_relation,
        },
        "candidate_lock_sha256": candidate_lock_sha256,
        "public_task_descriptor_sha256": task_descriptor_sha256,
        "maturity_result_sha256": maturity_sha256,
        "release_materials_sha256": materials_sha256,
        "live_review_verification_sha256": live_review_sha256,
    }
    result = {
        "schema_version": "rtlflowbench.task_release_promotion_result.v1",
        "observed_at": observed_at,
        "task_id": task_id,
        "candidate_release": lock["candidate_release"],
        "release_projection": {
            "candidate_lock_release": lock_release,
            "maturity_release": maturity_release,
            "relation": release_relation,
        },
        "candidate_lock_sha256": candidate_lock_sha256,
        "public_task_descriptor": public_task_descriptor,
        "status": "released" if released else "BLOCK",
        "decision": "RELEASE" if released else "BLOCK",
        "blockers": blockers,
        "technical_candidate_ready": technical_ready,
        "public_task_descriptor_frozen": public_task_descriptor_frozen,
        "independent_review_complete": review_complete,
        "release_materials_complete": materials_complete,
        "release_material_freezes_complete": (
            release_material_freezes_complete
        ),
        "benchmark_ready": released,
        "chipflow_adapter_ready": False,
        "published_score_permitted": released,
        "release_subject_sha256": _canonical_sha256(subject),
        "input_sha256": {
            "candidate_lock": candidate_lock_sha256,
            "public_task_descriptor": task_descriptor_sha256,
            "maturity_result": maturity_sha256,
            "expected_maturity_result": expected_maturity_result_sha256,
            "release_materials": materials_sha256,
            "expected_release_materials": expected_release_materials_sha256,
            "maturity_trust_anchor_digest_match": True,
            "release_materials_trust_anchor_digest_match": True,
            "live_review_verification": live_review_sha256,
        },
        "source": {
            "finalizer_sha256": finalizer_sha256,
            "expected_finalizer_sha256": expected_finalizer_sha256,
            "finalizer_trust_anchor_digest_match": True,
            "result_schema_sha256": _sha256(result_schema_path),
            "materials_schema_sha256": _sha256(materials_schema_path),
            "release_freeze_declaration_schema_sha256": _sha256(
                freeze_declaration_schema_path
            ),
            "maturity_schema_sha256": _sha256(maturity_schema_path),
            "task_schema_sha256": _sha256(task_schema_path),
            "review_verifier_sha256": _sha256(review_verifier_path),
        },
        "excluded_claims": [
            "Task benchmark release does not establish ChipFlow adapter readiness.",
            "Independent signatures cannot release a draft or provisional public task descriptor.",
            "A BLOCK result is not a functional, EDA, or workflow failure.",
            "No cross-workflow score exists until frozen-budget benchmark runs complete.",
            "No PPA, performance, human-level, or superhuman claim is made by release promotion.",
        ],
    }
    _validate_schema(result, result_schema_path, "release promotion result")
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--task-id", choices=sorted(ALL_TASKS), required=True)
    parser.add_argument("--maturity-result", type=Path, required=True)
    parser.add_argument("--expected-maturity-result-sha256", required=True)
    parser.add_argument("--release-materials", type=Path, required=True)
    parser.add_argument("--expected-release-materials-sha256", required=True)
    parser.add_argument("--trusted-reviewers", type=Path, required=True)
    parser.add_argument("--allowed-signers", type=Path, required=True)
    parser.add_argument("--attestations-root", type=Path, required=True)
    parser.add_argument("--registry-governance-attestation", type=Path)
    parser.add_argument("--registry-governance-signature", type=Path)
    parser.add_argument("--governance-allowed-signers", type=Path)
    parser.add_argument("--expected-governance-allowed-signers-sha256")
    parser.add_argument("--expected-finalizer-sha256", required=True)
    parser.add_argument("--observed-at", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--require-release", action="store_true")
    args = parser.parse_args()
    try:
        result = evaluate_release_promotion(
            repo_root=args.repo_root,
            task_id=args.task_id,
            maturity_result_path=args.maturity_result,
            expected_maturity_result_sha256=args.expected_maturity_result_sha256,
            release_materials_path=args.release_materials,
            expected_release_materials_sha256=args.expected_release_materials_sha256,
            registry_path=args.trusted_reviewers,
            allowed_signers_path=args.allowed_signers,
            attestations_root=args.attestations_root,
            observed_at=args.observed_at,
            expected_finalizer_sha256=args.expected_finalizer_sha256,
            governance_attestation_path=args.registry_governance_attestation,
            governance_signature_path=args.registry_governance_signature,
            governance_allowed_signers_path=args.governance_allowed_signers,
            expected_governance_allowed_signers_sha256=args.expected_governance_allowed_signers_sha256,
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
    if args.require_release and not result["benchmark_ready"]:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
