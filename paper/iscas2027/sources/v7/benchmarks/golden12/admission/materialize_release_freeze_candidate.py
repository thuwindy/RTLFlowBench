#!/usr/bin/env python3
"""Materialize an all-task release-freeze candidate outside the repository.

The builder invokes the existing live cryptographic task-review verifier for
every task.  It requires every non-final review item to be approved and the
external registry-governance chain to be verified, while the final admission
item must still be pending.  Output files are review candidates only: they
cannot be applied or released until a new candidate lock, supersession receipt,
review workspace, registry pin, and signatures are produced for the new bytes.
"""

from __future__ import annotations

import argparse
from copy import deepcopy
from datetime import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
from typing import Any, Callable

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
ADMISSION = Path("benchmarks/golden12/admission")
PREFLIGHT_SCHEMA = ADMISSION / "release_freeze_preflight.schema.json"
PROTOCOL_RELEASE_SCHEMA = ADMISSION / "protocol_release_result.schema.json"
DECLARATION_SCHEMA = ADMISSION / "release_freeze_declaration.schema.json"
RECEIPT_SCHEMA = (
    ADMISSION / "release_freeze_materialization_receipt.schema.json"
)
SELECTION = ADMISSION / "release_material_selection.json"
SELECTION_SCHEMA = ADMISSION / "release_material_selection.schema.json"
TASK_SCHEMA = Path("benchmarks/golden12/schemas/task.schema.json")
PROTOCOL_LOCK = Path("benchmarks/golden12/protocol/candidate.lock.json")
LIVE_REVIEW_FINALIZER = ADMISSION / "evaluate_release_promotion.py"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
FINAL_IDS = {"final_admission", "final_benchmark_admission"}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical_sha256(value: dict[str, Any]) -> str:
    return _sha256_bytes(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )


def _json_bytes(value: dict[str, Any]) -> bytes:
    return (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")


def _load(path: Path, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a regular non-symlink file: {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{label} must contain one JSON object")
    return value


def _validate(value: dict[str, Any], schema_path: Path, label: str) -> None:
    schema = _load(schema_path, f"{label} schema")
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(
        schema, format_checker=FormatChecker()
    ).validate(value)


def _parse_observed_at(value: str) -> None:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("--observed-at must include a timezone")


def _require_external(repo_root: Path, path: Path, label: str) -> Path:
    resolved = path.expanduser().resolve()
    try:
        resolved.relative_to(repo_root)
    except ValueError:
        return resolved
    raise ValueError(f"{label} must remain outside the repository")


def _load_default_review_runner(repo_root: Path) -> Callable[..., Any]:
    path = repo_root / LIVE_REVIEW_FINALIZER
    spec = importlib.util.spec_from_file_location(
        "rtlflowbench_freeze_materialization_live_review", path
    )
    if spec is None or spec.loader is None:
        raise ValueError("could not load live review finalizer")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module._run_live_review


def _preliminary_review(
    *, review: dict[str, Any], task_id: str, candidate_lock_sha256: str
) -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    if review.get("status") == "invalid_evidence":
        raise ValueError(f"live review rejected invalid evidence: {task_id}")
    if review.get("candidate_lock_sha256") != candidate_lock_sha256:
        raise ValueError(f"live review candidate drift: {task_id}")
    if review.get("task_id", task_id) != task_id:
        raise ValueError(f"live review task drift: {task_id}")
    if review.get("registry_independently_approved") is not True:
        raise ValueError(f"review registry governance incomplete: {task_id}")
    if (
        review.get("registry_governance_verified_by_external_anchor")
        is not True
    ):
        raise ValueError(f"external governance anchor missing: {task_id}")
    items = review.get("items")
    if not isinstance(items, list) or not items:
        raise ValueError(f"live review has no item evidence: {task_id}")
    final = [item for item in items if item.get("review_id") in FINAL_IDS]
    if len(final) != 1 or final[0].get("status") != "pending":
        raise ValueError(
            f"exactly one final review must remain pending before relock: {task_id}"
        )
    preliminary = [item for item in items if item not in final]
    if not preliminary or any(
        item.get("status") != "approved"
        or item.get("signature_verified") is not True
        or not isinstance(item.get("reviewer_identity"), str)
        or not item["reviewer_identity"]
        for item in preliminary
    ):
        raise ValueError(
            f"all non-final reviews must be cryptographically approved: {task_id}"
        )
    rights = [
        item
        for item in preliminary
        if "rights" in str(item.get("review_id", "")).lower()
    ]
    if len(rights) != 1:
        raise ValueError(f"could not identify one rights review: {task_id}")
    return preliminary, final[0], rights[0]


def _verified_rights_attestation(
    *,
    attestations_root: Path,
    rights_item: dict[str, Any],
    candidate_lock_sha256: str,
) -> tuple[dict[str, Any], str, str]:
    review_id = rights_item["review_id"]
    attestation_path = attestations_root / f"{review_id}.attestation.json"
    signature_path = Path(str(attestation_path) + ".sig")
    attestation = _load(attestation_path, "rights attestation")
    attestation_sha256 = _sha256(attestation_path)
    signature_sha256 = _sha256(signature_path)
    if (
        attestation_sha256 != rights_item.get("attestation_sha256")
        or signature_sha256 != rights_item.get("signature_sha256")
    ):
        raise ValueError("rights attestation/signature digest drift")
    if (
        attestation.get("candidate_lock_sha256") != candidate_lock_sha256
        or attestation.get("review_id") != review_id
        or attestation.get("decision") != "approve"
        or attestation.get("reviewer", {}).get("identity")
        != rights_item.get("reviewer_identity")
    ):
        raise ValueError("rights attestation disagrees with live verification")
    reviewed_at = attestation.get("reviewed_at")
    if not isinstance(reviewed_at, str):
        raise ValueError("rights attestation has no reviewed_at")
    _parse_observed_at(reviewed_at)
    return attestation, attestation_sha256, signature_sha256


def _approved_rights_receipt(
    *,
    current: dict[str, Any],
    reviewer_identity: str,
    reviewed_at: str,
    attestation_sha256: str,
    signature_sha256: str,
) -> dict[str, Any]:
    result = deepcopy(current)
    result["status"] = "approved"
    result["rights_review_complete"] = True
    result["independent_reviewer"] = reviewer_identity
    result["signed_at"] = reviewed_at
    result["blockers"] = []
    notes = list(result.get("evidence_notes", []))
    notes.append(
        "Pretransition independent rights approval is bound by attestation "
        f"SHA256 {attestation_sha256} and signature SHA256 {signature_sha256}; "
        "the materialized candidate still requires relock and new review."
    )
    result["evidence_notes"] = notes
    return result


def _public_digest_with_overrides(
    *, public_root: Path, overrides: dict[str, bytes]
) -> str:
    entries: list[dict[str, Any]] = []
    observed: set[str] = set()
    for path in sorted(public_root.rglob("*")):
        if path.is_symlink():
            raise ValueError(f"public packet contains symlink: {path}")
        if path.is_dir():
            continue
        if not path.is_file() or not path.resolve().is_relative_to(
            public_root.resolve()
        ):
            raise ValueError(f"public packet contains unsafe entry: {path}")
        relative = path.relative_to(public_root).as_posix()
        if relative == "external_task.json":
            continue
        payload = overrides.get(relative, path.read_bytes())
        observed.add(relative)
        entries.append(
            {
                "path": relative,
                "bytes": len(payload),
                "sha256": _sha256_bytes(payload),
            }
        )
    if set(overrides) - observed:
        raise ValueError("public override targets a missing public file")
    encoded = json.dumps(
        entries,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return _sha256_bytes(encoded)


def _freeze_declaration(
    *,
    task_id: str,
    role: str,
    material: dict[str, Any],
    candidate_lock_sha256: str,
    review: dict[str, Any],
    preliminary: list[dict[str, Any]],
    rights_attestation_sha256: str,
    rights_signature_sha256: str,
) -> dict[str, Any]:
    if role == "runner_lock":
        source_material = {
            "relative_path": material["candidate_relative"],
            "sha256": material["candidate_sha256"],
            "candidate_component_bound": True,
        }
        runner_source_closure = {
            "entrypoint": {
                "relative_path": material["entrypoint_relative"],
                "sha256": material["entrypoint_sha256"],
            },
            "candidate": {
                "relative_path": material["candidate_relative"],
                "sha256": material["candidate_sha256"],
            },
            "candidate_schema": {
                "relative_path": material["candidate_schema_relative"],
                "sha256": material["candidate_schema_sha256"],
            },
            "receipt_schema": {
                "relative_path": material["receipt_schema_relative"],
                "sha256": material["receipt_schema_sha256"],
            },
            "source_closure_file_count": material["source_closure_file_count"],
            "source_closure_verified": material["source_closure_verified"],
        }
    else:
        source_material = {
            "relative_path": material["relative_path"],
            "sha256": material["sha256"],
            "candidate_component_bound": material[
                "candidate_component_bound"
            ],
        }
        runner_source_closure = None
    result = {
        "schema_version": "rtlflowbench.release_freeze_declaration.v1",
        "task_id": task_id,
        "role": role,
        "status": "release_frozen",
        "freeze_status": "release_frozen",
        "independent_freeze": True,
        "source_material": source_material,
        "pretransition_review": {
            "candidate_lock_sha256": candidate_lock_sha256,
            "live_verification_sha256": _canonical_sha256(review),
            "approved_review_ids": sorted(
                item["review_id"] for item in preliminary
            ),
            "reviewer_identities": sorted(
                {item["reviewer_identity"] for item in preliminary}
            ),
            "rights_attestation_sha256": rights_attestation_sha256,
            "rights_signature_sha256": rights_signature_sha256,
        },
        "release_effective": False,
        "benchmark_ready": False,
        "chipflow_adapter_ready": False,
        "excluded_claims": [
            "This material declaration is not a benchmark release.",
            "The post-materialization candidate must be relocked and independently re-reviewed.",
            "Pretransition detached signatures cannot be reused for the new candidate digest.",
        ],
    }
    if runner_source_closure is not None:
        result["runner_source_closure"] = runner_source_closure
    return result


def _write_new(path: Path, payload: bytes) -> None:
    if path.exists() or path.is_symlink():
        raise FileExistsError(f"refusing to overwrite output: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)


def materialize_release_freeze_candidate(
    *,
    repo_root: Path,
    preflight_path: Path,
    expected_preflight_sha256: str,
    protocol_release_path: Path,
    expected_protocol_release_sha256: str,
    review_root: Path,
    output_dir: Path,
    observed_at: str,
    expected_builder_sha256: str,
    governance_attestation_path: Path | None = None,
    governance_signature_path: Path | None = None,
    governance_allowed_signers_path: Path | None = None,
    expected_governance_allowed_signers_sha256: str | None = None,
    review_runner: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    _parse_observed_at(observed_at)
    for value, label in (
        (expected_preflight_sha256, "expected preflight SHA256"),
        (
            expected_protocol_release_sha256,
            "expected protocol release SHA256",
        ),
        (expected_builder_sha256, "expected builder SHA256"),
    ):
        if SHA256_RE.fullmatch(value) is None:
            raise ValueError(f"{label} must be a lowercase digest")
    repo_root = repo_root.expanduser().resolve(strict=True)
    preflight_path = _require_external(
        repo_root, preflight_path, "preflight receipt"
    ).resolve(strict=True)
    protocol_release_path = _require_external(
        repo_root, protocol_release_path, "protocol release receipt"
    ).resolve(strict=True)
    review_root = _require_external(
        repo_root, review_root, "review root"
    ).resolve(strict=True)
    output_dir = _require_external(
        repo_root, output_dir, "materialization output"
    )
    if output_dir.exists() or output_dir.is_symlink():
        raise FileExistsError(f"refusing to overwrite output: {output_dir}")
    if review_root.is_symlink() or not review_root.is_dir():
        raise ValueError("review root must be a regular directory")
    builder_path = Path(__file__).resolve(strict=True)
    if _sha256(builder_path) != expected_builder_sha256:
        raise ValueError("materializer differs from its out-of-band trust anchor")
    if _sha256(preflight_path) != expected_preflight_sha256:
        raise ValueError("preflight differs from its out-of-band trust anchor")
    if _sha256(protocol_release_path) != expected_protocol_release_sha256:
        raise ValueError(
            "protocol release differs from its out-of-band trust anchor"
        )

    preflight = _load(preflight_path, "release freeze preflight")
    _validate(preflight, repo_root / PREFLIGHT_SCHEMA, "release freeze preflight")
    if (
        preflight.get("task_count") != 12
        or preflight.get("exact_budget_proposal_count") != 12
        or preflight.get("candidate_bound_material_count") != 12
        or preflight.get("benchmark_ready") is not False
    ):
        raise ValueError("preflight is not a complete fail-closed proposal")

    protocol_release = _load(
        protocol_release_path, "protocol release receipt"
    )
    _validate(
        protocol_release,
        repo_root / PROTOCOL_RELEASE_SCHEMA,
        "protocol release receipt",
    )
    if any(
        (
            protocol_release.get("status") != "released",
            protocol_release.get("decision") != "RELEASE",
            protocol_release.get("automatic_gates_complete") is not True,
            protocol_release.get("independent_review_complete") is not True,
            protocol_release.get("protocol_ready") is not True,
            protocol_release.get("external_protocol_use_permitted") is not True,
        )
    ):
        raise ValueError(
            "release-freeze materialization requires a released protocol"
        )
    protocol_lock_path = repo_root / PROTOCOL_LOCK
    protocol_lock = _load(protocol_lock_path, "protocol candidate lock")
    protocol_lock_sha256 = _sha256(protocol_lock_path)
    if (
        protocol_release.get("candidate_lock_sha256")
        != protocol_lock_sha256
        or protocol_release.get("input_sha256", {}).get("candidate_lock")
        != protocol_lock_sha256
    ):
        raise ValueError(
            "protocol release targets a different protocol candidate lock"
        )
    protocol_components = protocol_lock.get("component_sha256")
    if not isinstance(protocol_components, dict):
        raise ValueError("protocol candidate has no component digest map")
    release_control_paths = (
        "benchmarks/golden12/admission/release_freeze_policy_candidate.json",
        "benchmarks/golden12/admission/release_freeze_policy_candidate.schema.json",
        "benchmarks/golden12/admission/build_release_freeze_preflight.py",
        "benchmarks/golden12/admission/release_freeze_preflight.schema.json",
        "benchmarks/golden12/admission/materialize_release_freeze_candidate.py",
        "benchmarks/golden12/admission/release_freeze_materialization_receipt.schema.json",
        "benchmarks/golden12/admission/release_freeze_declaration.schema.json",
        "benchmarks/golden12/admission/release_material_selection.json",
        "benchmarks/golden12/admission/release_material_selection.schema.json",
        "benchmarks/golden12/admission/build_release_materials.py",
        "benchmarks/golden12/admission/release_materials.schema.json",
        "benchmarks/golden12/admission/build_public_release_archive.py",
        "benchmarks/golden12/admission/public_release_archive_receipt.schema.json",
        "benchmarks/golden12/admission/evaluate_release_promotion.py",
        "benchmarks/golden12/admission/release_promotion_result.schema.json",
        "benchmarks/golden12/admission/evaluate_suite_release.py",
        "benchmarks/golden12/admission/suite_release_result.schema.json",
        "benchmarks/golden12/admission/evaluate_protocol_release.py",
        "benchmarks/golden12/admission/protocol_release_result.schema.json",
    )
    for relative in release_control_paths:
        path = repo_root / relative
        if protocol_components.get(relative) != _sha256(path):
            raise ValueError(
                "protocol release does not bind release-freeze control: "
                + relative
            )
    if (
        preflight.get("policy_sha256")
        != protocol_components[
            "benchmarks/golden12/admission/"
            "release_freeze_policy_candidate.json"
        ]
        or preflight.get("source", {}).get("builder_sha256")
        != protocol_components[
            "benchmarks/golden12/admission/"
            "build_release_freeze_preflight.py"
        ]
    ):
        raise ValueError(
            "preflight policy/builder is not the independently released "
            "protocol control"
        )
    preflight_rows = {item["task_id"]: item for item in preflight["tasks"]}
    if tuple(preflight_rows) != TASK_IDS:
        raise ValueError("preflight task order/coverage drifted")

    selection = _load(repo_root / SELECTION, "release material selection")
    _validate(selection, repo_root / SELECTION_SCHEMA, "release material selection")
    selection_candidate = deepcopy(selection)
    selection_candidate["excluded_claims"] = list(
        selection_candidate["excluded_claims"]
    ) + [
        "Materialized freeze declarations remain ineffective until relock and new independent review."
    ]
    task_schema_path = repo_root / TASK_SCHEMA
    declaration_schema_path = repo_root / DECLARATION_SCHEMA
    runner = review_runner or _load_default_review_runner(repo_root)
    staged: dict[str, bytes] = {}
    records: list[dict[str, Any]] = []

    for task_id in TASK_IDS:
        row = preflight_rows[task_id]
        task_root = repo_root / "benchmarks/golden12/tasks" / task_id
        public_root = task_root / "public"
        lock_path = task_root / "private/admission/candidate.lock.json"
        lock_sha256 = _sha256(lock_path)
        if lock_sha256 != row["candidate_lock_sha256"]:
            raise ValueError(f"candidate lock drift after preflight: {task_id}")
        task_review_root = review_root / task_id
        attestations_root = task_review_root / "attestations"
        review, _verifier_path = runner(
            repo_root=repo_root,
            task_id=task_id,
            registry_path=task_review_root / "trusted_reviewers.json",
            allowed_signers_path=task_review_root / "allowed_signers",
            attestations_root=attestations_root,
            observed_at=observed_at,
            governance_attestation_path=governance_attestation_path,
            governance_signature_path=governance_signature_path,
            governance_allowed_signers_path=governance_allowed_signers_path,
            expected_governance_allowed_signers_sha256=(
                expected_governance_allowed_signers_sha256
            ),
        )
        preliminary, final_item, rights_item = _preliminary_review(
            review=review,
            task_id=task_id,
            candidate_lock_sha256=lock_sha256,
        )
        rights_attestation, rights_attestation_sha256, rights_signature_sha256 = (
            _verified_rights_attestation(
                attestations_root=attestations_root,
                rights_item=rights_item,
                candidate_lock_sha256=lock_sha256,
            )
        )
        current_rights = _load(
            public_root / "rights_review.json", f"{task_id} rights receipt"
        )
        rights = _approved_rights_receipt(
            current=current_rights,
            reviewer_identity=rights_item["reviewer_identity"],
            reviewed_at=rights_attestation["reviewed_at"],
            attestation_sha256=rights_attestation_sha256,
            signature_sha256=rights_signature_sha256,
        )
        budget = row["proposed_public_budget"]
        rights_payload = _json_bytes(rights)
        budget_payload = _json_bytes(budget)
        target_public_digest = _public_digest_with_overrides(
            public_root=public_root,
            overrides={
                "rights_review.json": rights_payload,
                "budget.json": budget_payload,
            },
        )
        descriptor = deepcopy(row["descriptor_transition_template"])
        descriptor["public_packet"]["sha256"] = target_public_digest
        _validate(descriptor, task_schema_path, f"{task_id} frozen descriptor")
        descriptor_payload = _json_bytes(descriptor)

        declarations: dict[str, dict[str, Any]] = {}
        for role in ("environment_lock", "scoring_profile", "runner_lock"):
            material_key = "runner" if role == "runner_lock" else role
            declaration = _freeze_declaration(
                task_id=task_id,
                role=role,
                material=row["materials"][material_key],
                candidate_lock_sha256=lock_sha256,
                review=review,
                preliminary=preliminary,
                rights_attestation_sha256=rights_attestation_sha256,
                rights_signature_sha256=rights_signature_sha256,
            )
            _validate(
                declaration,
                declaration_schema_path,
                f"{task_id} {role} freeze declaration",
            )
            declarations[role] = declaration

        task_prefix = f"benchmarks/golden12/tasks/{task_id}"
        files = {
            f"{task_prefix}/public/rights_review.json": rights_payload,
            f"{task_prefix}/public/budget.json": budget_payload,
            f"{task_prefix}/public/external_task.json": descriptor_payload,
            f"{task_prefix}/private/release/environment_lock.json": _json_bytes(
                declarations["environment_lock"]
            ),
            f"{task_prefix}/private/release/scoring_profile.json": _json_bytes(
                declarations["scoring_profile"]
            ),
            f"{task_prefix}/private/release/runner_lock.json": _json_bytes(
                declarations["runner_lock"]
            ),
        }
        staged.update(files)
        selection_candidate["tasks"][task_id].update(
            {
                "environment_lock_relative": (
                    f"{task_prefix}/private/release/environment_lock.json"
                ),
                "scoring_profile_relative": (
                    f"{task_prefix}/private/release/scoring_profile.json"
                ),
                "runner_lock_relative": (
                    f"{task_prefix}/private/release/runner_lock.json"
                ),
                "missing_candidate_components": [],
            }
        )
        records.append(
            {
                "task_id": task_id,
                "pretransition_candidate_lock_sha256": lock_sha256,
                "live_review_verification_sha256": _canonical_sha256(review),
                "preliminary_review_complete": True,
                "final_review_status": final_item["status"],
                "target_public_content_manifest_sha256": target_public_digest,
                "files": [
                    {
                        "relative_path": relative,
                        "sha256": _sha256_bytes(payload),
                        "bytes": len(payload),
                    }
                    for relative, payload in sorted(files.items())
                ],
                "relock_required": True,
                "new_review_required": True,
                "benchmark_ready": False,
                "chipflow_adapter_ready": False,
            }
        )

    _validate(
        selection_candidate,
        repo_root / SELECTION_SCHEMA,
        "release material selection candidate",
    )
    selection_payload = _json_bytes(selection_candidate)
    selection_relative = SELECTION.as_posix()
    staged[selection_relative] = selection_payload
    receipt = {
        "schema_version": (
            "rtlflowbench.release_freeze_materialization_receipt.v1"
        ),
        "observed_at": observed_at,
        "status": "materialized_candidate_pending_relock_review",
        "classification": "release_authority_only",
        "preflight_sha256": expected_preflight_sha256,
        "protocol_release_sha256": expected_protocol_release_sha256,
        "protocol_candidate_lock_sha256": protocol_lock_sha256,
        "task_count": 12,
        "tasks": records,
        "selection_candidate": {
            "relative_path": selection_relative,
            "sha256": _sha256_bytes(selection_payload),
        },
        "source": {
            "builder_sha256": _sha256(builder_path),
            "receipt_schema_sha256": _sha256(repo_root / RECEIPT_SCHEMA),
            "declaration_schema_sha256": _sha256(
                declaration_schema_path
            ),
            "preflight_schema_sha256": _sha256(repo_root / PREFLIGHT_SCHEMA),
            "protocol_release_schema_sha256": _sha256(
                repo_root / PROTOCOL_RELEASE_SCHEMA
            ),
            "task_schema_sha256": _sha256(task_schema_path),
            "release_selection_schema_sha256": _sha256(
                repo_root / SELECTION_SCHEMA
            ),
            "live_review_finalizer_sha256": _sha256(
                repo_root / LIVE_REVIEW_FINALIZER
            ),
        },
        "apply_permitted": False,
        "signature_reuse_permitted": False,
        "relock_required": True,
        "new_review_required": True,
        "benchmark_ready_task_count": 0,
        "chipflow_adapter_ready_task_count": 0,
        "suite_ready": False,
        "excluded_claims": [
            "The materialized files are an external release-authority candidate, not an applied source change.",
            "Pretransition signatures cannot be reused after any materialized byte changes.",
            "Every task must be relocked and its review workspace regenerated.",
            "A new externally governed independent review must approve each new candidate-lock digest.",
            "No benchmark readiness, adapter readiness, score, RTL PASS, QoR, PPA, or performance result is claimed.",
        ],
    }
    _validate(
        receipt,
        repo_root / RECEIPT_SCHEMA,
        "release freeze materialization receipt",
    )
    for relative, payload in sorted(staged.items()):
        _write_new(output_dir / "files" / relative, payload)
    _write_new(
        output_dir / "release_freeze_materialization_receipt.json",
        _json_bytes(receipt),
    )
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--preflight", type=Path, required=True)
    parser.add_argument("--expected-preflight-sha256", required=True)
    parser.add_argument("--protocol-release", type=Path, required=True)
    parser.add_argument(
        "--expected-protocol-release-sha256", required=True
    )
    parser.add_argument("--review-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--observed-at", required=True)
    parser.add_argument("--expected-builder-sha256", required=True)
    parser.add_argument("--registry-governance-attestation", type=Path)
    parser.add_argument("--registry-governance-signature", type=Path)
    parser.add_argument("--governance-allowed-signers", type=Path)
    parser.add_argument("--expected-governance-allowed-signers-sha256")
    args = parser.parse_args()
    try:
        result = materialize_release_freeze_candidate(
            repo_root=args.repo_root,
            preflight_path=args.preflight,
            expected_preflight_sha256=args.expected_preflight_sha256,
            protocol_release_path=args.protocol_release,
            expected_protocol_release_sha256=(
                args.expected_protocol_release_sha256
            ),
            review_root=args.review_root,
            output_dir=args.output_dir,
            observed_at=args.observed_at,
            expected_builder_sha256=args.expected_builder_sha256,
            governance_attestation_path=args.registry_governance_attestation,
            governance_signature_path=args.registry_governance_signature,
            governance_allowed_signers_path=args.governance_allowed_signers,
            expected_governance_allowed_signers_sha256=(
                args.expected_governance_allowed_signers_sha256
            ),
        )
    except Exception as exc:
        print(
            json.dumps(
                {
                    "schema_version": (
                        "rtlflowbench.release_freeze_materialization_receipt.v1"
                    ),
                    "status": "BLOCK",
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
