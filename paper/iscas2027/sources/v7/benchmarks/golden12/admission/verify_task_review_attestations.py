#!/usr/bin/env python3
"""Verify signed review attestations for Golden-12 task candidates.

The verifier is deliberately release-neutral.  It validates external review
signatures and an external registry trust chain, but it never mutates a review
packet and never promotes benchmark or adapter readiness.
"""

from __future__ import annotations

import argparse
from datetime import datetime
import importlib.util
import json
from pathlib import Path
import sys
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


TASKS: dict[str, dict[str, Any]] = {
    "G02-common-rr-arbiter-spec": {
        "candidate_release": "G02-ready-v1",
        "signature_namespace": "rtlflowbench-g02-review",
        "review_ids": (
            "rights_review", "spec_freeze", "alternative_solution_audit",
            "hidden_formal_coverage_audit", "runner_environment_freeze",
            "scoring_budget_freeze", "public_packet_freeze", "final_admission",
        ),
    },
    "G03-axis-fifo-backpressure": {
        "candidate_release": "G03-ready-v1",
        "signature_namespace": "rtlflowbench-g03-review",
        "review_ids": (
            "rights_projection_review", "spec_projection_freeze",
            "alternative_solution_audit", "hidden_oracle_mutation_audit",
            "runner_environment_coverage_freeze",
            "scoring_repeatability_freeze", "public_packet_freeze",
            "final_admission",
        ),
    },
    "G04-wb2axip-split-bridge": {
        "candidate_release": "G04-ready-v1-candidate",
        "signature_namespace": "rtlflowbench-g04-review",
        "review_ids": (
            "rights_projection_review", "specification_freeze",
            "alternate_solution_audit", "evaluator_review",
            "environment_budget_freeze", "scoring_freeze",
            "manifest_projection", "final_admission",
        ),
    },
    "G05-picorv32-missing-irq": {
        "candidate_release": "G05-ready-v1",
        "signature_namespace": "rtlflowbench-g05-review",
        "review_ids": (
            "rights_projection_review", "spec_repository_freeze",
            "alternative_solution_audit",
            "hidden_oracle_mutation_formal_audit",
            "firmware_environment_freeze", "scoring_budget_freeze",
            "public_packet_freeze", "final_admission",
        ),
    },
    "G06-ibex-debug-csr-exception": {
        "candidate_release": "G06-ready-v1",
        "signature_namespace": "rtlflowbench-g06-review",
        "review_ids": (
            "rights_and_redistribution", "public_specification",
            "public_packet_and_projection", "hidden_oracle_and_calibration",
            "reference_and_alternates", "environment_and_resource_policy",
            "scoring_and_release_digest", "final_benchmark_admission",
        ),
    },
    "G07-ibex-ifetch-error-timing": {
        "candidate_release": "G07-ready-v1",
        "signature_namespace": "rtlflowbench-g07-review",
        "review_ids": (
            "rights_and_redistribution", "public_specification",
            "public_packet_and_projection", "hidden_oracle_and_calibration",
            "reference_and_alternates", "environment_and_resource_policy",
            "scoring_and_release_digest", "final_benchmark_admission",
        ),
    },
    "G10-serv-area-qor": {
        "candidate_release": "G10-ready-v1",
        "signature_namespace": "rtlflowbench-g10-review",
        "review_ids": (
            "rights_projection_review", "spec_interface_freeze",
            "hidden_oracle_mutation_audit", "alternative_solution_audit",
            "physical_ppa_environment_freeze", "scoring_budget_freeze",
            "public_private_isolation_release_freeze",
            "adapter_independence_review", "final_admission",
        ),
    },
    "G11-picorv32-qor": {
        "candidate_release": "G11-ready-v1",
        "signature_namespace": "rtlflowbench-g11-review",
        "review_ids": (
            "rights_and_redistribution", "public_specification",
            "public_packet_and_projection", "hidden_oracle_and_calibration",
            "reference_and_alternates", "environment_and_resource_policy",
            "scoring_and_release_digest", "final_benchmark_admission",
        ),
    },
}

SHARED_COMPONENTS = (
    "benchmarks/golden12/admission/attestation_policy.schema.json",
    "benchmarks/golden12/admission/review_attestation.schema.json",
    "benchmarks/golden12/admission/rebind_pending_review_packet.py",
    "benchmarks/golden12/admission/trusted_reviewers.schema.json",
    "benchmarks/golden12/admission/verify_task_review_attestations.py",
    "benchmarks/golden12/protocol/REGISTRY_GOVERNANCE_INSTRUCTIONS.md",
    "benchmarks/golden12/protocol/build_registry_governance_request.py",
    "benchmarks/golden12/protocol/build_unsigned_review_attestation.py",
    "benchmarks/golden12/protocol/prepare_review_workspace.py",
    "benchmarks/golden12/protocol/registry_governance_attestation.schema.json",
    "benchmarks/golden12/protocol/registry_governance_request.schema.json",
    "benchmarks/golden12/protocol/registry_governance_request_receipt.schema.json",
    "benchmarks/golden12/protocol/review_workspace_receipt.schema.json",
    "benchmarks/golden12/protocol/unsigned_review_checklist.schema.json",
    "benchmarks/golden12/protocol/verify_review_attestations.py",
    "backend/tests/test_chipflow_golden12_task_review_attestations.py",
)


def _load(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"must be a regular non-symlink file: {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"must contain one JSON object: {path}")
    return value


def _sha256(path: Path) -> str:
    import hashlib

    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_engine(repo_root: Path):
    path = repo_root / "benchmarks/golden12/protocol/verify_review_attestations.py"
    spec = importlib.util.spec_from_file_location(
        "rtlflowbench_task_shared_review_verifier", path
    )
    if spec is None or spec.loader is None:
        raise ValueError("could not load shared review verifier")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _validate_candidate_contract(
    *, repo_root: Path, task_id: str
) -> tuple[Path, dict[str, Any], dict[str, Any], dict[str, Any]]:
    config = TASKS[task_id]
    admission_root = (
        repo_root / "benchmarks/golden12/tasks" / task_id / "private/admission"
    )
    lock = _load(admission_root / "candidate.lock.json")
    packet = _load(admission_root / "review_packet.json")
    policy_path = admission_root / "attestation_policy.json"
    policy = _load(policy_path)
    policy_schema_path = (
        repo_root / "benchmarks/golden12/admission/attestation_policy.schema.json"
    )
    policy_schema = _load(policy_schema_path)
    Draft202012Validator.check_schema(policy_schema)
    Draft202012Validator(policy_schema).validate(policy)

    if any(value.get("task_id") != task_id for value in (lock, packet, policy)):
        raise ValueError("candidate, packet, and attestation policy task ids differ")
    release = config["candidate_release"]
    if any(
        value.get("candidate_release") != release
        for value in (lock, packet, policy)
    ):
        raise ValueError("candidate, packet, and attestation policy releases differ")
    if policy["signature_namespace"] != config["signature_namespace"]:
        raise ValueError("attestation policy has an unexpected signature namespace")
    required_ids = tuple(config["review_ids"])
    if tuple(policy["required_review_ids"]) != required_ids:
        raise ValueError("attestation policy review ids differ from task contract")
    packet_items = packet.get("review_items")
    if not isinstance(packet_items, list):
        raise ValueError("review packet has no review item list")
    if tuple(item.get("review_id") for item in packet_items) != required_ids:
        raise ValueError("review packet review ids differ from attestation policy")
    review_lists = [("review_items", packet_items)]
    if "reviews" in packet:
        review_lists.append(("reviews", packet["reviews"]))
    for label, items in review_lists:
        if tuple(item.get("review_id") for item in items) != required_ids:
            raise ValueError(f"{label} review ids differ from attestation policy")
        for item in items:
            if item.get("status") != "pending":
                raise ValueError("review packet must remain pending; signatures are external")
            for field in (
                "reviewer", "independent_reviewer", "signed_at",
                "signed_candidate_lock_sha256", "signature_sha256",
            ):
                if item.get(field) is not None:
                    raise ValueError(
                        f"review packet embeds forbidden approval field: {field}"
                    )
    if packet.get("benchmark_ready") not in (None, False):
        raise ValueError("review packet cannot claim benchmark readiness")
    if packet.get("chipflow_adapter_ready") not in (None, False):
        raise ValueError("review packet cannot claim adapter readiness")

    components = lock.get("component_sha256")
    if not isinstance(components, dict):
        raise ValueError("candidate lock has no component digest map")
    task_policy_relative = (
        f"benchmarks/golden12/tasks/{task_id}/private/admission/"
        "attestation_policy.json"
    )
    for relative in (*SHARED_COMPONENTS, task_policy_relative):
        path = repo_root / relative
        if components.get(relative) != _sha256(path):
            raise ValueError(f"candidate lock does not bind current component: {relative}")
    return admission_root, lock, packet, policy


def _validate_external_formats(
    *,
    schema_path: Path,
    registry_schema_path: Path,
    registry_path: Path,
    attestations_root: Path,
    review_ids: set[str],
) -> None:
    attestation_schema = _load(schema_path)
    registry_schema = _load(registry_schema_path)
    for schema in (attestation_schema, registry_schema):
        Draft202012Validator.check_schema(schema)
    registry = _load(registry_path)
    Draft202012Validator(registry_schema).validate(registry)
    identities = [item["identity"] for item in registry["reviewers"]]
    if len(identities) != len(set(identities)):
        raise ValueError("trusted registry contains duplicate reviewer identities")
    if registry["registry_authority"] in set(identities):
        raise ValueError("registry authority must be distinct from reviewers")
    for reviewer in registry["reviewers"]:
        if not set(reviewer["allowed_review_ids"]).issubset(review_ids):
            raise ValueError("registry grants review ids outside the task contract")
    validator = Draft202012Validator(
        attestation_schema, format_checker=FormatChecker()
    )
    for review_id in review_ids:
        path = attestations_root / f"{review_id}.attestation.json"
        if not path.exists():
            continue
        attestation = _load(path)
        validator.validate(attestation)
        reviewed_at = attestation["reviewed_at"]
        parsed = datetime.fromisoformat(
            reviewed_at[:-1] + "+00:00"
            if reviewed_at.endswith("Z")
            else reviewed_at
        )
        if parsed.tzinfo is None:
            raise ValueError("reviewed_at must include a timezone")


def verify_task_attestations(
    *,
    repo_root: Path,
    task_id: str,
    registry_path: Path,
    allowed_signers_path: Path,
    attestations_root: Path,
    observed_at: str,
    governance_attestation_path: Path | None = None,
    governance_signature_path: Path | None = None,
    governance_allowed_signers_path: Path | None = None,
    expected_governance_allowed_signers_sha256: str | None = None,
) -> dict[str, Any]:
    if task_id not in TASKS:
        raise ValueError(f"unsupported task review contract: {task_id}")
    repo_root = repo_root.expanduser().resolve()
    admission_root, _lock, _packet, policy = _validate_candidate_contract(
        repo_root=repo_root, task_id=task_id
    )
    schema_path = repo_root / "benchmarks/golden12/admission/review_attestation.schema.json"
    registry_schema_path = (
        repo_root / "benchmarks/golden12/admission/trusted_reviewers.schema.json"
    )
    review_ids = set(TASKS[task_id]["review_ids"])
    _validate_external_formats(
        schema_path=schema_path,
        registry_schema_path=registry_schema_path,
        registry_path=registry_path,
        attestations_root=attestations_root,
        review_ids=review_ids,
    )
    engine = _load_engine(repo_root)
    policy_relative = (
        f"benchmarks/golden12/tasks/{task_id}/private/admission/"
        "attestation_policy.json"
    )
    result = engine.verify_attestations(
        repo_root=repo_root,
        candidate_lock_path=admission_root / "candidate.lock.json",
        review_policy_path=admission_root / "attestation_policy.json",
        review_policy_component_path=policy_relative,
        review_packet_path=admission_root / "review_packet.json",
        attestation_schema_path=schema_path,
        registry_schema_path=registry_schema_path,
        governance_attestation_schema_path=(
            repo_root / "benchmarks/golden12/protocol/registry_governance_attestation.schema.json"
        ),
        registry_path=registry_path,
        allowed_signers_path=allowed_signers_path,
        attestations_root=attestations_root,
        observed_at=observed_at,
        review_ids=review_ids,
        expected_signature_namespace=policy["signature_namespace"],
        governance_attestation_path=governance_attestation_path,
        governance_signature_path=governance_signature_path,
        governance_allowed_signers_path=governance_allowed_signers_path,
        expected_governance_allowed_signers_sha256=(
            expected_governance_allowed_signers_sha256
        ),
    )
    result["schema_version"] = "rtlflowbench.task_review_verification.v1"
    result["task_id"] = task_id
    result["benchmark_ready"] = False
    result["chipflow_adapter_ready"] = False
    result.pop("protocol_ready", None)
    result["excluded_claims"] = [
        "Signature verification does not prove trust-registry governance.",
        "Calibration keys or a self-created registry cannot admit a task.",
        "The current empty registry allowlist keeps every task pending an independent registry pin and candidate relock.",
        "Verified signatures alone do not freeze or release a benchmark or workflow adapter.",
        "No RTL, DV, QoR, PPA, workflow, human-level, or superhuman PASS is claimed.",
    ]
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--task-id", choices=sorted(TASKS), required=True)
    parser.add_argument("--trusted-reviewers", type=Path, required=True)
    parser.add_argument("--allowed-signers", type=Path, required=True)
    parser.add_argument("--attestations-root", type=Path, required=True)
    parser.add_argument("--registry-governance-attestation", type=Path)
    parser.add_argument("--registry-governance-signature", type=Path)
    parser.add_argument("--governance-allowed-signers", type=Path)
    parser.add_argument("--expected-governance-allowed-signers-sha256")
    parser.add_argument("--observed-at", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--require-complete", action="store_true")
    args = parser.parse_args()
    try:
        result = verify_task_attestations(
            repo_root=args.repo_root,
            task_id=args.task_id,
            registry_path=args.trusted_reviewers.expanduser().resolve(),
            allowed_signers_path=args.allowed_signers.expanduser().resolve(),
            attestations_root=args.attestations_root.expanduser().resolve(),
            observed_at=args.observed_at,
            governance_attestation_path=(
                args.registry_governance_attestation.expanduser().resolve()
                if args.registry_governance_attestation else None
            ),
            governance_signature_path=(
                args.registry_governance_signature.expanduser().resolve()
                if args.registry_governance_signature else None
            ),
            governance_allowed_signers_path=(
                args.governance_allowed_signers.expanduser().resolve()
                if args.governance_allowed_signers else None
            ),
            expected_governance_allowed_signers_sha256=(
                args.expected_governance_allowed_signers_sha256
            ),
        )
    except Exception as exc:
        result = {
            "schema_version": "rtlflowbench.task_review_verification.v1",
            "task_id": args.task_id,
            "observed_at": args.observed_at,
            "status": "invalid_evidence",
            "cryptographic_verification_complete": False,
            "independent_review_complete": False,
            "benchmark_ready": False,
            "chipflow_adapter_ready": False,
            "error": f"{type(exc).__name__}: {exc}",
        }
    output = args.output.expanduser().resolve()
    if output.exists() or output.is_symlink():
        print("refusing to overwrite output")
        return 2
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    if result["status"] == "invalid_evidence":
        return 2
    if args.require_complete and not result["independent_review_complete"]:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
