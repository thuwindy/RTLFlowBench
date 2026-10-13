#!/usr/bin/env python3
"""Release the workflow-neutral RTLFlowBench protocol after live review.

The protocol candidate checker and detached-signature verifier are executed
live.  This finalizer never trusts a stored check or review-verification JSON.
"""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


SCHEMA_RELATIVE = (
    "benchmarks/golden12/admission/protocol_release_result.schema.json"
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


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
        raise ValueError(f"module must be a regular non-symlink file: {path}")
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ValueError(f"could not load module: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _parse_observed_at(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("--observed-at must include a timezone")
    return parsed


def evaluate_protocol_release(
    *,
    repo_root: Path,
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
    parsed_observed_at = _parse_observed_at(observed_at)
    if SHA256_RE.fullmatch(expected_finalizer_sha256) is None:
        raise ValueError("expected finalizer SHA256 must be a lowercase digest")
    repo_root = repo_root.expanduser().resolve(strict=True)
    finalizer_path = Path(__file__).resolve(strict=True)
    finalizer_sha256 = _sha256(finalizer_path)
    if finalizer_sha256 != expected_finalizer_sha256:
        raise ValueError("finalizer source differs from the out-of-band trust anchor")

    protocol_root = repo_root / "benchmarks/golden12/protocol"
    lock_path = protocol_root / "candidate.lock.json"
    lock = _load(lock_path, "protocol candidate lock")
    if lock.get("candidate_release") != "rtlflowbench-protocol-v1":
        raise ValueError("unexpected protocol candidate release")
    lock_sha256 = _sha256(lock_path)

    checker_path = protocol_root / "check.py"
    checker = _load_module("rtlflowbench_protocol_release_checker", checker_path)
    candidate_check = checker.check_protocol_candidate(
        repo_root=repo_root,
        observed_at=parsed_observed_at.date().isoformat(),
    )
    candidate_schema_path = protocol_root / "result.schema.json"
    candidate_schema = _load(candidate_schema_path, "protocol candidate schema")
    Draft202012Validator.check_schema(candidate_schema)
    Draft202012Validator(
        candidate_schema, format_checker=FormatChecker()
    ).validate(candidate_check)
    if candidate_check.get("status") == "invalid_evidence":
        raise ValueError("live protocol candidate checker found invalid evidence")

    verifier_path = protocol_root / "verify_review_attestations.py"
    verifier = _load_module("rtlflowbench_protocol_release_verifier", verifier_path)
    review = verifier.verify_attestations(
        repo_root=repo_root,
        candidate_lock_path=lock_path,
        review_policy_path=protocol_root / "review_policy.json",
        review_policy_component_path=(
            "benchmarks/golden12/protocol/review_policy.json"
        ),
        review_packet_path=protocol_root / "review_packet.json",
        attestation_schema_path=protocol_root / "review_attestation.schema.json",
        registry_schema_path=protocol_root / "trusted_reviewers.schema.json",
        governance_attestation_schema_path=(
            protocol_root / "registry_governance_attestation.schema.json"
        ),
        registry_path=registry_path.expanduser().resolve(),
        allowed_signers_path=allowed_signers_path.expanduser().resolve(),
        attestations_root=attestations_root.expanduser().resolve(),
        observed_at=observed_at,
        governance_attestation_path=(
            governance_attestation_path.expanduser().resolve()
            if governance_attestation_path else None
        ),
        governance_signature_path=(
            governance_signature_path.expanduser().resolve()
            if governance_signature_path else None
        ),
        governance_allowed_signers_path=(
            governance_allowed_signers_path.expanduser().resolve()
            if governance_allowed_signers_path else None
        ),
        expected_governance_allowed_signers_sha256=(
            expected_governance_allowed_signers_sha256
        ),
    )
    if review.get("status") == "invalid_evidence":
        raise ValueError("live protocol review verifier rejected invalid evidence")
    if review.get("candidate_lock_sha256") != lock_sha256:
        raise ValueError("live review targets a different protocol candidate")
    if review.get("candidate_release") != lock.get("candidate_release"):
        raise ValueError("live review targets a different protocol release")

    automatic_complete = bool(
        candidate_check.get("automatic_gates")
        and all(
            gate.get("status") == "pass"
            for gate in candidate_check["automatic_gates"]
        )
    )
    cryptographic_complete = review.get("cryptographic_verification_complete") is True
    governance_complete = bool(
        review.get("registry_independently_approved") is True
        and review.get("registry_governance_verified_by_external_anchor") is True
    )
    decisions_complete = review.get("all_review_decisions_approved") is True
    review_complete = bool(
        cryptographic_complete
        and governance_complete
        and decisions_complete
        and review.get("independent_review_complete") is True
    )
    blockers: list[str] = []
    if not automatic_complete:
        blockers.append("protocol_automatic_gates_incomplete")
    if not cryptographic_complete:
        blockers.append("review_cryptographic_verification_incomplete")
    if not governance_complete:
        blockers.append("review_registry_governance_incomplete")
    if not decisions_complete:
        blockers.append("review_decisions_incomplete")
    released = not blockers
    candidate_check_sha256 = _canonical_sha256(candidate_check)
    review_sha256 = _canonical_sha256(review)
    subject = {
        "candidate_release": lock["candidate_release"],
        "candidate_lock_sha256": lock_sha256,
        "live_candidate_check_sha256": candidate_check_sha256,
        "live_review_verification_sha256": review_sha256,
    }
    schema_path = repo_root / SCHEMA_RELATIVE
    result = {
        "schema_version": "rtlflowbench.protocol_release_result.v1",
        "observed_at": observed_at,
        "candidate_release": lock["candidate_release"],
        "candidate_lock_sha256": lock_sha256,
        "status": "released" if released else "BLOCK",
        "decision": "RELEASE" if released else "BLOCK",
        "blockers": blockers,
        "automatic_gates_complete": automatic_complete,
        "independent_review_complete": review_complete,
        "protocol_ready": released,
        "external_protocol_use_permitted": released,
        "release_subject_sha256": _canonical_sha256(subject),
        "input_sha256": {
            "candidate_lock": lock_sha256,
            "live_candidate_check": candidate_check_sha256,
            "live_review_verification": review_sha256,
        },
        "source": {
            "finalizer_sha256": finalizer_sha256,
            "expected_finalizer_sha256": expected_finalizer_sha256,
            "finalizer_trust_anchor_digest_match": True,
            "result_schema_sha256": _sha256(schema_path),
            "candidate_checker_sha256": _sha256(checker_path),
            "review_verifier_sha256": _sha256(verifier_path),
        },
        "excluded_claims": [
            "Protocol release is not RTL functional correctness.",
            "Protocol release does not admit any Golden-12 task.",
            "Protocol release does not establish any workflow adapter readiness.",
            "No AIRTL score, PPA, performance, human-level, or superhuman result is claimed.",
        ],
    }
    schema = _load(schema_path, "protocol release result schema")
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(
        schema, format_checker=FormatChecker()
    ).validate(result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--trusted-reviewers", type=Path, required=True)
    parser.add_argument("--allowed-signers", type=Path, required=True)
    parser.add_argument("--attestations-root", type=Path, required=True)
    parser.add_argument("--registry-governance-attestation", type=Path)
    parser.add_argument("--registry-governance-signature", type=Path)
    parser.add_argument("--governance-allowed-signers", type=Path)
    parser.add_argument("--expected-governance-allowed-signers-sha256")
    parser.add_argument("--observed-at", required=True)
    parser.add_argument("--expected-finalizer-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--require-release", action="store_true")
    args = parser.parse_args()
    try:
        result = evaluate_protocol_release(
            repo_root=args.repo_root,
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
    if args.require_release and not result["protocol_ready"]:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
