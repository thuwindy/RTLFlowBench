#!/usr/bin/env python3
"""Shared fail-closed admission helpers for Golden-12 task candidates.

This module deliberately separates development evidence from independent
release approval.  It may establish that a content-bound technical candidate
has no known automatic gate failure, but it cannot sign rights, freeze an
environment, or admit a benchmark.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import tarfile
from typing import Any


GENERATED_ADMISSION_PREFIXES = (
    "candidate.lock",
    "review_packet",
    "admission_result",
    "review_bundle_receipt",
)

SHARED_ATTESTATION_COMPONENTS = (
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

REVIEW_IDS = (
    "rights_and_redistribution",
    "public_specification",
    "public_packet_and_projection",
    "hidden_oracle_and_calibration",
    "reference_and_alternates",
    "environment_and_resource_policy",
    "scoring_and_release_digest",
    "final_benchmark_admission",
)
REVIEW_SCOPES = {
    "rights_and_redistribution": "Provenance, attribution, redistribution, and benchmark-use rights.",
    "public_specification": "Independent review and freeze of the public behavioral contract.",
    "public_packet_and_projection": "Public-only packet contents, projection integrity, and release digest.",
    "hidden_oracle_and_calibration": "Private oracle isolation, F2P/P2P calibration, mutation adequacy, and false-positive risk.",
    "reference_and_alternates": "Reference correctness and structurally independent positive alternatives.",
    "environment_and_resource_policy": "Toolchain, container, timeout, resource, repeatability, and network policy freeze.",
    "scoring_and_release_digest": "Scoring semantics, raw metric handling, and immutable release digest.",
    "final_benchmark_admission": "Atomic final admission after every preceding technical and independent gate.",
}

TASK_CONFIGS: dict[str, dict[str, Any]] = {
    "G06-ibex-debug-csr-exception": {
        "candidate_release": "G06-ready-v1",
        "docs_glob": "g06_*.json",
        "evidence": (
            ("repository_projection", "docs/chipflow/research/golden12/g06_repository_projection_receipt.json", ("server_byte_reproducible_not_frozen",)),
            ("public_packet", "docs/chipflow/research/golden12/g06_public_behavioral_packet_receipt.json", ("server_byte_reproducible_with_behavioral_smoke_not_frozen",)),
            ("visible_runner", "docs/chipflow/research/golden12/g06_visible_behavioral_runner_receipt.json", ("development_server_behavioral_calibrated_not_frozen",)),
            ("private_evaluator", "docs/chipflow/research/golden12/g06_private_evaluator_receipt.json", ("development_server_calibrated_not_frozen",)),
            ("hidden_formal_mutation", "docs/chipflow/research/golden12/g06_private_formal_mutation_receipt.json", ("development_server_hidden_formal_mutation_calibrated_not_frozen",)),
            ("multi_domain_preservation_smoke", "docs/chipflow/research/golden12/g06_broad_preservation_receipt.json", ("development_multi_domain_preservation_calibrated_not_admitted",)),
            ("broad_preservation_hermetic_matrix", "benchmarks/golden12/tasks/G06-ibex-debug-csr-exception/private/environment/broad_preservation_hermetic_matrix_receipt.json", ("development_two_positive_hermetic_preservation_calibrated_not_admitted",)),
            ("upstream_regression_feasibility", "benchmarks/golden12/tasks/G06-ibex-debug-csr-exception/private/admission/upstream_regression_feasibility_candidate.json", ("dependency_block_recorded_scoped_replacement_pending_review",)),
        ),
        "known_technical_gaps": (),
    },
    "G07-ibex-ifetch-error-timing": {
        "candidate_release": "G07-ready-v1",
        "docs_glob": "g07_*.json",
        "evidence": (
            ("repository_projection", "docs/chipflow/research/golden12/g07_repository_projection_receipt.json", ("development_server_materialized_not_frozen",)),
            ("public_packet", "docs/chipflow/research/golden12/g07_public_packet_receipt.json", ("development_public_packet_reproduced_not_frozen",)),
            ("visible_runner", "docs/chipflow/research/golden12/g07_visible_runner_receipt.json", ("development_server_calibrated_not_frozen",)),
            ("predicate_calibration", "docs/chipflow/research/golden12/g07_private_predicate_calibration_receipt.json", ("development_private_predicate_calibrated_not_frozen",)),
            ("control_path_calibration", "docs/chipflow/research/golden12/g07_private_control_path_calibration_receipt.json", ("development_instruction_control_path_calibrated_not_full_pipeline_not_frozen",)),
            ("bounded_formal", "docs/chipflow/research/golden12/g07_private_formal_calibration_receipt.json", ("development_bounded_control_path_calibrated_not_admitted",)),
            ("full_core_calibration", "docs/chipflow/research/golden12/g07_private_full_core_calibration_receipt.json", ("development_full_core_write_path_calibrated_not_admitted",)),
            ("full_core_write_set", "docs/chipflow/research/golden12/g07_private_full_core_write_set_calibration_receipt.json", ("development_full_core_write_set_paths_calibrated_not_admitted",)),
            ("combined_private_gates", "docs/chipflow/research/golden12/g07_private_combined_calibration_receipt.json", ("development_composed_private_gates_calibrated_not_admitted",)),
            ("repeatability", "benchmarks/golden12/tasks/G07-ibex-ifetch-error-timing/private/calibration/repeatability_receipt.json", ("development_two_positive_two_run_semantic_repeatability_observed_not_frozen",)),
            ("current_source_calibration", "benchmarks/golden12/calibration/g07_current_source_campaign_receipt_candidate.json", ("development_current_source_calibration_pass_not_frozen",)),
            ("reset_preservation", "docs/chipflow/research/golden12/g07_reset_hermetic_calibration_receipt.json", ("development_reset_and_hermetic_calibrated_not_admitted",)),
            ("hermetic_execution", "docs/chipflow/research/golden12/g07_reset_hermetic_calibration_receipt.json", ("development_reset_and_hermetic_calibrated_not_admitted",)),
        ),
        "known_technical_gaps": (),
    },
    "G11-picorv32-qor": {
        "candidate_release": "G11-ready-v1",
        "docs_glob": "g11_*.json",
        "evidence": (
            ("repository_projection", "benchmarks/golden12/tasks/G11-picorv32-qor/private/repository_projection/receipt.json", ("development_server_reproduced_not_frozen",)),
            ("visible_runner", "benchmarks/golden12/tasks/G11-picorv32-qor/private/calibration/visible_receipt.json", ("pass_not_frozen",)),
            ("rvfi_projection", "benchmarks/golden12/tasks/G11-picorv32-qor/private/calibration/riscv_formal_calibration_receipt.json", ("pass_not_frozen",)),
            ("bounded_preapproval_equivalence", "benchmarks/golden12/tasks/G11-picorv32-qor/private/calibration/public_preapproval_equivalence_receipt.json", ("development_server_depth4_calibrated_not_frozen",)),
            ("bounded_top_output_characterization", "benchmarks/golden12/tasks/G11-picorv32-qor/private/calibration/top_output_bmc_calibration_receipt.json", ("development_depth10_four_of_five_behavior_kills_not_frozen",)),
            ("hidden_differential", "benchmarks/golden12/tasks/G11-picorv32-qor/private/calibration/hidden_calibration_receipt.json", ("development_bounded_calibrated_not_frozen",)),
            ("hidden_f2p_expansion", "benchmarks/golden12/tasks/G11-picorv32-qor/private/calibration/hidden_f2p_expansion_receipt.json", ("development_five_mutant_kills_observed_not_frozen",)),
            ("workload_calibration", "benchmarks/golden12/tasks/G11-picorv32-qor/private/calibration/workload_calibration_receipt.json", ("development_upstream_workload_calibrated_not_frozen",)),
            ("alternate_calibration", "benchmarks/golden12/tasks/G11-picorv32-qor/private/calibration/orfs_alternate_calibration_receipt.json", ("development_two_alternates_calibrated_not_frozen",)),
            ("false_improvement_calibration", "benchmarks/golden12/tasks/G11-picorv32-qor/private/calibration/orfs_false_improvement_receipt.json", ("development_false_improvement_calibrated_not_frozen",)),
            ("physical_calibration", "benchmarks/golden12/tasks/G11-picorv32-qor/private/calibration/orfs_physical_calibration_receipt.json", ("development_calibration_pass_not_frozen",)),
            ("repeatability", "benchmarks/golden12/tasks/G11-picorv32-qor/private/repeatability/repeatability_receipt.json", ("development_five_run_observed_not_frozen",)),
            ("positive_physical_repeatability", "benchmarks/golden12/calibration/g11_positive_physical_repeatability_receipt_candidate.json", ("development_positive_repeatability_observed_not_frozen",)),
            ("scoring_calibration", "benchmarks/golden12/tasks/G11-picorv32-qor/private/calibration/scoring_calibration_receipt.json", ("development_five_case_calibrated_not_frozen",)),
            ("qor_positive_candidate", "benchmarks/golden12/tasks/G11-picorv32-qor/private/calibration/qor_positive_candidate_receipt.json", ("development_correct_qor_positive_pending_complete_equivalence_and_freeze",)),
            ("complete_transform_equivalence", "benchmarks/golden12/tasks/G11-picorv32-qor/private/calibration/positive_qor_transform_proof_receipt.json", ("development_exhaustive_transform_proof_calibrated_not_frozen",)),
            ("complete_hidden_functional_preservation", "benchmarks/golden12/tasks/G11-picorv32-qor/private/calibration/unified_preservation_receipt.json", ("development_complete_frozen_config_preservation_chain_calibrated_not_frozen",)),
            ("complete_formal_or_isa_equivalence", "benchmarks/golden12/tasks/G11-picorv32-qor/private/calibration/full_equivalence_calibration_receipt.json", ("development_full_frozen_configuration_equivalence_calibrated_not_frozen",)),
            ("environment_candidate", "benchmarks/golden12/tasks/G11-picorv32-qor/private/qor/orfs/current_environment_evidence_candidate.json", ("development_physical_repeatability_observed_not_frozen",)),
            ("scoring_candidate", "benchmarks/golden12/tasks/G11-picorv32-qor/private/scoring/scoring_profile.json", ("development_not_frozen",)),
        ),
        "known_technical_gaps": (),
    },
}


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sha256(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain one JSON object")
    return value


def _is_generated_admission_control(path: Path, admission: Path) -> bool:
    if path.parent != admission:
        return False
    name = path.name
    return any(
        name == f"{prefix}.json" or name.startswith(f"{prefix}.")
        for prefix in GENERATED_ADMISSION_PREFIXES
    )


def _task_root(repo_root: Path, task_id: str) -> Path:
    if task_id not in TASK_CONFIGS:
        raise ValueError(f"unsupported admission task: {task_id}")
    root = repo_root / "benchmarks/golden12/tasks" / task_id
    if not root.is_dir() or root.is_symlink():
        raise ValueError(f"invalid task root: {root}")
    return root


def _regular_files(root: Path) -> list[Path]:
    if not root.is_dir() or root.is_symlink():
        raise ValueError(f"invalid candidate tree root: {root}")
    result: list[Path] = []
    for path in sorted(root.rglob("*")):
        if "__pycache__" in path.parts or path.suffix == ".pyc":
            continue
        if path.is_symlink():
            raise ValueError(f"candidate tree contains symlink: {path}")
        if path.is_file():
            result.append(path)
    return result


def _candidate_paths(repo_root: Path, task_id: str) -> list[Path]:
    task_root = _task_root(repo_root, task_id)
    paths = set(_regular_files(task_root))
    admission = task_root / "private/admission"
    paths = {
        path for path in paths
        if not _is_generated_admission_control(path, admission)
    }
    paths.add(repo_root / "benchmarks/golden12/admission/common.py")
    paths.update(
        repo_root / relative
        for relative in SHARED_ATTESTATION_COMPONENTS
    )
    paths.update(
        repo_root / relative
        for _, relative, _ in TASK_CONFIGS[task_id]["evidence"]
    )
    task_prefix = task_id[:3].lower()
    paths.update(
        (repo_root / "benchmarks/golden12/calibration").glob(
            f"{task_prefix}_*current_source*receipt_candidate.json"
        )
    )
    paths.update(_regular_files(repo_root / "benchmarks/golden12/schemas"))
    docs = repo_root / "docs/chipflow/research/golden12"
    paths.update(
        path for path in docs.glob(TASK_CONFIGS[task_id]["docs_glob"])
        if "admission_development_receipt" not in path.name
        and "review_bundle_receipt" not in path.name
    )
    test_pattern = f"test_chipflow_golden12_{task_id[:3].lower()}_*.py"
    paths.update((repo_root / "backend/tests").glob(test_pattern))
    paths.add(repo_root / "backend/tests/test_chipflow_golden12_remaining_admission.py")
    return sorted(paths)


def build_candidate_lock(
    *, repo_root: Path, task_id: str, observed_at: str
) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    components: dict[str, str] = {}
    for path in _candidate_paths(repo_root, task_id):
        resolved = path.resolve()
        if (
            not resolved.is_relative_to(repo_root)
            or not resolved.is_file()
            or resolved.is_symlink()
        ):
            raise ValueError(f"invalid candidate component: {path}")
        components[resolved.relative_to(repo_root).as_posix()] = sha256(resolved)
    candidate_status = (
        "development_evidence_candidate_pending_technical_and_independent_gates"
        if TASK_CONFIGS[task_id]["known_technical_gaps"]
        else "development_evidence_candidate_pending_independent_gates"
    )
    return {
        "schema_version": "rtlflowbench.release_candidate_lock.v1",
        "task_id": task_id,
        "candidate_release": TASK_CONFIGS[task_id]["candidate_release"],
        "observed_at": observed_at,
        "status": candidate_status,
        "benchmark_ready": False,
        "chipflow_adapter_ready": False,
        "public_archive_sha256": None,
        "component_sha256": components,
        "registry_projection": {
            "manifest_locked": False,
            "reason": "The central manifest is excluded until an atomic multi-task registry projection is independently frozen.",
        },
        "pending_approvals": list(REVIEW_IDS),
        "excluded_claims": [
            "This development lock is not an independent signature or benchmark admission.",
            "Development EDA receipts are not a frozen environment or canonical score.",
            "Benchmark and ChipFlow adapter readiness remain false.",
            "No PPA, performance, human-level, or superhuman result is claimed.",
        ],
    }


def build_review_packet(
    *, repo_root: Path, task_id: str, observed_at: str
) -> dict[str, Any]:
    task_root = _task_root(repo_root.resolve(), task_id)
    lock_path = task_root / "private/admission/candidate.lock.json"
    policy = load_json(task_root / "private/admission/review_policy.json")
    lock = load_json(lock_path)
    if lock.get("task_id") != task_id:
        raise ValueError("candidate lock task id mismatch")
    policy_ids = tuple(item["review_id"] for item in policy["review_items"])
    if policy_ids != REVIEW_IDS:
        raise ValueError("review policy ids do not match the fail-closed baseline")
    return {
        "schema_version": "rtlflowbench.independent_review_packet.v1",
        "task_id": task_id,
        "candidate_release": lock["candidate_release"],
        "observed_at": observed_at,
        "status": "pending_independent_review",
        "candidate_lock_sha256": sha256(lock_path),
        "self_approval_forbidden": True,
        "benchmark_ready": False,
        "chipflow_adapter_ready": False,
        "review_items": [
            {
                "review_id": review_id,
                "scope": REVIEW_SCOPES[review_id],
                "status": "pending",
                "independent_reviewer": None,
                "signed_at": None,
                "signed_candidate_lock_sha256": None,
                "notes": None,
            }
            for review_id in REVIEW_IDS
        ],
        "excluded_claims": [
            "Packet generation is not review or approval.",
            "Only an eligible independent reviewer may complete these items.",
        ],
    }


def _gate(gate_id: str, status: str, detail: str, evidence: str) -> dict[str, str]:
    return {"gate_id": gate_id, "status": status, "detail": detail, "evidence": evidence}


def _component_issues(repo_root: Path, lock: dict[str, Any]) -> list[str]:
    components = lock.get("component_sha256")
    if not isinstance(components, dict) or not components:
        return ["candidate lock has no components"]
    issues: list[str] = []
    for relative, expected in sorted(components.items()):
        pure = PurePosixPath(relative)
        if pure.is_absolute() or ".." in pure.parts:
            issues.append(f"unsafe component path: {relative}")
            continue
        path = (repo_root / Path(*pure.parts)).resolve()
        if not path.is_relative_to(repo_root) or not path.is_file() or path.is_symlink():
            issues.append(f"missing or unsafe component: {relative}")
        elif sha256(path) != expected:
            issues.append(f"component digest drift: {relative}")
    return issues


def _public_private_issues(task_root: Path) -> list[str]:
    public = task_root / "public"
    private = task_root / "private"
    issues: list[str] = []
    public_digests: dict[str, str] = {}
    for path in _regular_files(public):
        relative = path.relative_to(public).as_posix()
        public_digests[relative] = sha256(path)
        if "private" in path.relative_to(public).parts:
            issues.append(f"public path contains private segment: {relative}")
    private_rtl = {
        sha256(path): path.relative_to(task_root).as_posix()
        for path in _regular_files(private)
        if path.suffix.lower() in {".v", ".sv", ".vh", ".svh"}
    }
    for relative, digest in public_digests.items():
        if digest in private_rtl:
            issues.append(
                f"public file duplicates evaluator-private RTL: {relative} == {private_rtl[digest]}"
            )
    return issues


def check_admission(
    *, repo_root: Path, task_id: str, observed_at: str
) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    task_root = _task_root(repo_root, task_id)
    admission_root = task_root / "private/admission"
    lock_path = admission_root / "candidate.lock.json"
    packet_path = admission_root / "review_packet.json"
    lock = load_json(lock_path)
    packet = load_json(packet_path)
    policy = load_json(admission_root / "review_policy.json")
    public_admission = load_json(task_root / "public/admission.json")
    rights = load_json(task_root / "public/rights_review.json")

    automatic: list[dict[str, str]] = []
    component_issues = _component_issues(repo_root, lock)
    expected_lock_status = (
        "development_evidence_candidate_pending_technical_and_independent_gates"
        if TASK_CONFIGS[task_id]["known_technical_gaps"]
        else "development_evidence_candidate_pending_independent_gates"
    )
    lock_ok = (
        not component_issues
        and lock.get("task_id") == task_id
        and lock.get("status") == expected_lock_status
        and lock.get("benchmark_ready") is False
        and lock.get("chipflow_adapter_ready") is False
        and lock.get("public_archive_sha256") is None
    )
    automatic.append(_gate(
        "candidate_lock", "pass" if lock_ok else "fail",
        "All locked components are current and readiness remains false." if lock_ok else "; ".join(component_issues) or "candidate lock metadata is invalid",
        lock_path.relative_to(repo_root).as_posix(),
    ))

    isolation_issues = _public_private_issues(task_root)
    automatic.append(_gate(
        "public_private_isolation", "pass" if not isolation_issues else "fail",
        "No public file duplicates evaluator-private RTL." if not isolation_issues else "; ".join(isolation_issues),
        f"benchmarks/golden12/tasks/{task_id}/public",
    ))

    rights_pending = (
        rights.get("task_id") == task_id
        and rights.get("rights_review_complete") is False
        and rights.get("independent_reviewer") is None
        and rights.get("status") == "pending_independent_review"
        and public_admission.get("rights_review_complete") is False
        and public_admission.get("independent_review_complete") is False
        and public_admission.get("benchmark_status") == "not_ready"
    )
    automatic.append(_gate(
        "readiness_fail_closed", "pass" if rights_pending else "fail",
        "Unsigned rights and admission fields remain explicitly not_ready." if rights_pending else "public readiness or rights metadata overclaims approval",
        f"benchmarks/golden12/tasks/{task_id}/public/admission.json",
    ))

    for gate_id, relative, accepted in TASK_CONFIGS[task_id]["evidence"]:
        path = repo_root / relative
        try:
            evidence = load_json(path)
            ok = (
                evidence.get("status") in accepted
                and evidence.get("task_id", task_id) == task_id
                and isinstance(evidence.get("schema_version"), str)
            )
            detail = (
                f"Content-locked development evidence reports {evidence.get('status')}; no freeze is inferred."
                if ok else f"unexpected evidence status or task binding: {evidence.get('status')}"
            )
        except Exception as exc:
            ok = False
            detail = f"{type(exc).__name__}: {exc}"
        automatic.append(_gate(gate_id, "pass" if ok else "fail", detail, relative))

    for gate_id, detail, evidence in TASK_CONFIGS[task_id]["known_technical_gaps"]:
        automatic.append(_gate(gate_id, "pending", detail, evidence))

    packet_ok = (
        packet.get("task_id") == task_id
        and packet.get("candidate_lock_sha256") == sha256(lock_path)
        and packet.get("status") == "pending_independent_review"
        and packet.get("self_approval_forbidden") is True
        and packet.get("benchmark_ready") is False
        and packet.get("chipflow_adapter_ready") is False
        and tuple(item.get("review_id") for item in packet.get("review_items", [])) == REVIEW_IDS
        and all(
            item.get("status") == "pending"
            and item.get("independent_reviewer") is None
            and item.get("signed_candidate_lock_sha256") is None
            for item in packet.get("review_items", [])
        )
        and policy.get("self_approval_forbidden") is True
    )
    automatic.append(_gate(
        "independent_review_handoff", "pass" if packet_ok else "fail",
        "Eight unsigned review items bind the current candidate without self-approval." if packet_ok else "review packet is stale, incomplete, or overclaims approval",
        packet_path.relative_to(repo_root).as_posix(),
    ))

    independent = [
        _gate(review_id, "pending", "Independent signature and freeze have not been supplied.", packet_path.relative_to(repo_root).as_posix())
        for review_id in REVIEW_IDS
    ]
    automatic_failures = [gate["gate_id"] for gate in automatic if gate["status"] == "fail"]
    automatic_pending = [gate["gate_id"] for gate in automatic if gate["status"] == "pending"]
    benchmark_ready = not automatic_failures and not automatic_pending and all(gate["status"] == "pass" for gate in independent)
    return {
        "schema_version": "rtlflowbench.admission_result.v1",
        "task_id": task_id,
        "candidate_release": TASK_CONFIGS[task_id]["candidate_release"],
        "observed_at": observed_at,
        "status": (
            "automatic_gate_fail"
            if automatic_failures
            else "development_candidate_with_technical_gaps"
            if automatic_pending
            else "development_technical_candidate_pending_independent_review"
        ),
        "benchmark_ready": benchmark_ready,
        "chipflow_adapter_ready": False,
        "candidate_lock_sha256": sha256(lock_path),
        "automatic_gates": automatic,
        "independent_gates": independent,
        "counts": {
            "automatic_pass": sum(gate["status"] == "pass" for gate in automatic),
            "automatic_fail": len(automatic_failures),
            "automatic_pending": len(automatic_pending),
            "independent_pending": len(independent),
        },
        "excluded_claims": [
            "Automatic Gate PASS does not freeze or admit the benchmark.",
            "This checker cannot act as an independent reviewer.",
            "ChipFlow adapter readiness is evaluated separately.",
        ],
    }


def _tar_payload(members: dict[str, bytes]) -> bytes:
    plain = io.BytesIO()
    with tarfile.open(fileobj=plain, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name, payload in sorted(members.items()):
            info = tarfile.TarInfo(name=name)
            info.size = len(payload)
            info.mode = 0o644
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mtime = 0
            archive.addfile(info, io.BytesIO(payload))
    compressed = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=compressed, mtime=0, compresslevel=9) as output:
        output.write(plain.getvalue())
    return compressed.getvalue()


def build_review_bundle(
    *, repo_root: Path, task_id: str, output_dir: Path, observed_at: str
) -> dict[str, Any]:
    if output_dir.exists():
        raise FileExistsError(f"refusing to overwrite output: {output_dir}")
    repo_root = repo_root.resolve()
    task_root = _task_root(repo_root, task_id)
    admission_root = task_root / "private/admission"
    lock_path = admission_root / "candidate.lock.json"
    packet_path = admission_root / "review_packet.json"
    lock = load_json(lock_path)
    packet = load_json(packet_path)
    lock_sha = sha256(lock_path)
    if packet.get("candidate_lock_sha256") != lock_sha:
        raise ValueError("review packet targets a different candidate lock")
    members: dict[str, bytes] = {}
    entries: list[dict[str, Any]] = []
    for relative, expected in sorted(lock["component_sha256"].items()):
        source = (repo_root / relative).resolve()
        payload = source.read_bytes()
        observed = _sha256_bytes(payload)
        if observed != expected:
            raise ValueError(f"candidate component digest drift: {relative}")
        name = f"candidate/{PurePosixPath(relative)}"
        members[name] = payload
        entries.append({
            "path": name,
            "role": "locked_candidate_component",
            "bytes": len(payload),
            "sha256": observed,
        })
    for name, source in {
        "control/candidate.lock.json": lock_path,
        "control/review_packet.json": packet_path,
    }.items():
        payload = source.read_bytes()
        members[name] = payload
        entries.append({
            "path": name,
            "role": "control",
            "bytes": len(payload),
            "sha256": _sha256_bytes(payload),
        })
    manifest = {
        "schema_version": "rtlflowbench.review_bundle_manifest.v1",
        "task_id": task_id,
        "candidate_release": lock["candidate_release"],
        "observed_at": observed_at,
        "status": "pending_independent_review",
        "classification": "evaluator_private",
        "workflow_workspace_exposed": False,
        "candidate_lock_sha256": lock_sha,
        "review_packet_sha256": sha256(packet_path),
        "review_items": [
            {"review_id": item["review_id"], "status": item["status"]}
            for item in packet["review_items"]
        ],
        "entries": sorted(entries, key=lambda item: item["path"]),
    }
    manifest_payload = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    members["control/bundle_manifest.json"] = manifest_payload
    output_dir.mkdir(parents=True)
    archive_path = output_dir / f"{task_id[:3].lower()}-independent-review.tar.gz"
    manifest_path = output_dir / "bundle_manifest.json"
    receipt_path = output_dir / "bundle_receipt.json"
    archive_path.write_bytes(_tar_payload(members))
    manifest_path.write_bytes(manifest_payload)
    receipt = {
        "schema_version": "rtlflowbench.review_bundle_receipt.v1",
        "task_id": task_id,
        "observed_at": observed_at,
        "status": "pending_independent_review",
        "classification": "evaluator_private",
        "workflow_workspace_exposed": False,
        "archive_sha256": sha256(archive_path),
        "archive_bytes": archive_path.stat().st_size,
        "manifest_sha256": sha256(manifest_path),
        "candidate_lock_sha256": lock_sha,
        "review_packet_sha256": sha256(packet_path),
        "locked_component_count": len(lock["component_sha256"]),
        "approved_review_item_count": 0,
        "benchmark_ready": False,
        "chipflow_adapter_ready": False,
    }
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return receipt


def write_json_new(path: Path, value: dict[str, Any]) -> None:
    if path.exists():
        raise FileExistsError(f"refusing to overwrite output: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def candidate_main(task_id: str) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--observed-at", required=True)
    args = parser.parse_args()
    value = build_candidate_lock(repo_root=args.repo_root, task_id=task_id, observed_at=args.observed_at)
    write_json_new(args.output.expanduser().resolve(), value)
    print(json.dumps(value, indent=2, sort_keys=True))
    return 0


def review_packet_main(task_id: str) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--observed-at", required=True)
    args = parser.parse_args()
    value = build_review_packet(repo_root=args.repo_root, task_id=task_id, observed_at=args.observed_at)
    write_json_new(args.output.expanduser().resolve(), value)
    print(json.dumps(value, indent=2, sort_keys=True))
    return 0


def check_main(task_id: str) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--observed-at", required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--require-ready", action="store_true")
    args = parser.parse_args()
    result = check_admission(repo_root=args.repo_root, task_id=task_id, observed_at=args.observed_at)
    if args.output:
        write_json_new(args.output.expanduser().resolve(), result)
    print(json.dumps(result, indent=2, sort_keys=True))
    if result["counts"]["automatic_fail"]:
        return 2
    if args.require_ready and not result["benchmark_ready"]:
        return 2
    return 0


def review_bundle_main(task_id: str) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--observed-at", required=True)
    args = parser.parse_args()
    try:
        result = build_review_bundle(repo_root=args.repo_root, task_id=task_id, output_dir=args.output_dir.expanduser().resolve(), observed_at=args.observed_at)
    except Exception as exc:
        print(json.dumps({"status": "fail", "error": f"{type(exc).__name__}: {exc}"}, indent=2, sort_keys=True))
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0
