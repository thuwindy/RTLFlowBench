#!/usr/bin/env python3
"""Build an exact, fail-closed Golden-12 release-freeze preflight.

The output is a private release-authority proposal.  It binds the current
candidate locks and release-material selections, derives an exact frozen
budget proposal, and identifies every input that still prevents a freeze.
It never edits a public packet, creates an approval, reuses a signature, or
changes benchmark/adapter readiness.
"""

from __future__ import annotations

import argparse
from copy import deepcopy
from datetime import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import runpy
import sys
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
POLICY_RELATIVE = ADMISSION_ROOT / "release_freeze_policy_candidate.json"
POLICY_SCHEMA_RELATIVE = (
    ADMISSION_ROOT / "release_freeze_policy_candidate.schema.json"
)
OUTPUT_SCHEMA_RELATIVE = ADMISSION_ROOT / "release_freeze_preflight.schema.json"
SELECTION_RELATIVE = ADMISSION_ROOT / "release_material_selection.json"
SELECTION_SCHEMA_RELATIVE = (
    ADMISSION_ROOT / "release_material_selection.schema.json"
)
OFFLINE_REGISTRY_SCHEMA_RELATIVE = Path(
    "benchmarks/golden12/evaluation/offline_evaluator_registry.schema.json"
)
PROTOCOL_CANDIDATE_LOCK_RELATIVE = Path(
    "benchmarks/golden12/protocol/candidate.lock.json"
)
TASK_SCHEMA_RELATIVE = Path("benchmarks/golden12/schemas/task.schema.json")
PUBLIC_PACKAGER_RELATIVE = Path("benchmarks/golden12/conformance/package_public.py")
RELEASE_MATERIAL_BUILDER_RELATIVE = (
    ADMISSION_ROOT / "build_release_materials.py"
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


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
        schema,
        format_checker=FormatChecker(),
    ).validate(value)


def _parse_observed_at(value: str) -> None:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("--observed-at must include a timezone")


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ValueError(f"could not load module: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _require_external_output(repo_root: Path, output_dir: Path) -> None:
    try:
        output_dir.relative_to(repo_root)
    except ValueError:
        return
    raise ValueError("freeze preflight output must remain outside the repository")


def _write_new(path: Path, value: dict[str, Any]) -> None:
    if path.exists() or path.is_symlink():
        raise FileExistsError(f"refusing to overwrite output: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _public_content_digest(packager: Any, public_root: Path) -> str:
    task_root = public_root.parent
    observed_root, files = packager._public_files(task_root)
    if observed_root != public_root.resolve():
        raise ValueError("public packager resolved an unexpected task root")
    manifest = packager._content_manifest(observed_root, files)
    return packager._canonical_json_sha256(manifest)


def _proposed_budget(
    current: dict[str, Any], policy: dict[str, Any]
) -> dict[str, Any]:
    result = deepcopy(current)
    result["status"] = "frozen"
    result["llm_calls"] = {"maximum": policy["maximum_llm_calls"]}
    result["human_interventions"] = {
        "maximum": policy["maximum_human_interventions"]
    }
    result["tokens"] = {
        "accounting_policy": policy["token_accounting_policy"],
        "maximum_input_tokens": policy["maximum_input_tokens"],
        "maximum_output_tokens": policy["maximum_output_tokens"],
        "missing_measurement_policy": policy[
            "missing_token_measurement_policy"
        ],
    }
    return result


def _proposed_public_budget(
    current: dict[str, Any], policy: dict[str, Any]
) -> dict[str, Any]:
    result = deepcopy(current)
    result["status"] = "frozen"
    result["limits"] = {
        **result["limits"],
        "maximum_llm_calls": policy["maximum_llm_calls"],
        "maximum_human_interventions": policy[
            "maximum_human_interventions"
        ],
        "maximum_input_tokens": policy["maximum_input_tokens"],
        "maximum_output_tokens": policy["maximum_output_tokens"],
        "token_accounting_policy": policy["token_accounting_policy"],
        "missing_token_measurement_policy": policy[
            "missing_token_measurement_policy"
        ],
    }
    result["measurement_status"] = "not_exercised"
    result["excluded_claims"] = [
        "This is an exact frozen-budget proposal pending independent review.",
        "No resource use, runtime, score, performance, or PPA measurement is reported.",
    ]
    return result


def _material_projection(
    *,
    release_materials: Any,
    repo_root: Path,
    components: dict[str, str],
    relative: str,
    role: str,
) -> dict[str, Any]:
    material = release_materials._component_material(
        repo_root=repo_root,
        components=components,
        relative=relative,
        label=role.replace("_", " "),
    )
    if material["relative_path"] is None or material["sha256"] is None:
        raise ValueError(f"selected {role} is not available")
    return {
        "role": role,
        "relative_path": material["relative_path"],
        "sha256": material["sha256"],
        "candidate_component_bound": material["candidate_component_bound"],
        "current_release_freeze_status": material["release_freeze_status"],
        "current_release_freeze_verified": material[
            "release_freeze_verified"
        ],
        "proposed_release_freeze_status": "release_frozen",
        "review_status": "pending_independent_review",
        "effective": False,
    }


def _runner_projection(
    *,
    repo_root: Path,
    task_id: str,
    registry_entry: dict[str, Any],
    registry_sources: dict[str, str],
) -> dict[str, Any]:
    paths = {
        "entrypoint": registry_entry["runner_path"],
        "candidate": registry_entry["runner_candidate_path"],
        "candidate_schema": registry_entry["runner_candidate_schema_path"],
        "receipt_schema": registry_entry["runner_receipt_schema_path"],
    }
    observed: dict[str, str] = {}
    for role, relative in paths.items():
        path = repo_root / relative
        digest = _sha256(path)
        if registry_sources.get(relative) != digest:
            raise ValueError(
                f"runner registry source closure drift: {task_id} {role}"
            )
        observed[role] = digest

    candidate = _load(repo_root / paths["candidate"], f"{task_id} runner candidate")
    _validate(
        candidate,
        repo_root / paths["candidate_schema"],
        f"{task_id} runner candidate",
    )
    if candidate.get("task_id") != task_id:
        raise ValueError(f"runner candidate task identity drift: {task_id}")
    previous = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        namespace = runpy.run_path(str(repo_root / paths["entrypoint"]))
        candidate_verifier = namespace.get("_verify_candidate_sources")
        profile_verifier = namespace.get("_verify_profile")
        if callable(candidate_verifier):
            source_observed = candidate_verifier(candidate)
        elif callable(profile_verifier):
            _, verified_profile_path, source_observed = profile_verifier(task_id)
            if verified_profile_path.resolve() != (repo_root / paths["candidate"]).resolve():
                raise ValueError(f"runner profile resolution drift: {task_id}")
        else:
            raise ValueError(f"runner has no source-closure verifier: {task_id}")
    finally:
        sys.dont_write_bytecode = previous
    if not isinstance(source_observed, dict) or not source_observed:
        raise ValueError(f"runner source closure is empty: {task_id}")
    if observed["entrypoint"] not in source_observed.values():
        raise ValueError(f"runner entrypoint digest is outside candidate closure: {task_id}")

    frozen = bool(
        candidate.get("runner_frozen") is True
        or candidate.get("status") in {"release_frozen", "frozen"}
    )
    return {
        "role": "runner_lock",
        "registry_status": registry_entry["status"],
        "entrypoint_relative": paths["entrypoint"],
        "entrypoint_sha256": observed["entrypoint"],
        "candidate_relative": paths["candidate"],
        "candidate_sha256": observed["candidate"],
        "candidate_schema_relative": paths["candidate_schema"],
        "candidate_schema_sha256": observed["candidate_schema"],
        "receipt_schema_relative": paths["receipt_schema"],
        "receipt_schema_sha256": observed["receipt_schema"],
        "source_closure_file_count": len(source_observed),
        "source_closure_verified": True,
        "current_release_freeze_verified": frozen,
        "proposed_release_freeze_status": "release_frozen",
        "review_status": "pending_independent_review",
        "effective": False,
    }


def build_release_freeze_preflight(
    *, repo_root: Path, output_dir: Path, observed_at: str
) -> dict[str, Any]:
    _parse_observed_at(observed_at)
    repo_root = repo_root.expanduser().resolve(strict=True)
    output_dir = output_dir.expanduser().resolve()
    _require_external_output(repo_root, output_dir)
    if output_dir.exists() or output_dir.is_symlink():
        raise FileExistsError(f"refusing to overwrite output: {output_dir}")

    policy_path = repo_root / POLICY_RELATIVE
    policy = _load(policy_path, "freeze policy candidate")
    _validate(
        policy,
        repo_root / POLICY_SCHEMA_RELATIVE,
        "freeze policy candidate",
    )
    if tuple(policy["task_ids"]) != TASK_IDS:
        raise ValueError("freeze policy does not cover exactly Golden-12")

    selection_path = repo_root / SELECTION_RELATIVE
    selection = _load(selection_path, "release material selection")
    _validate(
        selection,
        repo_root / SELECTION_SCHEMA_RELATIVE,
        "release material selection",
    )
    if tuple(selection["tasks"]) != TASK_IDS:
        raise ValueError("release material selection order/coverage drifted")

    registry_relative = selection["offline_evaluator_registry_relative"]
    registry_path = repo_root / registry_relative
    registry = _load(registry_path, "offline evaluator registry")
    _validate(
        registry,
        repo_root / OFFLINE_REGISTRY_SCHEMA_RELATIVE,
        "offline evaluator registry",
    )
    registry_rows = {row["task_id"]: row for row in registry["tasks"]}
    if tuple(registry_rows) != TASK_IDS:
        raise ValueError("offline evaluator registry order/coverage drifted")
    registry_sources = registry.get("source_sha256")
    if not isinstance(registry_sources, dict):
        raise ValueError("offline evaluator registry has no source map")
    for relative, expected in registry_sources.items():
        if _sha256(repo_root / relative) != expected:
            raise ValueError(f"offline evaluator registry source drift: {relative}")
    protocol_lock_path = repo_root / PROTOCOL_CANDIDATE_LOCK_RELATIVE
    protocol_lock = _load(protocol_lock_path, "protocol candidate lock")
    protocol_components = protocol_lock.get("component_sha256")
    registry_candidate_bound = bool(
        isinstance(protocol_components, dict)
        and protocol_components.get(registry_relative) == _sha256(registry_path)
    )

    task_schema_path = repo_root / TASK_SCHEMA_RELATIVE
    public_packager_path = repo_root / PUBLIC_PACKAGER_RELATIVE
    release_material_builder_path = (
        repo_root / RELEASE_MATERIAL_BUILDER_RELATIVE
    )
    packager = _load_module(
        public_packager_path,
        "rtlflowbench_release_freeze_public_packager",
    )
    release_materials = _load_module(
        release_material_builder_path,
        "rtlflowbench_release_freeze_material_builder",
    )

    rows: list[dict[str, Any]] = []
    for task_id in TASK_IDS:
        task_root = repo_root / "benchmarks/golden12/tasks" / task_id
        public_root = task_root / "public"
        external_path = public_root / "external_task.json"
        public_budget_path = public_root / "budget.json"
        rights_path = public_root / "rights_review.json"
        lock_path = task_root / "private/admission/candidate.lock.json"
        descriptor = _load(external_path, f"{task_id} external task")
        public_budget = _load(public_budget_path, f"{task_id} public budget")
        rights = _load(rights_path, f"{task_id} rights receipt")
        lock = _load(lock_path, f"{task_id} candidate lock")
        _validate(descriptor, task_schema_path, f"{task_id} external task")
        if descriptor.get("task_id") != task_id or lock.get("task_id") != task_id:
            raise ValueError(f"task identity drift: {task_id}")
        components = lock.get("component_sha256")
        if not isinstance(components, dict):
            raise ValueError(f"candidate lock has no component map: {task_id}")

        selected = selection["tasks"][task_id]
        if selected["missing_candidate_components"]:
            raise ValueError(f"release material selection is incomplete: {task_id}")
        environment = _material_projection(
            release_materials=release_materials,
            repo_root=repo_root,
            components=components,
            relative=selected["environment_lock_relative"],
            role="environment_lock",
        )
        scoring = _material_projection(
            release_materials=release_materials,
            repo_root=repo_root,
            components=components,
            relative=selected["scoring_profile_relative"],
            role="scoring_profile",
        )
        runner = _runner_projection(
            repo_root=repo_root,
            task_id=task_id,
            registry_entry=registry_rows[task_id],
            registry_sources=registry_sources,
        )

        public_digest = _public_content_digest(packager, public_root)
        descriptor_template = deepcopy(descriptor)
        descriptor_template["benchmark_version"] = policy[
            "benchmark_version_target"
        ]
        descriptor_template["packet_status"] = "frozen"
        descriptor_template["rights"] = {
            **descriptor_template["rights"],
            "status": "approved",
            "redistribution_review_complete": True,
        }
        descriptor_template["public_packet"] = {
            **descriptor_template["public_packet"],
            "digest_status": "frozen",
            "sha256": None,
        }
        descriptor_template["budget"] = _proposed_budget(
            descriptor["budget"], policy["budget_policy"]
        )
        descriptor_template["evaluation_contract"] = {
            **descriptor_template["evaluation_contract"],
            "evaluator_status": "frozen",
        }
        validation_projection = deepcopy(descriptor_template)
        validation_projection["public_packet"]["sha256"] = public_digest
        _validate(
            validation_projection,
            task_schema_path,
            f"{task_id} descriptor transition template projection",
        )
        proposed_public_budget = _proposed_public_budget(
            public_budget, policy["budget_policy"]
        )

        rights_ready = bool(
            rights.get("status") == "approved"
            and rights.get("rights_review_complete") is True
            and rights.get("independent_reviewer")
            and rights.get("signed_at")
        )
        all_bound = bool(
            components.get(
                external_path.relative_to(repo_root).as_posix()
            )
            == _sha256(external_path)
            and environment["candidate_component_bound"]
            and scoring["candidate_component_bound"]
            and registry_candidate_bound
            and runner["source_closure_verified"]
        )
        exact_budget = bool(
            isinstance(
                descriptor_template["budget"]["llm_calls"]["maximum"], int
            )
            and isinstance(
                descriptor_template["budget"]["human_interventions"][
                    "maximum"
                ],
                int,
            )
            and proposed_public_budget["limits"]["maximum_llm_calls"]
            == descriptor_template["budget"]["llm_calls"]["maximum"]
            and proposed_public_budget["limits"]
            ["maximum_human_interventions"]
            == descriptor_template["budget"]["human_interventions"][
                "maximum"
            ]
        )
        blockers = ["release_freeze_policy_pending_independent_review"]
        if not rights_ready:
            blockers.extend(
                [
                    "independent_rights_receipt_missing",
                    "public_digest_must_be_recomputed_after_rights_and_budget_materialization",
                ]
            )
        if not all_bound:
            blockers.append("selected_release_material_not_candidate_bound")
        if not environment["current_release_freeze_verified"]:
            blockers.append("environment_release_freeze_missing")
        if not scoring["current_release_freeze_verified"]:
            blockers.append("scoring_release_freeze_missing")
        if not runner["current_release_freeze_verified"]:
            blockers.append("runner_release_freeze_missing")
        blockers.extend(
            [
                "candidate_relock_and_supersession_pending",
                "new_post_relock_signatures_missing",
                "final_independent_admission_missing",
            ]
        )
        rows.append(
            {
                "task_id": task_id,
                "candidate_lock_sha256": _sha256(lock_path),
                "external_task_sha256": _sha256(external_path),
                "rights_receipt_sha256": _sha256(rights_path),
                "current_public_content_manifest_sha256": public_digest,
                "current_public_budget_sha256": _sha256(public_budget_path),
                "target_public_content_manifest_sha256": None,
                "current_descriptor_state": {
                    "benchmark_version": descriptor["benchmark_version"],
                    "packet_status": descriptor["packet_status"],
                    "rights_status": descriptor["rights"]["status"],
                    "public_digest_status": descriptor["public_packet"][
                        "digest_status"
                    ],
                    "budget_status": descriptor["budget"]["status"],
                    "evaluator_status": descriptor["evaluation_contract"][
                        "evaluator_status"
                    ],
                },
                "descriptor_transition_template_status": (
                    "awaiting_post_materialization_public_digest"
                ),
                "descriptor_transition_template": descriptor_template,
                "proposed_public_budget": proposed_public_budget,
                "exact_budget_proposal_complete": exact_budget,
                "materials": {
                    "environment_lock": environment,
                    "scoring_profile": scoring,
                    "runner": runner,
                },
                "all_selected_materials_candidate_bound": all_bound,
                "public_rights_ready": rights_ready,
                "freeze_transition_eligible": False,
                "blockers": sorted(set(blockers)),
            }
        )

    result = {
        "schema_version": "rtlflowbench.release_freeze_preflight.v1",
        "observed_at": observed_at,
        "status": "blocked_pending_independent_freeze",
        "policy_sha256": _sha256(policy_path),
        "selection_sha256": _sha256(selection_path),
        "task_count": len(rows),
        "exact_budget_proposal_count": sum(
            item["exact_budget_proposal_complete"] for item in rows
        ),
        "candidate_bound_material_count": sum(
            item["all_selected_materials_candidate_bound"] for item in rows
        ),
        "public_rights_ready_count": sum(
            item["public_rights_ready"] for item in rows
        ),
        "environment_release_frozen_count": sum(
            item["materials"]["environment_lock"][
                "current_release_freeze_verified"
            ]
            for item in rows
        ),
        "scoring_release_frozen_count": sum(
            item["materials"]["scoring_profile"][
                "current_release_freeze_verified"
            ]
            for item in rows
        ),
        "runner_source_closure_verified_count": sum(
            item["materials"]["runner"]["source_closure_verified"]
            for item in rows
        ),
        "runner_release_frozen_count": sum(
            item["materials"]["runner"]["current_release_freeze_verified"]
            for item in rows
        ),
        "freeze_transition_eligible_count": 0,
        "tasks": rows,
        "source": {
            "builder_sha256": _sha256(Path(__file__).resolve()),
            "output_schema_sha256": _sha256(
                repo_root / OUTPUT_SCHEMA_RELATIVE
            ),
            "policy_schema_sha256": _sha256(
                repo_root / POLICY_SCHEMA_RELATIVE
            ),
            "selection_schema_sha256": _sha256(
                repo_root / SELECTION_SCHEMA_RELATIVE
            ),
            "offline_evaluator_registry_sha256": _sha256(registry_path),
            "offline_evaluator_registry_schema_sha256": _sha256(
                repo_root / OFFLINE_REGISTRY_SCHEMA_RELATIVE
            ),
            "protocol_candidate_lock_sha256": _sha256(protocol_lock_path),
            "task_schema_sha256": _sha256(task_schema_path),
            "public_packager_sha256": _sha256(public_packager_path),
            "release_material_builder_sha256": _sha256(
                release_material_builder_path
            ),
        },
        "independent_review_complete": False,
        "benchmark_ready": False,
        "chipflow_adapter_ready": False,
        "excluded_claims": [
            "This preflight proposes exact budgets and descriptor templates but does not modify their source files.",
            "The target public digest remains null until approved rights and frozen budget bytes are materialized.",
            "Development environment/scoring/runner files remain release blockers even when candidate-bound and source-closed.",
            "No signature, independent review, relock, admission, benchmark result, score, or PPA claim is created.",
        ],
    }
    _validate(
        result,
        repo_root / OUTPUT_SCHEMA_RELATIVE,
        "release freeze preflight",
    )
    _write_new(output_dir / "release_freeze_preflight.json", result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--observed-at", required=True)
    args = parser.parse_args()
    try:
        result = build_release_freeze_preflight(
            repo_root=args.repo_root,
            output_dir=args.output_dir,
            observed_at=args.observed_at,
        )
    except Exception as exc:
        print(
            json.dumps(
                {
                    "schema_version": "rtlflowbench.release_freeze_preflight.v1",
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
