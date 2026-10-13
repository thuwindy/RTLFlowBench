#!/usr/bin/env python3
"""Build the twelve-task release-material handoff without copying private assets."""

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


TASK_IDS = (
    "G01-common-fifo-spec", "G02-common-rr-arbiter-spec",
    "G03-axis-fifo-backpressure", "G04-wb2axip-split-bridge",
    "G05-picorv32-missing-irq", "G06-ibex-debug-csr-exception",
    "G07-ibex-ifetch-error-timing", "G08-common-fifo-dv",
    "G09-axis-fifo-dv", "G10-serv-area-qor",
    "G11-picorv32-qor", "G12-common-cdc-missing-contract",
)
ROLES = (
    "public_task_archive", "evaluator_private_archive", "environment_lock",
    "scoring_profile", "runner_lock", "protocol_release",
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load(path: Path, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a regular non-symlink file: {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{label} must contain one JSON object")
    return value


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ValueError(f"could not load module: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _validate(value: dict[str, Any], schema_path: Path, label: str) -> None:
    schema = _load(schema_path, f"{label} schema")
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(value)


def build_release_material_handoff(
    *,
    repo_root: Path,
    review_handoff_root: Path,
    expected_review_handoff_sha256: str,
    output_dir: Path,
    observed_at: str,
    protocol_release_receipt: Path | None = None,
    expected_protocol_release_sha256: str | None = None,
) -> dict[str, Any]:
    parsed = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("--observed-at must include a timezone")
    if SHA256_RE.fullmatch(expected_review_handoff_sha256) is None:
        raise ValueError("expected review handoff SHA256 must be a lowercase digest")
    repo_root = repo_root.expanduser().resolve(strict=True)
    review_handoff_root = review_handoff_root.expanduser().resolve(strict=True)
    output_dir = output_dir.expanduser().resolve()
    for path, label in (
        (review_handoff_root, "review handoff root"),
        (output_dir, "release material output"),
    ):
        try:
            path.relative_to(repo_root)
        except ValueError:
            pass
        else:
            raise ValueError(f"{label} must remain outside the repository")
    if review_handoff_root.is_symlink() or not review_handoff_root.is_dir():
        raise ValueError("review handoff root must be a regular directory")
    if output_dir.exists() or output_dir.is_symlink():
        raise FileExistsError(f"refusing to overwrite output: {output_dir}")

    admission_root = repo_root / "benchmarks/golden12/admission"
    review_receipt_path = review_handoff_root / "golden12_review_handoff_receipt.json"
    review_receipt = _load(review_receipt_path, "review handoff receipt")
    review_digest = _sha256(review_receipt_path)
    if review_digest != expected_review_handoff_sha256:
        raise ValueError("review handoff differs from its out-of-band trust anchor")
    _validate(
        review_receipt,
        admission_root / "review_handoff.schema.json",
        "review handoff receipt",
    )
    if (
        review_receipt.get("task_count") != 12
        or review_receipt.get("workflow_workspace_exposure_permitted") is not False
    ):
        raise ValueError("review handoff is incomplete or exposure-unsafe")

    selection_path = admission_root / "release_material_selection.json"
    selection_schema_path = admission_root / "release_material_selection.schema.json"
    selection = _load(selection_path, "release material selection")
    _validate(selection, selection_schema_path, "release material selection")
    public_builder_path = admission_root / "build_public_release_archive.py"
    materials_builder_path = admission_root / "build_release_materials.py"
    public_builder = _load_module(
        "rtlflowbench_handoff_public_builder", public_builder_path
    )
    materials_builder = _load_module(
        "rtlflowbench_handoff_materials_builder", materials_builder_path
    )
    output_dir.mkdir(parents=True)
    task_records: list[dict[str, Any]] = []
    verified_counts = {role: 0 for role in ROLES}
    missing_counts = {role: 0 for role in ROLES}
    for index, task_id in enumerate(TASK_IDS, start=1):
        task_output = output_dir / "public" / task_id
        public_receipt = public_builder.build_public_release_archive(
            repo_root=repo_root,
            task_id=task_id,
            output_dir=task_output,
            observed_at=observed_at,
        )
        public_archive = task_output / f"{task_id[:3].lower()}-public-input.tar.gz"
        if _sha256(public_archive) != public_receipt["archive_sha256"]:
            raise ValueError(f"public archive receipt drift: {task_id}")
        private_bundle_dir = review_handoff_root / "bundles" / task_id
        private_archives = sorted(private_bundle_dir.glob("*.tar.gz"))
        if len(private_archives) != 1:
            raise ValueError(f"expected one evaluator-private bundle for {task_id}")
        private_receipt = private_bundle_dir / "bundle_receipt.json"
        selected = selection["tasks"][task_id]
        materials = materials_builder.build_release_materials(
            repo_root=repo_root,
            task_id=task_id,
            observed_at=observed_at,
            public_archive=public_archive,
            evaluator_private_archive=private_archives[0],
            evaluator_bundle_receipt=private_receipt,
            environment_lock_relative=selected["environment_lock_relative"],
            scoring_profile_relative=selected["scoring_profile_relative"],
            runner_lock_relative=selected["runner_lock_relative"],
            protocol_release_receipt=protocol_release_receipt,
            expected_protocol_release_sha256=expected_protocol_release_sha256,
        )
        materials_path = output_dir / "materials" / f"{task_id}.json"
        materials_path.parent.mkdir(parents=True, exist_ok=True)
        materials_path.write_text(
            json.dumps(materials, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        statuses = {
            role: materials["materials"][role]["status"] for role in ROLES
        }
        for role, status in statuses.items():
            if status == "verified":
                verified_counts[role] += 1
            else:
                missing_counts[role] += 1
        task_records.append({
            "task_id": task_id,
            "candidate_lock_sha256": materials["candidate_lock_sha256"],
            "materials_receipt_sha256": _sha256(materials_path),
            "status": materials["status"],
            "missing_roles": materials["missing_roles"],
            "material_status": statuses,
        })
    complete_count = sum(record["status"] == "complete_candidate_bound" for record in task_records)
    schema_path = admission_root / "release_material_handoff.schema.json"
    builder_path = Path(__file__).resolve(strict=True)
    result = {
        "schema_version": "rtlflowbench.release_material_handoff.v1",
        "observed_at": observed_at,
        "status": (
            "complete_candidate_bound_not_admitted"
            if complete_count == 12
            else "incomplete_candidate_bound_handoff"
        ),
        "classification": "release_authority_only",
        "task_count": 12,
        "verified_role_counts": verified_counts,
        "complete_task_count": complete_count,
        "missing_role_counts": missing_counts,
        "review_handoff": {
            "receipt_sha256": review_digest,
            "expected_receipt_sha256": expected_review_handoff_sha256,
            "trust_anchor_digest_match": True,
            "workflow_workspace_exposure_permitted": False,
        },
        "tasks": task_records,
        "workflow_workspace_exposure_permitted": False,
        "benchmark_ready_task_count": 0,
        "chipflow_adapter_ready_task_count": 0,
        "suite_ready": False,
        "source": {
            "builder_sha256": _sha256(builder_path),
            "schema_sha256": _sha256(schema_path),
            "selection_sha256": _sha256(selection_path),
            "selection_schema_sha256": _sha256(selection_schema_path),
            "public_archive_builder_sha256": _sha256(public_builder_path),
            "materials_builder_sha256": _sha256(materials_builder_path),
            "materials_schema_sha256": _sha256(admission_root / "release_materials.schema.json"),
            "review_handoff_schema_sha256": _sha256(admission_root / "review_handoff.schema.json"),
        },
        "excluded_claims": [
            "This handoff validates candidate-bound materials but does not admit a task.",
            "Evaluator-private archives are read in place and are not copied into this handoff.",
            "Missing protocol, environment, scoring, runner, or reviewer gates remain blocking.",
            "No AIRTL score, PPA, performance, human-level, or superhuman result is claimed.",
        ],
    }
    _validate(result, schema_path, "release material handoff")
    (output_dir / "release_material_handoff_receipt.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--review-handoff-root", type=Path, required=True)
    parser.add_argument("--expected-review-handoff-sha256", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--observed-at", required=True)
    parser.add_argument("--protocol-release-receipt", type=Path)
    parser.add_argument("--expected-protocol-release-sha256")
    args = parser.parse_args()
    try:
        result = build_release_material_handoff(
            repo_root=args.repo_root,
            review_handoff_root=args.review_handoff_root,
            expected_review_handoff_sha256=args.expected_review_handoff_sha256,
            output_dir=args.output_dir,
            observed_at=args.observed_at,
            protocol_release_receipt=args.protocol_release_receipt,
            expected_protocol_release_sha256=args.expected_protocol_release_sha256,
        )
    except Exception as exc:
        print(json.dumps({"status": "invalid_evidence", "error": f"{type(exc).__name__}: {exc}"}, indent=2, sort_keys=True))
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
