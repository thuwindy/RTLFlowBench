#!/usr/bin/env python3
"""Build all twelve unsigned Golden-12 reviewer workspaces in one handoff.

The output contains evaluator-private evidence and must stay outside the
repository and every evaluated workflow workspace.  Building this handoff
does not create review decisions, signatures, freezes, or admissions.
"""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any

from jsonschema import Draft202012Validator


CONTROL_ROOT = Path(__file__).resolve().parent
SCHEMA_PATH = CONTROL_ROOT / "review_handoff.schema.json"
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


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ValueError(f"could not load Python module: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _parse_observed_at(value: str) -> None:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("--observed-at must include a timezone")


def _require_outside_repository(repo_root: Path, output_dir: Path) -> None:
    try:
        output_dir.relative_to(repo_root)
    except ValueError:
        return
    raise ValueError(
        "reviewer-only handoff output must remain outside the repository"
    )


def _validate_unsigned(
    *,
    task_id: str,
    bundle_receipt: dict[str, Any],
    workspace_receipt: dict[str, Any],
) -> None:
    if bundle_receipt.get("task_id") != task_id:
        raise ValueError(f"review bundle task mismatch for {task_id}")
    bundle_status = bundle_receipt.get("status")
    allowed_statuses = {"pending_independent_review"}
    if task_id == "G09-axis-fifo-dv":
        allowed_statuses.add("built_pending_reproduction_check")
    if bundle_status not in allowed_statuses:
        raise ValueError(f"review bundle is not pending for {task_id}")
    if bundle_receipt.get("classification") != "evaluator_private":
        raise ValueError(f"review bundle is not private for {task_id}")
    if bundle_receipt.get("workflow_workspace_exposed") is not False:
        raise ValueError(f"review bundle exposure is unsafe for {task_id}")
    if bundle_receipt.get("approved_review_item_count") != 0:
        raise ValueError(f"review bundle contains an approval for {task_id}")
    if workspace_receipt.get("task_id") != task_id:
        raise ValueError(f"review workspace task mismatch for {task_id}")
    if workspace_receipt.get("status") != (
        "verified_unsigned_review_workspace"
    ):
        raise ValueError(f"review workspace is not unsigned for {task_id}")
    for field in (
        "independent_review_complete",
        "benchmark_ready",
        "protocol_ready",
        "workflow_workspace_exposure_permitted",
    ):
        if workspace_receipt.get(field) is not False:
            raise ValueError(
                f"review workspace field must remain false: {task_id}.{field}"
            )
    if workspace_receipt.get("approved_review_item_count") != 0:
        raise ValueError(f"review workspace contains an approval for {task_id}")
    if (
        workspace_receipt.get("source_archive_sha256")
        != bundle_receipt.get("archive_sha256")
    ):
        raise ValueError(f"review workspace archive drift for {task_id}")
    if (
        workspace_receipt.get("candidate_lock_sha256")
        != bundle_receipt.get("candidate_lock_sha256")
    ):
        raise ValueError(f"review workspace candidate drift for {task_id}")


def _validate_protocol_unsigned(
    *,
    bundle_receipt: dict[str, Any],
    workspace_receipt: dict[str, Any],
) -> None:
    if bundle_receipt.get("status") != "pending_independent_review":
        raise ValueError("protocol review bundle is not pending")
    if bundle_receipt.get("classification") != (
        "reviewer_only_protocol_candidate"
    ):
        raise ValueError("protocol review bundle has the wrong classification")
    if bundle_receipt.get("workflow_workspace_exposed") is not False:
        raise ValueError("protocol review bundle exposure is unsafe")
    if bundle_receipt.get("contains_hidden_evaluator_assets") is not False:
        raise ValueError("protocol review bundle contains hidden assets")
    if bundle_receipt.get("approved_review_item_count") != 0:
        raise ValueError("protocol review bundle contains an approval")
    if workspace_receipt.get("task_id") is not None:
        raise ValueError("protocol review workspace unexpectedly targets a task")
    if workspace_receipt.get("candidate_release") != (
        bundle_receipt.get("candidate_release")
    ):
        raise ValueError("protocol review workspace candidate drift")
    if workspace_receipt.get("status") != (
        "verified_unsigned_review_workspace"
    ):
        raise ValueError("protocol review workspace is not unsigned")
    for field in (
        "independent_review_complete",
        "benchmark_ready",
        "protocol_ready",
        "workflow_workspace_exposure_permitted",
    ):
        if workspace_receipt.get(field) is not False:
            raise ValueError(
                f"protocol review workspace field must remain false: {field}"
            )
    if workspace_receipt.get("approved_review_item_count") != 0:
        raise ValueError("protocol review workspace contains an approval")
    if (
        workspace_receipt.get("source_archive_sha256")
        != bundle_receipt.get("archive_sha256")
    ):
        raise ValueError("protocol review workspace archive drift")
    if (
        workspace_receipt.get("candidate_lock_sha256")
        != bundle_receipt.get("candidate_lock_sha256")
    ):
        raise ValueError("protocol review workspace lock drift")


def build_review_handoff(
    *,
    repo_root: Path,
    output_dir: Path,
    observed_at: str,
    acknowledge_reviewer_only_private_evidence: bool,
) -> dict[str, Any]:
    if not acknowledge_reviewer_only_private_evidence:
        raise ValueError(
            "explicit reviewer-only private-evidence acknowledgement is required"
        )
    _parse_observed_at(observed_at)
    repo_root = repo_root.expanduser().resolve(strict=True)
    output_dir = output_dir.expanduser().resolve()
    if output_dir.exists() or output_dir.is_symlink():
        raise FileExistsError(f"refusing to overwrite output: {output_dir}")
    _require_outside_repository(repo_root, output_dir)

    preparer_path = (
        repo_root
        / "benchmarks/golden12/protocol/prepare_review_workspace.py"
    )
    schema_path = (
        repo_root
        / "benchmarks/golden12/admission/review_handoff.schema.json"
    )
    preparer = _load_module(
        "golden12_review_workspace_preparer",
        preparer_path,
    )
    handoff_builder_path = (
        repo_root
        / "benchmarks/golden12/admission/build_review_handoff.py"
    )
    source_sha256: dict[str, str] = {
        handoff_builder_path.relative_to(repo_root).as_posix(): _sha256(
            handoff_builder_path
        ),
        schema_path.relative_to(repo_root).as_posix(): _sha256(schema_path),
        preparer_path.relative_to(repo_root).as_posix(): _sha256(preparer_path),
    }
    protocol_builder_path = (
        repo_root / "benchmarks/golden12/protocol/build_review_bundle.py"
    )
    source_sha256[
        protocol_builder_path.relative_to(repo_root).as_posix()
    ] = _sha256(protocol_builder_path)
    protocol_builder = _load_module(
        "golden12_protocol_review_builder",
        protocol_builder_path,
    )
    protocol_bundle_dir = output_dir / "protocol" / "bundle"
    protocol_bundle_receipt = protocol_builder.build_review_bundle(
        repo_root=repo_root,
        output_dir=protocol_bundle_dir,
        observed_at=observed_at,
    )
    protocol_archives = sorted(protocol_bundle_dir.glob("*.tar.gz"))
    if len(protocol_archives) != 1:
        raise ValueError(
            "expected one protocol review archive, "
            f"found {len(protocol_archives)}"
        )
    protocol_archive = protocol_archives[0]
    protocol_workspace_dir = output_dir / "protocol" / "workspace"
    protocol_workspace_receipt = preparer.prepare_review_workspace(
        archive_path=protocol_archive,
        expected_archive_sha256=protocol_bundle_receipt["archive_sha256"],
        output_dir=protocol_workspace_dir,
        acknowledge_reviewer_only_private_evidence=True,
    )
    _validate_protocol_unsigned(
        bundle_receipt=protocol_bundle_receipt,
        workspace_receipt=protocol_workspace_receipt,
    )
    protocol_record = {
        "candidate_release": protocol_bundle_receipt["candidate_release"],
        "status": "verified_unsigned_review_workspace",
        "bundle_archive_path": protocol_archive.relative_to(
            output_dir
        ).as_posix(),
        "bundle_archive_sha256": protocol_bundle_receipt["archive_sha256"],
        "bundle_archive_bytes": protocol_bundle_receipt["archive_bytes"],
        "bundle_manifest_sha256": protocol_bundle_receipt["manifest_sha256"],
        "bundle_receipt_sha256": _sha256(
            protocol_bundle_dir / "bundle_receipt.json"
        ),
        "candidate_lock_sha256": protocol_bundle_receipt[
            "candidate_lock_sha256"
        ],
        "review_packet_sha256": protocol_bundle_receipt[
            "review_packet_sha256"
        ],
        "locked_component_count": protocol_bundle_receipt[
            "locked_component_count"
        ],
        "review_item_count": protocol_bundle_receipt["review_item_count"],
        "approved_review_item_count": 0,
        "review_workspace_path": protocol_workspace_dir.relative_to(
            output_dir
        ).as_posix(),
        "review_workspace_receipt_sha256": _sha256(
            protocol_workspace_dir / "review_workspace_receipt.json"
        ),
        "unsigned_review_checklist_sha256": _sha256(
            protocol_workspace_dir / "review_checklist.json"
        ),
        "contains_hidden_evaluator_assets": False,
        "independent_review_complete": False,
        "protocol_ready": False,
        "workflow_workspace_exposure_permitted": False,
    }
    task_records: list[dict[str, Any]] = []

    for task_id in TASK_IDS:
        builder_path = (
            repo_root
            / "benchmarks/golden12/tasks"
            / task_id
            / "private/admission/build_review_bundle.py"
        )
        source_sha256[builder_path.relative_to(repo_root).as_posix()] = (
            _sha256(builder_path)
        )
        bundle_dir = output_dir / "bundles" / task_id
        environment = os.environ.copy()
        harness = str(repo_root / "backend/packages/harness")
        environment["PYTHONPATH"] = (
            harness
            if not environment.get("PYTHONPATH")
            else harness + os.pathsep + environment["PYTHONPATH"]
        )
        completed = subprocess.run(
            [
                sys.executable,
                str(builder_path),
                "--repo-root",
                str(repo_root),
                "--output-dir",
                str(bundle_dir),
                "--observed-at",
                observed_at,
            ],
            cwd=repo_root,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
        if completed.returncode != 0:
            raise ValueError(
                f"review bundle builder failed for {task_id}: "
                f"exit {completed.returncode}"
            )
        bundle_receipt = json.loads(
            (bundle_dir / "bundle_receipt.json").read_text(encoding="utf-8")
        )
        archives = sorted(bundle_dir.glob("*.tar.gz"))
        if len(archives) != 1:
            raise ValueError(
                f"expected one review archive for {task_id}, found {len(archives)}"
            )
        archive = archives[0]
        workspace_dir = output_dir / "workspaces" / task_id
        workspace_receipt = preparer.prepare_review_workspace(
            archive_path=archive,
            expected_archive_sha256=bundle_receipt["archive_sha256"],
            output_dir=workspace_dir,
            acknowledge_reviewer_only_private_evidence=True,
        )
        _validate_unsigned(
            task_id=task_id,
            bundle_receipt=bundle_receipt,
            workspace_receipt=workspace_receipt,
        )
        review_packet_path = (
            repo_root
            / "benchmarks/golden12/tasks"
            / task_id
            / "private/admission/review_packet.json"
        )
        review_packet = json.loads(
            review_packet_path.read_text(encoding="utf-8")
        )
        review_items = review_packet.get("review_items", [])
        if (
            review_packet.get("task_id") != task_id
            or review_packet.get("status") != "pending_independent_review"
            or bundle_receipt.get("review_packet_sha256")
            != _sha256(review_packet_path)
            or not isinstance(review_items, list)
            or not review_items
            or any(
                item.get("status") != "pending"
                or item.get("independent_reviewer") is not None
                or item.get("signature_sha256") is not None
                for item in review_items
            )
        ):
            raise ValueError(f"review packet is not unsigned/current: {task_id}")
        review_item_count = bundle_receipt.get(
            "review_item_count",
            len(review_items),
        )
        if review_item_count != len(review_items):
            raise ValueError(f"review item count drift for {task_id}")
        task_records.append(
            {
                "task_id": task_id,
                "status": "verified_unsigned_review_workspace",
                "bundle_build_status": bundle_receipt["status"],
                "bundle_archive_path": archive.relative_to(output_dir).as_posix(),
                "bundle_archive_sha256": bundle_receipt["archive_sha256"],
                "bundle_archive_bytes": bundle_receipt["archive_bytes"],
                "bundle_manifest_sha256": bundle_receipt["manifest_sha256"],
                "bundle_receipt_sha256": _sha256(
                    bundle_dir / "bundle_receipt.json"
                ),
                "candidate_lock_sha256": bundle_receipt[
                    "candidate_lock_sha256"
                ],
                "review_packet_sha256": bundle_receipt[
                    "review_packet_sha256"
                ],
                "locked_component_count": bundle_receipt[
                    "locked_component_count"
                ],
                "review_item_count": review_item_count,
                "approved_review_item_count": 0,
                "review_workspace_path": workspace_dir.relative_to(
                    output_dir
                ).as_posix(),
                "review_workspace_receipt_sha256": _sha256(
                    workspace_dir / "review_workspace_receipt.json"
                ),
                "unsigned_review_checklist_sha256": _sha256(
                    workspace_dir / "review_checklist.json"
                ),
                "independent_review_complete": False,
                "benchmark_ready": False,
                "chipflow_adapter_ready": False,
                "workflow_workspace_exposure_permitted": False,
            }
        )

    receipt = {
        "schema_version": "rtlflowbench.golden12_review_handoff.v1",
        "observed_at": observed_at,
        "status": "verified_unsigned_handoff_pending_independent_review",
        "classification": "evaluator_private_reviewer_only",
        "task_count": len(task_records),
        "benchmark_ready_task_count": 0,
        "chipflow_adapter_ready_task_count": 0,
        "protocol_ready": False,
        "task_review_item_count": sum(
            task["review_item_count"] for task in task_records
        ),
        "protocol_review_item_count": protocol_record["review_item_count"],
        "total_review_item_count": (
            sum(task["review_item_count"] for task in task_records)
            + protocol_record["review_item_count"]
        ),
        "approved_review_item_count": 0,
        "independent_review_complete": False,
        "suite_ready": False,
        "workflow_workspace_exposure_permitted": False,
        "source_sha256": dict(sorted(source_sha256.items())),
        "protocol": protocol_record,
        "tasks": task_records,
        "excluded_claims": [
            "Bundle and workspace verification is not independent review.",
            "No task is frozen, admitted, scored, or benchmark-ready by this handoff.",
            "Evaluator-private handoff files must never enter a workflow workspace.",
            "No AIRTL PASS, QoR, PPA, or performance result is claimed.",
        ],
    }
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(receipt)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "golden12_review_handoff_receipt.json").write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--observed-at", required=True)
    parser.add_argument(
        "--acknowledge-reviewer-only-private-evidence",
        action="store_true",
    )
    args = parser.parse_args()
    try:
        result = build_review_handoff(
            repo_root=args.repo_root,
            output_dir=args.output_dir,
            observed_at=args.observed_at,
            acknowledge_reviewer_only_private_evidence=(
                args.acknowledge_reviewer_only_private_evidence
            ),
        )
    except Exception as exc:
        print(
            json.dumps(
                {
                    "status": "fail",
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
