#!/usr/bin/env python3
"""Build external post-materialization candidate locks and pending packets.

This builder verifies every byte in a release-freeze materialization overlay,
repackages each projected public packet deterministically, updates the existing
candidate component closure, and rebinds a still-unsigned review packet.  It
does not apply the overlay, rebuild evaluator-private bundles/workspaces, reuse
old signatures, admit a benchmark, or change adapter readiness.
"""

from __future__ import annotations

import argparse
from copy import deepcopy
from datetime import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import tempfile
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
ADMISSION = Path("benchmarks/golden12/admission")
MATERIALIZATION_SCHEMA = (
    ADMISSION / "release_freeze_materialization_receipt.schema.json"
)
RELOCK_SCHEMA = ADMISSION / "release_freeze_relock_receipt.schema.json"
PACKAGER = Path("benchmarks/golden12/conformance/package_public.py")
REBINDER = ADMISSION / "rebind_pending_review_packet.py"
SHARED_TRANSITION_COMPONENTS = (
    "benchmarks/golden12/admission/build_release_freeze_preflight.py",
    "benchmarks/golden12/admission/release_freeze_policy_candidate.json",
    "benchmarks/golden12/admission/release_freeze_policy_candidate.schema.json",
    "benchmarks/golden12/admission/release_freeze_preflight.schema.json",
    "benchmarks/golden12/admission/materialize_release_freeze_candidate.py",
    "benchmarks/golden12/admission/release_freeze_declaration.schema.json",
    "benchmarks/golden12/admission/release_freeze_materialization_receipt.schema.json",
    "benchmarks/golden12/admission/build_release_freeze_relock_candidate.py",
    "benchmarks/golden12/admission/release_freeze_relock_receipt.schema.json",
    "benchmarks/golden12/admission/rebind_pending_review_packet.py",
    "benchmarks/golden12/admission/release_material_selection.json",
    "benchmarks/golden12/admission/release_material_selection.schema.json",
    "benchmarks/golden12/admission/build_release_materials.py",
    "benchmarks/golden12/admission/release_materials.schema.json",
    "benchmarks/golden12/admission/build_public_release_archive.py",
    "benchmarks/golden12/admission/public_release_archive_receipt.schema.json",
    "benchmarks/golden12/admission/evaluate_release_promotion.py",
    "benchmarks/golden12/admission/release_promotion_result.schema.json",
    "benchmarks/golden12/conformance/package_public.py",
    "benchmarks/golden12/schemas/task.schema.json",
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


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


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ValueError(f"could not load module: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _parse_observed_at(value: str) -> None:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("--observed-at must include a timezone")


def _external(repo_root: Path, path: Path, label: str) -> Path:
    resolved = path.expanduser().resolve()
    try:
        resolved.relative_to(repo_root)
    except ValueError:
        return resolved
    raise ValueError(f"{label} must remain outside the repository")


def _overlay_files(
    *, materialization_root: Path, receipt: dict[str, Any]
) -> dict[str, bytes]:
    result: dict[str, bytes] = {}
    expected: dict[str, tuple[str, int]] = {}
    for task in receipt["tasks"]:
        for item in task["files"]:
            relative = item["relative_path"]
            if relative in expected:
                raise ValueError(f"duplicate materialized path: {relative}")
            expected[relative] = (item["sha256"], item["bytes"])
    selection = receipt["selection_candidate"]
    expected[selection["relative_path"]] = (selection["sha256"], -1)
    for relative, (digest, size) in sorted(expected.items()):
        path = materialization_root / "files" / relative
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"materialized file missing: {relative}")
        payload = path.read_bytes()
        if _sha256_bytes(payload) != digest:
            raise ValueError(f"materialized file digest drift: {relative}")
        if size >= 0 and len(payload) != size:
            raise ValueError(f"materialized file size drift: {relative}")
        result[relative] = payload
    observed = {
        path.relative_to(materialization_root / "files").as_posix()
        for path in (materialization_root / "files").rglob("*")
        if path.is_file() and not path.is_symlink()
    }
    if observed != set(result):
        raise ValueError("materialization overlay contains unreceipted files")
    return result


def _component_payload(
    *, repo_root: Path, overlay: dict[str, bytes], relative: str
) -> bytes:
    if relative in overlay:
        return overlay[relative]
    path = repo_root / relative
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"candidate component missing: {relative}")
    return path.read_bytes()


def _stage_public_tree(
    *,
    repo_root: Path,
    task_id: str,
    overlay: dict[str, bytes],
    destination: Path,
) -> Path:
    source = repo_root / "benchmarks/golden12/tasks" / task_id / "public"
    public = destination / task_id / "public"
    public.mkdir(parents=True)
    prefix = f"benchmarks/golden12/tasks/{task_id}/public/"
    for path in sorted(source.rglob("*")):
        if path.is_symlink():
            raise ValueError(f"public source contains symlink: {path}")
        if path.is_dir():
            continue
        if not path.is_file():
            raise ValueError(f"public source contains non-file: {path}")
        relative_public = path.relative_to(source)
        relative_repo = prefix + relative_public.as_posix()
        target = public / relative_public
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(overlay.get(relative_repo, path.read_bytes()))
    return destination / task_id


def build_release_freeze_relock_candidate(
    *,
    repo_root: Path,
    materialization_root: Path,
    expected_materialization_receipt_sha256: str,
    output_dir: Path,
    observed_at: str,
    expected_builder_sha256: str,
) -> dict[str, Any]:
    _parse_observed_at(observed_at)
    repo_root = repo_root.expanduser().resolve(strict=True)
    materialization_root = _external(
        repo_root, materialization_root, "materialization root"
    ).resolve(strict=True)
    output_dir = _external(repo_root, output_dir, "relock output")
    if output_dir.exists() or output_dir.is_symlink():
        raise FileExistsError(f"refusing to overwrite output: {output_dir}")
    builder_path = Path(__file__).resolve(strict=True)
    if _sha256(builder_path) != expected_builder_sha256:
        raise ValueError("relock builder differs from its trust anchor")
    receipt_path = (
        materialization_root / "release_freeze_materialization_receipt.json"
    )
    if _sha256(receipt_path) != expected_materialization_receipt_sha256:
        raise ValueError("materialization receipt differs from its trust anchor")
    materialization = _load(receipt_path, "materialization receipt")
    _validate(
        materialization,
        repo_root / MATERIALIZATION_SCHEMA,
        "materialization receipt",
    )
    if (
        materialization.get("status")
        != "materialized_candidate_pending_relock_review"
        or materialization.get("apply_permitted") is not False
        or materialization.get("signature_reuse_permitted") is not False
        or materialization.get("task_count") != 12
    ):
        raise ValueError("materialization receipt weakens relock boundaries")
    overlay = _overlay_files(
        materialization_root=materialization_root, receipt=materialization
    )
    task_rows = {item["task_id"]: item for item in materialization["tasks"]}
    if tuple(task_rows) != TASK_IDS:
        raise ValueError("materialization task coverage/order drifted")

    packager = _load_module(
        repo_root / PACKAGER, "rtlflowbench_freeze_relock_packager"
    )
    rebinder = _load_module(
        repo_root / REBINDER, "rtlflowbench_freeze_relock_packet_rebinder"
    )
    records: list[dict[str, Any]] = []
    output_dir.mkdir(parents=True)
    for task_id in TASK_IDS:
        task_root = repo_root / "benchmarks/golden12/tasks" / task_id
        admission = task_root / "private/admission"
        old_lock_path = admission / "candidate.lock.json"
        old_packet_path = admission / "review_packet.json"
        old_lock = _load(old_lock_path, f"{task_id} candidate lock")
        old_lock_sha256 = _sha256(old_lock_path)
        if (
            old_lock_sha256
            != task_rows[task_id]["pretransition_candidate_lock_sha256"]
        ):
            raise ValueError(f"pretransition lock drift: {task_id}")

        archive_dir = output_dir / "public_archives" / task_id
        archive_dir.mkdir(parents=True)
        archive_path = archive_dir / f"{task_id[:3].lower()}-public-input.tar.gz"
        archive_receipt_path = archive_dir / "public_archive_receipt.json"
        with tempfile.TemporaryDirectory(
            prefix=f"{task_id[:3].lower()}-public-", dir=output_dir
        ) as temporary:
            projected_task_root = _stage_public_tree(
                repo_root=repo_root,
                task_id=task_id,
                overlay=overlay,
                destination=Path(temporary),
            )
            archive_receipt = packager.package_public_task(
                task_root=projected_task_root,
                archive_path=archive_path,
                receipt_path=archive_receipt_path,
            )
        if (
            archive_receipt["public_content_manifest_sha256"]
            != task_rows[task_id]["target_public_content_manifest_sha256"]
        ):
            raise ValueError(f"post-materialization public digest drift: {task_id}")

        new_lock = deepcopy(old_lock)
        components = new_lock.get("component_sha256")
        if not isinstance(components, dict) or not components:
            raise ValueError(f"candidate lock has no component map: {task_id}")
        prefix = f"benchmarks/golden12/tasks/{task_id}/"
        for relative, payload in overlay.items():
            if relative.startswith(prefix) or relative == SELECTION_RELATIVE:
                components[relative] = _sha256_bytes(payload)
        for relative in SHARED_TRANSITION_COMPONENTS:
            components[relative] = _sha256_bytes(
                _component_payload(
                    repo_root=repo_root, overlay=overlay, relative=relative
                )
            )
        for relative, expected in sorted(components.items()):
            observed = _sha256_bytes(
                _component_payload(
                    repo_root=repo_root, overlay=overlay, relative=relative
                )
            )
            if observed != expected:
                raise ValueError(
                    f"posttransition component drift: {task_id}:{relative}"
                )
        new_lock["component_sha256"] = dict(sorted(components.items()))
        new_lock["public_archive_sha256"] = archive_receipt["archive_sha256"]
        new_lock["status"] = "release_freeze_materialized_pending_new_review"
        new_lock["observed_at"] = observed_at
        new_lock["benchmark_ready"] = False
        new_lock["chipflow_adapter_ready"] = False
        new_lock["pretransition_candidate_lock_sha256"] = old_lock_sha256
        new_lock["freeze_transition"] = {
            "materialization_receipt_sha256": (
                expected_materialization_receipt_sha256
            ),
            "pretransition_signatures_invalidated": True,
            "private_bundle_rebuild_required": True,
            "review_workspace_rebuild_required": True,
            "new_review_required": True,
            "final_admission_status": "pending",
        }
        new_lock_path = (
            output_dir
            / "files"
            / f"benchmarks/golden12/tasks/{task_id}/private/admission/candidate.lock.json"
        )
        new_lock_path.parent.mkdir(parents=True, exist_ok=True)
        new_lock_path.write_bytes(_json_bytes(new_lock))
        new_lock_sha256 = _sha256(new_lock_path)
        rebound = rebinder.rebind_pending_review_packet(
            packet_path=old_packet_path,
            candidate_lock_path=new_lock_path,
            observed_at=observed_at,
        )
        items = rebound.get("review_items", [])
        all_pending = bool(
            items
            and all(item.get("status") == "pending" for item in items)
            and all(
                item.get("signed_candidate_lock_sha256") is None
                and item.get("signature_sha256") is None
                for item in items
            )
        )
        if not all_pending:
            raise ValueError(f"rebound review packet is not unsigned: {task_id}")
        new_packet_path = new_lock_path.with_name("review_packet.json")
        new_packet_path.write_bytes(_json_bytes(rebound))
        records.append(
            {
                "task_id": task_id,
                "pretransition_candidate_lock_sha256": old_lock_sha256,
                "posttransition_candidate_lock_sha256": new_lock_sha256,
                "posttransition_review_packet_sha256": _sha256(new_packet_path),
                "public_archive_sha256": archive_receipt["archive_sha256"],
                "public_archive_bytes": archive_receipt["archive_bytes"],
                "public_archive_receipt_sha256": _sha256(
                    archive_receipt_path
                ),
                "public_content_manifest_sha256": archive_receipt[
                    "public_content_manifest_sha256"
                ],
                "component_count": len(components),
                "all_components_content_bound": True,
                "all_review_items_pending": True,
                "pretransition_signatures_invalidated": True,
                "private_bundle_rebuild_required": True,
                "review_workspace_rebuild_required": True,
                "new_review_required": True,
                "benchmark_ready": False,
                "chipflow_adapter_ready": False,
            }
        )

    result = {
        "schema_version": "rtlflowbench.release_freeze_relock_receipt.v1",
        "observed_at": observed_at,
        "status": "relocked_candidate_pending_package_and_new_review",
        "classification": "release_authority_only",
        "materialization_receipt_sha256": (
            expected_materialization_receipt_sha256
        ),
        "task_count": 12,
        "tasks": records,
        "source": {
            "builder_sha256": _sha256(builder_path),
            "schema_sha256": _sha256(repo_root / RELOCK_SCHEMA),
            "materialization_schema_sha256": _sha256(
                repo_root / MATERIALIZATION_SCHEMA
            ),
            "public_packager_sha256": _sha256(repo_root / PACKAGER),
            "review_packet_rebinder_sha256": _sha256(repo_root / REBINDER),
        },
        "apply_permitted": False,
        "pretransition_signature_reuse_permitted": False,
        "private_bundle_rebuild_required": True,
        "review_workspace_rebuild_required": True,
        "new_review_required": True,
        "benchmark_ready_task_count": 0,
        "chipflow_adapter_ready_task_count": 0,
        "suite_ready": False,
        "excluded_claims": [
            "Candidate locks and packets remain in an external overlay and are not applied source state.",
            "Pretransition signatures are invalid for every posttransition candidate-lock digest.",
            "Evaluator-private bundles and review workspaces must be rebuilt against the new locks.",
            "New externally governed signatures and final admission are mandatory before release.",
            "No benchmark readiness, adapter readiness, score, RTL PASS, QoR, PPA, or performance result is claimed.",
        ],
    }
    _validate(result, repo_root / RELOCK_SCHEMA, "freeze relock receipt")
    (output_dir / "release_freeze_relock_receipt.json").write_bytes(
        _json_bytes(result)
    )
    return result


SELECTION_RELATIVE = (
    "benchmarks/golden12/admission/release_material_selection.json"
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--materialization-root", type=Path, required=True)
    parser.add_argument(
        "--expected-materialization-receipt-sha256", required=True
    )
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--observed-at", required=True)
    parser.add_argument("--expected-builder-sha256", required=True)
    args = parser.parse_args()
    try:
        result = build_release_freeze_relock_candidate(
            repo_root=args.repo_root,
            materialization_root=args.materialization_root,
            expected_materialization_receipt_sha256=(
                args.expected_materialization_receipt_sha256
            ),
            output_dir=args.output_dir,
            observed_at=args.observed_at,
            expected_builder_sha256=args.expected_builder_sha256,
        )
    except Exception as exc:
        print(
            json.dumps(
                {
                    "schema_version": (
                        "rtlflowbench.release_freeze_relock_receipt.v1"
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
