#!/usr/bin/env python3
"""Verify the Golden-12 review-item to task maturity-gate crosswalk."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


ADMISSION = Path("benchmarks/golden12/admission")
CROSSWALK = ADMISSION / "review_to_maturity_crosswalk.json"
CROSSWALK_SCHEMA = ADMISSION / "review_to_maturity_crosswalk.schema.json"
RECEIPT_SCHEMA = ADMISSION / "review_to_maturity_receipt.schema.json"
MATURITY_BUILDER = Path("benchmarks/golden12/maturity/build_candidate_maturity.py")
PROTOCOL_PACKET = Path("benchmarks/golden12/protocol/review_packet.json")
PROTOCOL_LOCK = Path("benchmarks/golden12/protocol/candidate.lock.json")


def _sha256(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"expected regular non-symlink file: {path}")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected one JSON object: {path}")
    return value


def _validate(schema_path: Path, value: dict[str, Any]) -> None:
    schema = _load(schema_path)
    Draft202012Validator.check_schema(schema)
    errors = sorted(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(value),
        key=lambda error: list(error.absolute_path),
    )
    if errors:
        first = errors[0]
        location = "/".join(str(item) for item in first.absolute_path)
        raise ValueError(f"schema validation failed at {location or '<root>'}: {first.message}")


def _load_maturity_module(repo_root: Path):
    path = repo_root / MATURITY_BUILDER
    spec = importlib.util.spec_from_file_location("review_crosswalk_maturity_builder", path)
    if spec is None or spec.loader is None:
        raise ValueError("could not load maturity builder")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _review_ids(packet: dict[str, Any]) -> list[str]:
    items = packet.get("review_items")
    if not isinstance(items, list) or not items:
        raise ValueError("review packet has no review items")
    ids = [item.get("review_id") for item in items]
    if any(not isinstance(item, str) or not item for item in ids) or len(ids) != len(set(ids)):
        raise ValueError("review IDs must be unique non-empty strings")
    return ids


def _assert_unsigned(packet: dict[str, Any]) -> None:
    if packet.get("status") != "pending_independent_review" or packet.get("self_approval_forbidden") is not True:
        raise ValueError("review packet must be pending and forbid self approval")
    for item in packet["review_items"]:
        if (
            item.get("status") != "pending"
            or item.get("independent_reviewer") is not None
            or item.get("signature_sha256") is not None
            or item.get("signed_candidate_lock_sha256") is not None
        ):
            raise ValueError("crosswalk only accepts a fully unsigned pending packet")


def _gate_mappings(task: dict[str, Any], gate_ids: list[str], review_ids: list[str]) -> list[dict[str, Any]]:
    if task["mapping_mode"] == "identity":
        if gate_ids != review_ids:
            raise ValueError(f"identity mapping order mismatch: {task['task_id']}")
        mappings = [
            {
                "gate_id": gate_id,
                "primary_review_ids": [gate_id],
                "required_review_ids": (
                    list(review_ids)
                    if gate_id == task["final_gate_id"]
                    else [gate_id]
                ),
            }
            for gate_id in gate_ids
        ]
    else:
        mappings = task["gate_mappings"]
    mapped_gate_ids = [item["gate_id"] for item in mappings]
    if mapped_gate_ids != gate_ids:
        raise ValueError(f"maturity gate mapping must exactly preserve policy order: {task['task_id']}")
    review_set = set(review_ids)
    primary = [review_id for item in mappings for review_id in item["primary_review_ids"]]
    if len(primary) != len(set(primary)) or set(primary) != review_set:
        raise ValueError(f"primary review accounting must partition every review item once: {task['task_id']}")
    for item in mappings:
        required = set(item["required_review_ids"])
        if not required or not required <= review_set:
            raise ValueError(f"required review IDs escape packet: {task['task_id']}:{item['gate_id']}")
        if not set(item["primary_review_ids"]) <= required:
            raise ValueError(f"primary review IDs must also be required: {task['task_id']}:{item['gate_id']}")
    final = next((item for item in mappings if item["gate_id"] == task["final_gate_id"]), None)
    if final is None or set(final["required_review_ids"]) != review_set:
        raise ValueError(f"final admission gate must require all review items: {task['task_id']}")
    return mappings


def build_receipt(*, repo_root: Path, observed_at: str) -> dict[str, Any]:
    repo_root = repo_root.resolve(strict=True)
    crosswalk_path = repo_root / CROSSWALK
    crosswalk = _load(crosswalk_path)
    _validate(repo_root / CROSSWALK_SCHEMA, crosswalk)
    maturity = _load_maturity_module(repo_root)
    task_roots = sorted((repo_root / "benchmarks/golden12/tasks").glob("G*-*"))
    task_ids = [path.name for path in task_roots]
    mapping_by_task = {item["task_id"]: item for item in crosswalk["tasks"]}
    if len(mapping_by_task) != len(crosswalk["tasks"]) or sorted(mapping_by_task) != task_ids:
        raise ValueError("crosswalk task set must exactly match the 12 task directories")

    source_paths = {CROSSWALK, CROSSWALK_SCHEMA, RECEIPT_SCHEMA, MATURITY_BUILDER}
    tasks = []
    total_gates = total_reviews = total_primary = 0
    for task_root in task_roots:
        task_id = task_root.name
        admission = task_root / "private/admission"
        policy_path = admission / "maturity_policy.json"
        packet_path = admission / "review_packet.json"
        lock_path = admission / "candidate.lock.json"
        source_paths.update({policy_path.relative_to(repo_root), packet_path.relative_to(repo_root), lock_path.relative_to(repo_root)})
        raw_policy = _load(policy_path)
        policy = maturity._normalized_policy(raw_policy=raw_policy)
        gate_ids = policy["independent_gate_ids"]
        packet = _load(packet_path)
        _assert_unsigned(packet)
        review_ids = _review_ids(packet)
        lock_sha256 = _sha256(lock_path)
        if packet.get("candidate_lock_sha256") != lock_sha256:
            raise ValueError(f"review packet is not bound to current lock: {task_id}")
        mappings = _gate_mappings(mapping_by_task[task_id], gate_ids, review_ids)
        tasks.append({
            "task_id": task_id,
            "maturity_policy_sha256": _sha256(policy_path),
            "review_packet_sha256": _sha256(packet_path),
            "candidate_lock_sha256": lock_sha256,
            "maturity_gate_count": len(gate_ids),
            "review_item_count": len(review_ids),
            "primary_review_assignment_count": sum(len(item["primary_review_ids"]) for item in mappings),
            "approved_review_item_count": 0,
            "independent_review_complete": False,
            "independent_gates": [
                {**item, "status": "pending"}
                for item in mappings
            ],
        })
        total_gates += len(gate_ids)
        total_reviews += len(review_ids)
        total_primary += sum(len(item["primary_review_ids"]) for item in mappings)

    protocol_packet_path = repo_root / PROTOCOL_PACKET
    protocol_lock_path = repo_root / PROTOCOL_LOCK
    source_paths.update({PROTOCOL_PACKET, PROTOCOL_LOCK})
    protocol_packet = _load(protocol_packet_path)
    _assert_unsigned(protocol_packet)
    protocol_ids = _review_ids(protocol_packet)
    protocol_lock_sha256 = _sha256(protocol_lock_path)
    if protocol_ids != crosswalk["protocol_review_ids"]:
        raise ValueError("protocol review IDs do not match crosswalk")
    if protocol_packet.get("candidate_lock_sha256") != protocol_lock_sha256:
        raise ValueError("protocol review packet is not bound to current lock")

    receipt = {
        "schema_version": "rtlflowbench.review_to_maturity_receipt.v1",
        "observed_at": observed_at,
        "status": "verified_unsigned_crosswalk_pending_independent_review",
        "classification": "reviewer_control_plane_no_private_oracle",
        "source_sha256": {
            relative.as_posix(): _sha256(repo_root / relative)
            for relative in sorted(source_paths)
        },
        "summary": {
            "task_count": len(tasks),
            "task_maturity_gate_count": total_gates,
            "task_review_item_count": total_reviews,
            "primary_review_assignment_count": total_primary,
            "protocol_review_item_count": len(protocol_ids),
            "approved_review_item_count": 0,
        },
        "tasks": tasks,
        "protocol": {
            "candidate_lock_sha256": protocol_lock_sha256,
            "review_packet_sha256": _sha256(protocol_packet_path),
            "review_item_count": len(protocol_ids),
            "approved_review_item_count": 0,
            "independent_review_complete": False,
            "review_ids": protocol_ids,
        },
        "readiness": {
            "independent_gate_pass_count": 0,
            "independent_gate_pending_count": total_gates,
            "independent_review_complete": False,
            "suite_ready": False,
        },
        "excluded_claims": crosswalk["excluded_claims"],
    }
    _validate(repo_root / RECEIPT_SCHEMA, receipt)
    rendered = json.dumps(receipt, sort_keys=True)
    if "/home/" in rendered or "/Users/" in rendered:
        raise ValueError("crosswalk receipt exposes a private host path")
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--observed-at", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.expanduser().resolve()
    if output.exists() or output.is_symlink():
        raise FileExistsError(f"refusing to overwrite output: {output}")
    receipt = build_receipt(repo_root=args.repo_root, observed_at=args.observed_at)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
