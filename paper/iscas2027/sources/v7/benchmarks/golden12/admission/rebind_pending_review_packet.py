#!/usr/bin/env python3
"""Rebind an unsigned, fully pending review packet to a new candidate lock."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


def _load(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"must be a regular non-symlink file: {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"must contain one JSON object: {path}")
    return value


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _assert_pending(items: Any, label: str) -> None:
    if not isinstance(items, list) or not items:
        raise ValueError(f"{label} must be a non-empty list")
    ids = []
    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get("review_id"), str):
            raise ValueError(f"{label} has an invalid review item")
        ids.append(item["review_id"])
        if item.get("status") != "pending":
            raise ValueError(f"{label} contains a non-pending review decision")
        for field in (
            "reviewer", "independent_reviewer", "signed_at",
            "signed_candidate_lock_sha256", "signature_sha256",
        ):
            if item.get(field) is not None:
                raise ValueError(f"{label} contains signed review state: {field}")
    if len(ids) != len(set(ids)):
        raise ValueError(f"{label} contains duplicate review ids")


def rebind_pending_review_packet(
    *, packet_path: Path, candidate_lock_path: Path, observed_at: str
) -> dict[str, Any]:
    packet = _load(packet_path)
    lock = _load(candidate_lock_path)
    if packet.get("task_id") != lock.get("task_id"):
        raise ValueError("review packet and candidate lock task ids differ")
    if packet.get("candidate_release") != lock.get("candidate_release"):
        raise ValueError("review packet and candidate lock releases differ")
    if lock.get("schema_version") == "rtlflowbench.protocol_candidate_lock.v1":
        if lock.get("protocol_ready") is not False:
            raise ValueError("protocol candidate lock must remain not_ready")
        if lock.get("schema_frozen") is not False:
            raise ValueError("protocol candidate schema must remain unfrozen")
    else:
        if lock.get("benchmark_ready") is not False:
            raise ValueError("candidate lock must remain benchmark not_ready")
        if (
            "chipflow_adapter_ready" in lock
            and lock.get("chipflow_adapter_ready") is not False
        ):
            raise ValueError("candidate lock must remain adapter not_ready")
    _assert_pending(packet.get("review_items"), "review_items")
    if "reviews" in packet:
        _assert_pending(packet["reviews"], "reviews")
        if [item["review_id"] for item in packet["reviews"]] != [
            item["review_id"] for item in packet["review_items"]
        ]:
            raise ValueError("duplicate review lists disagree")
    if packet.get("self_approval_forbidden") is not True:
        raise ValueError("review packet must forbid self-approval")
    if packet.get("benchmark_ready") not in (None, False):
        raise ValueError("review packet cannot claim benchmark readiness")
    if packet.get("chipflow_adapter_ready") not in (None, False):
        raise ValueError("review packet cannot claim adapter readiness")
    packet["candidate_lock_sha256"] = _sha256(candidate_lock_path)
    map_path = packet.get("review_evidence_map_path")
    map_digest = packet.get("review_evidence_map_sha256")
    if (map_path is None) != (map_digest is None):
        raise ValueError("review evidence map path/hash must be paired")
    if map_path is not None:
        component_sha256 = lock.get("component_sha256")
        if not isinstance(map_path, str) or not isinstance(component_sha256, dict):
            raise ValueError("review evidence map cannot be rebound")
        locked_digest = component_sha256.get(map_path)
        if not isinstance(locked_digest, str):
            raise ValueError("review evidence map is absent from candidate lock")
        packet["review_evidence_map_sha256"] = locked_digest
    if "observed_at" in packet:
        packet["observed_at"] = observed_at
    return packet


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--packet", type=Path, required=True)
    parser.add_argument("--candidate-lock", type=Path, required=True)
    parser.add_argument("--observed-at", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.expanduser().resolve()
    if output.exists() or output.is_symlink():
        raise FileExistsError(f"refusing to overwrite output: {output}")
    result = rebind_pending_review_packet(
        packet_path=args.packet.expanduser().resolve(),
        candidate_lock_path=args.candidate_lock.expanduser().resolve(),
        observed_at=args.observed_at,
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
