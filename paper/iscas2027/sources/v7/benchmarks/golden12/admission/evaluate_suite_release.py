#!/usr/bin/env python3
"""Aggregate twelve independently pinned task releases into Golden-12 v1."""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
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


def _validate(value: dict[str, Any], schema_path: Path, label: str) -> None:
    schema = _load(schema_path, f"{label} schema")
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(
        schema, format_checker=FormatChecker()
    ).validate(value)


def _parse_mapping(values: list[str], label: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for value in values:
        task_id, separator, item = value.partition("=")
        if not separator or task_id not in TASK_IDS or not item:
            raise ValueError(f"invalid {label}; expected TASK_ID=value")
        if task_id in result:
            raise ValueError(f"duplicate {label} for {task_id}")
        result[task_id] = item
    missing = sorted(set(TASK_IDS) - set(result))
    extra = sorted(set(result) - set(TASK_IDS))
    if missing or extra:
        raise ValueError(f"{label} must cover exactly Golden-12; missing={missing}, extra={extra}")
    return result


def evaluate_suite_release(
    *,
    repo_root: Path,
    task_release_paths: dict[str, Path],
    expected_task_release_sha256: dict[str, str],
    protocol_release_path: Path,
    expected_protocol_release_sha256: str,
    observed_at: str,
    expected_aggregator_sha256: str,
) -> dict[str, Any]:
    parsed = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("--observed-at must include a timezone")
    if set(task_release_paths) != set(TASK_IDS):
        raise ValueError("task release paths must cover exactly Golden-12")
    if set(expected_task_release_sha256) != set(TASK_IDS):
        raise ValueError("expected task release digests must cover exactly Golden-12")
    for digest, label in (
        (expected_protocol_release_sha256, "expected protocol release SHA256"),
        (expected_aggregator_sha256, "expected aggregator SHA256"),
        *(
            (expected_task_release_sha256[task_id], f"expected {task_id} release SHA256")
            for task_id in TASK_IDS
        ),
    ):
        if SHA256_RE.fullmatch(digest) is None:
            raise ValueError(f"{label} must be a lowercase digest")

    repo_root = repo_root.expanduser().resolve(strict=True)
    admission_root = repo_root / "benchmarks/golden12/admission"
    aggregator_path = Path(__file__).resolve(strict=True)
    aggregator_sha256 = _sha256(aggregator_path)
    if aggregator_sha256 != expected_aggregator_sha256:
        raise ValueError("aggregator source differs from the out-of-band trust anchor")
    task_schema_path = admission_root / "release_promotion_result.schema.json"
    protocol_schema_path = admission_root / "protocol_release_result.schema.json"
    result_schema_path = admission_root / "suite_release_result.schema.json"
    task_finalizer_path = admission_root / "evaluate_release_promotion.py"
    protocol_finalizer_path = admission_root / "evaluate_protocol_release.py"
    task_finalizer_sha256 = _sha256(task_finalizer_path)
    protocol_finalizer_sha256 = _sha256(protocol_finalizer_path)

    task_records: list[dict[str, Any]] = []
    for task_id in TASK_IDS:
        path = task_release_paths[task_id].expanduser().resolve(strict=True)
        digest = _sha256(path)
        expected = expected_task_release_sha256[task_id]
        if digest != expected:
            raise ValueError(f"{task_id} release result differs from its trust anchor")
        release = _load(path, f"{task_id} release result")
        _validate(release, task_schema_path, f"{task_id} release result")
        if release.get("task_id") != task_id:
            raise ValueError(f"task release result id mismatch: {task_id}")
        lock_path = (
            repo_root / "benchmarks/golden12/tasks" / task_id
            / "private/admission/candidate.lock.json"
        )
        if release.get("candidate_lock_sha256") != _sha256(lock_path):
            raise ValueError(f"task release candidate drift: {task_id}")
        source = release["source"]
        if source["finalizer_sha256"] != task_finalizer_sha256:
            raise ValueError(f"task release finalizer drift: {task_id}")
        if source["result_schema_sha256"] != _sha256(task_schema_path):
            raise ValueError(f"task release schema drift: {task_id}")
        task_records.append({
            "task_id": task_id,
            "status": release["status"],
            "release_result_sha256": digest,
            "expected_release_result_sha256": expected,
            "trust_anchor_digest_match": True,
            "benchmark_ready": release["benchmark_ready"],
            "chipflow_adapter_ready": release["chipflow_adapter_ready"],
        })

    protocol_path = protocol_release_path.expanduser().resolve(strict=True)
    protocol_digest = _sha256(protocol_path)
    if protocol_digest != expected_protocol_release_sha256:
        raise ValueError("protocol release result differs from its trust anchor")
    protocol_release = _load(protocol_path, "protocol release result")
    _validate(protocol_release, protocol_schema_path, "protocol release result")
    protocol_lock_path = repo_root / "benchmarks/golden12/protocol/candidate.lock.json"
    if protocol_release["candidate_lock_sha256"] != _sha256(protocol_lock_path):
        raise ValueError("protocol release candidate drift")
    if protocol_release["source"]["finalizer_sha256"] != protocol_finalizer_sha256:
        raise ValueError("protocol release finalizer drift")
    if protocol_release["source"]["result_schema_sha256"] != _sha256(protocol_schema_path):
        raise ValueError("protocol release schema drift")
    protocol_record = {
        "status": protocol_release["status"],
        "release_result_sha256": protocol_digest,
        "expected_release_result_sha256": expected_protocol_release_sha256,
        "trust_anchor_digest_match": True,
        "independent_review_complete": protocol_release["independent_review_complete"],
        "protocol_ready": protocol_release["protocol_ready"],
    }

    blockers: list[str] = []
    if not protocol_record["protocol_ready"]:
        blockers.append("protocol_release_incomplete")
    blockers.extend(
        f"task_release_incomplete:{record['task_id'][:3]}"
        for record in task_records
        if not record["benchmark_ready"]
    )
    benchmark_ready_count = sum(record["benchmark_ready"] for record in task_records)
    adapter_ready_count = sum(record["chipflow_adapter_ready"] for record in task_records)
    suite_ready = not blockers and benchmark_ready_count == len(TASK_IDS)
    subject = {
        "suite_release": "Golden-12-v1",
        "protocol_release_result_sha256": protocol_digest,
        "task_release_result_sha256": {
            record["task_id"]: record["release_result_sha256"]
            for record in task_records
        },
    }
    result = {
        "schema_version": "rtlflowbench.golden12_suite_release_result.v1",
        "observed_at": observed_at,
        "suite_release": "Golden-12-v1",
        "status": "released" if suite_ready else "BLOCK",
        "decision": "RELEASE" if suite_ready else "BLOCK",
        "blockers": blockers,
        "protocol": protocol_record,
        "tasks": task_records,
        "task_count": len(task_records),
        "benchmark_ready_task_count": benchmark_ready_count,
        "chipflow_adapter_ready_task_count": adapter_ready_count,
        "benchmark_suite_ready": suite_ready,
        "chipflow_adapter_suite_ready": False,
        "published_score_permitted": suite_ready,
        "release_subject_sha256": _canonical_sha256(subject),
        "source": {
            "aggregator_sha256": aggregator_sha256,
            "expected_aggregator_sha256": expected_aggregator_sha256,
            "aggregator_trust_anchor_digest_match": True,
            "result_schema_sha256": _sha256(result_schema_path),
            "task_release_schema_sha256": _sha256(task_schema_path),
            "protocol_release_schema_sha256": _sha256(protocol_schema_path),
            "task_finalizer_sha256": task_finalizer_sha256,
            "protocol_finalizer_sha256": protocol_finalizer_sha256,
        },
        "excluded_claims": [
            "Golden-12 benchmark release is independent of ChipFlow adapter readiness.",
            "A suite BLOCK is not a functional or workflow failure.",
            "Published scores require frozen-budget runs after suite release.",
            "No PPA, performance, human-level, or superhuman result is claimed by aggregation.",
        ],
    }
    _validate(result, result_schema_path, "suite release result")
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--task-release-result", action="append", default=[])
    parser.add_argument("--expected-task-release-sha256", action="append", default=[])
    parser.add_argument("--protocol-release-result", type=Path, required=True)
    parser.add_argument("--expected-protocol-release-sha256", required=True)
    parser.add_argument("--observed-at", required=True)
    parser.add_argument("--expected-aggregator-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--require-release", action="store_true")
    args = parser.parse_args()
    try:
        task_paths = {
            task_id: Path(value)
            for task_id, value in _parse_mapping(
                args.task_release_result, "task release result"
            ).items()
        }
        task_digests = _parse_mapping(
            args.expected_task_release_sha256,
            "expected task release SHA256",
        )
        result = evaluate_suite_release(
            repo_root=args.repo_root,
            task_release_paths=task_paths,
            expected_task_release_sha256=task_digests,
            protocol_release_path=args.protocol_release_result,
            expected_protocol_release_sha256=args.expected_protocol_release_sha256,
            observed_at=args.observed_at,
            expected_aggregator_sha256=args.expected_aggregator_sha256,
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
    if args.require_release and not result["benchmark_suite_ready"]:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
