"""Read-only resume accounting; never authorize calls or create verdicts."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


def slot_state(row: dict[str, Any], receipt: dict[str, Any] | None) -> str:
    outcome = row.get("outcome")
    if outcome not in {"not_launched", "resource_receipt_created"}:
        raise ValueError("unknown/failed runner requires investigation, not retry")
    if outcome == "not_launched":
        if (
            any(
                row.get(k) is not None
                for k in ("token_usage", "provider_budget_exhausted", "error_class")
            )
            or row.get("anomaly_codes") != []
        ):
            raise ValueError("nonlaunch projection contains execution or error claims")
        if row.get("receipt_sha256") is None:
            if receipt is not None:
                raise ValueError("unbound receipt is not an unstarted placeholder")
            return "pending"
    if not receipt or receipt.get("measurement_id") != row.get("slot_id"):
        raise ValueError("missing or mismatched terminal receipt")
    if outcome == "resource_receipt_created":
        if (
            receipt.get("schema_version")
            != "rtlflowbench.full_workflow_resource_measurement_receipt.v1"
            or receipt.get("status") != "full_workflow_resource_sample_complete"
        ):
            raise ValueError(
                "resource receipt does not establish a completed observation"
            )
        return "executed"
    expected = {
        "controller_disposition": {
            "workflow_process_started": False,
            "workflow_block_verdict_created": False,
        },
        "attempt_accounting": {
            "official_attempt_started": False,
            "official_semantic_attempt_consumed": False,
            "benchmark_result_created": False,
            "private_evaluator_calls": 0,
        },
        "readiness": {
            "resource_sample_created": False,
            "resource_sample_eligible": False,
        },
        "metrics": {"llm_call_count": None, "eda_call_count": None},
    }
    if (
        receipt.get("schema_version")
        != "rtlflowbench.controller_resource_nonlaunch_receipt.v1"
    ):
        raise ValueError("unsupported nonlaunch receipt")
    for section, fields in expected.items():
        for key, value in fields.items():
            observed = receipt.get(section, {})
            if (
                key not in observed
                or type(observed[key]) is not type(value)
                or observed[key] != value
            ):
                raise ValueError("nonlaunch receipt is not fail-closed")
    return "terminal_nonlaunch"


def resume_schedule(
    schedule: list[str], batches: list[list[tuple[str, str]]]
) -> dict[str, list[str]]:
    if len(schedule) != len(set(schedule)):
        raise ValueError("duplicate scheduled slot")
    known = set(schedule)
    done: dict[str, str] = {}
    for batch in batches:
        seen: set[str] = set()
        for slot_id, state in batch:
            if slot_id not in known or slot_id in seen or slot_id in done:
                raise ValueError("unknown, duplicate or reused slot")
            if state not in {"pending", "executed", "terminal_nonlaunch"}:
                raise ValueError("unknown slot state")
            seen.add(slot_id)
            if state != "pending":
                done[slot_id] = state
    return {
        "processed_slot_ids": [x for x in schedule if x in done],
        "actual_workflow_slot_ids": [x for x in schedule if done.get(x) == "executed"],
        "terminal_nonlaunch_slot_ids": [
            x for x in schedule if done.get(x) == "terminal_nonlaunch"
        ],
        "pending_slot_ids": [x for x in schedule if x not in done],
    }


def read_bound(path: Path, expected: str | None = None) -> tuple[dict[str, Any], str]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("expected regular non-symlink evidence file")
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if expected is not None and digest != expected:
        raise ValueError("evidence hash drift")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("evidence must be an object")
    return value, digest


def inspect_campaign(
    *,
    request_set_path: Path,
    request_set_sha256: str,
    batch_root: Path,
    campaign_sha256: str,
) -> dict[str, Any]:
    requests, _ = read_bound(request_set_path, request_set_sha256)
    schedule = [row["measurement_id"] for row in requests["requests"]]
    request_rows = {row["measurement_id"]: row for row in requests["requests"]}
    batches = []
    evidence = []
    plans = sorted(batch_root.glob("batch-*.plan.json"))
    receipts = sorted(batch_root.glob("batch-*.receipt.json"))
    if len(plans) != len(receipts):
        raise ValueError("inflight or incomplete batch requires investigation")
    for index, path in enumerate(receipts, 1):
        if path.name != f"batch-{index:03d}.receipt.json":
            raise ValueError("batch history has a gap or unexpected filename")
        value, receipt_sha = read_bound(path)
        plan, _ = read_bound(
            path.with_name(f"batch-{index:03d}.plan.json"), value["plan_sha256"]
        )
        if plan["expected_author_alpha_content_lock_sha256"] != campaign_sha256:
            raise ValueError("campaign lock drift")
        read_bound(Path(plan["author_alpha_content_lock"]), campaign_sha256)
        rows = []
        for row, slot in zip(value["slot_results"], plan["slots"], strict=True):
            if row["slot_id"] != slot["slot_id"] or row["slot_id"] not in request_rows:
                raise ValueError("slot identity drift")
            planned = request_rows[row["slot_id"]]
            request, _ = read_bound(
                Path(slot["resource_request"]), planned["request_sha256"]
            )
            if request["measurement_id"] != row["slot_id"]:
                raise ValueError("request identity drift")
            filename = (
                "full-workflow-resource-receipt.json"
                if row["outcome"] == "resource_receipt_created"
                else "controller-disposition-receipt.json"
            )
            subject_path = Path(slot["output_root"]) / filename
            subject = None
            if row.get("receipt_sha256") is not None:
                subject, _ = read_bound(subject_path, row["receipt_sha256"])
                for field in ("task_id", "workflow_id"):
                    if subject.get(field) != planned[field]:
                        raise ValueError("receipt task/workflow identity drift")
            elif subject_path.exists():
                raise ValueError(
                    "unbound evidence cannot become a retryable placeholder"
                )
            rows.append((row["slot_id"], slot_state(row, subject)))
        batches.append(rows)
        evidence.append({"path": str(path), "sha256": receipt_sha})
    return {
        "schema_version": "rtlflowbench.campaign_resume_observation.v1",
        "status": "OBSERVED_QUEUE_NOT_LAUNCH_AUTHORIZATION",
        "request_set_sha256": request_set_sha256,
        "campaign_sha256": campaign_sha256,
        "batch_receipts": evidence,
        **resume_schedule(schedule, batches),
        "provider_calls_authorized": False,
        "benchmark_verdicts_created": False,
        "official_attempts_permitted": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request-set", type=Path, required=True)
    parser.add_argument("--expected-request-set-sha256", required=True)
    parser.add_argument("--batch-root", type=Path, required=True)
    parser.add_argument("--expected-campaign-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = inspect_campaign(
        request_set_path=args.request_set,
        request_set_sha256=args.expected_request_set_sha256,
        batch_root=args.batch_root,
        campaign_sha256=args.expected_campaign_sha256,
    )
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(
        json.dumps(
            {
                key: len(result[key])
                for key in (
                    "processed_slot_ids",
                    "actual_workflow_slot_ids",
                    "terminal_nonlaunch_slot_ids",
                    "pending_slot_ids",
                )
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
