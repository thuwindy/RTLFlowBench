#!/usr/bin/env python3
"""Derive peak provider/EDA concurrency from a controller-only activity ledger."""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
from typing import Any, Iterable

from jsonschema import Draft202012Validator, FormatChecker


HERE = Path(__file__).resolve().parent
LEDGER_SCHEMA = HERE / "workflow_activity_ledger.schema.json"
RECEIPT_SCHEMA = HERE / "workflow_activity_concurrency_receipt.schema.json"
EDA_KINDS = {
    "eda_compile_or_lint": "compile_or_lint",
    "eda_simulation": "simulation",
    "eda_formal": "formal",
    "eda_synthesis": "synthesis",
}


def _load(path: Path, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a regular non-symlink file")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{label} must contain one JSON object")
    return value


def _sha(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"expected regular non-symlink file: {path}")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _peak(intervals: Iterable[tuple[int, int]]) -> int:
    events: list[tuple[int, int]] = []
    for started, completed in intervals:
        if started >= completed:
            raise ValueError("activity interval must have positive duration")
        events.append((started, 1))
        events.append((completed, -1))
    active = 0
    peak = 0
    for _, delta in sorted(events, key=lambda row: (row[0], row[1])):
        active += delta
        if active < 0:
            raise ValueError("activity interval sweep underflow")
        peak = max(peak, active)
    if active != 0:
        raise ValueError("activity interval sweep did not close")
    return peak


def build_receipt(*, ledger_path: Path, observed_at: str) -> dict[str, Any]:
    parsed = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("observed_at must include a timezone")
    ledger_path = ledger_path.expanduser()
    if ledger_path.is_symlink():
        raise ValueError("activity ledger must not be a symlink")
    ledger_path = ledger_path.resolve(strict=True)
    ledger_schema = _load(LEDGER_SCHEMA, "activity ledger schema")
    receipt_schema = _load(RECEIPT_SCHEMA, "concurrency receipt schema")
    for schema in (ledger_schema, receipt_schema):
        Draft202012Validator.check_schema(schema)
    ledger = _load(ledger_path, "activity ledger")
    Draft202012Validator(
        ledger_schema, format_checker=FormatChecker()
    ).validate(ledger)

    activities = ledger["activities"]
    ordered = sorted(
        activities,
        key=lambda row: (
            row["started_offset_ns"],
            row["completed_offset_ns"],
            row["activity_id"],
        ),
    )
    if activities != ordered:
        raise ValueError("activity ledger must use canonical interval order")
    activity_ids = [row["activity_id"] for row in activities]
    bindings = [row["event_binding_sha256"] for row in activities]
    if len(activity_ids) != len(set(activity_ids)):
        raise ValueError("activity ledger contains duplicate activity IDs")
    if len(bindings) != len(set(bindings)):
        raise ValueError("activity ledger contains duplicate event bindings")
    for row in activities:
        if row["started_offset_ns"] >= row["completed_offset_ns"]:
            raise ValueError("activity interval must have positive duration")

    llm = [row for row in activities if row["kind"] == "llm_call"]
    eda = [row for row in activities if row["kind"] in EDA_KINDS]
    provider_budget = ledger["provider_budget"]
    if (
        provider_budget["forwarded_call_count"] != len(llm)
        or provider_budget["forwarded_call_count"]
        > provider_budget["maximum_forwarded_calls"]
        or provider_budget["exhausted"]
        != (provider_budget["rejected_call_count"] > 0)
    ):
        raise ValueError("provider budget accounting differs from activity ledger")
    if sum(provider_budget["rejection_counts"].values()) != provider_budget[
        "rejected_call_count"
    ]:
        raise ValueError("provider rejection breakdown differs from total")
    token_usage = provider_budget["token_usage"]
    expected = token_usage["expected_call_count"]
    observed = token_usage["observed_call_count"]
    unobserved = token_usage["unobserved_call_count"]
    complete = token_usage["measurement_complete"]
    cache_observed = token_usage["cache_observed_call_count"]
    cache_unobserved = token_usage["cache_unobserved_call_count"]
    cache_complete = token_usage["cache_measurement_complete"]
    if (
        expected > provider_budget["forwarded_call_count"]
        or observed + unobserved != expected
        or complete != (unobserved == 0)
        or cache_observed + cache_unobserved != expected
        or cache_complete != (complete and cache_unobserved == 0)
    ):
        raise ValueError("provider token accounting differs from call ledger")
    if complete and (
        token_usage["total_tokens"]
        != token_usage["input_tokens"] + token_usage["output_tokens"]
        or token_usage["input_tokens"] > provider_budget["maximum_input_tokens"]
        or token_usage["output_tokens"] > provider_budget["maximum_output_tokens"]
    ):
        raise ValueError("provider token totals are internally inconsistent")
    if cache_complete and (
        token_usage["cache_hit_input_tokens"]
        + token_usage["cache_miss_input_tokens"]
        != token_usage["input_tokens"]
    ):
        raise ValueError("provider cache-token totals are internally inconsistent")
    def intervals(rows):
        return (
            (row["started_offset_ns"], row["completed_offset_ns"])
            for row in rows
        )

    by_kind = {
        public_name: _peak(intervals([row for row in eda if row["kind"] == kind]))
        for kind, public_name in EDA_KINDS.items()
    }
    metrics = {
        "activity_count": len(activities),
        "llm_activity_count": len(llm),
        "provider_call_limit": provider_budget["maximum_forwarded_calls"],
        "provider_call_count": provider_budget["forwarded_call_count"],
        "provider_budget_rejection_count": provider_budget[
            "rejected_call_count"
        ],
        "provider_budget_exhausted": provider_budget["exhausted"],
        "eda_activity_count": len(eda),
        "peak_llm_concurrency": _peak(intervals(llm)),
        "peak_eda_concurrency": _peak(intervals(eda)),
        "peak_eda_concurrency_by_kind": by_kind,
        "latest_completed_offset_ns": (
            max(row["completed_offset_ns"] for row in activities)
            if activities
            else None
        ),
        "failed_activity_count": sum(
            row["outcome"] == "failed" for row in activities
        ),
        "timed_out_activity_count": sum(
            row["outcome"] == "timed_out" for row in activities
        ),
    }
    metrics["token_usage"] = dict(token_usage)
    result = {
        "schema_version": "rtlflowbench.workflow_activity_concurrency_receipt.v1",
        "observed_at": observed_at,
        "status": "activity_concurrency_measured_no_benchmark_verdict",
        "measurement_id": ledger["measurement_id"],
        "measurement_scope": ledger["measurement_scope"],
        "workflow_slot_id": ledger["workflow_slot_id"],
        "workflow_id": ledger["workflow_id"],
        "task_id": ledger["task_id"],
        "attempt_id": ledger["attempt_id"],
        "source_binding": ledger["source_binding"],
        "runtime_binding": ledger["runtime_binding"],
        "process_measurement_receipt_sha256": ledger[
            "process_measurement_receipt_sha256"
        ],
        "ledger_sha256": _sha(ledger_path),
        "builder_sha256": _sha(Path(__file__).resolve()),
        "ledger_schema_sha256": _sha(LEDGER_SCHEMA),
        "receipt_schema_sha256": _sha(RECEIPT_SCHEMA),
        "controller_bindings": ledger["controllers"],
        "metrics": metrics,
        "completeness": ledger["completeness"],
        "attempt_accounting": ledger["attempt_accounting"],
        "readiness": {
            "activity_timeline_complete": True,
            "full_resource_merge_eligible": True,
            "host_capacity_policy_derivation_permitted": False,
            "official_attempts_permitted": False,
        },
        "excluded_claims": [
            "Controller activity intervals measure concurrency but do not classify RTL correctness or QoR.",
            "The controller-only ledger exposes no raw provider response, credential, hidden oracle, or private evaluator.",
            "This receipt alone is not full-workflow resource calibration and cannot derive a host-capacity policy.",
            "No official Golden-12 attempt is started or consumed, and no benchmark result is created.",
        ],
    }
    Draft202012Validator(
        receipt_schema, format_checker=FormatChecker()
    ).validate(result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--observed-at", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.expanduser().absolute()
    if output.exists() or output.is_symlink():
        raise FileExistsError(f"refusing to overwrite: {output}")
    try:
        result = build_receipt(
            ledger_path=args.ledger,
            observed_at=args.observed_at,
        )
    except Exception as exc:
        print(json.dumps({"status": "error", "error_class": type(exc).__name__}))
        return 2
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
