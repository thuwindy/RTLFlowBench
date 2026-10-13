#!/usr/bin/env python3
"""Run at most three resource-calibration slots, then stop for review.

The wrapper checks the official provider balance before and after the batch,
projects content-free token/cache accounting from each slot receipt, and stops
the current batch after the first accounting or consumption anomaly.  Exact
balances, credentials, prompts, responses, and benchmark verdicts are never
persisted.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import importlib.util
import json
import os
import ssl
from collections.abc import Callable
from datetime import datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

HERE = Path(__file__).resolve().parent
PLAN_SCHEMA = HERE / "guarded_resource_batch_plan.schema.json"
RECEIPT_SCHEMA = HERE / "guarded_resource_batch_receipt.schema.json"
SLOT_RUNNER = HERE / "run_controller_aware_resource_measurement.py"
MAX_BALANCE_RESPONSE_BYTES = 64 * 1024


def _load(path: Path, label: str) -> dict[str, Any]:
    path = path.expanduser().resolve(strict=True)
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a regular non-symlink file")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{label} must contain one JSON object")
    return value


def _sha(path: Path) -> str:
    path = path.expanduser().resolve(strict=True)
    if path.is_symlink() or not path.is_file():
        raise ValueError("expected a regular non-symlink file")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_new(path: Path, value: dict[str, Any]) -> None:
    path = path.expanduser().absolute()
    if path.exists() or path.is_symlink():
        raise FileExistsError("refusing to overwrite batch receipt")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _validate(schema_path: Path, value: dict[str, Any], label: str) -> None:
    schema = _load(schema_path, f"{label} schema")
    Draft202012Validator(
        schema, format_checker=FormatChecker()
    ).validate(value)


def _verify_author_alpha_lock(plan: dict[str, Any]) -> dict[str, Any]:
    lock_path = Path(plan["author_alpha_content_lock"])
    expected_sha256 = plan["expected_author_alpha_content_lock_sha256"]
    if _sha(lock_path) != expected_sha256:
        raise ValueError("author alpha content lock binding drifted")
    lock = _load(lock_path, "author alpha content lock")
    permissions = lock.get("permissions", {})
    review = lock.get("review", {})
    common = lock.get("common_execution", {})
    schedule = lock.get("attempt_schedule", {})
    legacy_lock = (
        lock.get("schema_version")
        == "rtlflowbench.author_reviewed_alpha_content_lock.v1"
        and lock.get("lock_id")
        == "golden12-author-reviewed-alpha-wave0-current-source"
        and lock.get("status")
        == "author_reviewed_alpha_content_locked_provider_preflight_required"
        and review.get("author_technical_review_complete") is True
        and review.get("self_approval_used_for_official_release") is False
        and permissions.get(
            "development_wave0_launch_permitted_after_fresh_provider_preflight_pass"
        )
        is True
        and permissions.get("official_attempts_permitted") is False
        and permissions.get("publication_permitted") is False
        and permissions.get("benchmark_ready") is False
        and permissions.get("adapter_ready") is False
        and schedule.get("total_attempt_slots") == 200
        and schedule.get("started_attempts_at_lock_time") == 0
    )
    release_bound_lock = (
        lock.get("schema_version")
        == "rtlflowbench.ai_reviewed_v1_campaign_launch_lock.v1"
        and lock.get("lock_id")
        == "golden12-ai-reviewed-v1-author-supervised-pilot"
        and lock.get("status")
        == "pilot_content_locked_fresh_provider_preflight_required"
        and lock.get("benchmark_release", {}).get("release_class")
        == "Golden-12 AI-reviewed v1"
        and permissions.get(
            "author_supervised_pilot_launch_after_fresh_provider_preflight"
        )
        is True
        and permissions.get("official_attempts_permitted") is False
        and permissions.get("publication_of_workflow_results_permitted") is False
        and permissions.get("benchmark_bytes_may_change") is False
        and permissions.get("workflow_specific_budget_override_permitted") is False
        and lock.get("schedule", {}).get("total_semantic_slots") == 200
        and lock.get("schedule", {}).get("started_slots") == 0
        and lock.get("schedule", {}).get("semantic_slots_consumed") == 0
    )
    author_alpha_relock = (
        lock.get("schema_version")
        == "rtlflowbench.author_alpha_campaign_relock.v1"
        and lock.get("lock_id")
        == "golden12-author-alpha-v2.3-five-workflow-full-rerun"
        and lock.get("status")
        == "AUTHOR_ALPHA_V2_3_CONTENT_LOCKED_FRESH_PROVIDER_PREFLIGHT_REQUIRED"
        and (
            lock.get("benchmark_release", {}).get("release_class")
            == "Golden-12 AI-reviewed v1"
            or (
                lock.get("benchmark_release", {}).get("release_class")
                == "Golden-12 author-alpha v2.3 current-content development"
                and lock.get("benchmark_release", {}).get("official_release") is False
            )
        )
        and permissions.get("author_alpha_pilot_after_preflight") is True
        and permissions.get("official_attempts_permitted") is False
        and permissions.get("publication_of_workflow_results_permitted") is False
        and permissions.get("benchmark_bytes_may_change") is False
        and permissions.get("workflow_specific_budget_override_permitted") is False
        and lock.get("schedule", {}).get("restart_from_zero") is True
        and lock.get("schedule", {}).get("total_semantic_slots") == 200
        and lock.get("schedule", {}).get("started_slots") == 0
        and lock.get("schedule", {}).get("semantic_slots_consumed") == 0
    )
    if not (
        (legacy_lock or release_bound_lock or author_alpha_relock)
        and common.get("provider") == "deepseek"
        and common.get("model") == "deepseek-v4-pro"
        and common.get("thinking_mode") == "disabled"
        and common.get("temperature") == 0
        and common.get("top_p") == 1
        and common.get("maximum_provider_calls_per_slot") == 4
        and common.get("maximum_provider_retries") == 0
        and common.get("maximum_output_candidates_per_call") == 1
        and common.get("maximum_output_tokens_per_call") == 8192
        and common.get("maximum_input_tokens_per_slot") == 163840
        and common.get("maximum_output_tokens_per_slot") == 16384
        and common.get("maximum_consecutive_identical_requests") == 2
        and common.get("maximum_consecutive_identical_errors") == 2
        and common.get("provider_timeout_seconds") == 120
        and common.get("maximum_slots_per_batch") == 3
        and common.get("balance_probe_before_and_after_batch_required") is True
        and common.get("fresh_provider_preflight_required") is True
    ):
        if lock.get("schema_version") == (
            "rtlflowbench.author_reviewed_alpha_content_lock.v1"
        ):
            raise ValueError("author alpha content lock is not launch-eligible")
        raise ValueError("campaign content lock is not pilot launch-eligible")
    return lock


def _balance_result(
    *,
    credential_present: bool,
    http_status: int | None,
    is_available: bool,
    positive_total_balance_present: bool | None,
    balance_entry_count: int | None,
    error_classification: str | None,
) -> dict[str, Any]:
    return {
        "credential_present": credential_present,
        "http_status": http_status,
        "is_available": is_available,
        "positive_total_balance_present": positive_total_balance_present,
        "balance_entry_count": balance_entry_count,
        "error_classification": error_classification,
        "raw_response_persisted": False,
        "exact_balance_persisted": False,
    }


def probe_deepseek_balance() -> dict[str, Any]:
    """Return a content-free official balance diagnostic."""
    api_key = os.environ.get("DEEPSEEK_API_KEY", "")
    if not api_key or any(character.isspace() for character in api_key):
        return _balance_result(
            credential_present=False,
            http_status=None,
            is_available=False,
            positive_total_balance_present=None,
            balance_entry_count=None,
            error_classification="credential_missing",
        )
    connection = http.client.HTTPSConnection(
        "api.deepseek.com",
        443,
        timeout=30,
        context=ssl.create_default_context(),
    )
    try:
        connection.request(
            "GET",
            "/user/balance",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Accept": "application/json",
                "User-Agent": "rtlflowbench-guarded-batch/1",
            },
        )
        response = connection.getresponse()
        body = response.read(MAX_BALANCE_RESPONSE_BYTES + 1)
        if len(body) > MAX_BALANCE_RESPONSE_BYTES:
            raise ValueError("balance response exceeds reviewed limit")
        if response.status != 200:
            return _balance_result(
                credential_present=True,
                http_status=response.status,
                is_available=False,
                positive_total_balance_present=None,
                balance_entry_count=None,
                error_classification="http_error",
            )
        value = json.loads(body.decode("utf-8"))
        entries = value.get("balance_infos") if isinstance(value, dict) else None
        if not isinstance(entries, list):
            raise ValueError("balance response shape is invalid")
        positive = False
        for entry in entries:
            if not isinstance(entry, dict):
                raise ValueError("balance entry is invalid")
            try:
                amount = Decimal(str(entry["total_balance"]))
            except (KeyError, InvalidOperation, ValueError) as exc:
                raise ValueError("balance amount is invalid") from exc
            positive = positive or amount > 0
        available = value.get("is_available") is True and positive
        return _balance_result(
            credential_present=True,
            http_status=200,
            is_available=available,
            positive_total_balance_present=positive,
            balance_entry_count=len(entries),
            error_classification=None if available else "insufficient_balance",
        )
    except Exception:
        return _balance_result(
            credential_present=True,
            http_status=None,
            is_available=False,
            positive_total_balance_present=None,
            balance_entry_count=None,
            error_classification="network_or_response_error",
        )
    finally:
        connection.close()


def _slot_runner() -> Callable[..., dict[str, Any]]:
    spec = importlib.util.spec_from_file_location(
        "rtlflowbench_guarded_slot_runner", SLOT_RUNNER
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("slot runner module cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.run_controller_measurement


def _runner_arguments(slot: dict[str, Any], observed_at: str) -> dict[str, Any]:
    return {
        "resource_request_path": Path(slot["resource_request"]),
        "bridge_set_path": Path(slot["bridge_request_set"]),
        "expected_bridge_set_sha256": slot["expected_bridge_request_set_sha256"],
        "common_provider_gate_path": Path(slot["common_provider_gate"]),
        "expected_common_provider_gate_sha256": slot[
            "expected_common_provider_gate_sha256"
        ],
        "resource_campaign_authorization_path": Path(
            slot["resource_campaign_authorization"]
        ),
        "expected_resource_campaign_authorization_sha256": slot[
            "expected_resource_campaign_authorization_sha256"
        ],
        "podman_path": Path(slot["podman"]),
        "expected_podman_sha256": slot["expected_podman_sha256"],
        "scratch_root": Path(slot["scratch_root"]),
        "output_root": Path(slot["output_root"]),
        "observed_at": observed_at,
        "mage_eda_image_digest": slot["mage_eda_image_digest"],
    }


def _project_token_usage(value: dict[str, Any]) -> dict[str, Any]:
    names = (
        "measurement_complete",
        "cache_measurement_complete",
        "input_tokens",
        "output_tokens",
        "total_tokens",
        "cache_hit_input_tokens",
        "cache_miss_input_tokens",
    )
    if any(name not in value for name in names):
        raise ValueError("slot token usage is incomplete")
    projected = {name: value[name] for name in names}
    optional_names = (
        "finish_reason_measurement_complete",
        "finish_reason_observed_call_count",
        "finish_reason_unobserved_call_count",
        "finish_reason_counts",
        "output_cap_reached_call_count",
        "output_cap_with_length_finish_count",
    )
    projected.update({name: value.get(name) for name in optional_names})
    return projected


def _unlaunched_projection(slot: dict[str, Any]) -> dict[str, Any]:
    """Record a planned slot that the guarded batch deliberately did not run."""
    return {
        "slot_id": slot["slot_id"],
        "outcome": "not_launched",
        "receipt_sha256": None,
        "token_usage": None,
        "provider_budget_exhausted": None,
        "anomaly_codes": [],
        "error_class": None,
    }


def _slot_projection(
    *, slot: dict[str, Any], result: dict[str, Any], plan: dict[str, Any]
) -> dict[str, Any]:
    output_root = Path(slot["output_root"])
    if result.get("schema_version") == (
        "rtlflowbench.full_workflow_resource_measurement_receipt.v1"
    ):
        receipt_path = output_root / "full-workflow-resource-receipt.json"
        usage = _project_token_usage(result.get("metrics", {}).get("token_usage", {}))
        exhausted = result.get("metrics", {}).get("provider_budget_exhausted")
        anomalies: list[str] = []
        if exhausted is not False:
            anomalies.append("provider_budget_rejected")
        if not usage["measurement_complete"]:
            anomalies.append("token_measurement_incomplete")
        if not usage["cache_measurement_complete"]:
            anomalies.append("cache_measurement_incomplete")
        if usage["finish_reason_measurement_complete"] is not True:
            anomalies.append("finish_reason_measurement_incomplete")
        if (usage["output_cap_reached_call_count"] or 0) > 0:
            anomalies.append("output_cap_boundary_observed")
        if (usage["output_cap_with_length_finish_count"] or 0) > 0:
            anomalies.append("provider_length_truncation_observed")
        thresholds = plan["anomaly_thresholds"]
        if (
            usage["input_tokens"] is not None
            and usage["input_tokens"]
            >= thresholds["warning_input_tokens_per_slot"]
        ):
            anomalies.append("high_input_token_consumption")
        if (
            usage["output_tokens"] is not None
            and usage["output_tokens"]
            >= thresholds["warning_output_tokens_per_slot"]
        ):
            anomalies.append("high_output_token_consumption")
        return {
            "slot_id": slot["slot_id"],
            "outcome": "resource_receipt_created",
            "receipt_sha256": _sha(receipt_path),
            "token_usage": usage,
            "provider_budget_exhausted": exhausted,
            "anomaly_codes": sorted(set(anomalies)),
            "error_class": None,
        }
    if result.get("schema_version") == (
        "rtlflowbench.controller_resource_nonlaunch_receipt.v1"
    ):
        disposition = result.get("controller_disposition", {})
        accounting = result.get("attempt_accounting", {})
        readiness = result.get("readiness", {})
        metrics = result.get("metrics", {})
        if not (
            disposition.get("workflow_process_started") is False
            and disposition.get("workflow_block_verdict_created") is False
            and accounting.get("official_attempt_started") is False
            and accounting.get("official_semantic_attempt_consumed") is False
            and accounting.get("benchmark_result_created") is False
            and accounting.get("private_evaluator_calls") == 0
            and readiness.get("resource_sample_created") is False
            and readiness.get("resource_sample_eligible") is False
            and metrics.get("llm_call_count") is None
            and metrics.get("eda_call_count") is None
        ):
            raise ValueError("nonlaunch receipt is not fail-closed")
        receipt_path = output_root / "controller-disposition-receipt.json"
        return {
            "slot_id": slot["slot_id"],
            "outcome": "not_launched",
            "receipt_sha256": _sha(receipt_path),
            "token_usage": None,
            "provider_budget_exhausted": None,
            "anomaly_codes": [],
            "error_class": None,
        }
    raise ValueError("slot runner returned an unsupported receipt")


def run_batch(
    *,
    plan_path: Path,
    receipt_path: Path,
    observed_at: str,
    balance_probe: Callable[[], dict[str, Any]] = probe_deepseek_balance,
    measurement_runner: Callable[..., dict[str, Any]] | None = None,
) -> dict[str, Any]:
    parsed = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("observed_at must include a timezone")
    plan = _load(plan_path, "guarded batch plan")
    _validate(PLAN_SCHEMA, plan, "guarded batch plan")
    _verify_author_alpha_lock(plan)
    if plan["runner_sha256"] != _sha(SLOT_RUNNER):
        raise ValueError("guarded batch slot runner binding drifted")
    slot_ids = [slot["slot_id"] for slot in plan["slots"]]
    if len(slot_ids) != len(set(slot_ids)):
        raise ValueError("guarded batch slot ids are duplicated")

    before = balance_probe()
    slot_results: list[dict[str, Any]] = []
    batch_anomalies: list[str] = []
    runner_failed = False
    after: dict[str, Any] | None = None
    if before.get("is_available") and before.get(
        "positive_total_balance_present"
    ):
        runner = measurement_runner or _slot_runner()
        for slot in plan["slots"]:
            try:
                result = runner(**_runner_arguments(slot, observed_at))
                projection = _slot_projection(slot=slot, result=result, plan=plan)
            except Exception as exc:
                projection = {
                    "slot_id": slot["slot_id"],
                    "outcome": "runner_error",
                    "receipt_sha256": None,
                    "token_usage": None,
                    "provider_budget_exhausted": None,
                    "anomaly_codes": [],
                    "error_class": type(exc).__name__,
                }
                runner_failed = True
            slot_results.append(projection)
            batch_anomalies.extend(projection["anomaly_codes"])
            if runner_failed or projection["anomaly_codes"]:
                break
        after = balance_probe()

    executed_slot_count = len(slot_results)
    executed_results = list(slot_results)
    slot_results.extend(
        _unlaunched_projection(slot)
        for slot in plan["slots"][executed_slot_count:]
    )

    complete_usages = [
        row["token_usage"]
        for row in executed_results
        if row["token_usage"] is not None
    ]
    tokens_complete = (
        len(complete_usages) == len(executed_results)
        and bool(executed_results)
        and all(row["measurement_complete"] for row in complete_usages)
    )
    cache_complete = tokens_complete and all(
        row["cache_measurement_complete"] for row in complete_usages
    )
    finish_reason_complete = (
        tokens_complete
        and all(
            row["finish_reason_measurement_complete"] is True
            for row in complete_usages
        )
    )

    if not before.get("is_available"):
        status = "blocked_before_launch_balance_unavailable"
    elif runner_failed:
        status = "stopped_after_slot_error"
    elif batch_anomalies:
        status = "stopped_after_anomalous_consumption"
    elif after is None or not after.get("is_available"):
        status = "stopped_after_batch_balance_unavailable"
    else:
        status = "completed_batch_boundary_review_required"

    def total(name: str, complete: bool) -> int | None:
        if not complete:
            return None
        return sum(int(row[name]) for row in complete_usages)

    finish_reason_counts = None
    if finish_reason_complete:
        finish_reason_counts = {
            reason: sum(
                int(row["finish_reason_counts"][reason])
                for row in complete_usages
            )
            for reason in (
                "stop",
                "length",
                "tool_calls",
                "content_filter",
                "function_call",
                "unknown",
            )
        }

    receipt = {
        "schema_version": "rtlflowbench.guarded_resource_batch_receipt.v1",
        "observed_at": observed_at,
        "batch_id": plan["batch_id"],
        "plan_sha256": _sha(plan_path),
        "status": status,
        "balance_checks": {"before": before, "after": after},
        "slot_results": slot_results,
        "summary": {
            "planned_slot_count": len(plan["slots"]),
            "executed_slot_count": executed_slot_count,
            "launch_slot_count": sum(
                row["outcome"] == "resource_receipt_created"
                for row in slot_results
            ),
            "not_launched_slot_count": sum(
                row["outcome"] == "not_launched" for row in slot_results
            ),
            "input_tokens": total("input_tokens", tokens_complete),
            "output_tokens": total("output_tokens", tokens_complete),
            "total_tokens": total("total_tokens", tokens_complete),
            "cache_hit_input_tokens": total(
                "cache_hit_input_tokens", cache_complete
            ),
            "cache_miss_input_tokens": total(
                "cache_miss_input_tokens", cache_complete
            ),
            "token_measurement_complete": tokens_complete,
            "cache_measurement_complete": cache_complete,
            "finish_reason_measurement_complete": finish_reason_complete,
            "finish_reason_counts": finish_reason_counts,
            "output_cap_reached_call_count": total(
                "output_cap_reached_call_count", finish_reason_complete
            ),
            "output_cap_with_length_finish_count": total(
                "output_cap_with_length_finish_count", finish_reason_complete
            ),
            "anomaly_codes": sorted(set(batch_anomalies)),
            "next_batch_permitted": False,
        },
        "attempt_accounting": {
            "official_attempts_started": 0,
            "official_semantic_attempts_consumed": 0,
            "benchmark_results_created": 0,
        },
        "readiness": {
            "batch_boundary_reached": True,
            "manual_next_batch_launch_required": True,
            "official_attempts_permitted": False,
        },
        "excluded_claims": [
            "This guarded batch receipt is resource-calibration control evidence and is not an RTL benchmark verdict or score.",
            "No exact provider balance, credential, prompt, response, user identifier, private oracle, or hidden evaluator content is persisted.",
            "A completed batch does not authorize the next batch; a fresh balance and anomaly review is required before another invocation.",
            "The warning thresholds are development safeguards and are not frozen publication budgets or evidence of benchmark readiness.",
        ],
    }
    _validate(RECEIPT_SCHEMA, receipt, "guarded batch receipt")
    _write_new(receipt_path, receipt)
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--observed-at", required=True)
    args = parser.parse_args()
    try:
        receipt = run_batch(
            plan_path=args.plan,
            receipt_path=args.receipt,
            observed_at=args.observed_at,
        )
    except Exception as exc:
        print(json.dumps({"status": "error", "error_class": type(exc).__name__}))
        return 2
    print(json.dumps({"status": receipt["status"]}, sort_keys=True))
    return 0 if receipt["status"] == (
        "completed_batch_boundary_review_required"
    ) else 2


if __name__ == "__main__":
    raise SystemExit(main())
