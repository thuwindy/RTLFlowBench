#!/usr/bin/env python3
"""Build a content-bound, fail-closed public resource-calibration batch plan."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
MAGE_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
EXPECTED_PROVIDER_POLICY = {
    "maximum_calls_per_slot": 4,
    "maximum_output_tokens_per_call": 8192,
    "maximum_input_tokens_per_slot": 163840,
    "maximum_output_tokens_per_slot": 16384,
    "maximum_consecutive_identical_requests": 2,
    "maximum_consecutive_identical_errors": 2,
}
REQUEST_POLICY_KEYS = {
    "maximum_provider_calls": "maximum_calls_per_slot",
    "maximum_output_tokens_per_call": "maximum_output_tokens_per_call",
    "maximum_input_tokens": "maximum_input_tokens_per_slot",
    "maximum_output_tokens": "maximum_output_tokens_per_slot",
    "maximum_consecutive_identical_requests": "maximum_consecutive_identical_requests",
    "maximum_consecutive_identical_errors": "maximum_consecutive_identical_errors",
}


class PlanError(ValueError):
    """A fail-closed plan construction error."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_regular_absolute(path_text: str, label: str) -> Path:
    path = Path(path_text)
    if not path.is_absolute():
        raise PlanError(f"{label} must be absolute")
    if path.is_symlink() or not path.is_file():
        raise PlanError(f"{label} must be a regular non-symlink file: {path}")
    return path


def require_expected_sha(path: Path, expected: str, label: str) -> str:
    if not SHA256_RE.fullmatch(expected):
        raise PlanError(f"{label} expected sha256 is malformed")
    actual = sha256_file(path)
    if actual != expected:
        raise PlanError(f"{label} sha256 mismatch")
    return actual


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PlanError(f"{label} is not readable JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise PlanError(f"{label} must be a JSON object")
    return value


def validate_json(instance: dict[str, Any], schema_path: Path, label: str) -> None:
    schema = load_json(schema_path, f"{label} schema")
    errors = sorted(Draft202012Validator(schema).iter_errors(instance), key=lambda e: list(e.path))
    if errors:
        first = errors[0]
        location = "/".join(str(part) for part in first.path) or "<root>"
        raise PlanError(f"{label} schema validation failed at {location}: {first.message}")


def require_campaign_cross_bindings(
    *,
    bridge: dict[str, Any],
    bridge_sha256: str,
    common_gate: dict[str, Any],
    common_gate_sha256: str,
    authorization: dict[str, Any],
    runner_sha256: str,
) -> None:
    """Reject a resource-only authorization from a different campaign lock.

    The authorization is the content-addressed link between the provider gate,
    controller envelope, request set, bridge set, and controller runner.  A
    batch plan must not reuse an otherwise valid authorization after any of
    those inputs has been rebuilt.
    """

    bridge_inputs = bridge.get("input_sha256")
    authorization_inputs = authorization.get("input_sha256")
    provider_binding = common_gate.get("provider_binding")
    if not isinstance(bridge_inputs, dict):
        raise PlanError("bridge request set input bindings are missing")
    if not isinstance(authorization_inputs, dict):
        raise PlanError("authorization input bindings are missing")
    if not isinstance(provider_binding, dict):
        raise PlanError("common provider gate binding is missing")

    request_set_sha256 = bridge_inputs.get("resource_request_set")
    common_model_sha256 = bridge_inputs.get("common_model_candidate")
    if not isinstance(request_set_sha256, str) or not SHA256_RE.fullmatch(
        request_set_sha256
    ):
        raise PlanError("bridge request-set binding is malformed")
    if not isinstance(common_model_sha256, str) or not SHA256_RE.fullmatch(
        common_model_sha256
    ):
        raise PlanError("bridge common-model binding is malformed")

    expected = {
        "bridge_request_set": bridge_sha256,
        "common_provider_gate": common_gate_sha256,
        "controller_runner": runner_sha256,
        "full_workflow_request_set": request_set_sha256,
        "common_model_candidate": common_model_sha256,
    }
    for name, digest in expected.items():
        if authorization_inputs.get(name) != digest:
            raise PlanError(f"authorization {name} binding mismatch")

    if not (
        provider_binding.get("provider") == "deepseek"
        and provider_binding.get("common_model_candidate_sha256")
        == common_model_sha256
        and provider_binding.get("automatic_model_fallback_permitted") is False
    ):
        raise PlanError("common provider gate model/provider binding mismatch")

    planned = bridge.get("summary", {}).get("planned_run_count")
    if not (
        planned == 200
        and authorization.get("permissions", {}).get(
            "maximum_planned_resource_measurements"
        )
        == planned
    ):
        raise PlanError("authorization measurement-count binding mismatch")


def require_author_alpha_cross_bindings(
    *,
    author_alpha: dict[str, Any],
    requests: list[dict[str, Any]],
) -> None:
    """Bind every resource slot to the reviewed alpha execution envelope."""

    permissions = author_alpha.get("permissions", {})
    review = author_alpha.get("review", {})
    common = author_alpha.get("common_execution", {})
    schedule = author_alpha.get("attempt_schedule", {})
    schema_version = author_alpha.get("schema_version")
    legacy_lock = (
        schema_version == "rtlflowbench.author_reviewed_alpha_content_lock.v1"
        and author_alpha.get("status")
        == "author_reviewed_alpha_content_locked_provider_preflight_required"
        and review.get("author_technical_review_complete") is True
        and review.get("self_approval_used_for_official_release") is False
        and permissions.get(
            "development_wave0_launch_permitted_after_fresh_provider_preflight_pass"
        )
        is True
        and permissions.get("official_attempts_permitted") is False
        and permissions.get("publication_permitted") is False
        and schedule.get("total_attempt_slots") == 200
        and schedule.get("started_attempts_at_lock_time") == 0
    )
    release_bound_lock = (
        schema_version == "rtlflowbench.ai_reviewed_v1_campaign_launch_lock.v1"
        and author_alpha.get("lock_id")
        == "golden12-ai-reviewed-v1-author-supervised-pilot"
        and author_alpha.get("status")
        == "pilot_content_locked_fresh_provider_preflight_required"
        and author_alpha.get("benchmark_release", {}).get("release_class")
        == "Golden-12 AI-reviewed v1"
        and permissions.get(
            "author_supervised_pilot_launch_after_fresh_provider_preflight"
        )
        is True
        and permissions.get("official_attempts_permitted") is False
        and permissions.get("publication_of_workflow_results_permitted") is False
        and permissions.get("benchmark_bytes_may_change") is False
        and permissions.get("workflow_specific_budget_override_permitted") is False
        and author_alpha.get("schedule", {}).get("total_semantic_slots") == 200
        and author_alpha.get("schedule", {}).get("started_slots") == 0
        and author_alpha.get("schedule", {}).get("semantic_slots_consumed") == 0
    )
    author_alpha_relock = (
        schema_version == "rtlflowbench.author_alpha_campaign_relock.v1"
        and author_alpha.get("lock_id")
        == "golden12-author-alpha-v2.3-five-workflow-full-rerun"
        and author_alpha.get("status")
        == "AUTHOR_ALPHA_V2_3_CONTENT_LOCKED_FRESH_PROVIDER_PREFLIGHT_REQUIRED"
        and (
            author_alpha.get("benchmark_release", {}).get("release_class")
            == "Golden-12 AI-reviewed v1"
            or (
                author_alpha.get("benchmark_release", {}).get("release_class")
                == "Golden-12 author-alpha v2.3 current-content development"
                and author_alpha.get("benchmark_release", {}).get("official_release") is False
            )
        )
        and permissions.get("author_alpha_pilot_after_preflight") is True
        and permissions.get("official_attempts_permitted") is False
        and permissions.get("publication_of_workflow_results_permitted") is False
        and permissions.get("benchmark_bytes_may_change") is False
        and permissions.get("workflow_specific_budget_override_permitted") is False
        and author_alpha.get("schedule", {}).get("restart_from_zero") is True
        and author_alpha.get("schedule", {}).get("total_semantic_slots") == 200
        and author_alpha.get("schedule", {}).get("started_slots") == 0
        and author_alpha.get("schedule", {}).get("semantic_slots_consumed") == 0
    )
    if not (legacy_lock or release_bound_lock or author_alpha_relock):
        raise PlanError("campaign lock does not permit a fail-closed research pilot")

    expected_common = {
        "provider": "deepseek",
        "model": "deepseek-v4-pro",
        "thinking_mode": "disabled",
        "temperature": 0,
        "top_p": 1,
        "maximum_provider_calls_per_slot": 4,
        "maximum_provider_retries": 0,
        "maximum_output_candidates_per_call": 1,
        "maximum_output_tokens_per_call": 8192,
        "maximum_input_tokens_per_slot": 163840,
        "maximum_output_tokens_per_slot": 16384,
        "maximum_consecutive_identical_requests": 2,
        "maximum_consecutive_identical_errors": 2,
        "provider_timeout_seconds": 120,
        "maximum_slots_per_batch": 3,
        "balance_probe_before_and_after_batch_required": True,
        "fresh_provider_preflight_required": True,
    }
    if any(common.get(key) != value for key, value in expected_common.items()):
        raise PlanError("author alpha common execution bounds mismatch")

    tasks = {
        task.get("task_id"): task
        for task in author_alpha.get("tasks", [])
        if isinstance(task, dict) and isinstance(task.get("task_id"), str)
    }
    workflows = {
        workflow.get("workflow_id"): workflow
        for workflow in author_alpha.get("workflows", [])
        if isinstance(workflow, dict)
        and isinstance(workflow.get("workflow_id"), str)
    }
    if len(tasks) != 12 or len(workflows) != 5:
        raise PlanError("author alpha task/workflow inventory is incomplete")

    for request in requests:
        measurement_id = request.get("measurement_id", "<unknown>")
        task = tasks.get(request.get("task_id"))
        workflow = workflows.get(request.get("workflow_id"))
        if task is None or workflow is None:
            raise PlanError(f"{measurement_id}: absent from author alpha lock")

        runtime = request.get("runtime_binding", {})
        source = request.get("source_binding", {})
        if not (
            runtime.get("image_digest") == workflow.get("runtime_image_digest")
            and runtime.get("image_id") == workflow.get("runtime_image_id")
            and source.get("commit") == workflow.get("source_commit")
            and source.get("manifest_sha256")
            == workflow.get("source_manifest_sha256")
        ):
            raise PlanError(f"{measurement_id}: workflow runtime/source lock mismatch")

        official = request.get("official_attempt_binding", {})
        run_index = official.get("independent_run_index")
        seeds = {
            row.get("independent_run_index"): row.get("seed")
            for row in task.get("seed_schedule", [])
            if isinstance(row, dict)
        }
        if not (
            isinstance(run_index, int)
            and seeds.get(run_index) == official.get("seed")
            and official.get("semantic_attempt_consumed") is False
        ):
            raise PlanError(f"{measurement_id}: seed or attempt-state lock mismatch")

        policy = request.get("resource_policy", {})
        budget = task.get("budget", {})
        if not (
            policy.get("maximum_provider_calls")
            == common.get("maximum_provider_calls_per_slot")
            and policy.get("maximum_input_tokens")
            == common.get("maximum_input_tokens_per_slot")
            and policy.get("maximum_output_tokens")
            == common.get("maximum_output_tokens_per_slot")
            and policy.get("maximum_provider_calls")
            <= budget.get("maximum_llm_calls")
            and policy.get("maximum_input_tokens")
            <= budget.get("maximum_input_tokens")
            and policy.get("maximum_output_tokens")
            <= budget.get("maximum_output_tokens")
            and policy.get("wall_time_seconds") == budget.get("wall_time_seconds")
            and budget.get("maximum_human_interventions") == 0
            and budget.get("network_access") is False
        ):
            raise PlanError(f"{measurement_id}: task budget lock mismatch")


def campaign_lock_schema(repo_root: Path, schema_version: str) -> Path:
    schemas = {
        "rtlflowbench.author_reviewed_alpha_content_lock.v1": "author_reviewed_alpha_lock.schema.json",
        "rtlflowbench.ai_reviewed_v1_campaign_launch_lock.v1": "ai_reviewed_v1_campaign_launch_lock.schema.json",
        "rtlflowbench.author_alpha_campaign_relock.v1": "author_alpha_campaign_relock.schema.json",
    }
    if schema_version not in schemas:
        raise PlanError("unsupported campaign lock schema")
    return repo_root / "benchmarks/golden12/evaluation" / schemas[schema_version]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--batch-id", required=True)
    parser.add_argument("--batch-root", required=True)
    parser.add_argument("--resource-request", action="append", required=True)
    parser.add_argument("--bridge-request-set", required=True)
    parser.add_argument("--expected-bridge-request-set-sha256", required=True)
    parser.add_argument("--common-provider-gate", required=True)
    parser.add_argument("--expected-common-provider-gate-sha256", required=True)
    parser.add_argument("--resource-campaign-authorization", required=True)
    parser.add_argument("--expected-resource-campaign-authorization-sha256", required=True)
    parser.add_argument("--launch-policy", required=True)
    parser.add_argument("--expected-launch-policy-sha256", required=True)
    parser.add_argument("--author-alpha-content-lock", required=True)
    parser.add_argument("--expected-author-alpha-content-lock-sha256", required=True)
    parser.add_argument(
        "--slot-runner",
        required=True,
        help="run_controller_aware_resource_measurement.py bound by the batch runner",
    )
    parser.add_argument("--expected-slot-runner-sha256", required=True)
    parser.add_argument("--podman", required=True)
    parser.add_argument("--expected-podman-sha256", required=True)
    parser.add_argument("--mage-eda-image-digest")
    parser.add_argument("--output", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if not 1 <= len(args.resource_request) <= 3:
            raise PlanError("a guarded batch must contain between one and three resource requests")
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,127}", args.batch_id):
            raise PlanError("batch id is invalid")

        repo_root = Path(args.repo_root)
        batch_root = Path(args.batch_root)
        output = Path(args.output)
        if not repo_root.is_absolute() or not repo_root.is_dir():
            raise PlanError("repo root must be an existing absolute directory")
        if not batch_root.is_absolute():
            raise PlanError("batch root must be absolute")
        if not output.is_absolute() or output.exists():
            raise PlanError("output must be an absent absolute path")

        bridge_path = require_regular_absolute(args.bridge_request_set, "bridge request set")
        common_gate_path = require_regular_absolute(args.common_provider_gate, "common provider gate")
        authorization_path = require_regular_absolute(
            args.resource_campaign_authorization, "resource campaign authorization"
        )
        launch_policy_path = require_regular_absolute(args.launch_policy, "launch policy")
        author_alpha_path = require_regular_absolute(
            args.author_alpha_content_lock, "author alpha content lock"
        )
        runner_path = require_regular_absolute(args.slot_runner, "guarded slot runner")
        podman_path = require_regular_absolute(args.podman, "podman binary")

        bridge_sha = require_expected_sha(
            bridge_path, args.expected_bridge_request_set_sha256, "bridge request set"
        )
        common_gate_sha = require_expected_sha(
            common_gate_path, args.expected_common_provider_gate_sha256, "common provider gate"
        )
        authorization_sha = require_expected_sha(
            authorization_path,
            args.expected_resource_campaign_authorization_sha256,
            "resource campaign authorization",
        )
        launch_policy_sha = require_expected_sha(
            launch_policy_path, args.expected_launch_policy_sha256, "launch policy"
        )
        author_alpha_sha = require_expected_sha(
            author_alpha_path,
            args.expected_author_alpha_content_lock_sha256,
            "author alpha content lock",
        )
        if runner_path.name != "run_controller_aware_resource_measurement.py":
            raise PlanError("guarded slot runner has an unexpected filename")
        runner_sha = require_expected_sha(
            runner_path,
            args.expected_slot_runner_sha256,
            "guarded slot runner",
        )
        podman_sha = require_expected_sha(podman_path, args.expected_podman_sha256, "podman binary")

        launch_policy = load_json(launch_policy_path, "launch policy")
        if launch_policy.get("schema_version") != "rtlflowbench.full_workflow_resource_launch_policy_candidate.v2":
            raise PlanError("unsupported launch policy schema")
        if launch_policy.get("provider") != {
            "maximum_calls_per_measurement": 4,
            "maximum_consecutive_identical_errors": 2,
            "maximum_consecutive_identical_requests": 2,
            "maximum_input_tokens_per_measurement": 163840,
            "maximum_output_tokens_per_call": 8192,
            "maximum_output_tokens_per_measurement": 16384,
            "maximum_retries": 0,
            "thinking_mode": "disabled",
            "timeout_seconds": 120,
        }:
            raise PlanError("launch policy provider bounds do not equal the cap4 guard contract")

        bridge = load_json(bridge_path, "bridge request set")
        if bridge.get("schema_version") != "rtlflowbench.full_workflow_bridge_request_set.v1":
            raise PlanError("unsupported bridge request set schema")
        bridge_entries = bridge.get("requests")
        if not isinstance(bridge_entries, list):
            raise PlanError("bridge request set has no request list")
        bridge_by_measurement: dict[str, dict[str, Any]] = {}
        for entry in bridge_entries:
            if not isinstance(entry, dict) or not isinstance(entry.get("measurement_id"), str):
                raise PlanError("bridge request entry is malformed")
            measurement_id = entry["measurement_id"]
            if measurement_id in bridge_by_measurement:
                raise PlanError("bridge request set contains duplicate measurement ids")
            bridge_by_measurement[measurement_id] = entry

        common_gate = load_json(common_gate_path, "common provider gate")
        gate_summary = common_gate.get("summary", {})
        gate_decision = common_gate.get("gate_decision", {})
        if not (
            common_gate.get("schema_version") == "rtlflowbench.common_provider_gate_receipt.v2"
            and gate_summary.get("required_route_count") == 5
            and gate_summary.get("passed_route_count") == 5
            and gate_summary.get("infra_route_count") == 0
            and gate_summary.get("not_run_route_count") == 0
            and gate_decision.get("all_native_client_routes_passed") is True
            and gate_decision.get("official_attempts_permitted") is False
        ):
            raise PlanError("common provider gate is not a 5/5 resource-only PASS")

        authorization = load_json(authorization_path, "resource campaign authorization")
        permissions = authorization.get("permissions", {})
        if not (
            authorization.get("schema_version")
            == "rtlflowbench.full_workflow_resource_campaign_authorization.v1"
            and authorization.get("decision") == "PASS_RESOURCE_CALIBRATION_ONLY"
            and permissions.get("resource_calibration_campaign_permitted") is True
            and permissions.get("official_attempts_permitted") is False
            and permissions.get("benchmark_results_permitted") is False
            and permissions.get("private_evaluator_reachable") is False
        ):
            raise PlanError("authorization does not permit only public resource calibration")

        require_campaign_cross_bindings(
            bridge=bridge,
            bridge_sha256=bridge_sha,
            common_gate=common_gate,
            common_gate_sha256=common_gate_sha,
            authorization=authorization,
            runner_sha256=runner_sha,
        )

        request_schema = (
            repo_root
            / "benchmarks/golden12/execution/full_workflow_resource_measurement_request.schema.json"
        )
        plan_schema = (
            repo_root
            / "benchmarks/golden12/execution/guarded_resource_batch_plan.schema.json"
        )
        bridge_schema = (
            repo_root
            / "benchmarks/golden12/execution/full_workflow_bridge_request_set.schema.json"
        )
        authorization_schema = (
            repo_root
            / "benchmarks/golden12/execution/full_workflow_resource_campaign_authorization.schema.json"
        )
        common_gate_schema = (
            repo_root
            / "benchmarks/golden12/evaluation/common_provider_gate_receipt.schema.json"
        )
        author_alpha = load_json(author_alpha_path, "author alpha content lock")
        author_alpha_schema = campaign_lock_schema(
            repo_root, author_alpha.get("schema_version")
        )
        for path, label in [
            (request_schema, "resource request schema"),
            (plan_schema, "plan schema"),
            (bridge_schema, "bridge request set schema"),
            (authorization_schema, "resource campaign authorization schema"),
            (common_gate_schema, "common provider gate schema"),
            (author_alpha_schema, "author alpha content lock schema"),
        ]:
            if path.is_symlink() or not path.is_file():
                raise PlanError(f"{label} is missing or is a symlink")
        validate_json(bridge, bridge_schema, "bridge request set")
        validate_json(
            authorization,
            authorization_schema,
            "resource campaign authorization",
        )
        validate_json(common_gate, common_gate_schema, "common provider gate")
        validate_json(
            author_alpha, author_alpha_schema, "author alpha content lock"
        )

        slots: list[dict[str, Any]] = []
        measurement_ids: set[str] = set()
        workflow_ids: set[str] = set()
        for request_text in args.resource_request:
            request_path = require_regular_absolute(request_text, "resource request")
            request = load_json(request_path, "resource request")
            validate_json(request, request_schema, "resource request")
            measurement_id = request["measurement_id"]
            workflow_id = request["workflow_id"]
            if measurement_id in measurement_ids:
                raise PlanError("duplicate measurement id in batch")
            if workflow_id in workflow_ids:
                raise PlanError("a guarded batch may contain only one slot per workflow")
            measurement_ids.add(measurement_id)
            workflow_ids.add(workflow_id)

            request_policy = request["resource_policy"]
            if request_policy.get("launch_policy_sha256") != launch_policy_sha:
                raise PlanError(f"{measurement_id}: launch policy binding mismatch")
            for request_key, plan_key in REQUEST_POLICY_KEYS.items():
                if request_policy.get(request_key) != EXPECTED_PROVIDER_POLICY[plan_key]:
                    raise PlanError(f"{measurement_id}: resource policy {request_key} mismatch")

            bridge_entry = bridge_by_measurement.get(measurement_id)
            if bridge_entry is None:
                raise PlanError(f"{measurement_id}: no bridge request binding")
            if bridge_entry.get("resource_request_sha256") != sha256_file(request_path):
                raise PlanError(f"{measurement_id}: bridge request sha256 mismatch")
            for key in ("workflow_id", "workflow_slot_id", "task_id", "calibration_run_index"):
                if bridge_entry.get(key) != request.get(key):
                    raise PlanError(f"{measurement_id}: bridge {key} mismatch")

            mage_digest: str | None = None
            if workflow_id == "mage":
                if not args.mage_eda_image_digest or not MAGE_DIGEST_RE.fullmatch(
                    args.mage_eda_image_digest
                ):
                    raise PlanError("MAGE slot requires a valid EDA image digest")
                mage_digest = args.mage_eda_image_digest

            scratch_root = batch_root / "slots" / workflow_id / "scratch"
            output_root = batch_root / "slots" / workflow_id / "output"
            if scratch_root.exists() or output_root.exists():
                raise PlanError(f"{measurement_id}: scratch/output root already exists")
            slots.append(
                {
                    "slot_id": measurement_id,
                    "resource_request": str(request_path),
                    "bridge_request_set": str(bridge_path),
                    "expected_bridge_request_set_sha256": bridge_sha,
                    "common_provider_gate": str(common_gate_path),
                    "expected_common_provider_gate_sha256": common_gate_sha,
                    "resource_campaign_authorization": str(authorization_path),
                    "expected_resource_campaign_authorization_sha256": authorization_sha,
                    "podman": str(podman_path),
                    "expected_podman_sha256": podman_sha,
                    "scratch_root": str(scratch_root),
                    "output_root": str(output_root),
                    "mage_eda_image_digest": mage_digest,
                }
            )

        require_author_alpha_cross_bindings(
            author_alpha=author_alpha,
            requests=[
                load_json(Path(slot["resource_request"]), "resource request")
                for slot in slots
            ],
        )

        plan = {
            "schema_version": "rtlflowbench.guarded_resource_batch_plan.v4",
            "batch_id": args.batch_id,
            "provider": "deepseek",
            "runner_sha256": runner_sha,
            "author_alpha_content_lock": str(author_alpha_path),
            "expected_author_alpha_content_lock_sha256": author_alpha_sha,
            "maximum_slots_per_batch": 3,
            "provider_policy": EXPECTED_PROVIDER_POLICY,
            "anomaly_thresholds": {
                "warning_input_tokens_per_slot": 122880,
                "warning_output_tokens_per_slot": 12288,
            },
            "slots": slots,
            "attempt_accounting": {
                "official_attempts_permitted": False,
                "resource_calibration_only": True,
            },
            "excluded_claims": [
                "This generated plan authorizes public resource calibration only and cannot produce a benchmark score or RTL PASS.",
                "The private evaluator and hidden oracle remain unreachable, and official semantic attempts remain forbidden.",
                "The guarded runner must stop the batch after a slot error or anomalous consumption and record remaining slots as not launched.",
                "A fresh balance and anomaly review is required after this batch before any continuation is authorized.",
            ],
        }
        validate_json(plan, plan_schema, "guarded batch plan")
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(
            json.dumps(
                {
                    "batch_id": args.batch_id,
                    "output": str(output),
                    "plan_sha256": sha256_file(output),
                    "slot_count": len(slots),
                    "status": "resource_only_plan_built",
                },
                sort_keys=True,
            )
        )
        return 0
    except PlanError as exc:
        print(f"BLOCK: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
