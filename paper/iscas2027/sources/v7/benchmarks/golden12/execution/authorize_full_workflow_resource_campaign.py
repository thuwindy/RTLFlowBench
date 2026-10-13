#!/usr/bin/env python3
"""Authorize resource calibration only after all content-bound gates close."""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


HERE = Path(__file__).resolve().parent
SCHEMA = HERE / "full_workflow_resource_campaign_authorization.schema.json"
CONTROLLER_RUNNER = HERE / "run_controller_aware_resource_measurement.py"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _sha(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"expected regular non-symlink file: {path.name}")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _require_sha(path: Path, expected: str, label: str) -> str:
    if SHA256_RE.fullmatch(expected) is None or _sha(path) != expected:
        raise ValueError(f"{label} differs from its out-of-band trust anchor")
    return expected


def _load(path: Path, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a regular non-symlink file")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{label} must contain one JSON object")
    return value


def _validate_output(value: dict[str, Any]) -> None:
    schema = _load(SCHEMA, "authorization schema")
    Draft202012Validator.check_schema(schema)
    errors = sorted(
        Draft202012Validator(
            schema, format_checker=FormatChecker()
        ).iter_errors(value),
        key=lambda error: list(error.absolute_path),
    )
    if errors:
        first = errors[0]
        location = "/".join(str(part) for part in first.absolute_path)
        raise ValueError(
            f"authorization schema validation failed at {location or '<root>'}: "
            f"{first.message}"
        )


def build_authorization(
    *,
    blocked_preflight_path: Path,
    expected_blocked_preflight_sha256: str,
    workflow_release_candidate_path: Path,
    expected_workflow_release_candidate_sha256: str,
    common_provider_gate_path: Path,
    expected_common_provider_gate_sha256: str,
    controller_envelope_path: Path,
    expected_controller_envelope_sha256: str,
    observed_at: str,
) -> dict[str, Any]:
    parsed = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("observed_at must include a timezone")
    paths = {
        "blocked_preflight": blocked_preflight_path.expanduser().resolve(strict=True),
        "workflow_release_candidate": workflow_release_candidate_path.expanduser().resolve(strict=True),
        "common_provider_gate": common_provider_gate_path.expanduser().resolve(strict=True),
        "controller_envelope": controller_envelope_path.expanduser().resolve(strict=True),
    }
    digests = {
        "blocked_preflight": _require_sha(
            paths["blocked_preflight"],
            expected_blocked_preflight_sha256,
            "blocked resource preflight",
        ),
        "workflow_release_candidate": _require_sha(
            paths["workflow_release_candidate"],
            expected_workflow_release_candidate_sha256,
            "workflow release candidate",
        ),
        "common_provider_gate": _require_sha(
            paths["common_provider_gate"],
            expected_common_provider_gate_sha256,
            "common provider gate",
        ),
        "controller_envelope": _require_sha(
            paths["controller_envelope"],
            expected_controller_envelope_sha256,
            "controller envelope",
        ),
    }
    preflight = _load(paths["blocked_preflight"], "blocked resource preflight")
    release = _load(paths["workflow_release_candidate"], "workflow release candidate")
    gate = _load(paths["common_provider_gate"], "common provider gate")
    envelope = _load(paths["controller_envelope"], "controller envelope")

    preflight_input = preflight.get("input_sha256", {})
    preflight_readiness = preflight.get("readiness", {})
    if not (
        preflight.get("schema_version")
        == "rtlflowbench.full_workflow_resource_campaign_preflight.v1"
        and preflight.get("status") == "controller_preflight_blocked_not_started"
        and preflight.get("decision") == "BLOCK"
        and preflight.get("blockers") == ["common_provider_preflight_not_passed"]
        and preflight_input.get("workflow_release_candidate")
        == digests["workflow_release_candidate"]
        and preflight_input.get("controller_aware_measurement_envelope")
        == digests["controller_envelope"]
        and SHA256_RE.fullmatch(
            preflight_input.get("full_workflow_request_set", "")
        )
        and all(
            preflight_readiness.get(key) is True
            for key in (
                "static_inputs_complete",
                "launch_contracts_complete",
                "observed_provider_transport_complete",
                "observed_eda_transport_complete",
                "measurement_requests_materialized",
                "all_public_workspaces_materialized",
                "controller_envelope_bound",
            )
        )
        and all(
            preflight_readiness.get(key) is False
            for key in (
                "resource_campaign_permitted",
                "host_capacity_policy_derivation_permitted",
                "official_attempts_permitted",
            )
        )
        and preflight.get("summary", {}).get("resource_samples_created") == 0
        and preflight.get("attempt_accounting", {}).get("official_attempts_started")
        == 0
        and preflight.get("attempt_accounting", {}).get("private_evaluator_calls")
        == 0
    ):
        raise ValueError("blocked resource preflight is not authorization-eligible")

    release_summary = release.get("summary", {})
    release_readiness = release.get("readiness", {})
    release_input = release.get("input_sha256", {})
    if not (
        release.get("schema_version")
        == "rtlflowbench.workflow_release_set_candidate.v1"
        and release.get("status") == "automatic_inputs_assessed_release_pending"
        and release_input.get("common_provider_gate")
        == digests["common_provider_gate"]
        and release_summary.get("workflow_count") == 5
        and release_summary.get("task_count") == 12
        and release_summary.get("attempt_slot_count") == 200
        and release_summary.get("provider_route_pass_count") == 5
        and release_summary.get("provider_route_infra_count") == 0
        and release_summary.get("provider_route_not_run_count") == 0
        and release_readiness.get("all_five_provider_routes_passed") is True
        and release_readiness.get("official_attempts_permitted") is False
    ):
        raise ValueError("workflow release candidate is not resource-calibration eligible")

    gate_summary = gate.get("summary", {})
    gate_decision = gate.get("gate_decision", {})
    provider_binding = gate.get("provider_binding", {})
    if not (
        gate.get("schema_version") == "rtlflowbench.common_provider_gate_receipt.v2"
        and gate.get("status")
        == "pass_all_native_routes_model_candidate_not_frozen"
        and gate_summary.get("required_route_count") == 5
        and gate_summary.get("passed_route_count") == 5
        and gate_summary.get("infra_route_count") == 0
        and gate_summary.get("not_run_route_count") == 0
        and gate_summary.get("semantic_attempts_consumed") == 0
        and gate_summary.get("task_results_created") == 0
        and gate_decision.get("all_native_client_routes_passed") is True
        and gate_decision.get("official_attempts_permitted") is False
        and gate_decision.get("model_or_provider_substitution_permitted") is False
        and provider_binding.get("provider") == "deepseek"
        and provider_binding.get("thinking_mode") == "disabled"
        and provider_binding.get("temperature") == 0
        and provider_binding.get("common_model_release_frozen") is False
        and provider_binding.get("credential_value_or_hash_recorded") is False
        and SHA256_RE.fullmatch(
            provider_binding.get("common_model_candidate_sha256", "")
        )
    ):
        raise ValueError("common provider gate is not the exact five-route candidate gate")
    common_model_sha = provider_binding["common_model_candidate_sha256"]
    if release.get("source_sha256", {}).get("common_model_candidate") != common_model_sha:
        raise ValueError("workflow release and provider gate common-model bindings differ")

    envelope_input = envelope.get("input_sha256", {})
    if not (
        envelope.get("schema_version")
        == "rtlflowbench.controller_aware_measurement_envelope.v1"
        and envelope.get("status")
        == "controller_envelope_bound_provider_preflight_pending"
        and envelope.get("decision") == "BLOCK"
        and envelope.get("blockers") == ["common_provider_preflight_not_passed"]
        and envelope_input.get("resource_request_set")
        == preflight_input["full_workflow_request_set"]
        and SHA256_RE.fullmatch(envelope_input.get("bridge_request_set", ""))
        and envelope.get("summary", {}).get("planned_slot_count") == 200
        and envelope.get("summary", {}).get("launch_plan_bound_count") == 98
        and envelope.get("summary", {}).get("nonlaunch_disposition_bound_count")
        == 102
        and envelope.get("summary", {}).get("resource_sample_count") == 0
        and envelope.get("readiness", {}).get("controller_envelope_bound") is True
        and envelope.get("readiness", {}).get(
            "all_200_controller_dispositions_bound"
        )
        is True
        and envelope.get("readiness", {}).get("official_attempts_permitted")
        is False
    ):
        raise ValueError("controller envelope is not authorization-eligible")

    official_blockers = sorted(
        set(release.get("blockers", []))
        | {
            "common_model_release_not_frozen",
            "resource_calibration_not_completed",
        }
    )
    result = {
        "schema_version": "rtlflowbench.full_workflow_resource_campaign_authorization.v1",
        "observed_at": observed_at,
        "status": "resource_campaign_authorized_model_release_pending",
        "decision": "PASS_RESOURCE_CALIBRATION_ONLY",
        "scope": "five_workflows_all_twelve_tasks_resource_calibration_only",
        "input_sha256": {
            **digests,
            "full_workflow_request_set": preflight_input[
                "full_workflow_request_set"
            ],
            "bridge_request_set": envelope_input["bridge_request_set"],
            "common_model_candidate": common_model_sha,
            "controller_runner": _sha(CONTROLLER_RUNNER),
            "authorization_builder": _sha(Path(__file__).resolve()),
            "authorization_schema": _sha(SCHEMA),
        },
        "provider_gate": {
            "provider": "deepseek",
            "required_route_count": 5,
            "passed_route_count": 5,
            "infra_route_count": 0,
            "not_run_route_count": 0,
            "thinking_mode": "disabled",
            "temperature": 0,
            "credential_value_or_hash_recorded": False,
            "common_model_release_frozen": False,
        },
        "cohort": {
            "workflow_count": 5,
            "task_count": 12,
            "planned_resource_measurement_count": 200,
            "launch_plan_count": 98,
            "nonlaunch_disposition_count": 102,
        },
        "permissions": {
            "resource_calibration_campaign_permitted": True,
            "maximum_planned_resource_measurements": 200,
            "host_capacity_policy_derivation_permitted": False,
            "official_attempts_permitted": False,
            "benchmark_results_permitted": False,
            "private_evaluator_reachable": False,
        },
        "attempt_accounting": {
            "resource_calibration_attempts_consumed": 0,
            "official_attempts_started": 0,
            "official_semantic_attempts_consumed": 0,
            "benchmark_results_created": 0,
            "private_evaluator_calls": 0,
        },
        "readiness": {
            "common_provider_preflight_passed": True,
            "all_200_controller_dispositions_bound": True,
            "resource_campaign_permitted": True,
            "resource_calibration_complete": False,
            "host_capacity_policy_derivation_permitted": False,
            "official_attempts_permitted": False,
        },
        "resource_campaign_blockers": [],
        "official_attempt_blockers": official_blockers,
        "excluded_claims": [
            "This authorization permits resource calibration only and is not an RTL benchmark attempt, verdict, score, ranking, QoR result, or PPA result.",
            "The private evaluator and hidden oracle remain unreachable throughout the resource campaign.",
            "Provider prompts, responses, credentials, and user identifiers are not embedded in this authorization.",
            "The common model and workflow releases remain development candidates and official attempts remain prohibited.",
            "Resource samples must still be collected, validated, aggregated, and independently reviewed before host-capacity policy derivation.",
        ],
    }
    _validate_output(result)
    rendered = json.dumps(result, sort_keys=True)
    if "/home/" in rendered or "/Users/" in rendered:
        raise ValueError("authorization exposes a private host path")
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--blocked-preflight", type=Path, required=True)
    parser.add_argument("--expected-blocked-preflight-sha256", required=True)
    parser.add_argument("--workflow-release-candidate", type=Path, required=True)
    parser.add_argument("--expected-workflow-release-candidate-sha256", required=True)
    parser.add_argument("--common-provider-gate", type=Path, required=True)
    parser.add_argument("--expected-common-provider-gate-sha256", required=True)
    parser.add_argument("--controller-envelope", type=Path, required=True)
    parser.add_argument("--expected-controller-envelope-sha256", required=True)
    parser.add_argument("--observed-at", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists() or args.output.is_symlink():
        raise FileExistsError("refusing to overwrite resource campaign authorization")
    try:
        result = build_authorization(
            blocked_preflight_path=args.blocked_preflight,
            expected_blocked_preflight_sha256=args.expected_blocked_preflight_sha256,
            workflow_release_candidate_path=args.workflow_release_candidate,
            expected_workflow_release_candidate_sha256=args.expected_workflow_release_candidate_sha256,
            common_provider_gate_path=args.common_provider_gate,
            expected_common_provider_gate_sha256=args.expected_common_provider_gate_sha256,
            controller_envelope_path=args.controller_envelope,
            expected_controller_envelope_sha256=args.expected_controller_envelope_sha256,
            observed_at=args.observed_at,
        )
    except (OSError, TypeError, ValueError) as exc:
        print(json.dumps({"status": "authorization_block", "error_class": type(exc).__name__}, sort_keys=True))
        return 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(json.dumps({"status": result["status"], "decision": result["decision"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
