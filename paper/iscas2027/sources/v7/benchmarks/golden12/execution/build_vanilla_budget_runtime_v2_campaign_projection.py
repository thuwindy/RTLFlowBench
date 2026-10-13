#!/usr/bin/env python3
"""Project one task-neutral Vanilla runtime repair into the full campaign.

This builder performs no provider, EDA, workflow, or evaluator call.  It copies
the complete 200-slot request/bridge sets into a fresh output root, changes only
the 40 same-model Vanilla runtime bindings and their two bridge control files,
and validates every resulting JSON object against the existing frozen schemas.
"""

from __future__ import annotations

import argparse
from copy import deepcopy
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
import shutil
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[2]
RECEIPT_SCHEMA = HERE / "vanilla_budget_runtime_v2_campaign_projection.schema.json"
REQUEST_SCHEMA = HERE / "full_workflow_resource_measurement_request.schema.json"
REQUEST_SET_SCHEMA = HERE / "full_workflow_resource_measurement_request_set.schema.json"
BRIDGE_SET_SCHEMA = HERE / "full_workflow_bridge_request_set.schema.json"
RELEASE_SCHEMA = (
    REPO_ROOT
    / "benchmarks/golden12/evaluation/workflow_release_set_candidate.schema.json"
)
VANILLA_CONTROLLER = REPO_ROOT / "benchmarks/golden12/baselines/vanilla_agent/core.py"
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
IMAGE_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
VANILLA_ID = "same_model_vanilla_agent"


def _sha_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _sha(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"expected regular non-symlink file: {path}")
    return _sha_bytes(path.read_bytes())


def _require(path: Path, expected: str, label: str) -> Path:
    path = path.expanduser().resolve(strict=True)
    if SHA_RE.fullmatch(expected) is None or _sha(path) != expected:
        raise ValueError(f"{label} differs from its out-of-band SHA256")
    return path


def _load(path: Path, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a regular non-symlink file")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{label} must contain one JSON object")
    return value


def _write_new(path: Path, value: dict[str, Any]) -> None:
    if path.exists() or path.is_symlink():
        raise FileExistsError(f"refusing to overwrite: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _validate(schema_path: Path, value: dict[str, Any], label: str) -> None:
    schema = _load(schema_path, f"{label} schema")
    Draft202012Validator.check_schema(schema)
    errors = sorted(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(value),
        key=lambda error: list(error.absolute_path),
    )
    if errors:
        first = errors[0]
        location = "/".join(str(part) for part in first.absolute_path)
        raise ValueError(
            f"{label} schema error at {location or '<root>'}: {first.message}"
        )


def _canonical_digest(value: Any) -> str:
    return _sha_bytes(
        json.dumps(
            value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
    )


def _tree_entries(root: Path) -> list[dict[str, Any]]:
    if root.is_symlink() or not root.is_dir():
        raise ValueError("bridge request root must be a regular directory")
    rows: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError("bridge request root contains a symlink")
        if path.is_dir():
            continue
        if not path.is_file():
            raise ValueError("bridge request root contains a non-regular entry")
        relative = path.relative_to(root).as_posix()
        lowered = {part.casefold() for part in Path(relative).parts}
        if lowered & {"private", "oracle", "evaluator"}:
            raise ValueError("bridge request root exposes a forbidden path")
        payload = path.read_bytes()
        rows.append(
            {"path": relative, "bytes": len(payload), "sha256": _sha_bytes(payload)}
        )
    return rows


def _directory_manifest(root: Path) -> dict[str, str]:
    if root.is_symlink() or not root.is_dir():
        raise ValueError("directory manifest root is invalid")
    result: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError("directory manifest contains a symlink")
        if path.is_file():
            result[path.relative_to(root).as_posix()] = _sha(path)
        elif not path.is_dir():
            raise ValueError("directory manifest contains a non-regular entry")
    return result


def _project_vanilla_request(
    value: dict[str, Any], *, image_id: str, image_digest: str, source_manifest: str
) -> dict[str, Any]:
    result = deepcopy(value)
    if not (
        result.get("workflow_id") == VANILLA_ID
        and result.get("workflow_slot_id") == VANILLA_ID
        and result.get("schema_version")
        == "rtlflowbench.full_workflow_resource_measurement_request.v1"
        and result.get("controller_binding", {}).get("private_evaluator_reachable")
        is False
        and result.get("public_input_binding", {}).get("private_assets_included")
        is False
    ):
        raise ValueError("Vanilla resource request identity or isolation drifted")
    result["runtime_binding"] = {"image_digest": image_digest, "image_id": image_id}
    result["source_binding"]["manifest_sha256"] = source_manifest
    return result


def _project_vanilla_binding(
    value: dict[str, Any],
    *,
    controller_sha256: str,
    replacement: dict[str, Any] | None = None,
    decoding_transition: dict[str, Any] | None = None,
) -> dict[str, Any]:
    result = deepcopy(value)
    if not (
        result.get("schema_version") == "rtlflowbench.vanilla_workflow_binding.v1"
        and result.get("workflow", {}).get("name") == "same-model-vanilla-agent"
        and result.get("status") == "development_not_frozen"
    ):
        raise ValueError("Vanilla workflow binding identity drifted")
    if SHA_RE.fullmatch(str(controller_sha256)) is None:
        raise ValueError("controller digest is invalid")
    if replacement is not None:
        projected = deepcopy(replacement)
        comparison = deepcopy(projected)
        # Only runtime implementation identities and explicit version labels may
        # change. Model, decoding, budgets and all unknown fields remain exact.
        for key in (
            "controller_sha256",
            "provider_runner_sha256",
            "provider_response_schema_sha256",
        ):
            if key not in value or SHA_RE.fullmatch(str(projected.get(key))) is None:
                raise ValueError("replacement runtime component digest is invalid")
            comparison[key] = value[key]
        if projected["controller_sha256"] != controller_sha256:
            raise ValueError("replacement controller differs from bound source")
        if projected.get("decoding_config_sha256") != value.get(
            "decoding_config_sha256"
        ):
            transition = decoding_transition or {}
            old_config, new_config = (
                transition.get("prior_config"),
                transition.get("replacement_config"),
            )
            if not (
                isinstance(old_config, dict)
                and isinstance(new_config, dict)
                and _canonical_digest(old_config) == value.get("decoding_config_sha256")
                and _canonical_digest(new_config)
                == projected.get("decoding_config_sha256")
                and transition.get("prior_provider_runner_sha256")
                == value.get("provider_runner_sha256")
                and transition.get("replacement_provider_runner_sha256")
                == projected.get("provider_runner_sha256")
            ):
                raise ValueError("decoding transition is not content-bound")
            format_keys = {"response_contract", "prompt_projection"}
            if {k: v for k, v in old_config.items() if k not in format_keys} != {
                k: v for k, v in new_config.items() if k not in format_keys
            }:
                raise ValueError("decoding transition changes sampling or budget")
            comparison["decoding_config_sha256"] = value["decoding_config_sha256"]
        workflow = projected.get("workflow")
        if not isinstance(workflow, dict):
            raise ValueError("replacement workflow identity is missing")
        version = workflow.get("version")
        if (
            not isinstance(version, str)
            or re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,127}", version) is None
        ):
            raise ValueError("replacement version is invalid")
        if workflow.get("adapter_version") != version or version == value[
            "workflow"
        ].get("version"):
            raise ValueError("replacement must have a distinct, consistent version")
        for key in ("version", "adapter_version"):
            comparison["workflow"][key] = value["workflow"][key]
        if comparison != value:
            raise ValueError("replacement changes nonruntime workflow contract")
        return projected
    result["controller_sha256"] = controller_sha256
    version = "development-deepseek-v4-pro-budget-v2"
    result["workflow"]["adapter_version"] = version
    result["workflow"]["version"] = version
    return result


def _runtime_inputs(
    *,
    summary: dict[str, Any],
    preflight: dict[str, Any],
    gate: dict[str, Any],
    summary_sha: str,
    preflight_sha: str,
    gate_sha: str,
    replacement: dict[str, Any] | None = None,
    replacement_sha: str | None = None,
) -> dict[str, Any]:
    expected_schema = (
        "rtlflowbench.vanilla_versioned_runtime_candidate.v1"
        if replacement is not None
        else "rtlflowbench.vanilla_budget_runtime_v2_double_build.v1"
    )
    if not (
        summary.get("schema_version") == expected_schema
        and summary.get("status") == "PASS"
        and summary.get("benchmark_content_changed") is False
        and summary.get("private_evaluator_included") is False
        and summary.get("workflow_policy", {}).get("task_specific_logic_added") is False
        and summary.get("workflow_policy", {}).get("provider_budget_changed") is False
        and summary.get("build_policy", {}).get("two_build_digest_equal") is True
        and summary.get("build_policy", {}).get("offline_bind_probe_passed") is True
        and IMAGE_RE.fullmatch(str(summary.get("image_id")))
        and IMAGE_RE.fullmatch(str(summary.get("image_digest")))
        and SHA_RE.fullmatch(str(summary.get("runtime_component_manifest_sha256")))
        and SHA_RE.fullmatch(str(summary.get("controller_source_sha256")))
    ):
        raise ValueError("runtime summary is not projection eligible")
    if replacement is not None:
        if not (
            SHA_RE.fullmatch(str(replacement_sha))
            and summary.get("input_sha256", {}).get("workflow_binding")
            == replacement_sha
            and summary.get("workflow_version_id")
            == replacement.get("workflow", {}).get("version")
            and summary.get("controller_source_sha256")
            == replacement.get("controller_sha256")
            and summary.get("provider_runner_source_sha256")
            == replacement.get("provider_runner_sha256")
            and summary.get("provider_response_schema_sha256")
            == replacement.get("provider_response_schema_sha256")
            and summary.get("build_policy", {}).get("all_runtime_components_verified")
            is True
        ):
            raise ValueError("runtime candidate does not bind the replacement workflow")
    if not (
        preflight.get("schema_version")
        == "rtlflowbench.native_provider_route_preflight.v2"
        and preflight.get("status") == "pass"
        and preflight.get("workflow_slot_id") == VANILLA_ID
        and preflight.get("runtime_image_digest") == summary["image_digest"]
        and preflight.get("task_free_invariants", {}).get("semantic_attempt_consumed")
        is False
        and preflight.get("task_free_invariants", {}).get("private_evaluator_invoked")
        is False
        and preflight.get("secret_safety", {}).get("credential_value_recorded") is False
    ):
        raise ValueError("Vanilla provider preflight is not projection eligible")
    routes = [
        row
        for row in gate.get("native_routes", [])
        if row.get("workflow_slot_id") == VANILLA_ID
    ]
    if not (
        gate.get("schema_version") == "rtlflowbench.common_provider_gate_receipt.v2"
        and gate.get("status") == "pass_all_native_routes_model_candidate_not_frozen"
        and gate.get("summary", {}).get("passed_route_count") == 5
        and len(routes) == 1
        and routes[0].get("status") == "pass"
        and routes[0].get("preflight_sha256") == preflight_sha
        and routes[0].get("runtime_image_digest") == summary["image_digest"]
        and gate.get("provider_binding", {}).get("credential_value_or_hash_recorded")
        is False
    ):
        raise ValueError("common provider gate does not bind the Vanilla preflight")
    digests = {
        "runtime_summary": summary_sha,
        "vanilla_provider_preflight": preflight_sha,
        "common_provider_gate": gate_sha,
    }
    if replacement is not None:
        digests["replacement_workflow_binding"] = replacement_sha
    return digests


def build_projection(
    *,
    prior_request_root: Path,
    expected_prior_request_set_sha256: str,
    prior_bridge_root: Path,
    expected_prior_bridge_set_sha256: str,
    prior_release_candidate_path: Path,
    expected_prior_release_candidate_sha256: str,
    runtime_summary_path: Path,
    expected_runtime_summary_sha256: str,
    provider_preflight_path: Path,
    expected_provider_preflight_sha256: str,
    common_provider_gate_path: Path,
    expected_common_provider_gate_sha256: str,
    observed_at: str,
    projection_id: str,
    output_dir: Path,
    replacement_binding_path: Path | None = None,
    expected_replacement_binding_sha256: str | None = None,
) -> dict[str, Any]:
    parsed = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("observed_at must include a timezone")
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,127}", projection_id):
        raise ValueError("projection_id is invalid")
    output_dir = output_dir.expanduser().absolute()
    if output_dir.exists() or output_dir.is_symlink():
        raise FileExistsError("refusing to overwrite campaign projection")

    request_root = prior_request_root.expanduser().resolve(strict=True)
    bridge_root = prior_bridge_root.expanduser().resolve(strict=True)
    prior_request_set_path = _require(
        request_root / "request-set.json",
        expected_prior_request_set_sha256,
        "prior request set",
    )
    prior_bridge_set_path = _require(
        bridge_root / "bridge-request-set.json",
        expected_prior_bridge_set_sha256,
        "prior bridge set",
    )
    candidate_path = _require(
        prior_release_candidate_path,
        expected_prior_release_candidate_sha256,
        "prior release candidate",
    )
    runtime_path = _require(
        runtime_summary_path, expected_runtime_summary_sha256, "runtime summary"
    )
    preflight_path = _require(
        provider_preflight_path,
        expected_provider_preflight_sha256,
        "provider preflight",
    )
    gate_path = _require(
        common_provider_gate_path,
        expected_common_provider_gate_sha256,
        "common provider gate",
    )
    controller_sha = _sha(VANILLA_CONTROLLER)
    if (replacement_binding_path is None) != (
        expected_replacement_binding_sha256 is None
    ):
        raise ValueError(
            "replacement binding and expected digest must be supplied together"
        )
    replacement = None
    if replacement_binding_path is not None:
        replacement = _load(
            _require(
                replacement_binding_path,
                expected_replacement_binding_sha256,
                "replacement binding",
            ),
            "replacement binding",
        )
        _validate(
            VANILLA_CONTROLLER.parent / "workflow_binding.schema.json",
            replacement,
            "replacement binding",
        )
        for key, relative in (
            ("provider_runner_sha256", "openrouter_provider.py"),
            ("provider_response_schema_sha256", "provider_response.schema.json"),
        ):
            if replacement.get(key) != _sha(VANILLA_CONTROLLER.parent / relative):
                raise ValueError(
                    "replacement differs from current runtime component source"
                )

    prior_request_set = _load(prior_request_set_path, "prior request set")
    prior_bridge_set = _load(prior_bridge_set_path, "prior bridge set")
    prior_candidate = _load(candidate_path, "prior release candidate")
    _validate(REQUEST_SET_SCHEMA, prior_request_set, "prior request set")
    _validate(BRIDGE_SET_SCHEMA, prior_bridge_set, "prior bridge set")
    _validate(RELEASE_SCHEMA, prior_candidate, "prior release candidate")
    summary = _load(runtime_path, "runtime summary")
    preflight = _load(preflight_path, "provider preflight")
    gate = _load(gate_path, "common provider gate")
    runtime_digests = _runtime_inputs(
        summary=summary,
        preflight=preflight,
        gate=gate,
        summary_sha=expected_runtime_summary_sha256,
        preflight_sha=expected_provider_preflight_sha256,
        gate_sha=expected_common_provider_gate_sha256,
        replacement=replacement,
        replacement_sha=expected_replacement_binding_sha256,
    )
    if controller_sha != summary["controller_source_sha256"]:
        raise ValueError("current Vanilla controller differs from the runtime summary")
    if (
        len(prior_request_set.get("requests", [])) != 200
        or len(prior_bridge_set.get("requests", [])) != 200
    ):
        raise ValueError("prior campaign is not the full 200-slot matrix")

    output_dir.mkdir(parents=True)
    candidate_out = output_dir / "workflow-release-candidate.json"
    candidate = deepcopy(prior_candidate)
    candidate["observed_at"] = observed_at
    candidate["input_sha256"]["common_provider_gate"] = (
        expected_common_provider_gate_sha256
    )
    candidate_rows = [
        row for row in candidate["workflows"] if row.get("workflow_id") == VANILLA_ID
    ]
    if len(candidate_rows) != 1:
        raise ValueError("release candidate does not contain exactly one Vanilla row")
    candidate_row = candidate_rows[0]
    candidate_row.update(
        {
            "provider_route_preflight_sha256": expected_provider_preflight_sha256,
            "provider_route_status": "pass",
            "provider_route_passed": True,
            "runtime_image_digest": summary["image_digest"],
            "runtime_image_id": summary["image_id"],
            "runtime_receipt_sha256": expected_runtime_summary_sha256,
            "runtime_source_manifest_sha256": summary[
                "runtime_component_manifest_sha256"
            ],
            "runtime_stored_image_size_bytes": summary["stored_image_size_bytes"],
            "source_manifest_sha256": summary["runtime_component_manifest_sha256"],
            "runtime_candidate_status": "task_neutral_runtime_supersession_validated",
        }
    )
    _validate(RELEASE_SCHEMA, candidate, "projected release candidate")
    _write_new(candidate_out, candidate)
    candidate_sha = _sha(candidate_out)

    request_out_root = output_dir / "requests"
    shutil.copytree(request_root, request_out_root, copy_function=shutil.copy2)
    old_request_manifest = _directory_manifest(request_root)
    request_set = deepcopy(prior_request_set)
    request_set["observed_at"] = observed_at
    request_set["request_set_id"] = projection_id
    request_set["input_sha256"]["workflow_release_candidate"] = candidate_sha
    request_rows = {row["measurement_id"]: row for row in request_set["requests"]}
    vanilla_request_count = 0
    for measurement_id, row in request_rows.items():
        relative = Path(row["request_relative_path"])
        prior_path = request_root / relative
        output_path = request_out_root / relative
        if row["workflow_id"] != VANILLA_ID:
            continue
        prior_value = _load(prior_path, "prior Vanilla resource request")
        before_budget = deepcopy(prior_value["resource_policy"])
        before_seed = prior_value["official_attempt_binding"]["seed"]
        projected = _project_vanilla_request(
            prior_value,
            image_id=summary["image_id"],
            image_digest=summary["image_digest"],
            source_manifest=summary["runtime_component_manifest_sha256"],
        )
        if (
            projected["resource_policy"] != before_budget
            or projected["official_attempt_binding"]["seed"] != before_seed
        ):
            raise ValueError("Vanilla budget or seed changed during projection")
        _validate(REQUEST_SCHEMA, projected, "projected Vanilla resource request")
        output_path.write_text(
            json.dumps(projected, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        row["request_sha256"] = _sha(output_path)
        vanilla_request_count += 1
    if vanilla_request_count != 40:
        raise ValueError("projection did not replace exactly 40 Vanilla requests")
    _validate(REQUEST_SET_SCHEMA, request_set, "projected request set")
    (request_out_root / "request-set.json").write_text(
        json.dumps(request_set, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    request_set_sha = _sha(request_out_root / "request-set.json")
    new_request_manifest = _directory_manifest(request_out_root)
    non_vanilla_request_paths = {
        row["request_relative_path"]
        for row in prior_request_set["requests"]
        if row["workflow_id"] != VANILLA_ID
    }
    if any(
        old_request_manifest[path] != new_request_manifest[path]
        for path in non_vanilla_request_paths
    ):
        raise ValueError("a non-Vanilla resource request changed")

    bridge_out_root = output_dir / "bridge"
    shutil.copytree(bridge_root, bridge_out_root, copy_function=shutil.copy2)
    old_bridge_manifest = _directory_manifest(bridge_root)
    bridge_set = deepcopy(prior_bridge_set)
    bridge_set["observed_at"] = observed_at
    bridge_set["input_sha256"]["resource_request_set"] = request_set_sha
    bridge_rows = {row["measurement_id"]: row for row in bridge_set["requests"]}
    vanilla_binding_sha: str | None = None
    vanilla_bridge_count = 0
    for measurement_id, bridge_row in bridge_rows.items():
        request_row = request_rows[measurement_id]
        bridge_row["resource_request_sha256"] = request_row["request_sha256"]
        if bridge_row["workflow_id"] != VANILLA_ID:
            continue
        if bridge_row["disposition"] != "launch_request_materialized_not_run":
            raise ValueError("Vanilla bridge row is unexpectedly nonlaunch")
        root = bridge_out_root / bridge_row["request_relative_root"]
        binding_path = root / "workflow_binding.json"
        request_path = root / "vanilla_request.json"
        binding = _project_vanilla_binding(
            _load(binding_path, "Vanilla workflow binding"),
            controller_sha256=controller_sha,
            replacement=replacement,
            decoding_transition=summary.get("decoding_transition"),
        )
        binding_path.write_text(
            json.dumps(binding, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        current_binding_sha = _sha(binding_path)
        if vanilla_binding_sha is None:
            vanilla_binding_sha = current_binding_sha
        elif vanilla_binding_sha != current_binding_sha:
            raise ValueError(
                "Vanilla workflow bindings are not task-neutral and identical"
            )
        launch_request = _load(request_path, "Vanilla launch request")
        launch_request["sha256"]["workflow_binding"] = current_binding_sha
        request_path.write_text(
            json.dumps(launch_request, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        entries = _tree_entries(root)
        bridge_row["request_file_count"] = len(entries)
        bridge_row["request_payload_sha256"] = _canonical_digest(entries)
        vanilla_bridge_count += 1
    if vanilla_bridge_count != 40 or vanilla_binding_sha is None:
        raise ValueError("projection did not replace exactly 40 Vanilla bridge roots")
    bridge_set["input_sha256"]["vanilla_workflow_binding"] = vanilla_binding_sha
    _validate(BRIDGE_SET_SCHEMA, bridge_set, "projected bridge set")
    (bridge_out_root / "bridge-request-set.json").write_text(
        json.dumps(bridge_set, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    bridge_set_sha = _sha(bridge_out_root / "bridge-request-set.json")
    new_bridge_manifest = _directory_manifest(bridge_out_root)
    non_vanilla_bridge_paths: set[str] = set()
    for row in prior_bridge_set["requests"]:
        if row["workflow_id"] == VANILLA_ID or row["request_relative_root"] is None:
            continue
        prefix = row["request_relative_root"] + "/"
        non_vanilla_bridge_paths.update(
            path for path in old_bridge_manifest if path.startswith(prefix)
        )
    if any(
        old_bridge_manifest[path] != new_bridge_manifest[path]
        for path in non_vanilla_bridge_paths
    ):
        raise ValueError("a non-Vanilla bridge root changed")

    receipt = {
        "schema_version": "rtlflowbench.vanilla_budget_runtime_v2_campaign_projection.v1",
        "observed_at": observed_at,
        "status": "PASS_TASK_NEUTRAL_RUNTIME_BINDING_PROJECTED_NOT_RUN",
        "scope": "full_200_slot_campaign_vanilla_runtime_binding_only",
        "input_sha256": {
            "prior_resource_request_set": expected_prior_request_set_sha256,
            "prior_bridge_request_set": expected_prior_bridge_set_sha256,
            "prior_workflow_release_candidate": expected_prior_release_candidate_sha256,
            **runtime_digests,
            "vanilla_controller": controller_sha,
            "builder": _sha(Path(__file__).resolve()),
            "schema": _sha(RECEIPT_SCHEMA),
        },
        "output_sha256": {
            "workflow_release_candidate": candidate_sha,
            "resource_request_set": request_set_sha,
            "bridge_request_set": bridge_set_sha,
        },
        "summary": {
            "planned_slot_count": 200,
            "vanilla_slot_count": 40,
            "resource_request_replacement_count": 40,
            "resource_request_byte_identical_count": 160,
            "bridge_root_replacement_count": 40,
            "non_vanilla_bridge_root_byte_identical_count": len(
                non_vanilla_bridge_paths
            ),
            "provider_call_count": 0,
            "eda_call_count": 0,
            "private_evaluator_call_count": 0,
            "benchmark_result_count": 0,
        },
        "invariants": {
            "benchmark_bytes_changed": False,
            "public_workspace_payloads_changed": False,
            "budgets_changed": False,
            "seeds_changed": False,
            "scoring_changed": False,
            "private_evaluator_reachable": False,
            "task_specific_logic_added": False,
            "all_non_vanilla_resource_requests_byte_identical": True,
            "all_non_vanilla_bridge_roots_byte_identical": True,
        },
        "attempt_accounting": {
            "resource_calibration_attempts_consumed": 0,
            "official_attempts_started": 0,
            "semantic_attempts_consumed": 0,
        },
        "readiness": {
            "projection_validated": True,
            "controller_envelope_bound": False,
            "resource_campaign_authorized": False,
            "official_attempts_permitted": False,
        },
        "excluded_claims": [
            "This projection does not run Vanilla, a provider, EDA, or a private evaluator.",
            "Changing a task-neutral workflow runtime binding does not change benchmark inputs, scoring, seeds, budgets, or task difficulty.",
            "A projected request set is not a resource sample, benchmark verdict, QoR result, PPA result, or official attempt.",
            "The controller envelope, campaign preflight, and resource authorization must be regenerated before any public resource smoke.",
        ],
    }
    _validate(RECEIPT_SCHEMA, receipt, "projection receipt")
    rendered = json.dumps(receipt, sort_keys=True)
    if "/home/" in rendered or "/Users/" in rendered or "API_KEY" in rendered:
        raise ValueError("projection receipt exposes a host path or credential name")
    _write_new(output_dir / "projection-receipt.json", receipt)
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--prior-request-root", type=Path, required=True)
    parser.add_argument("--expected-prior-request-set-sha256", required=True)
    parser.add_argument("--prior-bridge-root", type=Path, required=True)
    parser.add_argument("--expected-prior-bridge-set-sha256", required=True)
    parser.add_argument("--prior-release-candidate", type=Path, required=True)
    parser.add_argument("--expected-prior-release-candidate-sha256", required=True)
    parser.add_argument("--runtime-summary", type=Path, required=True)
    parser.add_argument("--expected-runtime-summary-sha256", required=True)
    parser.add_argument("--provider-preflight", type=Path, required=True)
    parser.add_argument("--expected-provider-preflight-sha256", required=True)
    parser.add_argument("--common-provider-gate", type=Path, required=True)
    parser.add_argument("--expected-common-provider-gate-sha256", required=True)
    parser.add_argument("--observed-at", required=True)
    parser.add_argument("--projection-id", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--replacement-binding", type=Path)
    parser.add_argument("--expected-replacement-binding-sha256")
    args = parser.parse_args()
    result = build_projection(
        prior_request_root=args.prior_request_root,
        expected_prior_request_set_sha256=args.expected_prior_request_set_sha256,
        prior_bridge_root=args.prior_bridge_root,
        expected_prior_bridge_set_sha256=args.expected_prior_bridge_set_sha256,
        prior_release_candidate_path=args.prior_release_candidate,
        expected_prior_release_candidate_sha256=args.expected_prior_release_candidate_sha256,
        runtime_summary_path=args.runtime_summary,
        expected_runtime_summary_sha256=args.expected_runtime_summary_sha256,
        provider_preflight_path=args.provider_preflight,
        expected_provider_preflight_sha256=args.expected_provider_preflight_sha256,
        common_provider_gate_path=args.common_provider_gate,
        expected_common_provider_gate_sha256=args.expected_common_provider_gate_sha256,
        observed_at=args.observed_at,
        projection_id=args.projection_id,
        output_dir=args.output_dir,
        replacement_binding_path=args.replacement_binding,
        expected_replacement_binding_sha256=args.expected_replacement_binding_sha256,
    )
    print(json.dumps({"status": result["status"], **result["summary"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
