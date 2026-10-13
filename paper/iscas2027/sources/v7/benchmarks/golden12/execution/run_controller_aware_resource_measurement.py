#!/usr/bin/env python3
"""Run one public-only resource calibration behind the observed controller.

The runner has two deliberately separate paths:

* a materialized public launch is executed in a no-network OCI container and
  produces process, controller-activity, and merged resource receipts;
* a public capability preclassification is recorded as not launched with all
  workflow resource metrics unavailable.  It is not promoted to a workflow
  BLOCK verdict and consumes neither a resource nor an official attempt.

No private evaluator is mounted or invoked by either path.
"""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import signal
import subprocess
import sys
import time
from typing import Any, Callable

from jsonschema import Draft202012Validator, FormatChecker


HERE = Path(__file__).resolve().parent
RESOURCE_REQUEST_SCHEMA = HERE / "full_workflow_resource_measurement_request.schema.json"
BRIDGE_SET_SCHEMA = HERE / "full_workflow_bridge_request_set.schema.json"
PROVIDER_GATE_SCHEMA = HERE.parent / "evaluation/common_provider_gate_receipt.schema.json"
CAMPAIGN_AUTHORIZATION_SCHEMA = (
    HERE / "full_workflow_resource_campaign_authorization.schema.json"
)
CAMPAIGN_AUTHORIZATION_BUILDER = (
    HERE / "authorize_full_workflow_resource_campaign.py"
)
PROCESS_RECEIPT_SCHEMA = HERE / "workflow_resource_measurement_receipt.schema.json"
ACTIVITY_LEDGER_SCHEMA = HERE / "workflow_activity_ledger.schema.json"
NONLAUNCH_RECEIPT_SCHEMA = HERE / "controller_resource_nonlaunch_receipt.schema.json"
PROCESS_ENVELOPE = HERE / "run_workflow_resource_measurement.py"
TRANSPORT = HERE / "observed_controller_transport.py"
CLIENT = HERE / "controller_client.py"
ACTIVITY_BUILDER = HERE / "build_workflow_activity_concurrency_receipt.py"
MERGER = HERE / "merge_full_workflow_resource_measurement.py"
MERGED_RECEIPT_SCHEMA = HERE / "full_workflow_resource_measurement_receipt.schema.json"
MAGE_BROKER = HERE.parent / "conformance/external_workflows/mage_eda_broker.py"
RUNNER_ID = "rtlflowbench.controller_aware_resource_measurement_envelope.v1"
CHIPFLOW_BUDGET_REVIEWER_ENVIRONMENT = (
    "CHIPFLOW_DESIGN_UNIT_REVIEWER_MODE=budget-single-v1"
)
COMMON_MODEL = "deepseek-v4-pro"
LAUNCH_POLICY = HERE / "full_workflow_resource_launch_policy_candidate.json"
PROVIDER_RUNTIME_CONFIG = (
    HERE.parent / "evaluation/common_provider_runtime_config.yaml"
)
PROVIDER_CONFIG_CONTAINER_PATH = "/run/rtlflowbench-provider/config.yaml"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
UNIX_SOCKET_PATH_MAX_BYTES = 103
FORBIDDEN_PATH_PARTS = frozenset({"private", "oracle", "evaluator"})
SLOT_PYTHON = {
    "chipflow": "/opt/native-preflight-env/bin/python",
    "same_model_vanilla_agent": "/opt/native-preflight-env/bin/python",
    "external_airtl_1": "/usr/bin/python3",
    "external_airtl_2": "/usr/bin/python3",
    "external_airtl_3": "/usr/bin/python3",
}
RUNTIME_SOURCE_CLOSURE = (
    (RESOURCE_REQUEST_SCHEMA, "2f3f4e76f650191c73383c0a48ae7f413c0ec874e18fd36ceb96e927eec881ca"),
    (BRIDGE_SET_SCHEMA, "52fef9e9e6dd3e2a8e6c8104eb15e57280e5ba1fdeb45cd05ee8466f5bfbaa4f"),
    (PROVIDER_GATE_SCHEMA, "94aa9fa12c0932b8ab31c7682ef31591e22b99c77a4b67f9e1acddb52c3bee9b"),
    (CAMPAIGN_AUTHORIZATION_SCHEMA, "ad23e5ff9b027f4ed0e11bf16c290a5fb4ec1385a89885f76ebf2a39ea98173b"),
    (CAMPAIGN_AUTHORIZATION_BUILDER, "fe93477b6d5c820cadff2624671ef6d58961216ea6ff8b2e0f72e5cf20950ad3"),
    (PROCESS_RECEIPT_SCHEMA, "ac803c06736410983d1bbc4ee5c1571dc32b443e526afd7a6585a3ce23293622"),
    (ACTIVITY_LEDGER_SCHEMA, "e5c33f42f752286ee18df647ccfe839b2cbb47f9caf213d82886f4676d395727"),
    (NONLAUNCH_RECEIPT_SCHEMA, "1ed99557531f787f1718e22693253d66b5fe81e8c134715355a0364c2bd7b6d7"),
    (PROCESS_ENVELOPE, "725a82708255c5681709cc81356fb144f365c8701ab156556b695c8ec537b993"),
    (TRANSPORT, "0aeff03b0bdf44f8a7a03c0d123c213b7f9a66579aa9bff0f3235c37eab47788"),
    (CLIENT, "f65d26aa5f93ef39e4c72e6261fffacbd161502f2cbeb7d7e534a95500c86590"),
    (ACTIVITY_BUILDER, "372caf3140ad98e978ce6d87e51bfc1948cb09d3b32a42145569b6eda07bc49b"),
    (MERGER, "ea5db7015f0cf849c9093d839c0d0c46eb672350ea1b73753150c8d85d47b3e9"),
    (MERGED_RECEIPT_SCHEMA, "525b1db2cd59d70382013277dab86151fed62368052e98c6284cc519065498d7"),
    (MAGE_BROKER, "b17d727a91e1d575fe3d03020a78d471a39183d762f8360dada8fb920b1ba1ea"),
    (LAUNCH_POLICY, "12ad99db7e514ac4876a6c0c78bda30b88e2bdc2c799d6c587ac4f3f2dd05989"),
    (PROVIDER_RUNTIME_CONFIG, "4b9f281a1f4f974701e5c805cffe3ebbec0a06ae7849197e4ed17ba3b831a3f7"),
)


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


def _validate_runtime_source_closure() -> None:
    drifted = [
        path.name
        for path, expected_sha256 in RUNTIME_SOURCE_CLOSURE
        if _sha(path) != expected_sha256
    ]
    if drifted:
        raise ValueError(
            "controller runtime source closure drift: " + ", ".join(drifted)
        )


def _canonical_sha(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
    ).hexdigest()


def _private_runtime_root() -> Path:
    """Return the private user runtime root used only for ephemeral sockets."""
    runtime_value = os.environ.get("XDG_RUNTIME_DIR")
    if not runtime_value:
        raise ValueError("XDG_RUNTIME_DIR is required for controller sockets")
    runtime_root = Path(runtime_value).expanduser().absolute()
    if (
        runtime_root.is_symlink()
        or not runtime_root.is_dir()
        or runtime_root.stat().st_uid != os.geteuid()
        or runtime_root.stat().st_mode & 0o077
    ):
        raise ValueError("XDG_RUNTIME_DIR must be a private directory owned by this user")
    return runtime_root


def _controller_socket_path(
    *, measurement_id: str, expected_bridge_set_sha256: str
) -> tuple[Path, Path]:
    """Return a private, portable-length host socket path outside evidence roots."""
    runtime_root = _private_runtime_root()
    token = hashlib.sha256(
        (measurement_id + ":" + expected_bridge_set_sha256).encode("utf-8")
    ).hexdigest()[:16]
    controller_root = runtime_root / f"rtlflowbench-{token}"
    controller_socket = controller_root / "controller.sock"
    if controller_root.exists() or controller_root.is_symlink():
        raise FileExistsError("refusing to reuse controller socket root")
    if len(os.fsencode(controller_socket)) > UNIX_SOCKET_PATH_MAX_BYTES:
        raise ValueError("XDG_RUNTIME_DIR is too long for a portable controller socket")
    return controller_root, controller_socket


def _mage_broker_socket_path(
    *, measurement_id: str, expected_bridge_set_sha256: str
) -> tuple[Path, Path]:
    """Return a short private MAGE broker socket path outside evidence roots."""
    runtime_root = _private_runtime_root()
    token = hashlib.sha256(
        ("mage:" + measurement_id + ":" + expected_bridge_set_sha256).encode("utf-8")
    ).hexdigest()[:16]
    broker_root = runtime_root / f"rtlfb-mage-{token}"
    broker_socket = broker_root / "broker.sock"
    if broker_root.exists() or broker_root.is_symlink():
        raise FileExistsError("refusing to reuse MAGE broker socket root")
    if len(os.fsencode(broker_socket)) > UNIX_SOCKET_PATH_MAX_BYTES:
        raise ValueError("XDG_RUNTIME_DIR is too long for a portable MAGE broker socket")
    return broker_root, broker_socket


def _write_new(path: Path, value: Any) -> None:
    if path.exists() or path.is_symlink():
        raise FileExistsError(f"refusing to overwrite: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def _module(path: Path, name: str):
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"module source is unavailable: {path.name}")
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ValueError(f"cannot load module: {path.name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _validate(schema_path: Path, value: dict[str, Any], label: str) -> None:
    schema = _load(schema_path, f"{label} schema")
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(value)


def _safe_relative(value: str, label: str) -> PurePosixPath:
    relative = PurePosixPath(value)
    lowered = {part.casefold() for part in relative.parts}
    if (
        relative.is_absolute()
        or not relative.parts
        or any(part in {"", ".", ".."} for part in relative.parts)
        or lowered & FORBIDDEN_PATH_PARTS
    ):
        raise ValueError(f"unsafe {label}")
    return relative


def _tree_payload(root: Path) -> tuple[int, str]:
    if root.is_symlink() or not root.is_dir():
        raise ValueError("bridge request root must be a regular directory")
    rows: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        _safe_relative(relative, "bridge request entry")
        if path.is_symlink():
            raise ValueError("bridge request root contains a symlink")
        if path.is_dir():
            continue
        if not path.is_file():
            raise ValueError("bridge request root contains a non-regular entry")
        payload = path.read_bytes()
        rows.append(
            {
                "path": relative,
                "bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
    return len(rows), _canonical_sha(rows)


def _require_sha(path: Path, expected: str, label: str) -> Path:
    if SHA256_RE.fullmatch(expected) is None or _sha(path) != expected:
        raise ValueError(f"{label} differs from its out-of-band SHA256")
    return path


def _bound_inputs(
    *,
    resource_request_path: Path,
    bridge_set_path: Path,
    expected_bridge_set_sha256: str,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], Path | None]:
    resource_request_path = resource_request_path.expanduser().resolve(strict=True)
    bridge_set_path = bridge_set_path.expanduser().resolve(strict=True)
    _require_sha(bridge_set_path, expected_bridge_set_sha256, "bridge request set")
    request = _load(resource_request_path, "resource request")
    bridge_set = _load(bridge_set_path, "bridge request set")
    _validate(RESOURCE_REQUEST_SCHEMA, request, "resource request")
    _validate(BRIDGE_SET_SCHEMA, bridge_set, "bridge request set")
    request_sha256 = _sha(resource_request_path)
    matching = [
        row
        for row in bridge_set["requests"]
        if row["measurement_id"] == request["measurement_id"]
    ]
    if len(matching) != 1:
        raise ValueError("bridge set does not contain exactly one measurement row")
    row = matching[0]
    identity_keys = (
        "measurement_id",
        "workflow_slot_id",
        "workflow_id",
        "task_id",
        "calibration_run_index",
    )
    if any(row[key] != request[key] for key in identity_keys):
        raise ValueError("bridge/resource measurement identity drift")
    if row["resource_request_sha256"] != request_sha256:
        raise ValueError("bridge row does not bind the exact resource request")
    public = request["public_input_binding"]
    if not (
        row["public_workspace_set_sha256"]
        == public["workspace_set_receipt_sha256"]
        and row["public_workspace_receipt_sha256"]
        == public["workspace_receipt_sha256"]
        and row["public_workspace_payload_sha256"]
        == public["workspace_payload_sha256"]
        and public["private_assets_included"] is False
        and request["controller_binding"]["private_evaluator_reachable"] is False
        and request["launch_contract_binding"]["hidden_evaluator_reachable"] is False
        and request["launch_contract_binding"]["task_solution_knowledge_included"] is False
    ):
        raise ValueError("public workspace or isolation binding drift")
    request_root: Path | None = None
    if row["disposition"] == "launch_request_materialized_not_run":
        relative = _safe_relative(row["request_relative_root"], "bridge request root")
        set_root = bridge_set_path.parent.resolve(strict=True)
        request_root = (set_root / Path(*relative.parts)).resolve(strict=True)
        if not request_root.is_relative_to(set_root):
            raise ValueError("bridge request root escapes its set root")
        count, payload_sha = _tree_payload(request_root)
        if (
            count != row["request_file_count"]
            or payload_sha != row["request_payload_sha256"]
            or row["support_classification"]["supported"] is not True
        ):
            raise ValueError("bridge request tree differs from its set receipt")
    else:
        if not (
            row["request_relative_root"] is None
            and row["request_file_count"] is None
            and row["request_payload_sha256"] is None
            and row["support_classification"]["supported"] is False
        ):
            raise ValueError("preclassified bridge disposition is inconsistent")
    return request, bridge_set, row, request_root


def _resolved_workflow_command(
    request: dict[str, Any], *, observed_at: str
) -> list[str]:
    bindings = dict(request["launch_contract_binding"]["placeholder_bindings"])
    if bindings.get("FROZEN_MODEL", COMMON_MODEL) != COMMON_MODEL:
        raise ValueError("workflow launch model differs from the common model")
    if bindings.get("OBSERVED_AT") == "runtime_observed_at":
        bindings["OBSERVED_AT"] = observed_at
    unresolved = request["launch_contract_binding"]["unresolved_runtime_placeholders"]
    if unresolved not in ([], ["OBSERVED_AT"]):
        raise ValueError("unsupported runtime placeholder set")
    values: list[str] = []
    for item in request["launch_contract_binding"]["container_argv_template"]:
        rendered = item
        for key, value in bindings.items():
            rendered = rendered.replace("{" + key + "}", value)
        if "{" in rendered or "}" in rendered:
            raise ValueError("launch command contains an unresolved placeholder")
        values.append(rendered)
    expected_python = SLOT_PYTHON[request["workflow_slot_id"]]
    if not values or values[0] != expected_python:
        raise ValueError("workflow launch Python differs from the reviewed runtime")
    if values[1] != request["launch_contract_binding"]["entrypoint"]:
        raise ValueError("workflow launch entrypoint differs from its binding")
    return values


def _workflow_runtime_env_args(request: dict[str, Any]) -> list[str]:
    """Return task-neutral runtime configuration required by one workflow.

    ChipFlow's production graph defaults to three independent Critics.  The
    frozen common four-call budget instead uses the already-reviewed
    budget-single topology (one Critic plus the mandatory Judge).  This is a
    workflow runtime setting, not task knowledge or a workflow-specific budget.
    """

    if request.get("workflow_id") == "chipflow":
        return [f"--env={CHIPFLOW_BUDGET_REVIEWER_ENVIRONMENT}"]
    return []


def _provider_runtime_config_path(request: dict[str, Any]) -> Path:
    expected_policy_sha256 = request["resource_policy"]["launch_policy_sha256"]
    _require_sha(LAUNCH_POLICY, expected_policy_sha256, "resource launch policy")
    policy = _load(LAUNCH_POLICY, "resource launch policy")
    source = policy.get("source_evidence", {}).get("provider_runtime_config")
    expected_relative = (
        "benchmarks/golden12/evaluation/common_provider_runtime_config.yaml"
    )
    if not (
        isinstance(source, dict)
        and source.get("path") == expected_relative
        and SHA256_RE.fullmatch(str(source.get("sha256"))) is not None
    ):
        raise ValueError("resource launch policy provider config binding is invalid")
    repository_root = HERE.parents[2]
    config_path = (repository_root / expected_relative).resolve(strict=True)
    if config_path != PROVIDER_RUNTIME_CONFIG.resolve(strict=True):
        raise ValueError("provider runtime config path drifted")
    _require_sha(config_path, source["sha256"], "provider runtime config")
    return config_path


def build_launch_plan(
    *, request: dict[str, Any], bridge_row: dict[str, Any], observed_at: str
) -> dict[str, Any]:
    """Build a path-free, content-bound description of the OCI launch."""
    if bridge_row["disposition"] != "launch_request_materialized_not_run":
        raise ValueError("cannot build an OCI launch for a nonlaunch disposition")
    command = _resolved_workflow_command(request, observed_at=observed_at)
    is_mage = request["workflow_id"] == "mage"
    mount_roles = [
        {"role": "public_bridge_request", "container_path": "/input", "mode": "ro"},
        {"role": "workflow_scratch", "container_path": "/work", "mode": "rw"},
        {"role": "controller_socket", "container_path": "/run/rtlflowbench", "mode": "ro"},
        {"role": "controller_client_runtime", "container_path": "/run/rtlflowbench-client", "mode": "rw"},
        {"role": "controller_client_source", "container_path": "/opt/rtlflowbench-controller-client.py", "mode": "ro"},
        {"role": "provider_runtime_config", "container_path": PROVIDER_CONFIG_CONTAINER_PATH, "mode": "ro"},
    ]
    if is_mage:
        mount_roles.append(
            {"role": "mage_eda_broker_socket", "container_path": "/run/rtlflowbench-mage", "mode": "ro"}
        )
    return {
        "runner_id": RUNNER_ID,
        "measurement_id": request["measurement_id"],
        "workflow_slot_id": request["workflow_slot_id"],
        "workflow_id": request["workflow_id"],
        "task_id": request["task_id"],
        "runtime_binding": request["runtime_binding"],
        "network_policy": "none",
        "root_filesystem_read_only": True,
        "capabilities_dropped": "all",
        "no_new_privileges": True,
        "pids_limit": request["resource_policy"]["pids_limit"],
        "memory_limit_bytes": request["resource_policy"]["memory_limit_bytes"],
        "maximum_provider_calls": request["resource_policy"][
            "maximum_provider_calls"
        ],
        "maximum_output_tokens_per_call": request["resource_policy"][
            "maximum_output_tokens_per_call"
        ],
        "maximum_input_tokens": request["resource_policy"][
            "maximum_input_tokens"
        ],
        "maximum_output_tokens": request["resource_policy"][
            "maximum_output_tokens"
        ],
        "maximum_consecutive_identical_requests": request["resource_policy"][
            "maximum_consecutive_identical_requests"
        ],
        "maximum_consecutive_identical_errors": request["resource_policy"][
            "maximum_consecutive_identical_errors"
        ],
        "container_python": SLOT_PYTHON[request["workflow_slot_id"]],
        "workflow_runtime_profile": (
            "chipflow-budget-single-review-v1"
            if request["workflow_id"] == "chipflow"
            else "default-v1"
        ),
        "workflow_command_sha256": _canonical_sha(command),
        "workflow_argument_count": len(command),
        "workflow_arguments_recorded": False,
        "mount_roles": mount_roles,
        "provider_transport": request["controller_binding"]["provider_transport"],
        "eda_observation": request["controller_binding"]["eda_observation"],
        "credential_location": "host_controller_only",
        "provider_runtime_config_sha256": _sha(_provider_runtime_config_path(request)),
        "private_evaluator_reachable": False,
    }


def build_nonlaunch_receipt(
    *,
    request: dict[str, Any],
    bridge_set_sha256: str,
    bridge_row: dict[str, Any],
    resource_request_sha256: str,
    observed_at: str,
    resource_campaign_authorization_sha256: str | None = None,
) -> dict[str, Any]:
    if bridge_row["disposition"] != "controller_block_preclassified_not_run":
        raise ValueError("nonlaunch receipt requires a preclassified disposition")
    result = {
        "schema_version": "rtlflowbench.controller_resource_nonlaunch_receipt.v1",
        "observed_at": observed_at,
        "status": "not_available_not_launched",
        "measurement_id": request["measurement_id"],
        "workflow_slot_id": request["workflow_slot_id"],
        "workflow_id": request["workflow_id"],
        "task_id": request["task_id"],
        "attempt_id": request["attempt_id"],
        "input_sha256": {
            "resource_request": resource_request_sha256,
            "bridge_request_set": bridge_set_sha256,
            "runner": _sha(Path(__file__).resolve()),
            "schema": _sha(NONLAUNCH_RECEIPT_SCHEMA),
            **(
                {
                    "resource_campaign_authorization": (
                        resource_campaign_authorization_sha256
                    )
                }
                if resource_campaign_authorization_sha256 is not None
                else {}
            ),
        },
        "controller_disposition": {
            "reason_code": bridge_row["support_classification"]["reason_code"],
            "reason_sha256": hashlib.sha256(
                bridge_row["support_classification"]["reason"].encode("utf-8")
            ).hexdigest(),
            "raw_reason_embedded": False,
            "workflow_process_started": False,
            "workflow_block_verdict_created": False,
        },
        "metrics": {
            "wall_time_seconds": None,
            "cpu_time_seconds": None,
            "peak_memory_bytes": None,
            "peak_scratch_bytes": None,
            "peak_process_count": None,
            "peak_eda_concurrency": None,
            "peak_llm_concurrency": None,
            "llm_call_count": None,
            "eda_call_count": None,
        },
        "attempt_accounting": {
            "resource_calibration_attempt_consumed": False,
            "official_attempt_started": False,
            "official_semantic_attempt_consumed": False,
            "benchmark_result_created": False,
            "private_evaluator_calls": 0,
        },
        "readiness": {
            "resource_sample_created": False,
            "resource_sample_eligible": False,
            "host_capacity_policy_derivation_permitted": False,
            "official_attempts_permitted": False,
        },
        "excluded_claims": [
            "A public capability preclassification is not an observed workflow BLOCK verdict.",
            "No workflow process, provider, EDA tool, private evaluator, or official attempt was started.",
            "Unavailable workflow resource metrics remain null and are not represented as observed zeros.",
            "This controller disposition cannot support benchmark readiness, a score, ranking, QoR, or PPA claim.",
        ],
    }
    _validate(NONLAUNCH_RECEIPT_SCHEMA, result, "controller nonlaunch receipt")
    return result


def _provider_gate(
    path: Path, expected_sha256: str
) -> tuple[dict[str, Any], Path]:
    path = path.expanduser().resolve(strict=True)
    _require_sha(path, expected_sha256, "common provider gate")
    value = _load(path, "common provider gate")
    _validate(PROVIDER_GATE_SCHEMA, value, "common provider gate")
    if not (
        value["summary"]["passed_route_count"] == 5
        and value["summary"]["infra_route_count"] == 0
        and value["summary"]["not_run_route_count"] == 0
        and value["gate_decision"]["all_native_client_routes_passed"] is True
        and value["provider_binding"]["credential_value_or_hash_recorded"] is False
        and value["provider_binding"]["model_sha256"]
        == hashlib.sha256(COMMON_MODEL.encode("utf-8")).hexdigest()
    ):
        raise ValueError("common provider preflight has not passed all five routes")
    return value, path


def _campaign_authorization(
    path: Path,
    expected_sha256: str,
    *,
    common_provider_gate_sha256: str,
    bridge_request_set_sha256: str,
    resource_request_set_sha256: str,
) -> tuple[dict[str, Any], Path]:
    path = path.expanduser().resolve(strict=True)
    _require_sha(path, expected_sha256, "resource campaign authorization")
    value = _load(path, "resource campaign authorization")
    _validate(
        CAMPAIGN_AUTHORIZATION_SCHEMA,
        value,
        "resource campaign authorization",
    )
    inputs = value["input_sha256"]
    if not (
        value["status"]
        == "resource_campaign_authorized_model_release_pending"
        and value["decision"] == "PASS_RESOURCE_CALIBRATION_ONLY"
        and inputs["common_provider_gate"] == common_provider_gate_sha256
        and inputs["bridge_request_set"] == bridge_request_set_sha256
        and inputs["full_workflow_request_set"] == resource_request_set_sha256
        and inputs["controller_runner"] == _sha(Path(__file__).resolve())
        and inputs["authorization_builder"]
        == _sha(CAMPAIGN_AUTHORIZATION_BUILDER)
        and inputs["authorization_schema"] == _sha(CAMPAIGN_AUTHORIZATION_SCHEMA)
        and value["permissions"]["resource_calibration_campaign_permitted"]
        is True
        and value["permissions"]["official_attempts_permitted"] is False
        and value["permissions"]["benchmark_results_permitted"] is False
        and value["permissions"]["private_evaluator_reachable"] is False
        and value["readiness"]["resource_campaign_permitted"] is True
        and value["readiness"]["official_attempts_permitted"] is False
        and value["resource_campaign_blockers"] == []
    ):
        raise ValueError("resource campaign authorization binding drifted")
    return value, path


def _wait_socket(process: subprocess.Popen[bytes], path: Path) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("MAGE EDA broker exited before opening its socket")
        if path.exists() and not path.is_symlink():
            return
        time.sleep(0.02)
    raise RuntimeError("MAGE EDA broker socket did not become ready")


def _finish_process(process: subprocess.Popen[bytes]) -> tuple[int, bytes, bytes]:
    process.send_signal(signal.SIGTERM)
    try:
        stdout, stderr = process.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate(timeout=10)
    return process.returncode, stdout, stderr


def _terminate_process_group(process: subprocess.Popen[bytes]) -> int:
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        return process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        return process.wait(timeout=2)


def _wait_for_workflow_process(
    *,
    process: subprocess.Popen[bytes],
    state: Any,
    timeout_seconds: int,
    poll_interval_seconds: float = 0.02,
) -> tuple[int | None, bool, bool, str | None]:
    """Wait while enforcing controller terminal guards at process scope."""
    deadline = time.monotonic() + timeout_seconds
    while True:
        returncode = process.poll()
        if returncode is not None:
            return returncode, False, False, None
        guard_reason = state.terminal_guard_reason()
        if guard_reason is not None:
            return (
                _terminate_process_group(process),
                False,
                True,
                guard_reason,
            )
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _terminate_process_group(process)
            return None, True, False, None
        time.sleep(min(poll_interval_seconds, remaining))


def _actual_podman_argv(
    *,
    podman: Path,
    request: dict[str, Any],
    request_root: Path,
    work_root: Path,
    controller_root: Path,
    client_runtime: Path,
    session_id: str,
    observed_at: str,
    provider_runtime_config: Path,
    mage_broker_root: Path | None,
) -> tuple[list[str], int]:
    command = _resolved_workflow_command(request, observed_at=observed_at)
    argv = [
        str(podman),
        "run",
        "--rm",
        f"--name={request['measurement_id']}",
        "--pull=never",
        "--network=none",
        "--read-only",
        "--cap-drop=all",
        "--security-opt=no-new-privileges",
        f"--pids-limit={request['resource_policy']['pids_limit']}",
        f"--memory={request['resource_policy']['memory_limit_bytes']}",
        "--workdir=/work",
        f"--entrypoint={SLOT_PYTHON[request['workflow_slot_id']]}",
        f"--volume={request_root}:/input:ro",
        f"--volume={work_root}:/work:rw",
        f"--volume={controller_root}:/run/rtlflowbench:ro",
        f"--volume={client_runtime}:/run/rtlflowbench-client:rw",
        f"--volume={CLIENT}:/opt/rtlflowbench-controller-client.py:ro",
        f"--volume={provider_runtime_config}:{PROVIDER_CONFIG_CONTAINER_PATH}:ro",
    ]
    argv.extend(_workflow_runtime_env_args(request))
    if mage_broker_root is not None:
        argv.extend(
            [
                f"--volume={mage_broker_root}:/run/rtlflowbench-mage:ro",
                "--env=RTLFLOWBENCH_MAGE_EDA_SOCKET=/run/rtlflowbench-mage/broker.sock",
                f"--env=RTLFLOWBENCH_MAGE_EDA_SESSION_ID={session_id}",
                "--env=RTLFLOWBENCH_MAGE_EDA_CONTROL_ROOT=/work",
            ]
        )
    image_index = len(argv)
    argv.extend(
        [
            request["runtime_binding"]["image_id"],
            "/opt/rtlflowbench-controller-client.py",
            "--socket",
            "/run/rtlflowbench/controller.sock",
            "--session",
            session_id,
            "--shim-root",
            "/run/rtlflowbench-client/shims",
            "--",
            *command,
        ]
    )
    return argv, image_index


def run_controller_measurement(
    *,
    resource_request_path: Path,
    bridge_set_path: Path,
    expected_bridge_set_sha256: str,
    common_provider_gate_path: Path | None,
    expected_common_provider_gate_sha256: str | None,
    resource_campaign_authorization_path: Path | None = None,
    expected_resource_campaign_authorization_sha256: str | None = None,
    podman_path: Path | None,
    expected_podman_sha256: str | None,
    scratch_root: Path,
    output_root: Path,
    observed_at: str,
    provider_forwarder: Callable[..., tuple[int, dict[str, str], bytes]] | None = None,
    provider_api_key_environment: str = "DEEPSEEK_API_KEY",
    mage_eda_image_digest: str | None = None,
) -> dict[str, Any]:
    parsed = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("observed_at must include a timezone")
    _validate_runtime_source_closure()
    request, bridge_set, row, request_root = _bound_inputs(
        resource_request_path=resource_request_path,
        bridge_set_path=bridge_set_path,
        expected_bridge_set_sha256=expected_bridge_set_sha256,
    )
    output_root = output_root.expanduser().absolute()
    if output_root.exists() or output_root.is_symlink():
        raise FileExistsError("refusing to overwrite output root")
    output_root.mkdir(parents=True)
    if common_provider_gate_path is None or expected_common_provider_gate_sha256 is None:
        raise ValueError("a passed common provider gate is required for resource calibration")
    provider_gate, provider_gate_path = _provider_gate(
        common_provider_gate_path, expected_common_provider_gate_sha256
    )
    if (
        resource_campaign_authorization_path is None
        or expected_resource_campaign_authorization_sha256 is None
    ):
        raise ValueError("a content-bound resource campaign authorization is required")
    _authorization, authorization_path = _campaign_authorization(
        resource_campaign_authorization_path,
        expected_resource_campaign_authorization_sha256,
        common_provider_gate_sha256=_sha(provider_gate_path),
        bridge_request_set_sha256=expected_bridge_set_sha256,
        resource_request_set_sha256=bridge_set["input_sha256"][
            "resource_request_set"
        ],
    )
    if row["disposition"] == "controller_block_preclassified_not_run":
        result = build_nonlaunch_receipt(
            request=request,
            bridge_set_sha256=expected_bridge_set_sha256,
            bridge_row=row,
            resource_request_sha256=_sha(resource_request_path.resolve(strict=True)),
            observed_at=observed_at,
            resource_campaign_authorization_sha256=_sha(authorization_path),
        )
        _write_new(output_root / "controller-disposition-receipt.json", result)
        return result

    provider_runtime_config = _provider_runtime_config_path(request)
    if request_root is None:
        raise RuntimeError("launch disposition lacks a public request root")
    if podman_path is None or expected_podman_sha256 is None:
        raise ValueError("a bound Podman executable is required for launch")
    podman = podman_path.expanduser().resolve(strict=True)
    if podman.name != "podman" or not os.access(podman, os.X_OK):
        raise ValueError("Podman executable is unavailable")
    _require_sha(podman, expected_podman_sha256, "Podman executable")
    if provider_forwarder is None:
        api_key = os.environ.get(provider_api_key_environment)
        if not api_key:
            raise ValueError("host provider credential is unavailable")
        transport_module = _module(TRANSPORT, "rtlflowbench_observed_transport")
        provider_forwarder = transport_module.DeepSeekForwarder(api_key=api_key)
    else:
        transport_module = _module(TRANSPORT, "rtlflowbench_observed_transport")

    scratch_root = scratch_root.expanduser().absolute()
    if scratch_root.exists() or scratch_root.is_symlink():
        raise FileExistsError("refusing to reuse scratch root")
    if scratch_root == output_root or scratch_root.is_relative_to(output_root) or output_root.is_relative_to(scratch_root):
        raise ValueError("scratch and output roots must not overlap")
    work_root = scratch_root / "work"
    client_runtime = scratch_root / "client-runtime"
    work_root.mkdir(parents=True)
    client_runtime.mkdir()
    controller_root, controller_socket = _controller_socket_path(
        measurement_id=request["measurement_id"],
        expected_bridge_set_sha256=expected_bridge_set_sha256,
    )
    session_id = "session-" + hashlib.sha256(
        (request["measurement_id"] + expected_bridge_set_sha256).encode("utf-8")
    ).hexdigest()[:32]
    measurement = {
        key: request[key]
        for key in (
            "measurement_id",
            "measurement_scope",
            "workflow_slot_id",
            "workflow_id",
            "task_id",
            "attempt_id",
            "source_binding",
            "runtime_binding",
        )
    }
    state = transport_module.ControllerState(
        session_id=session_id,
        measurement=measurement,
        expected_model=request["launch_contract_binding"]["placeholder_bindings"].get(
            "FROZEN_MODEL", COMMON_MODEL
        ),
        maximum_provider_calls=request["resource_policy"][
            "maximum_provider_calls"
        ],
        maximum_output_tokens_per_call=request["resource_policy"][
            "maximum_output_tokens_per_call"
        ],
        maximum_input_tokens=request["resource_policy"][
            "maximum_input_tokens"
        ],
        maximum_output_tokens=request["resource_policy"][
            "maximum_output_tokens"
        ],
        maximum_consecutive_identical_requests=request["resource_policy"][
            "maximum_consecutive_identical_requests"
        ],
        maximum_consecutive_identical_errors=request["resource_policy"][
            "maximum_consecutive_identical_errors"
        ],
        provider_forwarder=provider_forwarder,
        provider_config_sha256=provider_gate["provider_binding"]["common_model_candidate_sha256"],
        provider_source_sha256=_sha(TRANSPORT),
        eda_config_sha256=request["controller_binding"]["observed_transport_probe_sha256"],
        eda_source_sha256=_sha(CLIENT),
    )
    plan = build_launch_plan(request=request, bridge_row=row, observed_at=observed_at)
    invocation = {
        "runner_id": RUNNER_ID,
        "measurement_id": request["measurement_id"],
        "resource_request_sha256": _sha(resource_request_path.resolve(strict=True)),
        "bridge_request_set_sha256": expected_bridge_set_sha256,
        "common_provider_gate_sha256": _sha(provider_gate_path),
        "resource_campaign_authorization_sha256": _sha(authorization_path),
        "podman_sha256": _sha(podman),
        "launch_plan_sha256": _canonical_sha(plan),
        "argv_values_recorded": False,
        "host_paths_recorded": False,
        "private_evaluator_reachable": False,
    }
    _write_new(output_root / "invocation.json", invocation)

    broker_process: subprocess.Popen[bytes] | None = None
    broker_root: Path | None = None
    broker_socket: Path | None = None
    broker_stdout = b""
    broker_stderr = b""
    broker_returncode: int | None = None
    if request["workflow_id"] == "mage":
        if mage_eda_image_digest is None or re.fullmatch(r"sha256:[0-9a-f]{64}", mage_eda_image_digest) is None:
            raise ValueError("MAGE offline EDA image digest is required")
        broker_root, broker_socket = _mage_broker_socket_path(
            measurement_id=request["measurement_id"],
            expected_bridge_set_sha256=expected_bridge_set_sha256,
        )
        max_requests = max(
            1,
            int(request["launch_contract_binding"]["placeholder_bindings"].get("MAGE_SIM_MAX_RETRY", "0")) + 1,
        )
        broker_process = subprocess.Popen(
            [
                sys.executable,
                str(MAGE_BROKER),
                "--socket",
                str(broker_socket),
                "--session-id",
                session_id,
                "--control-root",
                str(work_root),
                "--evidence-root",
                str(output_root / "mage-eda-calls"),
                "--scratch-root",
                str(scratch_root / "mage-eda-scratch"),
                "--image-digest",
                mage_eda_image_digest,
                "--max-requests",
                str(max_requests),
                "--controller-socket",
                str(controller_socket),
                "--controller-session-id",
                session_id,
            ],
            env={
                "PATH": "/usr/bin:/bin",
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "HOME": os.environ["HOME"],
                "XDG_RUNTIME_DIR": os.environ["XDG_RUNTIME_DIR"],
            },
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    environment = {
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "HOME": os.environ["HOME"],
        "XDG_RUNTIME_DIR": os.environ["XDG_RUNTIME_DIR"],
    }
    process_module = _module(PROCESS_ENVELOPE, "rtlflowbench_process_envelope")
    cpu_before = process_module._cpu_snapshot()
    timed_out = False
    controller_guard_terminated = False
    controller_guard_reason: str | None = None
    returncode: int | None = None
    started = time.monotonic()
    sampler = None
    try:
        with transport_module.ControllerServer(socket_path=controller_socket, state=state):
            if broker_process is not None and broker_socket is not None:
                _wait_socket(broker_process, broker_socket)
            argv, image_index = _actual_podman_argv(
                podman=podman,
                request=request,
                request_root=request_root,
                work_root=work_root,
                controller_root=controller_root,
                client_runtime=client_runtime,
                session_id=session_id,
                observed_at=observed_at,
                provider_runtime_config=provider_runtime_config,
                mage_broker_root=broker_root,
            )
            argv_sha256 = _canonical_sha(argv)
            with (
                (output_root / "stdout.log").open("wb") as stdout,
                (output_root / "stderr.log").open("wb") as stderr,
            ):
                state.set_origin(time.monotonic_ns())
                process = subprocess.Popen(
                    argv,
                    cwd=work_root,
                    env=environment,
                    stdin=subprocess.DEVNULL,
                    stdout=stdout,
                    stderr=stderr,
                    start_new_session=True,
                )
                sampler = process_module._Sampler(
                    root_pid=process.pid,
                    scratch_root=scratch_root,
                    interval_seconds=request["resource_policy"]["sampling_interval_ms"] / 1000,
                    podman=podman,
                    container_name=request["measurement_id"],
                    environment=environment,
                )
                sampler.start()
                try:
                    (
                        returncode,
                        timed_out,
                        controller_guard_terminated,
                        controller_guard_reason,
                    ) = _wait_for_workflow_process(
                        process=process,
                        state=state,
                        timeout_seconds=request["resource_policy"][
                            "wall_time_seconds"
                        ],
                    )
                finally:
                    sampler.finish()
    finally:
        if broker_process is not None:
            broker_returncode, broker_stdout, broker_stderr = _finish_process(broker_process)
            (output_root / "mage-broker.stdout.log").write_bytes(broker_stdout)
            (output_root / "mage-broker.stderr.log").write_bytes(broker_stderr)
        if broker_root is not None and broker_root.exists():
            broker_root.rmdir()
        if controller_root.exists():
            controller_root.rmdir()
    if sampler is None:
        raise RuntimeError("workflow process sampler was not created")
    forced_eda_activity_closure_count = state.close_unfinished_eda_on_process_exit(
        outcome="timed_out" if timed_out else "failed"
    )
    wall_time = time.monotonic() - started
    cpu_after = process_module._cpu_snapshot()
    user_cpu = max(0.0, cpu_after[0] - cpu_before[0])
    system_cpu = max(0.0, cpu_after[1] - cpu_before[1])
    process_receipt = {
        "schema_version": "rtlflowbench.workflow_resource_measurement_receipt.v1",
        "observed_at": observed_at,
        "status": "measurement_timeout" if timed_out else "measurement_completed",
        "runner_id": RUNNER_ID,
        **measurement,
        "request_sha256": _sha(resource_request_path.resolve(strict=True)),
        "runner_sha256": _sha(Path(__file__).resolve()),
        "request_schema_sha256": _sha(RESOURCE_REQUEST_SCHEMA),
        "receipt_schema_sha256": _sha(PROCESS_RECEIPT_SCHEMA),
        "launcher": {
            "kind": "podman_oci",
            "executable_sha256": _sha(podman),
            "exit_code": returncode,
            "timed_out": timed_out,
            "controller_guard_terminated": controller_guard_terminated,
            "controller_guard_reason": controller_guard_reason,
            "outcome": "timed_out" if timed_out else "exited_zero" if returncode == 0 else "exited_nonzero",
            "argv_sha256": argv_sha256,
            "argument_count": len(argv),
            "argv_values_recorded": False,
            "launcher_path_recorded": False,
            "runtime_image_argv_index": image_index,
            "runtime_image_binding_enforced_by_measurement_envelope": True,
            "network_policy_declared": "offline",
            "network_policy_enforced_by_measurement_envelope": True,
        },
        "metrics": {
            "wall_time_seconds": round(wall_time, 6),
            "envelope_child_user_cpu_time_seconds": round(user_cpu, 6),
            "envelope_child_system_cpu_time_seconds": round(system_cpu, 6),
            "envelope_child_cpu_time_seconds": round(user_cpu + system_cpu, 6),
            "peak_launcher_process_tree_rss_bytes": sampler.peak_rss_bytes,
            "peak_launcher_process_tree_count": sampler.peak_process_count,
            "peak_container_cgroup_memory_bytes": sampler.peak_container_memory_bytes,
            "container_cgroup_cpu_time_seconds": round(sampler.container_cpu_time_seconds, 6),
            "peak_container_cgroup_pids": sampler.peak_container_pids,
            "container_cgroup_sample_count": sampler.container_cgroup_sample_count,
            "container_cgroup_lookup_error_count": sampler.container_cgroup_lookup_error_count,
            "container_cgroup_read_error_count": sampler.container_cgroup_read_error_count,
            "peak_scratch_bytes": sampler.peak_scratch_bytes,
            "peak_eda_concurrency": None,
            "peak_llm_concurrency": None,
            "forced_eda_activity_closure_count": (
                forced_eda_activity_closure_count
            ),
            "sample_count": sampler.sample_count,
            "sampling_interval_ms": request["resource_policy"]["sampling_interval_ms"],
            "scratch_integrity_valid": sampler.scratch_integrity_valid,
        },
        "missing_measurements": ["peak_eda_concurrency", "peak_llm_concurrency"],
        "raw_evidence": {
            "invocation_sha256": _sha(output_root / "invocation.json"),
            "stdout_sha256": _sha(output_root / "stdout.log"),
            "stderr_sha256": _sha(output_root / "stderr.log"),
            "raw_content_embedded": False,
        },
        "attempt_accounting": {
            "official_attempt_started": False,
            "official_semantic_attempt_consumed": False,
            "resource_calibration_attempt_consumed": True,
            "benchmark_result_created": False,
            "private_evaluator_calls": 0,
        },
        "readiness": {
            "launcher_completed_successfully": not timed_out and returncode == 0,
            "process_tree_measurement_complete": not timed_out and sampler.sample_count > 0 and sampler.scratch_integrity_valid,
            "container_cgroup_measurement_complete": not timed_out and sampler.container_cgroup_sample_count > 0 and sampler.peak_container_memory_bytes > 0 and sampler.peak_container_pids > 0,
            "full_workflow_resource_calibration_eligible": False,
            "host_capacity_policy_derivation_permitted": False,
            "official_attempts_permitted": False,
        },
        "excluded_claims": [
            "This controller-aware resource measurement is not an RTL PASS, FAIL, BLOCK, INFRA verdict, score, or QoR result.",
            "The workflow container has no network and receives no real provider credential or private evaluator mount.",
            "Provider and EDA concurrency are merged only from a host-owned content-free activity ledger.",
            "No official Golden-12 semantic attempt is started or consumed by this resource calibration.",
            "Any EDA activity whose shim was terminated before eda_finish is conservatively closed at workflow process exit and counted explicitly.",
        ],
    }
    _validate(PROCESS_RECEIPT_SCHEMA, process_receipt, "process measurement receipt")
    process_path = output_root / "resource-measurement-receipt.json"
    _write_new(process_path, process_receipt)
    ledger = state.build_ledger(
        observed_at=observed_at,
        process_measurement_receipt_sha256=_sha(process_path),
    )
    _validate(ACTIVITY_LEDGER_SCHEMA, ledger, "activity ledger")
    ledger_path = output_root / "activity-ledger.json"
    _write_new(ledger_path, ledger)
    activity_module = _module(ACTIVITY_BUILDER, "rtlflowbench_activity_builder")
    activity_receipt = activity_module.build_receipt(
        ledger_path=ledger_path, observed_at=observed_at
    )
    activity_path = output_root / "activity-concurrency-receipt.json"
    _write_new(activity_path, activity_receipt)
    merger_module = _module(MERGER, "rtlflowbench_resource_merger")
    merged = merger_module.merge_receipts(
        process_receipt_path=process_path,
        activity_receipt_path=activity_path,
        observed_at=observed_at,
    )
    if broker_returncode not in (None, 0):
        merged["readiness"]["sample_complete"] = False
        merged["readiness"]["sample_eligible_for_resource_cohort"] = False
        merged["status"] = "full_workflow_resource_sample_ineligible"
    _validate(MERGED_RECEIPT_SCHEMA, merged, "merged resource receipt")
    _write_new(output_root / "full-workflow-resource-receipt.json", merged)
    return merged


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--resource-request", type=Path, required=True)
    parser.add_argument("--bridge-request-set", type=Path, required=True)
    parser.add_argument("--expected-bridge-request-set-sha256", required=True)
    parser.add_argument("--common-provider-gate", type=Path)
    parser.add_argument("--expected-common-provider-gate-sha256")
    parser.add_argument("--resource-campaign-authorization", type=Path)
    parser.add_argument("--expected-resource-campaign-authorization-sha256")
    parser.add_argument("--podman", type=Path)
    parser.add_argument("--expected-podman-sha256")
    parser.add_argument("--scratch-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--observed-at", required=True)
    parser.add_argument("--mage-eda-image-digest")
    args = parser.parse_args()
    try:
        result = run_controller_measurement(
            resource_request_path=args.resource_request,
            bridge_set_path=args.bridge_request_set,
            expected_bridge_set_sha256=args.expected_bridge_request_set_sha256,
            common_provider_gate_path=args.common_provider_gate,
            expected_common_provider_gate_sha256=args.expected_common_provider_gate_sha256,
            resource_campaign_authorization_path=args.resource_campaign_authorization,
            expected_resource_campaign_authorization_sha256=(
                args.expected_resource_campaign_authorization_sha256
            ),
            podman_path=args.podman,
            expected_podman_sha256=args.expected_podman_sha256,
            scratch_root=args.scratch_root,
            output_root=args.output_root,
            observed_at=args.observed_at,
            mage_eda_image_digest=args.mage_eda_image_digest,
        )
    except Exception as exc:
        print(json.dumps({"status": "error", "error_class": type(exc).__name__}))
        return 2
    print(json.dumps({"status": result["status"]}, sort_keys=True))
    if result["schema_version"] == "rtlflowbench.controller_resource_nonlaunch_receipt.v1":
        return 0
    return 0 if result["readiness"]["sample_eligible_for_resource_cohort"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
