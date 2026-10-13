#!/usr/bin/env python3
"""Task-neutral standalone bridge into the official ChipFlow native graph.

This module deliberately contains no Golden-12 task IDs, executor selection,
RTL templates, prompts with design knowledge, or evaluator access.  It runs
the same public task transport for every task and records the first durable
native checkpoint.  Under the zero-intervention policy it stops at a native
approval gate instead of inventing an approval or bypassing Safe Executor.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
from typing import Any

from jsonschema import Draft202012Validator


WORKFLOW_ID = "chipflow"
CONTROL_RECEIPT = "chipflow_public_control_receipt.json"
PREAPPROVAL_POLICY = "scope_hash_bound_controller_preapproval"
MAX_MACHINE_PREAPPROVALS = 16
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
TEXT_SUFFIXES = frozenset(
    {".c", ".cc", ".cfg", ".h", ".json", ".md", ".py", ".sby", ".sv", ".svh", ".tcl", ".txt", ".v", ".vh", ".yaml", ".yml"}
)
IGNORED_REPOSITORY_PARTS = frozenset(
    {".git", ".pytest_cache", ".ruff_cache", "__pycache__", "node_modules", "outputs"}
)


class ChipFlowControlPlaneBlock(RuntimeError):
    """A canonical fail-closed native workflow result, not an exception leak."""

    def __init__(self, reason_code: str, receipt: dict[str, Any]):
        super().__init__(reason_code)
        self.reason_code = reason_code
        self.receipt = receipt


def _load_object(path: Path, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a regular non-symlink file")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{label} must contain one JSON object")
    return value


def _validate(schema_path: Path, value: dict[str, Any], label: str) -> None:
    schema = _load_object(schema_path, f"{label} schema")
    Draft202012Validator.check_schema(schema)
    errors = sorted(
        Draft202012Validator(schema).iter_errors(value),
        key=lambda error: list(error.absolute_path),
    )
    if errors:
        first = errors[0]
        location = "/".join(str(part) for part in first.absolute_path)
        raise ValueError(f"{label} schema error at {location or '<root>'}")


def _sha256(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise ValueError("expected a regular non-symlink file")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _safe_identifier(value: str) -> str:
    return "g12-" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:24]


def _freeze_research_runtime(
    *, run_dir: Path, runnable_config: dict[str, Any]
) -> str:
    """Freeze the native team before the first research-agent dispatch."""

    from deerflow.chipflow.native_subagents import (
        freeze_native_chipflow_run_runtime,
    )

    frozen = freeze_native_chipflow_run_runtime(
        run_dir=run_dir,
        runnable_config=runnable_config,
    )
    if frozen.status != "completed" or not frozen.manifest_hash:
        raise ValueError(
            "Native SubagentConfig runtime could not be frozen: "
            + str(frozen.blocked_reason or frozen.status)
        )
    return frozen.manifest_hash


_PUBLIC_BLOCK_CATEGORY_MARKERS = (
    (
        "provider_infrastructure_unavailable",
        "configured LLM provider is temporarily unavailable after multiple retries",
    ),
    (
        "runtime_configuration_unavailable",
        "`config.yaml` file not found",
    ),
    (
        "native_design_contract_validation_failed",
        "did not produce a valid DesignSpec",
    ),
    (
        "capability_execution_preflight_failed",
        "selected CapabilityBlock failed deterministic execution_preflight",
    ),
    (
        "structured_implementation_anchor_contract_failed",
        "implementation_anchors",
    ),
    ("structured_schema_validation_failed", "ValidationError"),
    ("safe_executor_unavailable", "No matching Safe Executor"),
    ("judge_did_not_accept", "Judge did not ACCEPT"),
    ("eda_debug_budget_exhausted", "EDA did not pass within debug budget"),
)


def _public_block_evidence(state: dict[str, Any]) -> dict[str, Any]:
    """Project a content-bound BLOCK category without leaking model text."""

    reason = str(state.get("blocked_reason") or "").strip()
    encoded = reason.encode("utf-8")
    categories = sorted(
        {
            category
            for category, marker in _PUBLIC_BLOCK_CATEGORY_MARKERS
            if marker.casefold() in reason.casefold()
        }
    )
    if not reason:
        categories = ["missing_native_block_reason"]
    elif not categories:
        categories = ["unclassified_native_block"]
    return {
        "schema_version": "rtlflowbench.chipflow_public_block_evidence.v1",
        "categories": categories,
        "reason_sha256": hashlib.sha256(encoded).hexdigest() if reason else None,
        "reason_size_bytes": len(encoded),
        "raw_reason_included": False,
    }


def _copy_regular_tree(source: Path, target: Path, *, byte_limit: int) -> int:
    if target.exists() or target.is_symlink():
        raise FileExistsError("refusing to reuse the native workspace target")
    total = 0
    target.mkdir(parents=True)
    for path in sorted(source.rglob("*")):
        relative = path.relative_to(source)
        if any(part in IGNORED_REPOSITORY_PARTS for part in relative.parts):
            continue
        if path.is_symlink():
            raise ValueError("source workspace contains a symlink")
        if path.is_dir():
            continue
        if not path.is_file():
            raise ValueError("source workspace contains a non-regular entry")
        total += path.stat().st_size
        if total > byte_limit:
            raise ValueError("source workspace exceeds the frozen text-byte limit")
        destination = target / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, destination)
        destination.chmod(path.stat().st_mode & 0o755)
    return total


def _materialize_target_repo(
    source: Path | None,
    target: Path,
    *,
    byte_limit: int,
) -> int:
    """Create the task workspace even when the public task has no seed repo.

    Spec-to-RTL tasks still need a writable, attempt-local repository for repo
    intake and Safe Executor output.  An absent public repository means an
    empty scaffold, not an absent ``target_repo``.  The same path is used for
    every task and no RTL, executor choice, or task-specific knowledge is
    injected here.
    """

    if source is None:
        if target.exists() or target.is_symlink():
            raise FileExistsError("refusing to reuse the native workspace target")
        target.mkdir(parents=True)
        return 0
    return _copy_regular_tree(source, target, byte_limit=byte_limit)


def _public_prompt(public_root: Path, task: dict[str, Any], *, byte_limit: int) -> str:
    chunks = [
        "RTLFlowBench public task descriptor (canonical JSON):\n"
        + json.dumps(task, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    ]
    total = sum(len(item.encode("utf-8")) for item in chunks)
    for path in sorted(public_root.rglob("*")):
        relative = path.relative_to(public_root)
        if path.is_symlink():
            raise ValueError("public packet contains a symlink")
        if path.is_dir():
            continue
        if not path.is_file():
            raise ValueError("public packet contains a non-regular entry")
        if relative.as_posix() == "external_task.json" or path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        content = path.read_text(encoding="utf-8")
        chunk = f"\n\n--- public/{relative.as_posix()} ---\n{content}"
        total += len(chunk.encode("utf-8"))
        if total > byte_limit:
            raise ValueError("public task text exceeds the frozen byte limit")
        chunks.append(chunk)
    return "".join(chunks)


def _write_new(path: Path, value: dict[str, Any]) -> None:
    if path.exists() or path.is_symlink():
        raise FileExistsError("refusing to overwrite the ChipFlow control receipt")
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def _canonical_sha256(value: Any) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _safe_relative(value: Any, label: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value:
        raise ValueError(f"{label} is not a safe POSIX relative path")
    relative = PurePosixPath(value)
    if relative.is_absolute() or ".." in relative.parts or "." in relative.parts:
        raise ValueError(f"{label} escapes the workflow root")
    return relative


def _submission_manifest(
    *,
    task: dict[str, Any],
    workspace_root: Path,
    work_root: Path,
) -> dict[str, Any]:
    """Bind terminal public artifacts without packaging or evaluating them.

    The resource controller owns token and process telemetry only after the
    workflow exits, so this native boundary records exact output bytes and a
    safe run-relative source path.  A later task-neutral adapter combines this
    manifest with controller-observed usage and emits the common submission.
    """

    contract = task.get("submission_contract")
    if not isinstance(contract, dict):
        raise ValueError("public submission contract is missing")
    required_values = contract.get("required_files")
    editable_values = contract.get("editable_paths")
    max_files = contract.get("max_files_changed")
    max_bytes = contract.get("max_submission_bytes")
    if (
        not isinstance(required_values, list)
        or not required_values
        or not isinstance(editable_values, list)
        or type(max_files) is not int
        or max_files < 1
        or type(max_bytes) is not int
        or max_bytes < 1
    ):
        raise ValueError("public submission contract is incomplete")
    required = [
        _safe_relative(value, "required submission file")
        for value in required_values
    ]
    editable = {
        _safe_relative(value, "editable submission file").as_posix()
        for value in editable_values
    }
    if len(required) > max_files or not {
        item.as_posix() for item in required
    }.issubset(editable):
        raise ValueError("required submission files exceed public editable scope")

    workspace = workspace_root.resolve(strict=True)
    run = work_root.resolve(strict=True)
    if not workspace.is_dir() or not workspace.is_relative_to(run):
        raise ValueError("native workspace is outside the run root")
    artifacts: list[dict[str, Any]] = []
    total = 0
    for relative in required:
        candidate = workspace.joinpath(*relative.parts)
        if candidate.is_symlink():
            raise ValueError("required submission artifact is a symlink")
        try:
            source = candidate.resolve(strict=True)
        except FileNotFoundError as exc:
            raise ValueError("required submission artifact is missing") from exc
        if not source.is_file() or not source.is_relative_to(workspace):
            raise ValueError("required submission artifact escapes the workspace")
        current = workspace
        for part in relative.parts:
            current = current / part
            if current.is_symlink():
                raise ValueError("required submission artifact path contains a symlink")
        size = source.stat().st_size
        total += size
        artifacts.append(
            {
                "submission_path": relative.as_posix(),
                "source_path": source.relative_to(run).as_posix(),
                "sha256": _sha256(source),
                "bytes": size,
            }
        )
    if total > max_bytes:
        raise ValueError("required submission artifacts exceed the byte budget")
    return {
        "schema_version": "rtlflowbench.chipflow_output_manifest.v1",
        "artifact_count": len(artifacts),
        "total_bytes": total,
        "artifacts": artifacts,
    }


def _request_from_interrupt(
    graph_result: dict[str, Any],
    state: dict[str, Any],
    *,
    run_dir: Path,
) -> tuple[str, dict[str, Any]]:
    interrupts = graph_result.get("__interrupt__")
    if not isinstance(interrupts, (list, tuple)) or len(interrupts) != 1:
        raise ValueError("native approval checkpoint has no unique resumable interrupt")
    raw_interrupt = interrupts[0]
    interrupt = getattr(raw_interrupt, "value", raw_interrupt)
    if not isinstance(interrupt, dict):
        raise ValueError("native approval interrupt is not one object")
    if interrupt.get("schema") != "chipflow.hitl_interrupt.v1":
        raise ValueError("native approval interrupt schema is invalid")
    if interrupt.get("status") != "pending":
        raise ValueError("native approval interrupt is not pending")
    request = interrupt.get("approval_request")
    if not isinstance(request, dict) or request.get("status") != "pending":
        raise ValueError("native approval request is missing or not pending")
    gate = str(request.get("gate") or "")
    if gate not in {"design_brief", "patch_plan"} or interrupt.get("gate") != gate:
        raise ValueError("native approval gate is unsupported or inconsistent")
    request_id = str(request.get("request_id") or "")
    generation = request.get("generation")
    scope = request.get("scope_snapshot")
    if not request_id or type(generation) is not int or generation <= 0:
        raise ValueError("native approval request identity is incomplete")
    if not isinstance(scope, dict):
        raise ValueError("native approval scope snapshot is missing")
    artifacts = scope.get("artifacts")
    scope_hash = str(scope.get("scope_hash") or "")
    if (
        not isinstance(artifacts, dict)
        or type(scope.get("artifact_count")) is not int
        or scope["artifact_count"] != len(artifacts)
        or SHA256_RE.fullmatch(scope_hash) is None
        or _canonical_sha256(artifacts) != scope_hash
    ):
        raise ValueError("native approval scope hash is invalid")
    for relative_text, metadata in artifacts.items():
        relative = _safe_relative(relative_text, "approval artifact")
        if not isinstance(metadata, dict):
            raise ValueError("approval artifact metadata is invalid")
        path = run_dir.joinpath(*relative.parts)
        if path.is_symlink() or not path.is_file():
            raise ValueError("approval artifact is missing or unsafe")
        if (
            metadata.get("sha256") != _sha256(path)
            or metadata.get("size_bytes") != path.stat().st_size
        ):
            raise ValueError("approval artifact differs from the checkpoint scope")
    for label, actual, expected in (
        ("request id", interrupt.get("request_id"), request_id),
        ("scope hash", interrupt.get("scope_hash"), scope_hash),
        ("generation", interrupt.get("generation"), generation),
        ("checkpoint request id", state.get("approval_request_id"), request_id),
        ("checkpoint scope hash", state.get("approval_scope_hash"), scope_hash),
        ("checkpoint generation", state.get("approval_generation"), generation),
    ):
        if actual != expected:
            raise ValueError(f"native approval {label} mismatch")
    return gate, request


def _path_is_within(value: str, prefix: str) -> bool:
    normalized = prefix.rstrip("/")
    return value == normalized or value.startswith(normalized + "/")


def _validate_patch_plan_public_scope(
    *,
    state: dict[str, Any],
    run_dir: Path,
    public_root: Path,
    task_id: str,
    request: dict[str, Any],
) -> None:
    if str(state.get("judge_decision") or "").upper() != "ACCEPT":
        raise ValueError("PatchPlan preapproval requires Judge ACCEPT")
    if state.get("executor_matched") is not True:
        raise ValueError("PatchPlan preapproval requires a matching Safe Executor")
    allowed_scope = _load_object(public_root / "allowed_scope.json", "public allowed scope")
    if allowed_scope.get("task_id") != task_id or allowed_scope.get("network_access") is not False:
        raise ValueError("public allowed scope identity or network policy is invalid")
    editable_values = allowed_scope.get("editable_paths")
    operation_values = allowed_scope.get("allowed_file_operations")
    forbidden_values = allowed_scope.get("forbidden_paths")
    max_files = allowed_scope.get("max_files_changed")
    if (
        not isinstance(editable_values, list)
        or not editable_values
        or not isinstance(operation_values, list)
        or not operation_values
        or not isinstance(forbidden_values, list)
        or type(max_files) is not int
        or max_files <= 0
    ):
        raise ValueError("public allowed scope is incomplete")
    editable = {_safe_relative(value, "editable path").as_posix() for value in editable_values}
    allowed_operations = {str(value) for value in operation_values}
    forbidden = [_safe_relative(value.rstrip("/"), "forbidden path").as_posix() for value in forbidden_values]
    plan_path = run_dir / "implementation" / "modular_patch_plan.json"
    match_path = run_dir / "implementation" / "executor_match.json"
    plan = _load_object(plan_path, "native ModularPatchPlan")
    match = _load_object(match_path, "native executor match")
    if match.get("matched") is not True or not isinstance(plan.get("executor"), str):
        raise ValueError("native executor match artifact is incomplete")
    changed_files = plan.get("changed_files")
    operations = plan.get("operations")
    if not isinstance(changed_files, list) or not isinstance(operations, list) or not operations:
        raise ValueError("native ModularPatchPlan has no executable operations")
    touched = {_safe_relative(value, "changed file").as_posix() for value in changed_files}
    for operation in operations:
        if not isinstance(operation, dict):
            raise ValueError("native PatchPlan operation is invalid")
        kind = str(operation.get("kind") or "")
        if kind not in allowed_operations:
            raise ValueError("native PatchPlan operation is outside public allowed scope")
        target = _safe_relative(operation.get("target_file"), "operation target").as_posix()
        touched.add(target)
    if not touched or len(touched) > max_files or not touched.issubset(editable):
        raise ValueError("native PatchPlan files are outside public allowed scope")
    if any(_path_is_within(path, prefix) for path in touched for prefix in forbidden):
        raise ValueError("native PatchPlan touches a public forbidden path")
    scope_artifacts = (request.get("scope_snapshot") or {}).get("artifacts") or {}
    required = {
        "repo_intake/cpu_interface_spec.json",
        "design/design_spec.json",
        "judge_decision.json",
        "implementation/modular_patch_plan.json",
    }
    if not required.issubset(scope_artifacts):
        raise ValueError("PatchPlan approval scope omits an execution-sensitive artifact")


def _controller_preapproval_payload(
    graph_result: dict[str, Any],
    state: dict[str, Any],
    *,
    run_dir: Path,
    public_root: Path,
    task_id: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    gate, request = _request_from_interrupt(graph_result, state, run_dir=run_dir)
    scope_artifacts = (request.get("scope_snapshot") or {}).get("artifacts") or {}
    if gate == "design_brief":
        required = {
            "requirements/design_brief.md",
            "requirements/acceptance_spec.json",
        }
        if not required.issubset(scope_artifacts):
            raise ValueError("DesignBrief approval scope omits frozen requirements")
    else:
        _validate_patch_plan_public_scope(
            state=state,
            run_dir=run_dir,
            public_root=public_root,
            task_id=task_id,
            request=request,
        )
    scope_hash = request["scope_snapshot"]["scope_hash"]
    payload = {
        "decision": "approve",
        "gate": gate,
        "approval_request_id": request["request_id"],
        "expected_scope_hash": scope_hash,
        "approval_generation": request["generation"],
        "decided_by": "rtlflowbench-machine-controller",
        "notes": "Task-neutral controller preapproval after public scope and checkpoint hash gates.",
    }
    evidence = {
        "gate": gate,
        "approval_request_id": request["request_id"],
        "scope_hash": scope_hash,
        "approval_generation": request["generation"],
        "judge_accept_required": gate == "patch_plan",
        "public_allowed_scope_required": gate == "patch_plan",
    }
    return payload, evidence


def _public_visible_oracle(
    *,
    public_root: Path,
    task_id: str,
    wall_time_seconds: int,
) -> tuple[dict[str, Any], str]:
    """Compile the workflow-neutral visible runner contract into one oracle."""

    contract_path = public_root / "visible" / "runner_contract.json"
    contract = _load_object(contract_path, "public visible runner contract")
    if contract.get("schema_version") != "rtlflowbench.visible_runner_contract.v1":
        raise ValueError("public visible runner contract version is unsupported")
    if contract.get("workspace_materialization") != "submission_root":
        raise ValueError("public visible runner workspace materialization is unsupported")
    if contract.get("preliminary_submission_required") is not False:
        raise ValueError("public visible runner requires unsupported preliminary metadata")
    runner_relative = _safe_relative(
        contract.get("runner_path"),
        "public visible runner path",
    )
    runner_path = public_root.joinpath(*runner_relative.parts)
    if runner_path.is_symlink() or not runner_path.is_file():
        raise ValueError("public visible runner is missing or unsafe")
    template = contract.get("argv_template")
    if not isinstance(template, list) or not template:
        raise ValueError("public visible runner argv template is missing")
    replacements = {
        "{PYTHON}": "python3",
        "{VISIBLE_RUNNER}": "../inputs/public/" + runner_relative.as_posix(),
        "{SUBMISSION_ROOT}": ".",
        "{WORKSPACE_ROOT}": ".",
        "{REPOSITORY_ROOT}": ".",
        "{OUTPUT_ROOT}": "../verification/visible_suite",
        "{OUTPUT_RESULT}": "../verification/visible_suite/result.json",
    }
    argv: list[str] = []
    for item in template:
        if not isinstance(item, str):
            raise ValueError("public visible runner argv entries must be strings")
        rendered = item
        for marker, value in replacements.items():
            rendered = rendered.replace(marker, value)
        if "{" in rendered or "}" in rendered:
            raise ValueError("public visible runner contains an unsupported placeholder")
        argv.append(rendered)
    suite_id = "public-visible-" + _sha256(contract_path)[:24]
    timeout = max(1, min(int(wall_time_seconds), 600))
    oracle = {
        "schema_version": "rtlflowbench.public_visible_oracle.v1",
        "design_unit_id": task_id,
        "suite_id": suite_id,
        "timeout_seconds": timeout,
        "commands": [
            {
                "command_id": "public-visible-runner",
                "kind": "simulation",
                "argv": argv,
                "timeout_seconds": timeout,
                "pass_patterns": ['"verdict": "pass"'],
                "fail_patterns": [
                    '"verdict": "invalid_submission"',
                    '"verdict": "scope_violation"',
                    '"verdict": "infra_error"',
                    '"verdict": "timeout"',
                    '"verdict": "compile_error"',
                    '"verdict": "functional_fail"',
                ],
            }
        ],
        "private_evaluator_included": False,
    }
    # Parameterized arbitration uses the same public packet for every workflow.
    # Only ChipFlow's compiler adds its frozen legal-parameter preapproval steps;
    # the functional/illegal-instance runner remains the shared public runner.
    interface_path = public_root / "spec/interface_spec.json"
    if interface_path.is_file():
        interface_payload = _load_object(interface_path, "public InterfaceSpec")
        if interface_payload.get("interface_kind") == "non_cpu_round_robin_arbiter":
            from deerflow.chipflow.executors.interface_bound_add_file import validate_interface_bound_scope
            from deerflow.chipflow.research.contracts import Golden12InterfaceSpec
            from deerflow.chipflow.research.round_robin_arbiter import arbiter_compile_commands

            from deerflow.chipflow.research.public_packet_runtime import admit_public_packet_interface

            admitted = admit_public_packet_interface(public_root=public_root, external_task={"task_id": task_id})
            if admitted is None:
                raise ValueError("arbiter public packet has no independent interface")
            interface = Golden12InterfaceSpec.model_validate(admitted[1])
            scope = _load_object(public_root / "allowed_scope.json", "public allowed scope")
            target, blocked = validate_interface_bound_scope(scope, interface_spec=interface)
            if blocked or target is None:
                raise ValueError("arbiter public scope is invalid: " + "; ".join(blocked))
            commands = arbiter_compile_commands(interface, target)
            oracle["commands"] = commands + oracle["commands"]
            oracle["preapproval_command_ids"] = [c["command_id"] for c in commands]
    return oracle, suite_id


def _research_preapproval_payload(
    *,
    graph_result: dict[str, Any],
    state: dict[str, Any],
    public_root: Path,
    task_id: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Approve one Research DesignUnit plan after public/hash gates."""

    interrupts = graph_result.get("__interrupt__")
    if not isinstance(interrupts, (list, tuple)) or len(interrupts) != 1:
        raise ValueError("research approval checkpoint has no unique interrupt")
    raw = interrupts[0]
    interrupt = getattr(raw, "value", raw)
    if (
        not isinstance(interrupt, dict)
        or interrupt.get("schema") != "chipflow.hitl_interrupt.v1"
        or interrupt.get("gate") != "patch_plan"
        or interrupt.get("status") != "pending"
    ):
        raise ValueError("research approval interrupt is invalid")
    request = interrupt.get("approval_request")
    if (
        not isinstance(request, dict)
        or request.get("approval_schema")
        != "chipflow.research_design_unit_approval.v2"
        or request.get("gate") != "research_design_unit_patch_plan"
        or request.get("design_unit_id") != task_id
    ):
        raise ValueError("research approval request is invalid")
    for key in ("scope_hash", "request_id"):
        if SHA256_RE.fullmatch(str(request.get(key) or "")) is None:
            raise ValueError("research approval request hash is invalid")
    generation = request.get("generation")
    if type(generation) is not int or generation <= 0:
        raise ValueError("research approval generation is invalid")
    scope_payload = {
        key: request[key]
        for key in (
            "approval_schema",
            "gate",
            "design_unit_id",
            "repo_snapshot_id",
            "design_unit_contract_sha256",
            "public_input_manifest_sha256",
            "runtime_manifest_hash",
            "dependency_artifact_refs_sha256",
            "design_spec_sha256",
            "patch_plan_sha256",
            "executor",
        )
    }
    # Python assets have an additional native executor-scope binding. Keep it
    # inside the existing outer approval hash, and verify the whole request
    # against current trusted checkpoint state rather than dropping the field.
    from deerflow.chipflow.executors.python_verification_assets import (
        EXECUTOR_ID as PYTHON_VERIFICATION_EXECUTOR_ID,
    )

    if request.get("executor") == PYTHON_VERIFICATION_EXECUTOR_ID:
        from deerflow.chipflow.research.design_unit_graph import (
            _build_approval_request,
        )

        inner_scope = request.get("python_verification_scope_hash")
        if (
            type(inner_scope) is not str
            or SHA256_RE.fullmatch(inner_scope) is None
            or inner_scope != state.get("python_verification_scope_hash")
        ):
            raise ValueError("Python preapproval requires the current executor scope")
        if request != _build_approval_request(state, generation=generation):
            raise ValueError("Python preapproval request differs from current native state")
        scope_payload["python_verification_scope_hash"] = inner_scope
    if _canonical_sha256(scope_payload) != request["scope_hash"]:
        raise ValueError("research approval scope hash is invalid")
    expected_request_id = _canonical_sha256(
        {
            "approval_schema": request["approval_schema"],
            "design_unit_id": task_id,
            "scope_hash": request["scope_hash"],
            "generation": generation,
        }
    )
    if request["request_id"] != expected_request_id:
        raise ValueError("research approval request id is invalid")
    if str(state.get("judge_decision") or "").upper() != "ACCEPT":
        raise ValueError("research PatchPlan preapproval requires Judge ACCEPT")
    plan = state.get("patch_plan")
    contract = state.get("design_unit_contract")
    if not isinstance(plan, dict) or not isinstance(contract, dict):
        raise ValueError("research PatchPlan or DesignUnit contract is missing")
    if (
        plan.get("executor") != contract.get("required_executor")
        or request.get("executor") != contract.get("required_executor")
    ):
        raise ValueError("research PatchPlan has no matching Safe Executor")
    allowed = _load_object(public_root / "allowed_scope.json", "public allowed scope")
    editable = {
        _safe_relative(value, "editable path").as_posix()
        for value in allowed.get("editable_paths") or []
    }
    operations = plan.get("operations")
    changed_files = plan.get("changed_files")
    if not isinstance(operations, list) or not operations:
        raise ValueError("research PatchPlan has no operations")
    if not isinstance(changed_files, list):
        raise ValueError("research PatchPlan has no changed-files list")
    touched = {
        _safe_relative(value, "changed file").as_posix()
        for value in changed_files
    }
    allowed_operations = {str(value) for value in allowed.get("allowed_file_operations") or []}
    for operation in operations:
        if not isinstance(operation, dict):
            raise ValueError("research PatchPlan operation is invalid")
        if str(operation.get("kind") or "") not in allowed_operations:
            raise ValueError("research PatchPlan operation is outside public scope")
        touched.add(
            _safe_relative(
                operation.get("target_file"),
                "operation target",
            ).as_posix()
        )
    max_files = allowed.get("max_files_changed")
    if (
        type(max_files) is not int
        or max_files <= 0
        or not touched
        or len(touched) > max_files
        or not touched.issubset(editable)
    ):
        raise ValueError("research PatchPlan files are outside public scope")
    payload = {
        "decision": "approve",
        "gate": "patch_plan",
        "approval_request_id": request["request_id"],
        "expected_scope_hash": request["scope_hash"],
        "approval_generation": generation,
        "decided_by": "rtlflowbench-machine-controller",
        "notes": "Task-neutral controller preapproval after public scope and checkpoint hash gates.",
    }
    evidence = {
        "gate": "patch_plan",
        "approval_request_id": request["request_id"],
        "scope_hash": request["scope_hash"],
        "approval_generation": generation,
        "judge_accept_required": True,
        "public_allowed_scope_required": True,
        "design_unit_route": True,
    }
    if request.get("executor") == PYTHON_VERIFICATION_EXECUTOR_ID:
        evidence["python_verification_scope_hash"] = request["python_verification_scope_hash"]
    return payload, evidence



def _public_python_runtime_selection(profile, compute_envelope):
    """Host-only selection; public JSON never creates a worker lease."""
    if profile is None and compute_envelope is None:
        return None
    from deerflow.chipflow.research.compute_worker_channel import ComputeWorkerClient

    if type(profile) is not dict or type(compute_envelope) is not ComputeWorkerClient:
        raise ValueError("explicit public Python profile and actual worker lease required")
    compute_envelope.check_active()
    return _public_python_selection_value(profile, compute_envelope.binding())


def _public_python_selection_value(profile, parent):
    from copy import deepcopy

    from deerflow.chipflow.research import design_unit_runtime as runtime
    from deerflow.chipflow.research.python_verification_planning import implementation_identity

    native_root = Path(runtime.__file__).parent
    native_sources = {
        name: _sha256(native_root / name)
        for name in ("design_unit_runtime.py", "design_unit_full_review.py", "design_unit_graph.py", "design_unit_approval_controller.py", "design_unit_issue_ledger.py", "round_robin_arbiter.py")
    }
    native_sources.update({
        name: _sha256(native_root.parent / name)
        for name in ("native_subagents.py", "native_stage_agents.py", "agents/profiles.py")
    })
    value = {
        "schema": "chipflow.public_python_controller_selection.v1",
        "profile": deepcopy({key: item for key, item in profile.items() if key not in {"archive", "runtime_base"}}),
        "implementation_sources": {"controller.py": _sha256(Path(__file__)), **implementation_identity(), **native_sources},
        "compute_budget": {key: parent[key] for key in ("limits", "worker_wall_seconds", "worker_file_bytes")},
    }
    # Reject non-JSON selections before any input, workspace or dispatch.
    json.dumps(value, allow_nan=False)
    return value


def _require_public_python_selection(policy, selection):
    expected = policy.get("public_python_runtime_sha256")
    if selection is None:
        if expected is not None:
            raise ValueError("public Python policy requires an actual trusted host runtime")
    elif type(expected) is not str or SHA256_RE.fullmatch(expected) is None or expected != _canonical_sha256(selection):
        raise ValueError("public Python runtime selection differs from workflow binding")


def _validate_public_python_host_locations(profile):
    from deerflow.chipflow.research.public_container_lifecycle import PublicImage, _directory

    try:
        image = PublicImage(Path(profile["archive"]), profile["archive_sha256"], profile["image_id"], profile["python"], tuple(profile["masked_roots"]))
        runtime_base = Path(profile["runtime_base"])
    except (KeyError, TypeError) as exc:
        raise ValueError("public Python host locations are missing or malformed") from exc
    image.validate()
    _directory(runtime_base, private=True)
    if len(str(runtime_base / "pub-12345678")) > 50:
        raise ValueError("public Python runtime requires a short owned runtime base")


def _build_public_python_session(context, *, checkpointer, config, compute_envelope, runtime_policy):
    from deerflow.chipflow.research.python_broker_session import PythonBrokerSession
    from deerflow.chipflow.research.design_unit_runtime import dispatch_native_chipflow_subagent

    native_keys = {"thread_id", "run_id", "user_id", "model_name", "subagent_enabled", "chipflow_target_repo", "chipflow_user_goal"}
    if type(config) is not dict or set(config) != {"configurable"} or type(config["configurable"]) is not dict or set(config["configurable"]) - native_keys:
        raise ValueError("fixed current native configuration required; checkpoint selectors forbidden")
    values = config["configurable"]
    fixed = {key: values[key] for key in ("thread_id", "run_id", "user_id", "model_name") if key in values}
    selection = _public_python_runtime_selection(context.python_public_verification, compute_envelope)
    _require_public_python_selection(runtime_policy, selection)
    digest = _canonical_sha256(selection)
    host_profile_digest = _canonical_sha256(context.python_public_verification)
    host_parent_digest = _canonical_sha256(compute_envelope.binding())

    def revalidate(*, require_active=False):
        if require_active:
            compute_envelope.check_active()
            parent = compute_envelope.binding()
        else:
            # Static cache/source validation must survive channel closure.
            # This local identity never authorizes an active operation.
            parent = compute_envelope.expected_binding
        if _canonical_sha256(context.python_public_verification) != host_profile_digest or _canonical_sha256(parent) != host_parent_digest:
            raise ValueError("public Python host runtime binding drift")
        current = _public_python_selection_value(context.python_public_verification, parent)
        if _canonical_sha256(current) != digest:
            raise ValueError("public Python host runtime binding drift")
        return digest

    return PythonBrokerSession(
        context, checkpointer=checkpointer,
        config={"configurable": fixed}, session_id=context.thread_id,
        dispatch=dispatch_native_chipflow_subagent, compute_envelope=compute_envelope,
        host_runtime_binding_sha256=digest, host_runtime_revalidator=revalidate,
    )


def _invoke_public_native_graph(graph, value, config, *, python_route):
    return graph.invoke(value) if python_route else graph.invoke(value, config)


def _read_public_native_graph(graph, config, *, python_route):
    return graph.get_state() if python_route else graph.get_state(config)


def _public_packet_digest(public_root: Path) -> str:
    """Bind the original public packet, rejecting redirected/special entries."""
    if public_root.is_symlink() or not public_root.is_dir():
        raise ValueError("public packet must be a regular directory")
    entries = []
    for path in sorted(public_root.rglob("*")):
        if path.is_symlink():
            raise ValueError("public packet symlink forbidden")
        if path.is_dir():
            entries.append({"path": path.relative_to(public_root).as_posix(), "kind": "directory"})
        elif path.is_file():
            content = path.read_bytes()
            entries.append({"path": path.relative_to(public_root).as_posix(), "bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()})
        else:
            raise ValueError("public packet special entry forbidden")
    return _canonical_sha256(entries)


def _require_public_packet_digest(public_root: Path, expected: str) -> None:
    if _public_packet_digest(public_root) != expected:
        raise ValueError("original public packet changed")


def _preapprove_public_native_graph(
    graph, graph_result, state, config, *, context, public_root,
    public_packet_digest, task_id, design_unit_route, python_route, native_run_dir,
):
    def builder(*, graph_result, state):
        _require_public_packet_digest(public_root, public_packet_digest)
        if design_unit_route:
            pair = _research_preapproval_payload(
                graph_result=graph_result, state=state, public_root=public_root, task_id=task_id,
            )
        else:
            pair = _controller_preapproval_payload(
                graph_result, state, run_dir=native_run_dir, public_root=public_root, task_id=task_id,
            )
        _require_public_packet_digest(public_root, public_packet_digest)
        return pair

    if python_route:
        result, evidence = graph.preapprove_and_resume(builder)
        _require_public_packet_digest(public_root, public_packet_digest)
        return result, evidence
    from langgraph.types import Command

    if context is not None:
        context.validate()
    payload, evidence = builder(graph_result=graph_result, state=state)
    result = _invoke_public_native_graph(graph, Command(resume=payload), config, python_route=False)
    _require_public_packet_digest(public_root, public_packet_digest)
    return result, evidence


def _validate_debug_review_study(selection):
    if selection is None:
        return None
    if type(selection) is not dict or set(selection) != {"path", "sha256"}:
        raise ValueError("debug study requires an explicit path and pinned SHA256")
    path, digest = selection["path"], selection["sha256"]
    if not isinstance(path, str) or not Path(path).is_absolute() or not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
        raise ValueError("debug study selector is malformed")
    source = Path(path)
    if any(part.is_symlink() for part in (source, *source.parents)) or not source.is_file() or source.stat().st_size > 16384:
        raise ValueError("debug study declaration must be bounded and nonsymlink")
    if hashlib.sha256(source.read_bytes()).hexdigest() != digest:
        raise ValueError("debug study declaration hash mismatch")
    return dict(selection)


def _study_attempt_limits(task, selection):
    """Lift structural repair stops only for a pinned equal-budget study.

    The external controller still owns all actual model/token/EDA admission.
    This permits saved critic calls to fund later planner repairs; it grants
    no additional provider calls and leaves the default entry unchanged.
    """
    if _validate_debug_review_study(selection) is None:
        return None
    declaration = json.loads(Path(selection["path"]).read_text())
    if declaration.get("schema") == "chipflow.debug_review_study.v1":
        return None
    if declaration.get("schema") != "chipflow.debug_review_study.v2":
        raise ValueError("unsupported study budget declaration")
    budget = task.get("budget")
    llm = budget.get("llm_calls") if isinstance(budget, dict) else None
    maximum = llm.get("maximum") if isinstance(llm, dict) else None
    if (type(maximum) is not int or not 1 <= maximum <= 128
            or type(declaration.get("maximum_debug_iterations")) is not int
            or declaration["maximum_debug_iterations"] != maximum):
        raise ValueError("debug study requires the exact bounded public model-call budget")
    return {
        "debug_limit": maximum,
        "machine_preapproval_limit": max(MAX_MACHINE_PREAPPROVALS, maximum),
    }


def _build_rtl_design_unit_graph(context, *, checkpointer, debug_review_study):
    selection = _validate_debug_review_study(debug_review_study)
    if selection is None:
        from deerflow.chipflow.research.design_unit_full_runtime import build_entrypoint_design_unit_graph

        return build_entrypoint_design_unit_graph(context, checkpointer=checkpointer, use_langgraph_interrupts=True)
    from deerflow.chipflow.research.debug_review_study import build_debug_review_study_graph

    return build_debug_review_study_graph(
        context, declaration_path=selection["path"], expected_declaration_sha256=selection["sha256"],
        checkpointer=checkpointer, use_langgraph_interrupts=True,
    )


def run_chipflow(
    *, task_path: Path, task_schema_path: Path, public_root: Path,
    repository_root: Path | None, workspace_receipt_path: Path,
    workspace_receipt_schema_path: Path, workflow_binding_path: Path,
    work_dir: Path, request: dict[str, Any], model: str,
    python_public_verification: dict[str, Any] | None = None, compute_envelope=None,
    debug_review_study: dict[str, str] | None = None,
) -> dict[str, Any]:
    debug_review_study = _validate_debug_review_study(debug_review_study)
    if debug_review_study is not None and (python_public_verification is not None or compute_envelope is not None):
        raise ValueError("debug study currently supports native RTL packets only")
    if os.environ.get("CHIPFLOW_DESIGN_UNIT_REVIEWER_MODE") is not None:
        from deerflow.chipflow.research.design_unit_full_runtime import (
            require_full_entrypoint_configuration,
        )

        require_full_entrypoint_configuration()

    python_selection = _public_python_runtime_selection(python_public_verification, compute_envelope)
    if python_selection is not None:
        from copy import deepcopy

        python_public_verification = deepcopy(python_public_verification)
        _validate_public_python_host_locations(python_public_verification)

    task = _load_object(task_path, "public task descriptor")
    workspace_receipt = _load_object(workspace_receipt_path, "workspace receipt")
    binding = _load_object(workflow_binding_path, "workflow binding")
    _validate(task_schema_path, task, "public task")
    _validate(workspace_receipt_schema_path, workspace_receipt, "workspace receipt")
    if task.get("task_id") != request["task_id"]:
        raise ValueError("public task identity differs from the launch request")
    policy = binding.get("runtime_policy")
    if not isinstance(policy, dict):
        raise ValueError("ChipFlow runtime policy is missing")
    if policy.get("private_evaluator_reachable") is not False:
        raise ValueError("ChipFlow runtime policy does not isolate private evaluation")
    approval_policy = policy.get("approval")
    if approval_policy not in {
        "fail_closed_zero_intervention",
        PREAPPROVAL_POLICY,
    }:
        raise ValueError("unknown controller approval policy must fail closed")

    _require_public_python_selection(policy, python_selection)
    public_packet_digest = _public_packet_digest(public_root)
    work = work_dir.expanduser().absolute()
    if work.exists() or work.is_symlink():
        raise FileExistsError("refusing to reuse the ChipFlow work directory")
    work.mkdir(parents=True)
    deer_home = work / "deerflow-home"
    thread_id = _safe_identifier(request["attempt"]["attempt_id"])
    user_id = (
        "rtlflowbench-machine-controller"
        if approval_policy == PREAPPROVAL_POLICY
        else "rtlflowbench"
    )
    thread_workspace = (
        deer_home / "users" / user_id / "threads" / thread_id
        / "user-data" / "workspace"
    )
    thread_workspace.mkdir(parents=True)
    _copy_regular_tree(
        public_root,
        thread_workspace / "public",
        byte_limit=request["limits"]["maximum_public_text_bytes"],
    )
    _materialize_target_repo(
        repository_root,
        thread_workspace / "worktree",
        byte_limit=request["limits"]["maximum_repository_text_bytes"],
    )
    prompt = _public_prompt(
        public_root,
        task,
        byte_limit=request["limits"]["maximum_public_text_bytes"],
    )

    _require_public_packet_digest(public_root, public_packet_digest)
    previous_home = os.environ.get("DEER_FLOW_HOME")
    os.environ["DEER_FLOW_HOME"] = str(deer_home)
    try:
        from langgraph.checkpoint.sqlite import SqliteSaver
        from deerflow.config import paths as paths_module

        # The launcher owns a fresh process/work directory.  Resetting the
        # lazy singleton binds the official path service to this attempt only.
        paths_module._paths = None
        config = {
            "configurable": {
                "thread_id": thread_id,
                "user_id": user_id,
                "run_id": request["attempt"]["attempt_id"],
                "model_name": model,
                "subagent_enabled": policy.get("subagents") == "enabled_frozen_runtime",
                "chipflow_target_repo": "worktree",
                "chipflow_user_goal": prompt,
            }
        }
        checkpoint_path = work / "checkpoints.sqlite"
        from deerflow.chipflow.research.public_packet_runtime import (
            admit_public_packet_interface,
            compile_public_packet_runtime_spec,
        )

        non_cpu_packet = admit_public_packet_interface(
            public_root=public_root,
            external_task=task,
        )
        from deerflow.chipflow.research.cpu_public_packet_runtime import (
            admit_cpu_repair_packet, compile_cpu_repair_runtime_spec, cpu_repair_public_oracle,
        )
        cpu_repair_packet = admit_cpu_repair_packet(public_root=public_root, external_task=task)
        design_unit_route = non_cpu_packet is not None or cpu_repair_packet is not None
        if debug_review_study is not None and not design_unit_route:
            raise ValueError("debug study requires an admitted native RTL DesignUnit packet")
        if python_selection is not None and not design_unit_route:
            raise ValueError("explicit Python runtime requires a public non-CPU contract")
        if python_selection is not None:
            checkpoint_path.touch(mode=0o600, exist_ok=False)
        execution_workspace = thread_workspace / "worktree"
        with SqliteSaver.from_conn_string(str(checkpoint_path)) as checkpointer:
            graph = None
            context = None
            if design_unit_route:
                from deerflow.chipflow.research.design_unit_full_runtime import (
                    ENTRYPOINT_REVIEW_CONFIGURATION,
                )
                from deerflow.chipflow.research.design_unit_runtime import (
                    materialize_design_unit_context,
                )

                budget = task.get("budget")
                wall_time = (
                    budget.get("wall_time_seconds")
                    if isinstance(budget, dict)
                    else None
                )
                if type(wall_time) is not int or wall_time <= 0:
                    raise ValueError("public task wall-time budget is invalid")
                if cpu_repair_packet is not None:
                    oracle_payload = cpu_repair_public_oracle(task_id=task["task_id"], wall_time_seconds=wall_time)
                else:
                    oracle_payload, _ = _public_visible_oracle(
                        public_root=public_root,
                        task_id=task["task_id"],
                        wall_time_seconds=wall_time,
                    )
                oracle_source = work / "public-visible-oracle.json"
                _write_new(oracle_source, oracle_payload)
                runtime_compiler = compile_cpu_repair_runtime_spec if cpu_repair_packet is not None else compile_public_packet_runtime_spec
                compiler_options = {} if cpu_repair_packet is not None else {"python_public_verification": python_public_verification}
                if cpu_repair_packet is not None and python_selection is not None:
                    raise ValueError("Python runtime cannot authorize CPU repair")
                runtime_spec = runtime_compiler(
                    public_root=public_root,
                    external_task=task,
                    workspace_source=execution_workspace,
                    oracle_source=oracle_source,
                    **compiler_options,
                )
                if runtime_spec is None:
                    raise ValueError("non-CPU route disappeared during runtime admission")
                study_limits = _study_attempt_limits(task, debug_review_study)
                if study_limits is not None:
                    from dataclasses import replace

                    runtime_spec = replace(runtime_spec, debug_limit=study_limits["debug_limit"])
                    _write_new(work / "study-attempt-limits.json", {
                        "schema": "chipflow.study_attempt_limits.v1",
                        "limits": study_limits,
                        "declaration_sha256": debug_review_study["sha256"],
                        "task_sha256": hashlib.sha256(task_path.read_bytes()).hexdigest(),
                        "controller_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                        "provider_admission_owner": "external_observed_controller",
                    })
                context, initial_state = materialize_design_unit_context(
                    spec=runtime_spec,
                    run_root=work / "research-design-unit",
                    owner_id=user_id,
                    thread_id=thread_id,
                    request_id=request["attempt"]["attempt_id"],
                    runnable_config=config,
                )
                execution_workspace = context.workspace_root
                native_run_dir = context.run_dir
                try:
                    initial_state["runtime_manifest_hash"] = (
                        _freeze_research_runtime(
                            run_dir=context.run_dir,
                            runnable_config=config,
                        )
                    )
                except (OSError, ValueError) as exc:
                    initial_state.update(
                        {
                            "current_stage": "BLOCKED",
                            "status": "blocked",
                            "blocked_reason": (
                                "Native runtime freeze failed closed: "
                                f"{type(exc).__name__}: {exc}"
                            ),
                        }
                    )
                    state = initial_state
                    graph_result = {}
                else:
                    _write_new(work / "review-profile.json", ENTRYPOINT_REVIEW_CONFIGURATION)
                    if python_selection is not None:
                        graph = _build_public_python_session(
                            context, checkpointer=checkpointer, config=config,
                            compute_envelope=compute_envelope, runtime_policy=policy,
                        )
                    else:
                        graph = _build_rtl_design_unit_graph(
                            context, checkpointer=checkpointer,
                            debug_review_study=debug_review_study,
                        )
                        if debug_review_study is not None:
                            from deerflow.chipflow.research.debug_review_study import bind_debug_review_policy

                            study_policy = bind_debug_review_policy(context, debug_review_study["path"], expected_sha256=debug_review_study["sha256"])
                            initial_state["debug_review_study"] = study_policy.projection()
                            _write_new(work / "debug-review-study.json", study_policy.projection())
                    _require_public_packet_digest(public_root, public_packet_digest)
                    graph_result = _invoke_public_native_graph(
                        graph, initial_state, config,
                        python_route=python_selection is not None,
                    )
            else:
                from deerflow.chipflow.agent import make_chipflow_agent

                template = make_chipflow_agent()
                graph = template.builder.compile(
                    checkpointer=checkpointer,
                    name="rtlflowbench-chipflow-native-stategraph",
                )
                _require_public_packet_digest(public_root, public_packet_digest)
                graph_result = graph.invoke(
                    {
                        "chipflow_request": {
                            "user_goal": prompt,
                            "target_repo": "worktree",
                        }
                    },
                    config,
                )
                native_run_dir = (
                    thread_workspace.parent / "outputs" / "chipflow" / "native"
                )
            _require_public_packet_digest(public_root, public_packet_digest)
            if graph is not None:
                state = dict(_read_public_native_graph(graph, config, python_route=python_selection is not None).values)
            machine_preapprovals: list[dict[str, Any]] = []
            machine_preapproval_blocked = False
            if approval_policy == PREAPPROVAL_POLICY:
                while isinstance(graph_result, dict) and graph_result.get("__interrupt__"):
                    study_limits = _study_attempt_limits(task, debug_review_study)
                    approval_limit = study_limits["machine_preapproval_limit"] if study_limits else MAX_MACHINE_PREAPPROVALS
                    if len(machine_preapprovals) >= approval_limit:
                        machine_preapproval_blocked = True
                        break
                    try:
                        graph_result, preapproval_evidence = _preapprove_public_native_graph(
                            graph, graph_result, state, config, context=context,
                            public_root=public_root, public_packet_digest=public_packet_digest,
                            task_id=task["task_id"], design_unit_route=design_unit_route,
                            python_route=python_selection is not None, native_run_dir=native_run_dir,
                        )
                    except ValueError:
                        machine_preapproval_blocked = True
                        break
                    machine_preapprovals.append(preapproval_evidence)
                    state = dict(_read_public_native_graph(graph, config, python_route=python_selection is not None).values)
    finally:
        if previous_home is None:
            os.environ.pop("DEER_FLOW_HOME", None)
        else:
            os.environ["DEER_FLOW_HOME"] = previous_home

    stage = str(state.get("current_stage") or "")
    workflow_status = str(state.get("status") or "blocked")
    block_evidence = (
        _public_block_evidence(state) if workflow_status == "blocked" else None
    )
    submission_manifest = None
    submission_contract_error = None
    if workflow_status in {"pass", "completed", "verified"} and python_selection is None:
        try:
            submission_manifest = _submission_manifest(
                task=task,
                workspace_root=execution_workspace,
                work_root=work,
            )
        except ValueError as exc:
            encoded = str(exc).encode("utf-8")
            submission_contract_error = {
                "category": "neutral_submission_contract_failed",
                "detail_sha256": hashlib.sha256(encoded).hexdigest(),
                "detail_size_bytes": len(encoded),
                "raw_detail_included": False,
            }
    if machine_preapproval_blocked:
        status = "machine_preapproval_block"
        reason_code = "controller_preapproval_gate_rejected"
    elif stage in {"DESIGN_BRIEF_APPROVAL", "PENDING_APPROVAL"}:
        status = "approval_required_block"
        reason_code = (
            "zero_intervention_policy_stopped_at_native_approval_gate"
            if approval_policy == "fail_closed_zero_intervention"
            else "controller_preapproval_checkpoint_not_resumable"
        )
    elif workflow_status == "blocked":
        if "provider_infrastructure_unavailable" in (
            block_evidence or {}
        ).get("categories", []):
            status = "workflow_provider_infra"
            reason_code = "provider_infrastructure_unavailable"
        else:
            status = "workflow_capability_block"
            reason_code = "native_workflow_blocked"
    elif workflow_status in {"pass", "completed", "verified"}:
        if submission_manifest is None:
            status = "workflow_completed_no_conformant_submission"
            reason_code = "neutral_submission_contract_failed"
        else:
            status = "workflow_completed_neutral_export_ready"
            reason_code = None
    else:
        status = "workflow_nonterminal_block"
        reason_code = "native_workflow_did_not_reach_a_terminal_export"
    receipt = {
        "schema_version": "rtlflowbench.chipflow_public_control_receipt.v1",
        "workflow_id": WORKFLOW_ID,
        "task_id": task["task_id"],
        "model": model,
        "status": status,
        "reason_code": reason_code,
        "native_stage": stage or None,
        "native_status": workflow_status,
        "block_evidence": block_evidence,
        "checkpoint_sha256": _sha256(checkpoint_path),
        "artifact_count": len(state.get("artifacts") or []),
        "approval_policy": approval_policy,
        "original_public_packet_sha256": public_packet_digest,
        "human_intervention_count": 0,
        "machine_preapproval_count": len(machine_preapprovals),
        "machine_preapprovals": machine_preapprovals,
        "design_unit_route": design_unit_route,
        "submission_observed": submission_manifest is not None,
        "submission_manifest": submission_manifest,
        "submission_contract_evidence": submission_contract_error,
        "private_evaluator_run": False,
        "benchmark_verdict_produced": False,
        "official_attempt": False,
        "excluded_claims": [
            "A native checkpoint or approval BLOCK is not a benchmark PASS or FAIL.",
            "No private evaluator or hidden oracle is mounted or invoked.",
            "The task-neutral bridge contains no task-specific executor selection or design knowledge."
        ]
    }
    if python_selection is not None:
        receipt["public_python_runtime_selection"] = python_selection
        receipt["compute_envelope_binding_sha256"] = _canonical_sha256(compute_envelope.binding())
        receipt["formal_experiment_eligible"] = False
    _write_new(work / CONTROL_RECEIPT, receipt)
    if reason_code is not None:
        raise ChipFlowControlPlaneBlock(reason_code, receipt)
    return receipt
