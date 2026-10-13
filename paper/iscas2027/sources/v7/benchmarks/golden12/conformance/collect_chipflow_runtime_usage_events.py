#!/usr/bin/env python3
"""Collect fail-closed benchmark usage events from one ChipFlow run.

The collector intentionally reads only canonical persisted artifacts.  It
does not infer a successful call from a trace message, treat a missing source
as zero usage, or classify an unknown command as a harmless non-EDA process.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import posixpath
import re
import shlex
from pathlib import Path, PurePosixPath
from typing import Any

from jsonschema import Draft202012Validator


CONFORMANCE_ROOT = Path(__file__).resolve().parent
ADAPTER_ROOT = CONFORMANCE_ROOT / "adapters"
EVENT_SCHEMA_PATH = ADAPTER_ROOT / "chipflow_usage_events.schema.json"
MONITOR_SCHEMA_PATH = (
    ADAPTER_ROOT / "chipflow_task_workspace_monitor.schema.json"
)
DIRECT_LLM_ROOT = Path("llm_calls")
SUBAGENT_ROOT = Path("agents")
SEMANTIC_CHECKPOINT_ROOT = Path("planning/semantic_dispatch_checkpoints")
RAW_EDA_PATH = Path("raw_eda_results.json")
HITL_LOG_PATH = Path("hitl/approval_decisions.jsonl")
MONITOR_PATH = Path("benchmark_evidence/task_workspace_monitor.json")

EDA_TOOLS = {
    "eda_compile_or_lint": {
        "iverilog",
        "slang",
        "surelog",
        "verible-verilog-lint",
        "verilator",
        "verilator_bin",
        "vlog",
    },
    "eda_simulation": {
        "simv",
        "vcs",
        "vvp",
        "vsim",
        "xrun",
    },
    "eda_formal": {
        "abc",
        "boolector",
        "sby",
        "yosys-smtbmc",
        "z3",
    },
    "eda_synthesis": {
        "dc_shell",
        "genus",
        "nextpnr",
        "openroad",
        "quartus_sh",
        "vivado",
        "yosys",
    },
}
EVENT_TO_MONITOR_KEY = {
    "eda_compile_or_lint": "compile_or_lint",
    "eda_simulation": "simulation",
    "eda_formal": "formal",
    "eda_synthesis": "synthesis",
}


def _load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} must contain one JSON object")
    return value


def _event_id(prefix: str, *values: object) -> str:
    encoded = "\0".join(str(value) for value in values).encode("utf-8")
    return f"{prefix}-{hashlib.sha256(encoded).hexdigest()[:24]}"


def _run_member(root: Path, relative: Path) -> tuple[str, Path]:
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError(f"non-canonical run evidence path: {relative}")
    candidate = root / relative
    if candidate.is_symlink():
        raise ValueError(f"run evidence must not be a symlink: {relative}")
    resolved = candidate.resolve(strict=True)
    if not resolved.is_file():
        raise ValueError(f"run evidence must be a regular file: {relative}")
    try:
        normalized = resolved.relative_to(root).as_posix()
    except ValueError as exc:
        raise ValueError(f"run evidence escapes run root: {relative}") from exc
    current = root
    for part in Path(normalized).parts:
        current = current / part
        if current.is_symlink():
            raise ValueError(
                f"run evidence path contains a symlink: {normalized}"
            )
    if normalized != relative.as_posix():
        raise ValueError(f"non-canonical run evidence path: {relative}")
    return normalized, resolved


def _json_files(root: Path, relative_root: Path, suffix: str) -> list[Path]:
    directory = root / relative_root
    if directory.is_symlink():
        raise ValueError(f"usage source root must not be a symlink: {relative_root}")
    if not directory.exists():
        return []
    if not directory.is_dir():
        raise ValueError(f"usage source root must be a directory: {relative_root}")
    paths = [
        path.relative_to(root)
        for path in directory.rglob(suffix)
        if path.is_file() or path.is_symlink()
    ]
    return sorted(paths, key=lambda item: item.as_posix())


def _integer_or_none(value: Any, *, field: str) -> int | None:
    if value is None:
        return None
    if type(value) is not int or value < 0:
        raise ValueError(f"{field} must be a non-negative integer or null")
    return value


def _token_pair(usage: Any, *, source: str) -> tuple[int | None, int | None]:
    if usage is None:
        return None, None
    if not isinstance(usage, dict):
        raise ValueError(f"{source} usage_metadata must be an object or null")
    input_value = usage.get("input_tokens")
    output_value = usage.get("output_tokens")
    if input_value is None and "prompt_tokens" in usage:
        input_value = usage["prompt_tokens"]
    if output_value is None and "completion_tokens" in usage:
        output_value = usage["completion_tokens"]
    input_tokens = _integer_or_none(
        input_value,
        field=f"{source} input tokens",
    )
    output_tokens = _integer_or_none(
        output_value,
        field=f"{source} output tokens",
    )
    total = _integer_or_none(
        usage.get("total_tokens"),
        field=f"{source} total tokens",
    )
    if (
        total is not None
        and input_tokens is not None
        and output_tokens is not None
        and total != input_tokens + output_tokens
    ):
        raise ValueError(f"{source} token total disagrees with input plus output")
    return input_tokens, output_tokens


def _sha256_json_value(value: Any) -> str:
    """Match the immutable semantic-checkpoint content identity."""

    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def _semantic_checkpoint_named_payload(
    root: Path,
    relative: Path,
    *,
    kind: str,
    ordinal: int,
) -> tuple[dict[str, Any], str, str]:
    evidence_ref, path = _run_member(root, relative)
    payload = _load_object(path)
    digest = _sha256_json_value(payload)
    match = re.fullmatch(
        rf"dispatch-{ordinal:04d}\.{kind}-([0-9a-f]{{64}})\.json",
        path.name,
    )
    if match is None or match.group(1) != digest:
        raise ValueError(
            f"{evidence_ref} semantic {kind} checkpoint hash changed"
        )
    return payload, digest, evidence_ref


def _semantic_checkpoint_record_map(
    root: Path,
    binding_relative: Path,
    *,
    kind: str,
) -> dict[int, Path]:
    directory = root / binding_relative
    records: dict[int, Path] = {}
    for path in sorted(directory.glob(f"dispatch-*.{kind}-*.json")):
        if not (path.is_file() or path.is_symlink()):
            continue
        match = re.fullmatch(
            rf"dispatch-([0-9]{{4}})\.{kind}-[0-9a-f]{{64}}\.json",
            path.name,
        )
        if match is None:
            raise ValueError(
                f"semantic dispatch {kind} checkpoint filename is invalid"
            )
        ordinal = int(match.group(1))
        if ordinal < 1 or ordinal in records:
            raise ValueError(
                f"semantic dispatch checkpoint has duplicate {kind} records"
            )
        records[ordinal] = path.relative_to(root)
    return records


def _semantic_checkpoint_artifacts(
    root: Path,
    artifacts: Any,
    *,
    source: str,
) -> dict[str, Path]:
    if not isinstance(artifacts, list):
        raise ValueError(f"{source} checkpoint artifacts are invalid")
    resolved_artifacts: dict[str, Path] = {}
    for item in artifacts:
        if not isinstance(item, dict):
            raise ValueError(f"{source} checkpoint artifact is invalid")
        raw_path = item.get("path")
        if not isinstance(raw_path, str) or not raw_path:
            raise ValueError(f"{source} checkpoint artifact path is invalid")
        evidence_ref, path = _run_member(root, Path(raw_path))
        if evidence_ref in resolved_artifacts:
            raise ValueError(f"{source} checkpoint artifact path is duplicated")
        size_bytes = item.get("size_bytes")
        if type(size_bytes) is not int or size_bytes < 0:
            raise ValueError(f"{source} checkpoint artifact size is invalid")
        if (
            hashlib.sha256(path.read_bytes()).hexdigest()
            != item.get("sha256")
            or path.stat().st_size != size_bytes
        ):
            raise ValueError(f"{source} checkpoint artifact hash changed")
        resolved_artifacts[evidence_ref] = path
    return resolved_artifacts


def _semantic_checkpoint_missing_usage_proofs(
    root: Path,
) -> dict[str, list[list[str]]]:
    """Index immutable proof of completed logical subagent model calls.

    One validation-failed or validated semantic completion proves one model
    response even when the provider omitted token metadata.  It does not prove
    provider-internal HTTP attempts, so the projection intentionally emits one
    logical call with null token counts.  The full binding chain and artifact
    hashes are revalidated before that fallback can be used.
    """

    checkpoint_root = root / SEMANTIC_CHECKPOINT_ROOT
    if checkpoint_root.is_symlink():
        raise ValueError("semantic dispatch checkpoint root is a symlink")
    if not checkpoint_root.exists():
        return {}
    if not checkpoint_root.is_dir():
        raise ValueError("semantic dispatch checkpoint root is not a directory")

    proofs: dict[str, list[list[str]]] = {}
    for binding_directory in sorted(checkpoint_root.iterdir()):
        if binding_directory.is_symlink():
            raise ValueError("semantic dispatch checkpoint binding is a symlink")
        if not binding_directory.is_dir():
            continue
        binding_sha256 = binding_directory.name
        if re.fullmatch(r"[0-9a-f]{64}", binding_sha256) is None:
            raise ValueError("semantic dispatch binding directory name is invalid")
        binding_relative = binding_directory.relative_to(root)
        binding_ref, binding_path = _run_member(
            root,
            binding_relative / "binding.json",
        )
        binding = _load_object(binding_path)
        if (
            binding.get("schema") != "chipflow.semantic_dispatch_binding.v1"
            or _sha256_json_value(binding) != binding_sha256
        ):
            raise ValueError(f"{binding_ref} semantic dispatch binding changed")
        max_semantic_attempts = binding.get("max_semantic_attempts")
        if (
            type(max_semantic_attempts) is not int
            or max_semantic_attempts < 1
        ):
            raise ValueError(f"{binding_ref} has invalid semantic attempt budget")
        lineage = binding.get("lineage")
        if not isinstance(lineage, dict):
            raise ValueError(f"{binding_ref} has invalid semantic lineage")

        started_records = _semantic_checkpoint_record_map(
            root,
            binding_relative,
            kind="started",
        )
        completed_records = _semantic_checkpoint_record_map(
            root,
            binding_relative,
            kind="completed",
        )
        if sorted(started_records) != list(range(1, len(started_records) + 1)):
            raise ValueError("semantic dispatch started records are not contiguous")
        if len(started_records) > 32:
            raise ValueError("semantic dispatch checkpoint exceeds runtime limit")
        if any(ordinal not in started_records for ordinal in completed_records):
            raise ValueError("semantic dispatch completion lacks its started record")

        semantic_attempts_used = 0
        previous_checkpoint_sha256 = binding_sha256
        for ordinal in sorted(started_records):
            started, started_sha256, started_ref = (
                _semantic_checkpoint_named_payload(
                    root,
                    started_records[ordinal],
                    kind="started",
                    ordinal=ordinal,
                )
            )
            semantic_attempt = started.get("semantic_attempt")
            dispatch_prompt_sha256 = started.get("dispatch_prompt_sha256")
            if (
                started.get("schema")
                != "chipflow.semantic_dispatch_started.v1"
                or started.get("binding_sha256") != binding_sha256
                or type(started.get("dispatch_ordinal")) is not int
                or started["dispatch_ordinal"] != ordinal
                or type(semantic_attempt) is not int
                or semantic_attempt != semantic_attempts_used + 1
                or semantic_attempt > max_semantic_attempts
                or started.get("previous_checkpoint_sha256")
                != previous_checkpoint_sha256
                or not isinstance(dispatch_prompt_sha256, str)
                or re.fullmatch(r"[0-9a-f]{64}", dispatch_prompt_sha256)
                is None
                or (
                    ordinal == 1
                    and dispatch_prompt_sha256 != binding.get("prompt_sha256")
                )
            ):
                raise ValueError(f"{started_ref} semantic started checkpoint changed")
            previous_checkpoint_sha256 = started_sha256

            completed_relative = completed_records.get(ordinal)
            if completed_relative is None:
                semantic_attempts_used += 1
                continue
            completed, completed_sha256, completed_ref = (
                _semantic_checkpoint_named_payload(
                    root,
                    completed_relative,
                    kind="completed",
                    ordinal=ordinal,
                )
            )
            if (
                completed.get("schema")
                != "chipflow.semantic_dispatch_completed.v1"
                or completed.get("binding_sha256") != binding_sha256
                or completed.get("started_sha256") != started_sha256
                or type(completed.get("dispatch_ordinal")) is not int
                or completed["dispatch_ordinal"] != ordinal
                or type(completed.get("semantic_attempt")) is not int
                or completed["semantic_attempt"] != semantic_attempt
            ):
                raise ValueError(
                    f"{completed_ref} semantic completed checkpoint changed"
                )
            previous_checkpoint_sha256 = completed_sha256
            artifact_paths = _semantic_checkpoint_artifacts(
                root,
                completed.get("artifacts"),
                source=completed_ref,
            )
            status = completed.get("status")
            if status == "provider_blocked":
                if completed.get("consumes_semantic_attempt") is not False:
                    raise ValueError(
                        f"{completed_ref} provider block consumed an attempt"
                    )
                continue
            if status not in {"validation_failed", "validated"}:
                raise ValueError(f"{completed_ref} has invalid semantic status")
            if completed.get("consumes_semantic_attempt") is not True:
                raise ValueError(
                    f"{completed_ref} candidate did not consume its attempt"
                )
            semantic_attempts_used += 1

            last_error = completed.get("last_error")
            if not isinstance(last_error, str) or (
                status == "validation_failed" and not last_error
            ):
                raise ValueError(f"{completed_ref} has invalid validation error")
            if hashlib.sha256(last_error.encode("utf-8")).hexdigest() != (
                completed.get("last_error_sha256")
            ):
                raise ValueError(f"{completed_ref} validation error hash changed")
            provider_result = completed.get("provider_result")
            if (
                not isinstance(provider_result, dict)
                or provider_result.get("status") != "completed"
            ):
                raise ValueError(
                    f"{completed_ref} does not prove a completed provider result"
                )

            dispatch_candidates: list[tuple[str, Path, dict[str, Any]]] = []
            for evidence_ref, path in artifact_paths.items():
                if not path.name.endswith("_dispatch_result.json"):
                    continue
                dispatch = _load_object(path)
                if (
                    dispatch.get("schema")
                    == "chipflow.native_subagent_dispatch_result.v2"
                ):
                    dispatch_candidates.append((evidence_ref, path, dispatch))
            if len(dispatch_candidates) != 1:
                raise ValueError(
                    f"{completed_ref} must bind exactly one subagent dispatch result"
                )
            dispatch_ref, _, dispatch = dispatch_candidates[0]
            runtime = dispatch.get("runtime")
            if (
                dispatch.get("status") != "completed"
                or dispatch.get("tool_policy") != "none"
                or not isinstance(runtime, dict)
                or runtime.get("tool_policy") != "none"
            ):
                raise ValueError(
                    f"{dispatch_ref} is not a completed tool-free semantic dispatch"
                )
            if (
                started.get("dispatch_stage") != dispatch.get("stage")
                or lineage.get("agent_id") != dispatch.get("agent_id")
                or binding.get("runtime_manifest_hash")
                != dispatch.get("run_runtime_manifest_hash")
                or provider_result.get("config_hash")
                != dispatch.get("config_hash")
                or provider_result.get("manifest_hash")
                != dispatch.get("official_manifest_hash")
                or provider_result.get("run_runtime_manifest_hash")
                != dispatch.get("run_runtime_manifest_hash")
            ):
                raise ValueError(f"{dispatch_ref} semantic identity binding changed")
            raw_response_ref = completed.get("raw_llm_call_path")
            if (
                not isinstance(raw_response_ref, str)
                or not raw_response_ref
                or dispatch.get("raw_response_path") != raw_response_ref
                or raw_response_ref not in artifact_paths
                or artifact_paths[raw_response_ref].stat().st_size == 0
            ):
                raise ValueError(
                    f"{completed_ref} raw model response binding is invalid"
                )
            proof_refs = [
                dispatch_ref,
                completed_ref,
                started_ref,
                binding_ref,
                raw_response_ref,
            ]
            proofs.setdefault(dispatch_ref, []).append(proof_refs)
    return proofs


def _direct_llm_events(root: Path) -> list[dict[str, Any]]:
    paths = _json_files(root, DIRECT_LLM_ROOT, "*.json")
    events: list[dict[str, Any]] = []
    identities: set[tuple[str, str]] = set()
    for relative in paths:
        evidence_ref, path = _run_member(root, relative)
        payload = _load_object(path)
        required = {
            "status",
            "agent_name",
            "model_name",
            "call_name",
            "created_at",
            "attempts",
        }
        missing = sorted(required - set(payload))
        if missing:
            raise ValueError(
                f"{evidence_ref} is not a complete ChipFlow LLM artifact; "
                f"missing {missing}"
            )
        status = payload["status"]
        if status not in {"pass", "fail", "timeout"}:
            raise ValueError(
                f"{evidence_ref} has non-terminal LLM status {status!r}"
            )
        for name in ("agent_name", "model_name", "call_name", "created_at"):
            if not isinstance(payload[name], str) or not payload[name].strip():
                raise ValueError(f"{evidence_ref} has invalid {name}")
        call_identity = (payload["agent_name"], payload["call_name"])
        if call_identity in identities:
            raise ValueError(
                "duplicate direct LLM agent/call identity: "
                f"{call_identity[0]}/{call_identity[1]}"
            )
        identities.add(call_identity)
        attempts = payload["attempts"]
        if not isinstance(attempts, list) or not attempts:
            raise ValueError(f"{evidence_ref} has no persisted LLM attempts")
        attempt_numbers: list[int] = []
        pass_indices: list[int] = []
        for index, attempt in enumerate(attempts):
            if not isinstance(attempt, dict):
                raise ValueError(f"{evidence_ref} LLM attempt is not an object")
            number = attempt.get("attempt")
            attempt_status = attempt.get("status")
            if type(number) is not int or number < 1:
                raise ValueError(f"{evidence_ref} has invalid LLM attempt number")
            if attempt_status not in {"pass", "fail", "retrying"}:
                raise ValueError(f"{evidence_ref} has invalid LLM attempt status")
            attempt_numbers.append(number)
            if attempt_status == "pass":
                pass_indices.append(index)
        if attempt_numbers != list(range(1, len(attempts) + 1)):
            raise ValueError(f"{evidence_ref} LLM attempts are not consecutive")
        if status == "pass" and pass_indices != [len(attempts) - 1]:
            raise ValueError(
                f"{evidence_ref} passing LLM artifact has inconsistent attempts"
            )
        if status != "pass" and pass_indices:
            raise ValueError(
                f"{evidence_ref} failing LLM artifact contains a pass attempt"
            )
        successful_tokens = _token_pair(
            payload.get("usage_metadata"),
            source=evidence_ref,
        )
        for index, attempt in enumerate(attempts):
            input_tokens, output_tokens = (
                successful_tokens
                if attempt["status"] == "pass"
                else (None, None)
            )
            events.append(
                {
                    "event_id": _event_id(
                        "llm-direct",
                        evidence_ref,
                        attempt["attempt"],
                    ),
                    "event_type": "llm_call",
                    "input_tokens": input_tokens,
                    "output_tokens": output_tokens,
                    "evidence_refs": [evidence_ref],
                }
            )
    return events


def _subagent_llm_events(root: Path) -> list[dict[str, Any]]:
    paths = _json_files(
        root,
        SUBAGENT_ROOT,
        "*_dispatch_result.json",
    )
    events: list[dict[str, Any]] = []
    source_run_ids: set[str] = set()
    checkpoint_proofs: dict[str, list[list[str]]] | None = None
    for relative in paths:
        evidence_ref, path = _run_member(root, relative)
        payload = _load_object(path)
        if payload.get("schema") != "chipflow.native_subagent_dispatch_result.v2":
            raise ValueError(f"{evidence_ref} has unsupported dispatch schema")
        status = payload.get("status")
        if status not in {
            "completed",
            "failed",
            "cancelled",
            "timed_out",
            "blocked",
        }:
            raise ValueError(f"{evidence_ref} has invalid dispatch status")
        records = payload.get("token_usage_records")
        if not isinstance(records, list):
            raise ValueError(f"{evidence_ref} has no token_usage_records list")
        if not records:
            if status != "completed":
                raise ValueError(
                    f"{evidence_ref} cannot prove subagent LLM call count: "
                    "token_usage_records is empty"
                )
            if checkpoint_proofs is None:
                checkpoint_proofs = _semantic_checkpoint_missing_usage_proofs(
                    root
                )
            matches = checkpoint_proofs.get(evidence_ref, [])
            if len(matches) != 1:
                detail = "missing" if not matches else "ambiguous"
                raise ValueError(
                    f"{evidence_ref} cannot prove subagent LLM call count: "
                    f"token_usage_records is empty and semantic proof is {detail}"
                )
            proof_refs = matches[0]
            events.append(
                {
                    "event_id": _event_id(
                        "llm-subagent-checkpoint",
                        proof_refs[1],
                    ),
                    "event_type": "llm_call",
                    "input_tokens": None,
                    "output_tokens": None,
                    "evidence_refs": proof_refs,
                }
            )
            continue
        for record in records:
            if not isinstance(record, dict):
                raise ValueError(f"{evidence_ref} token record is not an object")
            source_run_id = record.get("source_run_id")
            caller = record.get("caller")
            if (
                not isinstance(source_run_id, str)
                or not source_run_id
                or not isinstance(caller, str)
                or not caller
            ):
                raise ValueError(f"{evidence_ref} token record identity is invalid")
            if source_run_id in source_run_ids:
                raise ValueError(
                    f"duplicate subagent LLM source_run_id: {source_run_id}"
                )
            source_run_ids.add(source_run_id)
            input_tokens = _integer_or_none(
                record.get("input_tokens"),
                field=f"{evidence_ref} input_tokens",
            )
            output_tokens = _integer_or_none(
                record.get("output_tokens"),
                field=f"{evidence_ref} output_tokens",
            )
            total_tokens = _integer_or_none(
                record.get("total_tokens"),
                field=f"{evidence_ref} total_tokens",
            )
            if (
                input_tokens is None
                or output_tokens is None
                or total_tokens is None
                or total_tokens != input_tokens + output_tokens
                or total_tokens <= 0
            ):
                raise ValueError(
                    f"{evidence_ref} token record is incomplete or inconsistent"
                )
            events.append(
                {
                    "event_id": _event_id(
                        "llm-subagent",
                        source_run_id,
                    ),
                    "event_type": "llm_call",
                    "input_tokens": input_tokens,
                    "output_tokens": output_tokens,
                    "evidence_refs": [evidence_ref],
                }
            )
    return events


def _command_argv(command: str, *, source: str) -> list[str]:
    if not isinstance(command, str) or not command.strip():
        raise ValueError(f"{source} has no command")
    try:
        argv = shlex.split(command)
    except ValueError as exc:
        raise ValueError(f"{source} command cannot be parsed") from exc
    if not argv:
        raise ValueError(f"{source} command has no executable")
    return argv


def _command_executable(command: str, *, source: str) -> str:
    return Path(_command_argv(command, source=source)[0]).name


def _normalized_sandbox_path(
    value: str,
    *,
    cwd: str,
    source: str,
) -> str:
    path = PurePosixPath(value)
    if path.is_absolute():
        return posixpath.normpath(path.as_posix())
    base = PurePosixPath(cwd)
    if not base.is_absolute():
        raise ValueError(
            f"{source} uses a relative generated executable without an "
            "absolute sandbox cwd"
        )
    return posixpath.normpath((base / path).as_posix())


def _single_option_value(
    argv: list[str],
    option: str,
    *,
    source: str,
) -> str | None:
    indices = [index for index, value in enumerate(argv) if value == option]
    if not indices:
        return None
    if len(indices) != 1 or indices[0] + 1 >= len(argv):
        raise ValueError(f"{source} has ambiguous {option} output binding")
    value = argv[indices[0] + 1]
    if not value or value.startswith("-"):
        raise ValueError(f"{source} has invalid {option} output binding")
    return value


def _verilator_generated_executable(
    result: dict[str, Any],
    *,
    source: str,
) -> str | None:
    command = result.get("command")
    argv = _command_argv(command, source=source)
    if (
        Path(argv[0]).name not in {"verilator", "verilator_bin"}
        or "--binary" not in argv
    ):
        return None
    object_dir = _single_option_value(argv, "--Mdir", source=source)
    output_name = _single_option_value(argv, "-o", source=source)
    if object_dir is None or output_name is None:
        raise ValueError(
            f"{source} Verilator --binary command lacks an exact --Mdir/-o "
            "generated-executable binding"
        )
    cwd = result.get("cwd")
    if not isinstance(cwd, str) or not cwd:
        raise ValueError(f"{source} has no cwd for generated executable")
    normalized_dir = _normalized_sandbox_path(
        object_dir,
        cwd=cwd,
        source=source,
    )
    output_path = PurePosixPath(output_name)
    if output_path.is_absolute():
        return posixpath.normpath(output_path.as_posix())
    return posixpath.normpath(
        (PurePosixPath(normalized_dir) / output_path).as_posix()
    )


def _eda_event_type(
    command: str,
    *,
    source: str,
    cwd: str | None = None,
    generated_simulators: set[str] | None = None,
) -> str:
    argv = _command_argv(command, source=source)
    executable = Path(argv[0]).name
    matches = [
        event_type
        for event_type, tools in EDA_TOOLS.items()
        if executable in tools
    ]
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        raise ValueError(
            f"{source} has unknown or ambiguous EDA executable {executable!r}"
        )
    if (
        generated_simulators
        and isinstance(cwd, str)
        and cwd
        and (PurePosixPath(argv[0]).is_absolute() or "/" in argv[0])
    ):
        normalized = _normalized_sandbox_path(
            argv[0],
            cwd=cwd,
            source=source,
        )
        if normalized in generated_simulators:
            return "eda_simulation"
    raise ValueError(
        f"{source} has unknown or ambiguous EDA executable {executable!r}"
    )


def _eda_events(root: Path) -> list[dict[str, Any]]:
    evidence_ref, path = _run_member(root, RAW_EDA_PATH)
    payload = _load_object(path)
    if payload.get("schema_version") != "chipflow.native_verify.v1":
        raise ValueError("raw_eda_results.json has unsupported schema_version")
    modified = payload.get("modified")
    if not isinstance(modified, dict):
        raise ValueError("raw_eda_results.json has no modified result object")
    results = modified.get("results")
    if not isinstance(results, list):
        raise ValueError("raw_eda_results.json modified.results is not a list")
    events = []
    generated_simulators: set[str] = set()
    for index, result in enumerate(results):
        source = f"{evidence_ref} modified.results[{index}]"
        if not isinstance(result, dict):
            raise ValueError(f"{source} is not an object")
        event_type = _eda_event_type(
            result.get("command"),
            source=source,
            cwd=result.get("cwd"),
            generated_simulators=generated_simulators,
        )
        events.append(
            {
                "event_id": _event_id(
                    "eda",
                    evidence_ref,
                    index,
                    result["command"],
                ),
                "event_type": event_type,
                "input_tokens": None,
                "output_tokens": None,
                "evidence_refs": [evidence_ref],
            }
        )
        if result.get("status") == "pass" and result.get("exit_code") == 0:
            generated = _verilator_generated_executable(
                result,
                source=source,
            )
            if generated is not None:
                if generated in generated_simulators:
                    raise ValueError(
                        f"{source} duplicates generated executable {generated!r}"
                    )
                generated_simulators.add(generated)
    return events


def _hitl_events(root: Path) -> list[dict[str, Any]]:
    evidence_ref, path = _run_member(root, HITL_LOG_PATH)
    events = []
    identities: set[tuple[str, str, str, str]] = set()
    for line_number, raw_line in enumerate(
        path.read_text(encoding="utf-8").splitlines(),
        start=1,
    ):
        if not raw_line.strip():
            continue
        try:
            payload = json.loads(raw_line)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"{evidence_ref}:{line_number} is not valid JSON"
            ) from exc
        if not isinstance(payload, dict):
            raise ValueError(f"{evidence_ref}:{line_number} is not an object")
        values = tuple(
            payload.get(name)
            for name in (
                "approval_request_id",
                "gate",
                "decision",
                "approved_scope_hash",
            )
        )
        if not all(isinstance(value, str) and value for value in values):
            raise ValueError(
                f"{evidence_ref}:{line_number} has incomplete decision identity"
            )
        identity = values
        if identity in identities:
            raise ValueError(
                f"{evidence_ref}:{line_number} duplicates an approval decision"
            )
        identities.add(identity)
        events.append(
            {
                "event_id": _event_id(
                    "human",
                    evidence_ref,
                    *identity,
                ),
                "event_type": "human_intervention",
                "input_tokens": None,
                "output_tokens": None,
                "evidence_refs": [evidence_ref],
            }
        )
    return events


def _monitor_events(
    root: Path,
    *,
    chipflow_run_id: str,
    eda_events: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    evidence_ref, path = _run_member(root, MONITOR_PATH)
    monitor = _load_object(path)
    schema = _load_object(MONITOR_SCHEMA_PATH)
    Draft202012Validator(schema).validate(monitor)
    if monitor["chipflow_run_id"] != chipflow_run_id:
        raise ValueError("task-workspace monitor run ID does not match")
    observed_eda = {
        key: sum(
            event["event_type"] == event_type
            for event in eda_events
        )
        for event_type, key in EVENT_TO_MONITOR_KEY.items()
    }
    if monitor["eda_calls"] != observed_eda:
        raise ValueError(
            "task-workspace process monitor EDA counts disagree with "
            "raw_eda_results.json"
        )
    return [
        {
            "event_id": _event_id(
                "network",
                evidence_ref,
                index,
            ),
            "event_type": "network_attempt",
            "input_tokens": None,
            "output_tokens": None,
            "evidence_refs": [evidence_ref],
        }
        for index in range(monitor["network_attempt_count"])
    ]


def collect_runtime_usage_events(
    *,
    run_root: Path,
    chipflow_run_id: str,
) -> dict[str, Any]:
    if run_root.is_symlink():
        raise ValueError("ChipFlow run root must not be a symlink")
    run_root = run_root.expanduser().resolve(strict=True)
    if not run_root.is_dir():
        raise ValueError("ChipFlow run root must be a directory")
    if not chipflow_run_id:
        raise ValueError("ChipFlow run ID must be non-empty")
    direct_events = _direct_llm_events(run_root)
    subagent_events = _subagent_llm_events(run_root)
    if not direct_events and not subagent_events:
        raise ValueError(
            "no canonical direct or native-subagent LLM call evidence found"
        )
    eda_events = _eda_events(run_root)
    hitl_events = _hitl_events(run_root)
    monitor_events = _monitor_events(
        run_root,
        chipflow_run_id=chipflow_run_id,
        eda_events=eda_events,
    )
    events = [
        *direct_events,
        *subagent_events,
        *eda_events,
        *hitl_events,
        *monitor_events,
    ]
    event_ids = [event["event_id"] for event in events]
    if len(event_ids) != len(set(event_ids)):
        raise ValueError("derived usage event IDs are not unique")
    ledger = {
        "schema_version": "rtlflowbench.chipflow_usage_events.v1",
        "chipflow_run_id": chipflow_run_id,
        "collection_evidence_refs": [
            RAW_EDA_PATH.as_posix(),
            HITL_LOG_PATH.as_posix(),
            MONITOR_PATH.as_posix(),
        ],
        "network_monitor": {
            "evidence_ref": MONITOR_PATH.as_posix(),
            "method": _load_object(
                _run_member(run_root, MONITOR_PATH)[1]
            )["monitor_backend"],
        },
        "events": events,
    }
    schema = _load_object(EVENT_SCHEMA_PATH)
    Draft202012Validator(schema).validate(ledger)
    return ledger


def _write_new(path: Path, value: dict[str, Any]) -> None:
    path = path.expanduser().resolve()
    if path.exists() or path.is_symlink():
        raise FileExistsError(f"refusing to overwrite output: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    stage = path.with_name(f".{path.name}.tmp")
    if stage.exists() or stage.is_symlink():
        raise FileExistsError(f"temporary output already exists: {stage}")
    stage.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.replace(stage, path)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-root", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        ledger = collect_runtime_usage_events(
            run_root=args.run_root,
            chipflow_run_id=args.run_id,
        )
        _write_new(args.output, ledger)
    except Exception as exc:
        print(
            json.dumps(
                {
                    "status": "fail",
                    "error": f"{type(exc).__name__}: {exc}",
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 2
    print(json.dumps(ledger, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
