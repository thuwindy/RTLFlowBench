#!/usr/bin/env python3
"""Content-bound OpenAI-compatible bridge for the same-model vanilla baseline."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import os
from pathlib import Path
import sys
from typing import Any
from urllib.parse import urlsplit

import yaml


CONFIG_ENV = "RTLFLOWBENCH_VANILLA_CONFIG_PATH"
CREDENTIAL_ENV = "RTLFLOWBENCH_VANILLA_CREDENTIAL_ENV_FILE"
MODEL_ALIAS_ENV = "RTLFLOWBENCH_VANILLA_MODEL_ALIAS"
PROXY_BASE_URL_ENV = "RTLFLOWBENCH_PROVIDER_PROXY_BASE_URL"
CONTROLLER_SOCKET_ENV = "RTLFLOWBENCH_CONTROLLER_SOCKET"
CONTROLLER_SESSION_ENV = "RTLFLOWBENCH_CONTROLLER_SESSION"
SENSITIVE_KEY_PARTS = ("api_key", "password", "secret", "token", "header")
MODEL_METADATA_KEYS = {
    "name",
    "display_name",
    "description",
    "pricing",
    "supports_reasoning_effort",
    "supports_thinking",
    "supports_vision",
    "thinking",
    "when_thinking_disabled",
    "when_thinking_enabled",
}
SUPPORTED_PROVIDER_CLASSES = frozenset(
    {
        "langchain_openai:ChatOpenAI",
        "deerflow.models.patched_deepseek_openai:PatchedDeepSeekOpenAI",
    }
)
PROMPT_PROJECTION_VERSION = "rtlflowbench.vanilla_compact_prompt.v1"
DECODING_CONFIG = {
    "max_tokens": 8192,
    "prompt_projection": PROMPT_PROJECTION_VERSION,
    "response_contract": (
        "files_or_exact_edits_with_noop_claims_summary_strict_json_v3"
    ),
    "seed_policy": "attempt.seed",
    "temperature": 0,
    "top_p": 1,
}
FACTORY_DEFAULTS = {
    "stream_chunk_timeout": 240.0,
    "stream_usage": True,
}


def canonical_sha256(value: Any) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def sha256(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"source must be a regular non-symlink file: {path}")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _regular_file_from_env(name: str) -> Path:
    raw = os.environ.get(name)
    if not raw:
        raise ValueError(f"required provider environment is missing: {name}")
    path = Path(raw).expanduser()
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"provider input must be a regular non-symlink file: {name}")
    return path.resolve(strict=True)


def _resolve_environment(value: Any) -> Any:
    if isinstance(value, str) and value.startswith("$") and len(value) > 1:
        variable = value[1:]
        if not variable.replace("_", "").isalnum() or not variable.isupper():
            raise ValueError("model config contains an unsafe environment reference")
        resolved = os.environ.get(variable)
        if resolved is None:
            raise ValueError(f"model environment is missing: {variable}")
        return resolved
    if isinstance(value, dict):
        return {key: _resolve_environment(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_resolve_environment(item) for item in value]
    return value


def _is_sensitive(key: str) -> bool:
    lowered = key.lower()
    return any(part in lowered for part in SENSITIVE_KEY_PARTS)


def _load_model_entry(config_path: Path, model_alias: str) -> dict[str, Any]:
    raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict) or not isinstance(raw.get("models"), list):
        raise ValueError("provider config has no model list")
    matches = [
        item
        for item in raw["models"]
        if isinstance(item, dict) and item.get("name") == model_alias
    ]
    if len(matches) != 1:
        raise ValueError("provider model alias is missing or ambiguous")
    return matches[0]


def configuration_projection(
    *,
    config_path: Path,
    model_alias: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    entry = _load_model_entry(config_path, model_alias)
    if entry.get("use") not in SUPPORTED_PROVIDER_CLASSES:
        raise ValueError("provider bridge requires a supported OpenAI-compatible model class")
    runtime_settings = {
        key: _resolve_environment(value)
        for key, value in entry.items()
        if key not in MODEL_METADATA_KEYS | {"use"}
    }
    if not isinstance(runtime_settings.get("model"), str):
        raise ValueError("resolved provider model id is missing")
    if not isinstance(runtime_settings.get("base_url"), str):
        raise ValueError("resolved provider base URL is missing")
    sensitive_fields = sorted(
        key for key in runtime_settings if _is_sensitive(key)
    )
    public_settings = {
        key: value
        for key, value in runtime_settings.items()
        if key not in sensitive_fields
    }
    projection = {
        "schema_version": "rtlflowbench.vanilla_model_projection.v1",
        "model_alias": model_alias,
        "provider_class": entry["use"],
        "public_runtime_settings": public_settings,
        "credential_fields_present": sensitive_fields,
        "factory_defaults": FACTORY_DEFAULTS,
    }
    return projection, runtime_settings


def decoding_config_sha256() -> str:
    return canonical_sha256(DECODING_CONFIG)


def _runtime_configuration() -> tuple[dict[str, Any], dict[str, Any]]:
    config_path = _regular_file_from_env(CONFIG_ENV)
    model_alias = os.environ.get(MODEL_ALIAS_ENV)
    if not model_alias:
        raise ValueError(f"required provider environment is missing: {MODEL_ALIAS_ENV}")
    credential_path_value = os.environ.get(CREDENTIAL_ENV)
    if credential_path_value:
        credential_path = _regular_file_from_env(CREDENTIAL_ENV)
        from dotenv import load_dotenv

        load_dotenv(credential_path, override=False)
    projection, runtime_settings = configuration_projection(
        config_path=config_path,
        model_alias=model_alias,
    )
    return projection, runtime_settings


def _controller_proxy_base_url() -> str | None:
    raw = os.environ.get(PROXY_BASE_URL_ENV)
    if raw is None:
        return None
    if not os.environ.get(CONTROLLER_SOCKET_ENV) or not os.environ.get(
        CONTROLLER_SESSION_ENV
    ):
        raise ValueError("provider proxy override requires the observed controller")
    parsed = urlsplit(raw)
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("provider proxy override port is invalid") from exc
    if not (
        parsed.scheme == "http"
        and parsed.hostname == "127.0.0.1"
        and port is not None
        and 1 <= port <= 65535
        and parsed.path.rstrip("/") == "/v1"
        and parsed.username is None
        and parsed.password is None
        and not parsed.query
        and not parsed.fragment
    ):
        raise ValueError("provider proxy override is not a loopback v1 endpoint")
    return f"http://127.0.0.1:{port}/v1"


def _model_runtime_settings(runtime_settings: dict[str, Any]) -> dict[str, Any]:
    settings = dict(runtime_settings)
    proxy_base_url = _controller_proxy_base_url()
    if proxy_base_url is not None:
        settings["base_url"] = proxy_base_url
    return settings


def _build_model(
    runtime_settings: dict[str, Any],
    seed: int | None,
    *,
    maximum_output_tokens: int | None = None,
):
    from langchain_openai import ChatOpenAI

    settings = _model_runtime_settings(runtime_settings)
    settings.setdefault("stream_chunk_timeout", FACTORY_DEFAULTS["stream_chunk_timeout"])
    settings.setdefault("stream_usage", FACTORY_DEFAULTS["stream_usage"])
    settings["temperature"] = DECODING_CONFIG["temperature"]
    settings["max_tokens"] = (
        DECODING_CONFIG["max_tokens"]
        if maximum_output_tokens is None
        else maximum_output_tokens
    )
    settings["top_p"] = DECODING_CONFIG["top_p"]
    if seed is not None:
        settings["seed"] = seed
    return ChatOpenAI(**settings)


def _compact_prompt(request: dict[str, Any]) -> str:
    """Render the public request without nesting one JSON document in another.

    The controller transports this string inside the provider's JSON request.  A
    second JSON serialization of the complete request needlessly escapes every
    source newline twice and can trip the shared byte-conservative token guard
    before the provider sees a repository task.  This projection preserves every
    selected public/repository content byte and records omitted entries by hash;
    it only removes transport metadata that the model does not need to solve the
    task.
    """

    required = {
        "task_id": str,
        "instructions": str,
        "public_files": list,
    }
    for key, expected_type in required.items():
        if not isinstance(request.get(key), expected_type):
            raise ValueError(f"provider request has invalid {key}")

    lines = [
        PROMPT_PROJECTION_VERSION,
        f"task_id={request['task_id']}",
        "instructions_begin",
        request["instructions"],
        "instructions_end",
    ]

    def append_files(label: str, items: list[Any]) -> None:
        lines.append(f"{label}_begin")
        for item in items:
            if not isinstance(item, dict):
                raise ValueError(f"{label} contains a non-object entry")
            path = item.get("path")
            digest = item.get("sha256")
            byte_count = item.get("bytes")
            content = item.get("content")
            omitted_reason = item.get("omitted_reason")
            if (
                not isinstance(path, str)
                or not isinstance(digest, str)
                or len(digest) != 64
                or not isinstance(byte_count, int)
                or isinstance(byte_count, bool)
                or byte_count < 0
            ):
                raise ValueError(f"{label} contains invalid file metadata")
            quoted_path = json.dumps(path, ensure_ascii=False)
            if content is None:
                if not isinstance(omitted_reason, str) or not omitted_reason:
                    raise ValueError(f"{label} omitted file lacks a reason")
                lines.append(
                    f"omitted path={quoted_path} bytes={byte_count} "
                    f"sha256={digest} reason={omitted_reason}"
                )
                continue
            if not isinstance(content, str) or omitted_reason is not None:
                raise ValueError(f"{label} contains invalid text content")
            observed = content.encode("utf-8")
            if len(observed) != byte_count:
                raise ValueError(f"{label} content byte count drifted")
            if hashlib.sha256(observed).hexdigest() != digest:
                raise ValueError(f"{label} content SHA256 drifted")
            lines.extend(
                [
                    f"file_begin path={quoted_path} bytes={byte_count} sha256={digest}",
                    content,
                    f"file_end path={quoted_path} sha256={digest}",
                ]
            )
        lines.append(f"{label}_end")

    append_files("public_files", request["public_files"])
    repository_files = request.get("repository_files")
    if repository_files is not None:
        if not isinstance(repository_files, list):
            raise ValueError("provider request has invalid repository_files")
        append_files("repository_files", repository_files)

    feedback = request.get("visible_feedback")
    if feedback is not None:
        lines.extend(
            [
                "visible_feedback_begin",
                json.dumps(
                    feedback,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                "visible_feedback_end",
            ]
        )
    return "\n".join(lines)


def _message_text(message: Any) -> str:
    content = getattr(message, "content", None)
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict) and isinstance(item.get("text"), str):
                parts.append(item["text"])
        return "".join(parts)
    raise ValueError("provider returned no textual content")


def _preflight_response_ok(raw_text: str) -> bool:
    try:
        value = json.loads(raw_text)
    except json.JSONDecodeError:
        return False
    return value == {"status": "RTLFLOWBENCH_PREFLIGHT_OK"}


def usage_from_message(message: Any) -> dict[str, int | None]:
    usage = getattr(message, "usage_metadata", None)
    if isinstance(usage, dict):
        return {
            "input_tokens": usage.get("input_tokens"),
            "output_tokens": usage.get("output_tokens"),
        }
    metadata = getattr(message, "response_metadata", None)
    token_usage = metadata.get("token_usage") if isinstance(metadata, dict) else None
    if isinstance(token_usage, dict):
        return {
            "input_tokens": token_usage.get("prompt_tokens"),
            "output_tokens": token_usage.get("completion_tokens"),
        }
    return {"input_tokens": None, "output_tokens": None}


def response_envelope(
    *,
    raw_text: str,
    request: dict[str, Any],
    usage: dict[str, int | None],
) -> dict[str, Any]:
    # Accept only a single complete JSON fence, never surrounding prose or
    # several candidate blocks. Decoding and payload validation stay unchanged.
    framed = re.fullmatch(
        r"```(?:json)?[ \t]*\r?\n([\s\S]*?)\r?\n```", raw_text.strip()
    )
    parsed = json.loads(framed.group(1) if framed else raw_text)
    if not isinstance(parsed, dict):
        raise ValueError("provider payload is not the exact response body contract")
    observed_keys = set(parsed)
    accepted_keys = (
        {"files", "claims", "summary"},
        {"edits", "claims", "summary"},
    )
    claims_omitted_keys = (
        {"files", "summary"},
        {"edits", "summary"},
    )
    if observed_keys in claims_omitted_keys:
        # ``claims`` is non-semantic reporting metadata.  Some otherwise valid
        # providers omit it despite the strict prompt, so normalize only this
        # one omission to the schema-valid empty value.  Payload, summary,
        # scope, path, and materialization checks remain fail closed.
        parsed["claims"] = []
    elif observed_keys not in accepted_keys:
        raise ValueError("provider payload is not the exact response body contract")
    payload_key = "files" if "files" in parsed else "edits"
    payload = parsed[payload_key]
    if payload_key == "files":
        if isinstance(payload, dict):
            if not all(
                isinstance(path, str) and isinstance(content, str)
                for path, content in payload.items()
            ):
                raise ValueError("provider file mapping is not path-to-text")
            payload = [
                {"path": path, "content": content}
                for path, content in sorted(payload.items())
            ]
        if isinstance(payload, list):
            deduplicated = []
            observed: dict[str, str] = {}
            for item in payload:
                if not isinstance(item, dict):
                    deduplicated.append(item)
                    continue
                path = item.get("path")
                content = item.get("content")
                if not isinstance(path, str) or not isinstance(content, str):
                    deduplicated.append(item)
                    continue
                if path in observed:
                    if observed[path] != content:
                        raise ValueError(
                            "provider payload contains conflicting duplicate paths"
                        )
                    continue
                observed[path] = content
                deduplicated.append(item)
            payload = deduplicated
    envelope = {
        "schema_version": "rtlflowbench.vanilla_provider_response.v2",
        "request_id": request["request_id"],
        "model_config_sha256": request["model_config_sha256"],
        "usage": usage,
        "claims": parsed["claims"],
        "summary": parsed["summary"],
    }
    envelope[payload_key] = payload
    return envelope


def _write_new_json(path: Path, value: dict[str, Any]) -> None:
    if path.exists() or path.is_symlink():
        raise FileExistsError(f"refusing to overwrite provider output: {path}")
    with path.open("x", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")
    path.chmod(0o600)


def _write_invalid_payload(response_path: Path, raw_text: str) -> None:
    raw_path = response_path.with_name("provider_raw_response.txt")
    if raw_path.exists() or raw_path.is_symlink():
        raise FileExistsError("refusing to overwrite provider raw response")
    with raw_path.open("x", encoding="utf-8") as handle:
        handle.write(raw_text)
    raw_path.chmod(0o600)
    _write_new_json(
        response_path,
        {
            "schema_version": "rtlflowbench.vanilla_invalid_provider_payload.v1",
            "raw_response_sha256": hashlib.sha256(raw_text.encode()).hexdigest(),
            "raw_response_bytes": len(raw_text.encode()),
        },
    )


def _invoke(request: dict[str, Any], runtime_settings: dict[str, Any]):
    from langchain_core.messages import HumanMessage, SystemMessage

    seed = request.get("attempt", {}).get("seed")
    if seed is not None and not isinstance(seed, int):
        raise ValueError("attempt seed is not an integer or null")
    model = _build_model(runtime_settings, seed)
    system = SystemMessage(
        content=(
            "You are the single-agent RTL baseline. Return only one JSON object "
            "with exactly either files, claims, summary or edits, claims, summary. "
            "Use files for new or complete small files. Prefer edits for existing "
            "large files: edits is an array of objects with exactly path, old_text, "
            "new_text, expected_replacements; old_text must be an exact unique "
            "anchor and expected_replacements must be 1. In repository-overlay "
            "tasks, edits may be an empty array when no safe modification is "
            "justified; do not fabricate an edit. files is an array of "
            "objects with exactly path and content string keys. claims is a string "
            "array; summary is a string. "
            "Do not wrap JSON in Markdown and do not claim hidden PASS, PPA, "
            "benchmark readiness, or access to any private evaluator."
        )
    )
    human = HumanMessage(content=_compact_prompt(request))
    return model.invoke([system, human])


def run_provider(request_path: Path, response_path: Path) -> int:
    if request_path.is_symlink() or not request_path.is_file():
        raise ValueError("provider request must be a regular non-symlink file")
    if response_path.exists() or response_path.is_symlink():
        raise FileExistsError("provider response already exists")
    request = json.loads(request_path.read_text(encoding="utf-8"))
    if not isinstance(request, dict):
        raise ValueError("provider request is not one JSON object")
    projection, runtime_settings = _runtime_configuration()
    if request.get("model_config_sha256") != canonical_sha256(projection):
        raise ValueError("provider model configuration binding drifted")
    if request.get("decoding_config_sha256") != decoding_config_sha256():
        raise ValueError("provider decoding configuration binding drifted")
    message = _invoke(request, runtime_settings)
    raw_text = _message_text(message)
    usage = usage_from_message(message)
    try:
        envelope = response_envelope(
            raw_text=raw_text,
            request=request,
            usage=usage,
        )
    except (json.JSONDecodeError, TypeError, ValueError):
        _write_invalid_payload(response_path, raw_text)
        return 0
    _write_new_json(response_path, envelope)
    return 0


def run_preflight(output_path: Path) -> int:
    projection, runtime_settings = _runtime_configuration()
    model = _build_model(runtime_settings, seed=0, maximum_output_tokens=32)
    from langchain_core.messages import HumanMessage, SystemMessage

    message = model.invoke(
        [
            SystemMessage(
                content=(
                    'Return only this JSON object with no Markdown or extra text: '
                    '{"status":"RTLFLOWBENCH_PREFLIGHT_OK"}'
                )
            ),
            HumanMessage(
                content=(
                    'Provider connectivity and strict-JSON preflight. Return only '
                    '{"status":"RTLFLOWBENCH_PREFLIGHT_OK"}.'
                )
            ),
        ]
    )
    raw_text = _message_text(message).strip()
    status = (
        "provider_preflight_pass"
        if _preflight_response_ok(raw_text)
        else "provider_protocol_fail"
    )
    receipt = {
        "schema_version": "rtlflowbench.vanilla_provider_preflight.v1",
        "status": status,
        "provider_runner_sha256": sha256(Path(__file__)),
        "model_config_sha256": canonical_sha256(projection),
        "decoding_config_sha256": decoding_config_sha256(),
        "provider_model": projection["public_runtime_settings"]["model"],
        "llm_calls": 1,
        "usage": usage_from_message(message),
        "response_sha256": hashlib.sha256(raw_text.encode()).hexdigest(),
        "response_bytes": len(raw_text.encode()),
        "private_evaluator_run": False,
        "benchmark_ready": False,
        "execution_permitted": False,
        "excluded_claims": [
            "This is only a minimal provider-connectivity preflight.",
            "No task, RTL, EDA, private evaluator, score, PPA, or ranking was run.",
        ],
    }
    _write_new_json(output_path, receipt)
    return 0 if status == "provider_preflight_pass" else 4


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--request", type=Path)
    parser.add_argument("--response", type=Path)
    parser.add_argument("--preflight-output", type=Path)
    args = parser.parse_args()
    try:
        if args.preflight_output is not None:
            if args.request is not None or args.response is not None:
                raise ValueError("preflight and task invocation are mutually exclusive")
            return run_preflight(args.preflight_output)
        if args.request is None or args.response is None:
            raise ValueError("task invocation requires --request and --response")
        return run_provider(args.request, args.response)
    except (OSError, TypeError, ValueError) as exc:
        print(
            json.dumps(
                {
                    "status": "provider_control_error",
                    "exception_class": type(exc).__name__,
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2
    except Exception as exc:
        print(
            json.dumps(
                {
                    "status": "provider_infra_block",
                    "exception_class": type(exc).__name__,
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
