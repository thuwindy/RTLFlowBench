#!/usr/bin/env python3
"""Secret-safe, task-free provider compatibility preflight for external AIRTL."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from typing import Any

from source_snapshot_binding import bind_source


PROVIDER = "deepseek"
CREDENTIAL_ENV = "DEEPSEEK_API_KEY"
BASE_URL = "https://api.deepseek.com"
BASE_URL_SHA256 = "a34e2a4708ed1c61008a151688838dcf1c44d4e7f08054633e72ba7c0b16cfc1"
MODEL = "deepseek-v4-pro"
MODEL_SHA256 = "052e4fc0bc88e2a5376eb7461a1ec3686311e42a1f2219ebf9beeac1414e252e"
PROVIDER_EXTRA_BODY = {"thinking": {"type": "disabled"}}
PROBE_MESSAGES = [
    {
        "role": "system",
        "content": "Return exactly OK.",
    },
    {
        "role": "user",
        "content": "Provider connectivity preflight.",
    }
]
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

WORKFLOWS = {
    "verilogcoder": {
        "source_root": "/opt/workflow",
        "snapshot_manifest": "/opt/source_snapshot.json",
        "commit": "8b13108869f276c7b644dd88beabcb401a5cfa92",
        "tracked_manifest_sha256": "01ac57a9e5bdb79d12055554fc5646d2b6451602f982377f48f35505d2328d69",
        "image_digest": "sha256:702a5aebe52854489199657e076eb974425688119dc65bd163616601a6b25a81",
    },
    "hdlagent": {
        "source_root": "/opt/workflow",
        "snapshot_manifest": "/opt/source_snapshot.json",
        "commit": "bd2321e03d1d60b0656d7ff0992f35f5906a824d",
        "tracked_manifest_sha256": "843ccf62106d6ae2e953f5d5b5a8fd7ea4160c969084d010acc59d4e7ba6d91f",
        "image_digest": "sha256:20d317045a6ed61a7eca1ef206bf66aa03f6988ea062e455b50f15e29deb5afc",
    },
}


class ProbeFailure(Exception):
    def __init__(self, original: BaseException, provider_calls: int):
        super().__init__(type(original).__name__)
        self.original = original
        self.provider_calls = provider_calls


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _error_summary(error: BaseException) -> dict[str, Any]:
    status_code = getattr(error, "status_code", None)
    code = getattr(error, "code", None)
    if not isinstance(status_code, int):
        response = getattr(error, "response", None)
        status_code = getattr(response, "status_code", None)
    if not isinstance(status_code, int):
        status_code = None
    if not isinstance(code, str) or len(code) > 80:
        code = None
    if status_code in {401, 403}:
        classification = "authentication_or_authorization"
    elif status_code == 402:
        classification = "insufficient_balance_or_quota"
    elif status_code == 404:
        classification = "model_or_endpoint_not_found"
    elif status_code == 429:
        classification = "rate_limited"
    elif status_code is not None and status_code >= 500:
        classification = "provider_server_error"
    elif status_code is None:
        classification = "transport_or_client_error"
    else:
        classification = "provider_request_error"
    return {
        "exception_class": type(error).__name__,
        "http_status": status_code,
        "provider_error_code": code,
        "classification": classification,
        "exception_message_recorded": False,
    }


def _usage(response: Any) -> dict[str, Any]:
    usage = getattr(response, "usage", None)
    result: dict[str, Any] = {
        "input_tokens": None,
        "output_tokens": None,
        "total_tokens": None,
        "accounting_status": "not_available",
    }
    if usage is None:
        return result
    values = {
        "input_tokens": getattr(usage, "prompt_tokens", None),
        "output_tokens": getattr(usage, "completion_tokens", None),
        "total_tokens": getattr(usage, "total_tokens", None),
    }
    if all(isinstance(value, int) and value >= 0 for value in values.values()):
        result.update(values)
        result["accounting_status"] = "provider_reported"
    return result


def _response_summary(response: Any) -> dict[str, Any]:
    choices = getattr(response, "choices", None)
    content = None
    finish_reason = None
    if isinstance(choices, list) and choices:
        choice = choices[0]
        finish_reason = getattr(choice, "finish_reason", None)
        message = getattr(choice, "message", None)
        content = getattr(message, "content", None)
    if not isinstance(content, str) or not content.strip():
        raise ValueError("provider response has no non-empty text choice")
    if content.strip() != "OK":
        raise ValueError("provider response did not satisfy the probe protocol")
    returned_model = getattr(response, "model", None)
    return {
        "choice_count": len(choices),
        "nonempty_text_choice": True,
        "finish_reason": finish_reason if isinstance(finish_reason, str) else None,
        "returned_model_sha256": (
            _sha256_text(returned_model) if isinstance(returned_model, str) else None
        ),
        "response_text_recorded": False,
        "response_text_sha256_recorded": False,
        "raw_response_recorded": False,
        "probe_protocol_satisfied": True,
        "usage": _usage(response),
    }


def _verilogcoder_preflight(api_key: str) -> tuple[dict[str, Any], int]:
    from autogen import OpenAIWrapper

    client = OpenAIWrapper(
        config_list=[
            {
                "model": MODEL,
                "api_key": api_key,
                "base_url": BASE_URL,
                "cache_seed": None,
                "temperature": 0.0,
                "max_retries": 0,
            }
        ]
    )
    try:
        response = client.create(
            messages=PROBE_MESSAGES,
            temperature=0.0,
            max_tokens=4,
            stream=False,
            cache_seed=None,
            extra_body=PROVIDER_EXTRA_BODY,
        )
        response_summary = _response_summary(response)
    except BaseException as exc:
        raise ProbeFailure(exc, 1) from exc
    return {
        "native_client": "autogen.OpenAIWrapper",
        "native_model_listing_checked": False,
        **response_summary,
    }, 1


def _hdlagent_preflight(api_key: str) -> tuple[dict[str, Any], int]:
    os.environ["OPENAI_API_KEY"] = api_key
    os.environ["OPENAI_BASE_URL"] = BASE_URL
    sys.path.insert(0, "/opt/workflow/hdlagent")
    import openai
    from openai import OpenAI
    from agent import Agent

    # HDLAgent's model listing uses the module-level OpenAI client.  Disable
    # SDK retries there and replace the constructed completion client with an
    # equally non-retrying client so provider_calls is an HTTP-attempt count.
    openai.api_key = api_key
    openai.base_url = BASE_URL
    openai.max_retries = 0

    try:
        # Agent construction performs HDLAgent's native /models membership
        # check exactly once.  Do not pre-enumerate and double the request.
        agent = Agent(
            "/opt/workflow/hdlagent/resources",
            MODEL,
            "Verilog",
            [],
            False,
            True,
        )
    except BaseException as exc:
        raise ProbeFailure(exc, 1) from exc
    agent.client = OpenAI(api_key=api_key, base_url=BASE_URL, max_retries=0)
    try:
        response = agent.client.chat.completions.create(
            model=MODEL,
            messages=PROBE_MESSAGES,
            temperature=0.0,
            max_tokens=4,
            stream=False,
            extra_body=PROVIDER_EXTRA_BODY,
        )
        response_summary = _response_summary(response)
    except BaseException as exc:
        raise ProbeFailure(exc, 2) from exc
    return {
        "native_client": "hdlagent.Agent.openai_client",
        "native_model_listing_checked": True,
        "native_model_listing_contains_bound_model": True,
        **response_summary,
    }, 2


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workflow", choices=sorted(WORKFLOWS), required=True)
    parser.add_argument("--observed-at", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-image-digest", required=True)
    args = parser.parse_args()
    if args.output.exists() or args.output.is_symlink():
        raise FileExistsError("refusing to overwrite provider preflight receipt")
    spec = WORKFLOWS[args.workflow]
    if args.expected_image_digest != spec["image_digest"]:
        raise ValueError("runtime image digest binding drift")
    if _sha256_text(BASE_URL) != BASE_URL_SHA256:
        raise ValueError("provider base URL hash binding drift")
    if _sha256_text(MODEL) != MODEL_SHA256:
        raise ValueError("provider model hash binding drift")
    api_key = os.environ.get(CREDENTIAL_ENV)
    if not api_key:
        raise ValueError(f"{CREDENTIAL_ENV} is unavailable")
    bind_source(
        Path(spec["source_root"]),
        expected_commit=spec["commit"],
        expected_manifest_sha256=spec["tracked_manifest_sha256"],
        snapshot_manifest=Path(spec["snapshot_manifest"]),
    )
    status = "pass"
    response: dict[str, Any] | None = None
    error: dict[str, Any] | None = None
    provider_calls = 0
    try:
        if args.workflow == "verilogcoder":
            response, provider_calls = _verilogcoder_preflight(api_key)
        else:
            response, provider_calls = _hdlagent_preflight(api_key)
    except ProbeFailure as exc:
        status = "infra"
        provider_calls = exc.provider_calls
        error = _error_summary(exc.original)
    except BaseException as exc:
        status = "infra"
        error = _error_summary(exc)
    receipt = {
        "schema_version": "rtlflowbench.external_provider_preflight.v1",
        "status": status,
        "observed_at": args.observed_at,
        "workflow": args.workflow,
        "runtime_image_digest": spec["image_digest"],
        "source_binding": {
            "commit": spec["commit"],
            "tracked_manifest_sha256": spec["tracked_manifest_sha256"],
            "status": "pass",
        },
        "provider_binding": {
            "provider": PROVIDER,
            "base_url_sha256": BASE_URL_SHA256,
            "model": MODEL,
            "model_sha256": MODEL_SHA256,
            "thinking_mode": "disabled",
            "temperature": 0.0,
            "maximum_response_tokens": 4,
            "credential_present": True,
            "credential_value_recorded": False,
        },
        "probe": {
            "kind": "provider_compatibility_probe_no_benchmark_content",
            "benchmark_public_input_present": False,
            "benchmark_private_input_present": False,
            "eda_invoked": False,
            "provider_calls": provider_calls,
            "response": response,
            "error": error,
        },
        "claims": {
            "provider_preflight_passed": status == "pass",
            "airtl_run_observed": False,
            "benchmark_attempt_consumed": False,
            "hidden_evaluator_run": False,
            "rtl_verdict_produced": False,
            "adapter_ready": False,
            "benchmark_ready": False,
        },
        "excluded_claims": [
            "A provider compatibility preflight is not an AIRTL workflow run.",
            "No task packet, RTL submission, EDA result, benchmark verdict or readiness is produced.",
            "No raw provider response, response text, API key, credential hash or user identifier is recorded.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(
        json.dumps(
            {
                "status": status,
                "workflow": args.workflow,
                "provider_calls": provider_calls,
                "error_classification": error["classification"] if error else None,
            },
            sort_keys=True,
        )
    )
    return 0 if status == "pass" else 2


if __name__ == "__main__":
    raise SystemExit(main())
