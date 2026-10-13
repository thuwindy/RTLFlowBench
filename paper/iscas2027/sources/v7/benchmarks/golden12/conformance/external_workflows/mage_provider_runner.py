#!/usr/bin/env python3
"""Run pinned MAGE against one public-only bridge request.

This provider-side runner never receives a private evaluator, golden RTL, or
golden testbench.  MAGE's self-generated testbench result is recorded only as an
internal workflow signal and is never projected as a benchmark verdict.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import time
from typing import Any, Callable


REQUEST_SCHEMA_VERSION = "rtlflowbench.mage_bridge_request.v1"
RESULT_SCHEMA_VERSION = "rtlflowbench.mage_provider_run.v1"
TASK_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
FORBIDDEN_PARTS = {"evaluator", "golden", "hidden", "oracle", "private", "reference"}
COMPAT_PATH = Path("/usr/local/libexec/rtlflowbench/mage_openai_compat.py")
BENCHMARK_TYPE_NAME = "GOLDEN12_PUBLIC_SPEC"


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _safe_relative(value: str, *, label: str) -> Path:
    if not isinstance(value, str) or not value or any(ch in value for ch in "\x00\r\n"):
        raise ValueError(f"{label} is empty or contains control characters")
    pure = PurePosixPath(value)
    if pure.is_absolute() or ".." in pure.parts:
        raise ValueError(f"{label} escapes its public root")
    if any(part.casefold() in FORBIDDEN_PARTS for part in pure.parts):
        raise ValueError(f"{label} contains a forbidden path component")
    return Path(*pure.parts)


def _regular_root(path: Path, *, label: str) -> Path:
    unresolved = path.expanduser().absolute()
    if unresolved.is_symlink():
        raise ValueError(f"{label} cannot be a symlink")
    resolved = unresolved.resolve(strict=True)
    if not resolved.is_dir():
        raise ValueError(f"{label} must be a directory")
    return resolved


def _regular_file(root: Path, relative: Path, *, label: str) -> Path:
    path = root / relative
    resolved = path.resolve(strict=True)
    if root not in resolved.parents or path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a regular in-root file")
    return path


def load_public_request(request_root: Path) -> tuple[dict[str, Any], str, Path]:
    root = _regular_root(request_root, label="request root")
    if any(part.casefold() in FORBIDDEN_PARTS for part in root.parts[-2:]):
        raise ValueError("request root uses a forbidden path component")
    request_path = _regular_file(root, Path("mage_request.json"), label="request")
    request = json.loads(request_path.read_text(encoding="utf-8"))
    if not isinstance(request, dict) or request.get("schema_version") != REQUEST_SCHEMA_VERSION:
        raise ValueError("request schema version is invalid")
    if request.get("mode") not in {"development", "release"}:
        raise ValueError("request mode is invalid")
    expected_status = {
        "development": "development_only_not_run",
        "release": "release_request_prepared_not_run",
    }[request["mode"]]
    if request.get("status") != expected_status:
        raise ValueError("request status is invalid")
    task_id = request.get("task_id")
    if not isinstance(task_id, str) or not TASK_RE.fullmatch(task_id):
        raise ValueError("task id is invalid")
    if not SHA256_RE.fullmatch(request.get("configuration_sha256", "")):
        raise ValueError("request configuration binding is invalid")
    top_agent = request.get("mage", {}).get("top_agent")
    if not isinstance(top_agent, dict) or top_agent != {
        "golden_tb_path": None,
        "golden_rtl_blackbox_path": None,
        "expected_output_file": "rtl.sv",
    }:
        raise ValueError("request attempts to alter the reviewed MAGE boundary")
    for field in (
        "airtl_run_observed",
        "rtl_verdict_produced",
        "adapter_ready",
        "benchmark_ready",
    ):
        if request.get(field) is not False:
            raise ValueError("request contains a pre-existing success claim")

    prompt = request.get("prompt")
    if not isinstance(prompt, dict):
        raise ValueError("request prompt binding is missing")
    prompt_relative = _safe_relative(prompt.get("path"), label="prompt path")
    prompt_path = _regular_file(root, prompt_relative, label="public prompt")
    prompt_bytes = prompt_path.read_bytes()
    if len(prompt_bytes) > 1_048_576:
        raise ValueError("public prompt exceeds the reviewed byte limit")
    if prompt.get("bytes") != len(prompt_bytes) or prompt.get("sha256") != _sha256_bytes(
        prompt_bytes
    ):
        raise ValueError("public prompt binding drift")
    prompt_text = prompt_bytes.decode("utf-8")
    return request, prompt_text, request_path


def _load_compat(path: Path = COMPAT_PATH):
    spec = importlib.util.spec_from_file_location("rtlflowbench_mage_openai_compat", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("MAGE compatibility layer is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _write_new_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(payload, stream, indent=2, sort_keys=True)
        stream.write("\n")


def run_provider(
    *,
    request_root: Path,
    workspace_root: Path,
    result_path: Path,
    observed_at: str,
    model: str,
    context_window: int,
    max_tokens: int,
    max_retries: int,
    timeout_seconds: float,
    thinking_mode: str,
    sim_max_retry: int,
    rtl_max_candidates: int,
    rtl_selected_candidates: int,
    compat_loader: Callable[[], Any] = _load_compat,
    top_agent_class: Any | None = None,
) -> dict[str, Any]:
    request, prompt_text, request_path = load_public_request(request_root)
    workspace = _regular_root(workspace_root, label="workspace root")
    if any(workspace.iterdir()):
        raise ValueError("workspace root must be empty before the provider run")
    if Path.cwd().resolve() != workspace:
        raise ValueError("provider cwd must equal the isolated workspace root")
    if result_path.exists() or result_path.is_symlink():
        raise FileExistsError("result path already exists")
    if not 1 <= sim_max_retry <= 10:
        raise ValueError("sim_max_retry is outside the reviewed bounds")
    if not 1 <= rtl_max_candidates <= 20:
        raise ValueError("rtl_max_candidates is outside the reviewed bounds")
    if not 1 <= rtl_selected_candidates <= rtl_max_candidates:
        raise ValueError("rtl_selected_candidates is outside the reviewed bounds")
    for name in (
        "OPENAI_API_KEY",
        "OPENAI_API_BASE",
        "RTLFLOWBENCH_MAGE_EDA_SOCKET",
        "RTLFLOWBENCH_MAGE_EDA_SESSION_ID",
        "RTLFLOWBENCH_MAGE_EDA_CONTROL_ROOT",
    ):
        if not os.environ.get(name):
            raise ValueError(f"required runtime setting is absent: {name}")
    if Path(os.environ["RTLFLOWBENCH_MAGE_EDA_CONTROL_ROOT"]).resolve() != workspace:
        raise ValueError("EDA control root disagrees with the provider workspace")

    compat = compat_loader()
    llm, binding = compat.build_mage_openai_compatible_llm(
        model=model,
        context_window=context_window,
        max_tokens=max_tokens,
        max_retries=max_retries,
        timeout_seconds=timeout_seconds,
        thinking_mode=None if thinking_mode == "default" else thinking_mode,
        cfg_path=None,
    )
    if top_agent_class is None:
        from mage.agent import TopAgent

        top_agent_class = TopAgent
    agent = top_agent_class(llm)
    agent.sim_max_retry = sim_max_retry
    agent.rtl_max_candidates = rtl_max_candidates
    agent.rtl_selected_candidates = rtl_selected_candidates
    agent.set_output_path("output")
    agent.set_log_path("log")
    agent.set_redirect_log(False)
    started = time.monotonic()
    internal_pass, opaque_result = agent.run(
        benchmark_type_name=BENCHMARK_TYPE_NAME,
        task_id=request["task_id"],
        spec=prompt_text,
        golden_tb_path=None,
        golden_rtl_blackbox_path=None,
    )
    del opaque_result
    elapsed = time.monotonic() - started
    llm_calls = binding["provider_preflight_llm_calls"] + llm.observed_call_count
    run_relative = Path("output") / f"{BENCHMARK_TYPE_NAME}_{request['task_id']}"
    rtl_path = workspace / run_relative / "rtl.sv"
    output = None
    if rtl_path.exists() and rtl_path.is_file() and not rtl_path.is_symlink():
        output = {
            "relative_path": (run_relative / "rtl.sv").as_posix(),
            "sha256": _sha256(rtl_path),
            "bytes": rtl_path.stat().st_size,
        }
    result = {
        "schema_version": RESULT_SCHEMA_VERSION,
        "observed_at": observed_at,
        "status": "completed_output_observed" if output is not None else "completed_without_output",
        "mode": request["mode"],
        "task_id": request["task_id"],
        "request_sha256": _sha256(request_path),
        "configuration_sha256": request["configuration_sha256"],
        "runtime": {
            "model": model,
            "context_window": context_window,
            "max_tokens_per_call": max_tokens,
            "max_retries": max_retries,
            "timeout_seconds_per_call": float(timeout_seconds),
            "thinking_mode": thinking_mode,
            "sim_max_retry": sim_max_retry,
            "rtl_max_candidates": rtl_max_candidates,
            "rtl_selected_candidates": rtl_selected_candidates,
            "llm_calls": llm_calls,
            "input_tokens": None,
            "output_tokens": None,
            "token_accounting": binding["token_accounting"],
            "wall_time_seconds": elapsed,
        },
        "binding_receipt": binding,
        "output": output,
        "mage_internal_self_test_pass": bool(internal_pass),
        "mage_internal_self_test_is_benchmark_verdict": False,
        "provider_call_observed": True,
        "airtl_run_observed": True,
        "eda_broker_configured": True,
        "private_evaluator_mounted": False,
        "private_evaluator_executed": False,
        "raw_provider_response_recorded": False,
        "rtl_verdict_produced": False,
        "adapter_ready": False,
        "benchmark_ready": False,
        "excluded_claims": [
            "MAGE's generated testbench is not the RTLFlowBench private evaluator.",
            "An observed rtl.sv is not a benchmark PASS or score.",
            "Provider-native token usage is unavailable and is not represented as zero.",
        ],
    }
    _write_new_json(result_path, result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--request-root", type=Path, required=True)
    parser.add_argument("--workspace-root", type=Path, required=True)
    parser.add_argument("--result", type=Path, required=True)
    parser.add_argument("--observed-at", required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--context-window", type=int, required=True)
    parser.add_argument("--max-tokens", type=int, required=True)
    parser.add_argument("--max-retries", type=int, required=True)
    parser.add_argument("--timeout-seconds", type=float, required=True)
    parser.add_argument(
        "--thinking-mode", choices=("default", "disabled"), required=True
    )
    parser.add_argument("--sim-max-retry", type=int, required=True)
    parser.add_argument("--rtl-max-candidates", type=int, required=True)
    parser.add_argument("--rtl-selected-candidates", type=int, required=True)
    args = parser.parse_args()
    try:
        result = run_provider(
            request_root=args.request_root,
            workspace_root=args.workspace_root,
            result_path=args.result,
            observed_at=args.observed_at,
            model=args.model,
            context_window=args.context_window,
            max_tokens=args.max_tokens,
            max_retries=args.max_retries,
            timeout_seconds=args.timeout_seconds,
            thinking_mode=args.thinking_mode,
            sim_max_retry=args.sim_max_retry,
            rtl_max_candidates=args.rtl_max_candidates,
            rtl_selected_candidates=args.rtl_selected_candidates,
        )
    except BaseException as exc:
        print(
            json.dumps(
                {
                    "status": "infra_or_adapter_fail",
                    "exception_type": type(exc).__name__,
                    "raw_exception_text_recorded": False,
                    "benchmark_verdict_produced": False,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 2
    print(
        json.dumps(
            {
                "status": result["status"],
                "airtl_run_observed": result["airtl_run_observed"],
                "output_observed": result["output"] is not None,
                "benchmark_verdict_produced": False,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if result["output"] is not None else 2


if __name__ == "__main__":
    raise SystemExit(main())
