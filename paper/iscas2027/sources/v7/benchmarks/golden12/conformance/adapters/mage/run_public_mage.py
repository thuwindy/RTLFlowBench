#!/usr/bin/env python3
"""Run audited MAGE on one public Spec-to-RTL packet.

The process is a development-only external control plane. It receives the
complete public packet, never receives a golden testbench/reference RTL/private
evaluator, and writes a content-bound run receipt. MAGE's internal test result
is not accepted as an RTLFlowBench verdict.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import time
from typing import Any

from jsonschema import Draft202012Validator


MAGE_COMMIT = "90c96366c518d32bd7b81703bdef3cc46eeaeaf9"
MAGE_LICENSE_SHA256 = (
    "aa5a4458be46e4e17ac0a5d0da13213cc1058bbcaaa53377852e448078b80091"
)
OPENAI_LIKE_BRIDGE = "llama-index-llms-openai-like@0.7.2"
TOKENIZER_MAPPING = "o200k_base"
API_BASE = "https://openrouter.ai/api/v1"
SUPPORTED_TASK_IDS = {
    "G01-common-fifo-spec",
    "G02-common-rr-arbiter-spec",
}
RECEIPT_SCHEMA = Path(__file__).with_name("mage_run_receipt.schema.json")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _canonical_sha256(value: dict[str, Any]) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return _sha256_bytes(encoded)


def _load(path: Path, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a regular non-symlink file")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise TypeError(f"{label} must contain one JSON object")
    return value


def public_tree_manifest(public_root: Path) -> list[dict[str, Any]]:
    if public_root.is_symlink() or not public_root.is_dir():
        raise ValueError("public root must be a regular non-symlink directory")
    entries = []
    for path in sorted(public_root.rglob("*")):
        relative = path.relative_to(public_root).as_posix()
        if path.is_symlink():
            raise ValueError(f"public root contains symlink: {relative}")
        if not path.is_file():
            continue
        content = path.read_bytes()
        if b"\x00" in content:
            raise ValueError(f"public packet contains non-text file: {relative}")
        try:
            content.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError(
                f"public packet contains non-UTF-8 file: {relative}"
            ) from exc
        entries.append(
            {
                "path": relative,
                "bytes": len(content),
                "sha256": _sha256_bytes(content),
            }
        )
    return entries


def public_tree_sha256(public_root: Path) -> str:
    return _sha256_bytes(
        json.dumps(
            public_tree_manifest(public_root),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )


def compose_public_prompt(
    *,
    task: dict[str, Any],
    public_root: Path,
    maximum_bytes: int = 1_048_576,
) -> str:
    manifest = public_tree_manifest(public_root)
    total = sum(item["bytes"] for item in manifest)
    if total > maximum_bytes:
        raise ValueError("public packet exceeds MAGE prompt byte limit")
    sections = [
        "RTLFlowBench public-only task packet.",
        f"Task id: {task['task_id']}",
        "Use only the public files below. Do not assume a hidden testbench, reference RTL, or private oracle.",
        "Return the requested synthesizable SystemVerilog module; RTLFlowBench will evaluate it offline.",
    ]
    for item in manifest:
        relative = item["path"]
        content = (public_root / relative).read_text(encoding="utf-8")
        sections.extend(
            [
                f"\n<public-file path={json.dumps(relative)}>",
                content,
                "</public-file>",
            ]
        )
    return "\n".join(sections)


def _write_new_json(path: Path, value: dict[str, Any]) -> None:
    if path.exists() or path.is_symlink():
        raise FileExistsError(f"refusing to overwrite output: {path}")
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    path.chmod(0o600)


def _usage(
    *,
    llm_calls: int,
    observed_inputs: list[int],
    observed_outputs: list[int],
    eda_calls: dict[str, int],
    wall_time_seconds: float,
) -> tuple[dict[str, Any], dict[str, Any]]:
    complete = (
        llm_calls == len(observed_inputs) == len(observed_outputs)
    )
    input_tokens = sum(observed_inputs) if complete else None
    output_tokens = sum(observed_outputs) if complete else None
    missing = []
    if input_tokens is None:
        missing.append("input_tokens")
    if output_tokens is None:
        missing.append("output_tokens")
    if complete:
        measurement_status = "complete"
    elif observed_inputs or observed_outputs:
        measurement_status = "partial"
    else:
        measurement_status = "not_available"
    resource = {
        "wall_time_seconds": round(wall_time_seconds, 6),
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "llm_calls": llm_calls,
        "eda_calls": eda_calls,
        "human_interventions": 0,
        "missing_measurements": missing,
    }
    accounting = {
        "measurement_status": measurement_status,
        "observed_input_tokens": (
            sum(observed_inputs) if observed_inputs else None
        ),
        "observed_output_tokens": (
            sum(observed_outputs) if observed_outputs else None
        ),
        "input_token_observed_call_count": len(observed_inputs),
        "output_token_observed_call_count": len(observed_outputs),
        "token_usage_unobserved_call_count": max(
            llm_calls - min(len(observed_inputs), len(observed_outputs)),
            0,
        ),
    }
    return resource, accounting


def run_public_mage(
    *,
    task_path: Path,
    output_root: Path,
    receipt_path: Path,
    model: str,
    mode: str,
    attempt: dict[str, Any],
    max_tokens: int,
    temperature: float,
    top_p: float,
) -> dict[str, Any]:
    task_path = task_path.expanduser().resolve(strict=True)
    public_root = task_path.parent
    if task_path != public_root / "external_task.json":
        raise ValueError("task descriptor must be public_root/external_task.json")
    task = _load(task_path, "task descriptor")
    if task.get("task_id") not in SUPPORTED_TASK_IDS:
        raise ValueError("MAGE public runner supports only G01/G02")
    if task.get("family") != "spec_to_rtl":
        raise ValueError("MAGE public runner requires a Spec-to-RTL task")
    if task.get("benchmark_version") != "development":
        raise ValueError("this MAGE runner is development-only")
    if output_root.exists() or output_root.is_symlink():
        raise FileExistsError("refusing to overwrite MAGE output root")
    if receipt_path.exists() or receipt_path.is_symlink():
        raise FileExistsError("refusing to overwrite MAGE run receipt")
    if mode not in {
        "development_ablation_syntax_only",
        "full_multi_agent",
    }:
        raise ValueError("unsupported MAGE execution mode")
    api_key = os.environ.get("OPENROUTER_API_KEY")
    if not api_key:
        raise ValueError("OPENROUTER_API_KEY is required")

    prompt = compose_public_prompt(task=task, public_root=public_root)
    tree_digest = public_tree_sha256(public_root)
    config = {
        "source_commit": MAGE_COMMIT,
        "model": model,
        "mode": mode,
        "max_tokens": max_tokens,
        "temperature": temperature,
        "top_p": top_p,
        "api_base_sha256": _sha256_bytes(API_BASE.encode("utf-8")),
        "openai_like_bridge": OPENAI_LIKE_BRIDGE,
        "tokenizer_mapping": TOKENIZER_MAPPING,
        "public_tree_sha256": tree_digest,
    }
    output_root.mkdir(parents=True, exist_ok=False)
    output_root.chmod(0o700)
    started = time.monotonic()
    eda_calls = {
        "compile_or_lint": 0,
        "simulation": 0,
        "formal": 0,
        "synthesis": 0,
    }
    llm_calls = 0
    observed_inputs: list[int] = []
    observed_outputs: list[int] = []
    status = "control_plane_error"
    failure: dict[str, Any] | None = None
    output: dict[str, Any] | None = None
    internal_message = ""

    try:
        import tiktoken.model
        from llama_index.llms.openai_like import OpenAILike
        from mage.agent import TopAgent
        from mage.gen_config import set_exp_setting
        import mage.sim_reviewer as mage_sim_reviewer
        from pydantic import PrivateAttr

        class CountingOpenAILike(OpenAILike):
            _rtlflow_call_count: int = PrivateAttr(default=0)
            _rtlflow_inputs: list[int] = PrivateAttr(default_factory=list)
            _rtlflow_outputs: list[int] = PrivateAttr(default_factory=list)

            def _capture(self, response: Any) -> None:
                usage = getattr(getattr(response, "raw", None), "usage", None)
                input_count = getattr(usage, "prompt_tokens", None)
                output_count = getattr(usage, "completion_tokens", None)
                if isinstance(input_count, int):
                    self._rtlflow_inputs.append(input_count)
                if isinstance(output_count, int):
                    self._rtlflow_outputs.append(output_count)

            def chat(self, *args: Any, **kwargs: Any):
                self._rtlflow_call_count += 1
                response = super().chat(*args, **kwargs)
                self._capture(response)
                return response

            async def achat(self, *args: Any, **kwargs: Any):
                self._rtlflow_call_count += 1
                response = await super().achat(*args, **kwargs)
                self._capture(response)
                return response

        original_run_bash = mage_sim_reviewer.run_bash_command

        def counted_run_bash(command: str, timeout: float | None = None):
            if "iverilog -t null" in command:
                eda_calls["compile_or_lint"] += 1
            elif "iverilog" in command:
                eda_calls["compile_or_lint"] += 1
                if "vvp" in command:
                    eda_calls["simulation"] += 1
            return original_run_bash(command, timeout=timeout)

        mage_sim_reviewer.run_bash_command = counted_run_bash
        tiktoken.model.MODEL_TO_ENCODING[model] = TOKENIZER_MAPPING
        llm = CountingOpenAILike(
            model=model,
            api_key=api_key,
            api_base=API_BASE,
            context_window=131072,
            is_chat_model=True,
            is_function_calling_model=False,
            max_tokens=max_tokens,
            temperature=temperature,
            max_retries=2,
            timeout=120.0,
        )
        set_exp_setting(temperature=temperature, top_p=top_p)
        agent = TopAgent(llm)
        agent.set_ablation(mode == "development_ablation_syntax_only")
        agent.set_output_path(str(output_root / "mage-output"))
        agent.set_log_path(str(output_root / "mage-logs"))
        agent.set_redirect_log(True)
        _, internal_message = agent.run(
            benchmark_type_name="RTLFlowBench",
            task_id=task["task_id"][:3],
            spec=prompt,
            golden_tb_path=None,
            golden_rtl_blackbox_path=None,
        )
        llm_calls = llm._rtlflow_call_count
        observed_inputs = list(llm._rtlflow_inputs)
        observed_outputs = list(llm._rtlflow_outputs)
        produced = (
            output_root
            / "mage-output"
            / f"RTLFlowBench_{task['task_id'][:3]}"
            / "rtl.sv"
        )
        if produced.is_symlink() or not produced.is_file():
            status = "workflow_failure_no_output"
            failure = {
                "classification": status,
                "exception_class": None,
                "message_sha256": _sha256_bytes(
                    str(internal_message).encode("utf-8")
                ),
            }
        else:
            target = output_root / "rtl.sv"
            shutil.copyfile(produced, target)
            target.chmod(0o600)
            if target.stat().st_size == 0:
                target.unlink()
                status = "workflow_failure_no_output"
                failure = {
                    "classification": status,
                    "exception_class": None,
                    "message_sha256": _sha256_bytes(
                        b"MAGE produced an empty rtl.sv"
                    ),
                }
            else:
                status = "completed_public_only_not_evaluated"
                output = {
                    "relative_path": "rtl.sv",
                    "sha256": _sha256(target),
                    "bytes": target.stat().st_size,
                }
    except Exception as exc:
        status = "control_plane_error"
        failure = {
            "classification": status,
            "exception_class": type(exc).__name__,
            "message_sha256": _sha256_bytes(str(exc).encode("utf-8")),
        }

    resource, token_accounting = _usage(
        llm_calls=llm_calls,
        observed_inputs=observed_inputs,
        observed_outputs=observed_outputs,
        eda_calls=eda_calls,
        wall_time_seconds=time.monotonic() - started,
    )
    receipt = {
        "schema_version": "rtlflowbench.mage_run_receipt.v1",
        "status": status,
        "task_id": task["task_id"],
        "task_descriptor_sha256": _canonical_sha256(task),
        "public_tree_sha256": tree_digest,
        "source": {
            "upstream_url": "https://github.com/stable-lab/MAGE.git",
            "commit": MAGE_COMMIT,
            "license_sha256": MAGE_LICENSE_SHA256,
        },
        "mode": mode,
        "runtime_extensions": {
            "openai_like_bridge": OPENAI_LIKE_BRIDGE,
            "tokenizer_mapping": TOKENIZER_MAPPING,
        },
        "input_policy": {
            "public_packet_only": True,
            "golden_testbench_supplied": False,
            "golden_reference_rtl_supplied": False,
            "private_evaluator_exposed": False,
        },
        "execution_policy": {
            "use_golden_tb_in_mage": False,
            "provider_traffic_outside_workspace": True,
            "workspace_network_access_observed": False,
        },
        "workflow": {
            "model": {"provider": "openrouter", "name": model},
            "config_sha256": _canonical_sha256(config),
        },
        "attempt": attempt,
        "resource_usage": resource,
        "token_accounting": token_accounting,
        "output": output,
        "failure": failure,
        "private_evaluator_run": False,
        "benchmark_ready": False,
        "publication_permitted": False,
    }
    schema = _load(RECEIPT_SCHEMA, "MAGE receipt schema")
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(receipt)
    _write_new_json(receipt_path, receipt)
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--task", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument(
        "--mode",
        choices=["development_ablation_syntax_only", "full_multi_agent"],
        required=True,
    )
    parser.add_argument("--attempt-id", required=True)
    parser.add_argument("--attempt-index", type=int, default=1)
    parser.add_argument("--repeat-group-id", required=True)
    parser.add_argument("--seed", type=int)
    parser.add_argument("--max-tokens", type=int, default=8192)
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--top-p", type=float, default=1.0)
    args = parser.parse_args()
    receipt = run_public_mage(
        task_path=args.task,
        output_root=args.output_root,
        receipt_path=args.receipt,
        model=args.model,
        mode=args.mode,
        attempt={
            "attempt_id": args.attempt_id,
            "attempt_index": args.attempt_index,
            "repeat_group_id": args.repeat_group_id,
            "seed": args.seed,
        },
        max_tokens=args.max_tokens,
        temperature=args.temperature,
        top_p=args.top_p,
    )
    print(
        json.dumps(
            {
                "status": receipt["status"],
                "task_id": receipt["task_id"],
                "private_evaluator_run": False,
                "benchmark_ready": False,
            },
            sort_keys=True,
        )
    )
    return 0 if receipt["status"] == "completed_public_only_not_evaluated" else 2


if __name__ == "__main__":
    raise SystemExit(main())
