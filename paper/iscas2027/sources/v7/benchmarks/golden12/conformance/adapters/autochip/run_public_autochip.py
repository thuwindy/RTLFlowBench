#!/usr/bin/env python3
"""Run the audited AutoChip revision against one public Golden-12 packet.

This is a development-pilot runner.  It exposes only the public packet and the
public visible testbench to AutoChip.  It never imports or invokes a private
evaluator, and it never treats AutoChip's internal visible-test rank as a
benchmark verdict.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import time
import types
from typing import Any
import re

from jsonschema import Draft202012Validator


AUTOCHIP_COMMIT = "3abe0b606d8819dfe548661b0245b55a1ebab40b"
AUTOCHIP_LICENSE_SHA256 = (
    "c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4"
)
API_BASE = "https://openrouter.ai/api/v1"
SUPPORTED_TASK_IDS = {"G01-common-fifo-spec"}
RECEIPT_SCHEMA = Path(__file__).with_name("autochip_run_receipt.schema.json")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _canonical_sha256(value: dict[str, Any]) -> str:
    return _sha256_bytes(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )


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
    entries: list[dict[str, Any]] = []
    for path in sorted(public_root.rglob("*")):
        relative = path.relative_to(public_root).as_posix()
        if path.is_symlink():
            raise ValueError(f"public root contains symlink: {relative}")
        if not path.is_file():
            continue
        content = path.read_bytes()
        if b"\x00" in content:
            raise ValueError(f"public packet contains non-text file: {relative}")
        content.decode("utf-8")
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
    if sum(item["bytes"] for item in manifest) > maximum_bytes:
        raise ValueError("public packet exceeds AutoChip prompt byte limit")
    sections = [
        "RTLFlowBench public-only task packet.",
        f"Task id: {task['task_id']}",
        "Use only the public files below. Do not assume a hidden testbench, reference RTL, or private oracle.",
        "Return the requested synthesizable SystemVerilog module. Offline evaluation is outside AutoChip.",
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


def balanced_module_parser(response_text: str) -> list[str]:
    """Extract complete modules without assuming flat ANSI port syntax.

    AutoChip's upstream regular expression stops at nested parentheses in a
    module header (for example ``$clog2(...)``).  This compatibility bridge
    keeps the workflow's module-to-endmodule contract but searches fenced code
    blocks first and does not parse or alter module contents.
    """

    fenced = re.findall(
        r"```(?:systemverilog|verilog|sv)?\s*(.*?)```",
        response_text,
        flags=re.IGNORECASE | re.DOTALL,
    )
    sources = fenced or [response_text]
    modules: list[str] = []
    for source in sources:
        cursor = 0
        while True:
            start = re.search(
                r"\bmodule\b\s+[A-Za-z_][A-Za-z0-9_$]*",
                source[cursor:],
            )
            if start is None:
                break
            absolute_start = cursor + start.start()
            end = re.search(r"\bendmodule\b", source[absolute_start:])
            if end is None:
                break
            absolute_end = absolute_start + end.end()
            modules.append(source[absolute_start:absolute_end])
            cursor = absolute_end
    return modules


def _write_new_json(path: Path, value: dict[str, Any]) -> None:
    if path.exists() or path.is_symlink():
        raise FileExistsError(f"refusing to overwrite output: {path}")
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    path.chmod(0o600)


def _install_unused_optional_provider_stubs() -> None:
    """Stub only providers that the selected ChatGPT path never invokes."""

    if "google.generativeai" not in sys.modules:
        try:
            __import__("google.generativeai")
        except ModuleNotFoundError:
            google_module = sys.modules.get("google")
            if google_module is None:
                google_module = types.ModuleType("google")
                google_module.__path__ = []
                sys.modules["google"] = google_module
            module = types.ModuleType("google.generativeai")

            def _unavailable_configure(*_args: Any, **_kwargs: Any) -> None:
                raise RuntimeError("unused optional AutoChip provider invoked")

            class _UnavailableGenerativeModel:
                def __init__(self, *_args: Any, **_kwargs: Any) -> None:
                    raise RuntimeError("unused optional AutoChip provider invoked")

            module.configure = _unavailable_configure
            module.GenerativeModel = _UnavailableGenerativeModel
            google_module.generativeai = module
            sys.modules["google.generativeai"] = module
    if "transformers" not in sys.modules:
        try:
            __import__("transformers")
        except ModuleNotFoundError:
            module = types.ModuleType("transformers")

            class _Unavailable:
                @classmethod
                def from_pretrained(cls, *_args: Any, **_kwargs: Any) -> Any:
                    raise RuntimeError("unused optional AutoChip provider invoked")

            module.AutoTokenizer = _Unavailable
            module.AutoModelForCausalLM = _Unavailable
            module.BitsAndBytesConfig = _Unavailable
            sys.modules["transformers"] = module
    if "torch" not in sys.modules:
        try:
            __import__("torch")
        except ModuleNotFoundError:
            module = types.ModuleType("torch")
            module.float16 = object()
            sys.modules["torch"] = module
    if "mistralai" not in sys.modules:
        try:
            __import__("mistralai")
        except ModuleNotFoundError:
            module = types.ModuleType("mistralai")

            class _UnavailableMistral:
                def __init__(self, *_args: Any, **_kwargs: Any) -> None:
                    raise RuntimeError("unused optional AutoChip provider invoked")

            module.Mistral = _UnavailableMistral
            sys.modules["mistralai"] = module


def build_public_verdict_bridge(
    *, public_root: Path, bridge_root: Path
) -> tuple[Path, Path]:
    """Create a top alias and vvp marker adapter from public files only."""

    visible_tb = public_root / "visible/g01_visible_tb.sv"
    if visible_tb.is_symlink() or not visible_tb.is_file():
        raise ValueError("G01 public visible testbench is unavailable")
    if bridge_root.exists() or bridge_root.is_symlink():
        raise FileExistsError("refusing to overwrite public verdict bridge")
    bridge_root.mkdir(parents=True, mode=0o700)
    combined_tb = bridge_root / "autochip_public_tb.sv"
    escaped = visible_tb.resolve(strict=True).as_posix().replace("\"", "\\\"")
    combined_tb.write_text(
        f'`include "{escaped}"\n'
        "module tb;\n"
        "  g01_visible_tb public_visible_test();\n"
        "endmodule\n",
        encoding="utf-8",
    )
    combined_tb.chmod(0o600)

    real_vvp = shutil.which("vvp")
    if not real_vvp:
        raise RuntimeError("vvp is unavailable")
    wrapper = bridge_root / "vvp"
    wrapper.write_text(
        "#!/usr/bin/env bash\n"
        "set +e\n"
        "out=$(mktemp)\n"
        "err=$(mktemp)\n"
        "timeout 60 " + json.dumps(real_vvp) + " \"$@\" >\"$out\" 2>\"$err\"\n"
        "rc=$?\n"
        "sed -n '1,400p' \"$out\"\n"
        "sed -n '1,400p' \"$err\" >&2\n"
        "if test \"$rc\" -eq 0 && grep -q '^GOLDEN12_VISIBLE_PASS ' \"$out\"; then\n"
        "  printf 'Mismatches: 0 in 1 samples\\n'\n"
        "else\n"
        "  printf 'Mismatches: 1 in 1 samples\\n'\n"
        "fi\n"
        "rm -f \"$out\" \"$err\"\n"
        "exit 0\n",
        encoding="utf-8",
    )
    wrapper.chmod(0o700)
    return combined_tb, wrapper


def _usage(
    *,
    wall_time_seconds: float,
    llm_calls: int,
    observed_inputs: list[int],
    observed_outputs: list[int],
    eda_calls: dict[str, int],
) -> tuple[dict[str, Any], dict[str, Any]]:
    complete = llm_calls == len(observed_inputs) == len(observed_outputs)
    input_tokens = sum(observed_inputs) if complete else None
    output_tokens = sum(observed_outputs) if complete else None
    missing: list[str] = []
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
        "observed_input_tokens": sum(observed_inputs) if observed_inputs else None,
        "observed_output_tokens": sum(observed_outputs) if observed_outputs else None,
        "input_token_observed_call_count": len(observed_inputs),
        "output_token_observed_call_count": len(observed_outputs),
        "token_usage_unobserved_call_count": max(
            llm_calls - min(len(observed_inputs), len(observed_outputs)), 0
        ),
    }
    return resource, accounting


def normalize_openai_response_content(response: Any) -> int:
    """Turn provider ``None`` content into an explicit empty candidate."""

    normalized = 0
    for choice in getattr(response, "choices", []):
        message = getattr(choice, "message", None)
        if message is not None and getattr(message, "content", None) is None:
            message.content = ""
            normalized += 1
    return normalized


def run_public_autochip(
    *,
    task_path: Path,
    autochip_root: Path,
    source_archive_sha256: str,
    output_root: Path,
    receipt_path: Path,
    model: str,
    attempt: dict[str, Any],
    max_iterations: int,
    num_candidates: int,
    max_tokens: int,
    temperature: float,
) -> dict[str, Any]:
    task_path = task_path.expanduser().resolve(strict=True)
    public_root = task_path.parent
    if task_path != public_root / "external_task.json":
        raise ValueError("task descriptor must be public_root/external_task.json")
    task = _load(task_path, "task descriptor")
    if task.get("task_id") not in SUPPORTED_TASK_IDS:
        raise ValueError("AutoChip public runner currently supports only G01")
    if task.get("family") != "spec_to_rtl":
        raise ValueError("AutoChip public runner requires a Spec-to-RTL task")
    if task.get("benchmark_version") != "development":
        raise ValueError("this AutoChip runner is development-only")
    if output_root.exists() or output_root.is_symlink():
        raise FileExistsError("refusing to overwrite AutoChip output root")
    if receipt_path.exists() or receipt_path.is_symlink():
        raise FileExistsError("refusing to overwrite AutoChip run receipt")
    if not (0 <= max_iterations <= 10):
        raise ValueError("max_iterations must be between 0 and 10")
    if not (1 <= num_candidates <= 5):
        raise ValueError("num_candidates must be between 1 and 5")
    if not (1 <= max_tokens <= 8192):
        raise ValueError("max_tokens must be between 1 and 8192")
    api_key = os.environ.get("OPENROUTER_API_KEY")
    if not api_key:
        raise ValueError("OPENROUTER_API_KEY is required")

    autochip_root = autochip_root.expanduser().resolve(strict=True)
    scripts_root = autochip_root / "autochip_scripts"
    license_path = scripts_root / "LICENCE"
    if _sha256(license_path) != AUTOCHIP_LICENSE_SHA256:
        raise ValueError("AutoChip license digest drifted")
    if (
        len(source_archive_sha256) != 64
        or any(character not in "0123456789abcdef" for character in source_archive_sha256)
    ):
        raise ValueError("source archive sha256 is required")

    prompt = compose_public_prompt(task=task, public_root=public_root)
    tree_digest = public_tree_sha256(public_root)
    config = {
        "source_commit": AUTOCHIP_COMMIT,
        "source_archive_sha256": source_archive_sha256,
        "model": model,
        "max_iterations": max_iterations,
        "num_candidates": num_candidates,
        "max_tokens": max_tokens,
        "temperature": temperature,
        "public_tree_sha256": tree_digest,
        "feedback_surface": "public_visible_only",
        "provider_api_base_sha256": _sha256_bytes(API_BASE.encode("utf-8")),
        "runtime_extensions": [
            "openai-compatible-provider-bridge-v1",
            "unused-optional-provider-stubs-v1",
            "golden12-visible-marker-to-mismatch-count-v1",
            "autochip-balanced-module-parser-v1",
        ],
    }
    output_root.mkdir(parents=True, mode=0o700)
    raw_root = output_root / "raw"
    raw_root.mkdir(mode=0o700)
    prompt_path = raw_root / "public_prompt.txt"
    prompt_path.write_text(prompt, encoding="utf-8")
    prompt_path.chmod(0o600)
    combined_tb, vvp_wrapper = build_public_verdict_bridge(
        public_root=public_root,
        bridge_root=raw_root / "public_bridge",
    )

    started = time.monotonic()
    llm_calls = 0
    observed_inputs: list[int] = []
    observed_outputs: list[int] = []
    eda_calls = {
        "compile_or_lint": 0,
        "simulation": 0,
        "formal": 0,
        "synthesis": 0,
    }
    status = "control_plane_error"
    output: dict[str, Any] | None = None
    failure: dict[str, Any] | None = None
    internal_message = ""

    try:
        import openai

        real_client = openai.OpenAI(api_key=api_key, base_url=API_BASE)

        class _CountingCompletions:
            def create(self, *args: Any, **kwargs: Any) -> Any:
                nonlocal llm_calls
                kwargs.setdefault("max_tokens", max_tokens)
                kwargs.setdefault("temperature", temperature)
                response = real_client.chat.completions.create(*args, **kwargs)
                llm_calls += 1
                normalize_openai_response_content(response)
                usage = getattr(response, "usage", None)
                input_count = getattr(usage, "prompt_tokens", None)
                output_count = getattr(usage, "completion_tokens", None)
                if isinstance(input_count, int):
                    observed_inputs.append(input_count)
                if isinstance(output_count, int):
                    observed_outputs.append(output_count)
                return response

        class _ClientProxy:
            def __init__(self) -> None:
                self.chat = types.SimpleNamespace(completions=_CountingCompletions())

        original_openai_factory = openai.OpenAI
        original_path = os.environ.get("PATH")
        original_key = os.environ.get("OPENAI_API_KEY")
        original_base = os.environ.get("OPENAI_BASE_URL")
        original_sys_path = list(sys.path)
        try:
            openai.OpenAI = _ClientProxy
            os.environ["OPENAI_API_KEY"] = api_key
            os.environ["OPENAI_BASE_URL"] = API_BASE
            os.environ["PATH"] = f"{vvp_wrapper.parent}:{original_path or ''}"
            _install_unused_optional_provider_stubs()
            sys.path.insert(0, scripts_root.as_posix())
            import verilog_handling as vh

            original_compile = vh.compile_iverilog
            original_simulate = vh.simulate_iverilog
            vh.find_verilog_modules = balanced_module_parser

            def counted_compile(*args: Any, **kwargs: Any) -> Any:
                eda_calls["compile_or_lint"] += 1
                return original_compile(*args, **kwargs)

            def counted_simulate(*args: Any, **kwargs: Any) -> Any:
                eda_calls["simulation"] += 1
                return original_simulate(*args, **kwargs)

            vh.compile_iverilog = counted_compile
            vh.simulate_iverilog = counted_simulate
            response = vh.verilog_loop(
                design_prompt=prompt,
                module="golden12_fifo",
                testbench=combined_tb.as_posix(),
                max_iterations=max_iterations,
                model_type="ChatGPT",
                model_id=model,
                num_candidates=num_candidates,
                outdir=(raw_root / "autochip").as_posix(),
                log=(raw_root / "conversation.log").as_posix(),
            )
            parsed = getattr(response, "parsed_text", "")
            if isinstance(parsed, str) and parsed.strip():
                rtl_path = output_root / "rtl.sv"
                rtl_path.write_text(parsed.rstrip() + "\n", encoding="utf-8")
                rtl_path.chmod(0o600)
                if rtl_path.stat().st_size > 65536:
                    raise ValueError("AutoChip output exceeds submission byte limit")
                output = {
                    "relative_path": "rtl.sv",
                    "sha256": _sha256(rtl_path),
                    "bytes": rtl_path.stat().st_size,
                }
                status = "completed_public_only_not_evaluated"
            else:
                status = "workflow_failure_no_output"
                internal_message = "AutoChip returned no parsed RTL module"
        finally:
            openai.OpenAI = original_openai_factory
            sys.path[:] = original_sys_path
            if original_path is None:
                os.environ.pop("PATH", None)
            else:
                os.environ["PATH"] = original_path
            if original_key is None:
                os.environ.pop("OPENAI_API_KEY", None)
            else:
                os.environ["OPENAI_API_KEY"] = original_key
            if original_base is None:
                os.environ.pop("OPENAI_BASE_URL", None)
            else:
                os.environ["OPENAI_BASE_URL"] = original_base
    except Exception as exc:
        status = "control_plane_error"
        output = None
        internal_message = f"{type(exc).__name__}: {exc}"

    if status != "completed_public_only_not_evaluated":
        failure = {
            "classification": status,
            "exception_class": (
                internal_message.split(":", 1)[0]
                if status == "control_plane_error" and internal_message
                else None
            ),
            "message_sha256": _sha256_bytes(internal_message.encode("utf-8")),
        }
    resource, accounting = _usage(
        wall_time_seconds=time.monotonic() - started,
        llm_calls=llm_calls,
        observed_inputs=observed_inputs,
        observed_outputs=observed_outputs,
        eda_calls=eda_calls,
    )
    receipt = {
        "schema_version": "rtlflowbench.autochip_run_receipt.v1",
        "status": status,
        "task_id": task["task_id"],
        "task_descriptor_sha256": _canonical_sha256(task),
        "public_tree_sha256": tree_digest,
        "source": {
            "upstream_url": "https://github.com/shailja-thakur/AutoChip.git",
            "commit": AUTOCHIP_COMMIT,
            "archive_sha256": source_archive_sha256,
            "license_sha256": AUTOCHIP_LICENSE_SHA256,
        },
        "runtime_extensions": {
            "openai_compatible_provider_bridge": True,
            "unused_optional_provider_stubs": True,
            "public_verdict_bridge": "golden12-visible-marker-to-mismatch-count-v1",
            "module_parser_bridge": "autochip-balanced-module-parser-v1",
        },
        "input_policy": {
            "public_packet_only": True,
            "public_visible_testbench_supplied": True,
            "golden_testbench_supplied": False,
            "golden_reference_rtl_supplied": False,
            "private_evaluator_exposed": False,
        },
        "execution_policy": {
            "feedback_surface": "public_visible_only",
            "provider_traffic_outside_workspace": True,
            "workspace_network_access_observed": False,
        },
        "workflow": {
            "model": {"provider": "openrouter", "name": model},
            "config_sha256": _canonical_sha256(config),
        },
        "attempt": attempt,
        "resource_usage": resource,
        "token_accounting": accounting,
        "output": output,
        "failure": failure,
        "private_evaluator_run": False,
        "benchmark_ready": False,
        "publication_permitted": False,
    }
    schema = _load(RECEIPT_SCHEMA, "AutoChip receipt schema")
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(receipt)
    _write_new_json(receipt_path, receipt)
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--task", type=Path, required=True)
    parser.add_argument("--autochip-root", type=Path, required=True)
    parser.add_argument("--source-archive-sha256", required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--attempt-id", required=True)
    parser.add_argument("--attempt-index", type=int, default=1)
    parser.add_argument("--repeat-group-id", required=True)
    parser.add_argument("--seed", type=int)
    parser.add_argument("--max-iterations", type=int, default=2)
    parser.add_argument("--num-candidates", type=int, default=1)
    parser.add_argument("--max-tokens", type=int, default=4096)
    parser.add_argument("--temperature", type=float, default=0.2)
    args = parser.parse_args()
    receipt = run_public_autochip(
        task_path=args.task,
        autochip_root=args.autochip_root,
        source_archive_sha256=args.source_archive_sha256,
        output_root=args.output_root,
        receipt_path=args.receipt,
        model=args.model,
        attempt={
            "attempt_id": args.attempt_id,
            "attempt_index": args.attempt_index,
            "repeat_group_id": args.repeat_group_id,
            "seed": args.seed,
        },
        max_iterations=args.max_iterations,
        num_candidates=args.num_candidates,
        max_tokens=args.max_tokens,
        temperature=args.temperature,
    )
    print(
        json.dumps(
            {
                "status": receipt["status"],
                "task_id": receipt["task_id"],
                "llm_calls": receipt["resource_usage"]["llm_calls"],
                "eda_calls": receipt["resource_usage"]["eda_calls"],
                "private_evaluator_run": False,
                "benchmark_ready": False,
                "publication_permitted": False,
            },
            sort_keys=True,
        )
    )
    return 0 if receipt["status"] == "completed_public_only_not_evaluated" else 2


if __name__ == "__main__":
    raise SystemExit(main())
