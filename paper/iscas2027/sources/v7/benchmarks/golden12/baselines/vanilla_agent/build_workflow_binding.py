#!/usr/bin/env python3
"""Build a content-bound development binding for the vanilla provider bridge."""

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parent
BINDING_SCHEMA = ROOT / "workflow_binding.schema.json"
BINDING_VERSION = "development-deepseek-v4-pro-v1"
PROVIDER_NAME = "deepseek"


def _load_module(path: Path):
    spec = importlib.util.spec_from_file_location(
        "rtlflowbench_vanilla_bound_provider",
        path,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load provider runner")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("schema must contain one JSON object")
    return value


def build_binding(
    *,
    config_path: Path,
    credential_env_file: Path,
    model_alias: str,
    provider_runner: Path,
    output_path: Path,
    maximum_iterations: int,
) -> dict[str, Any]:
    for label, path in (
        ("config", config_path),
        ("credential environment", credential_env_file),
        ("provider runner", provider_runner),
    ):
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"{label} must be a regular non-symlink file")
    if output_path.exists() or output_path.is_symlink():
        raise FileExistsError("refusing to overwrite workflow binding")
    from dotenv import load_dotenv

    load_dotenv(credential_env_file, override=False)
    provider = _load_module(provider_runner)
    projection, _ = provider.configuration_projection(
        config_path=config_path,
        model_alias=model_alias,
    )
    model_id = projection["public_runtime_settings"]["model"]
    binding = {
        "schema_version": "rtlflowbench.vanilla_workflow_binding.v1",
        "status": "development_not_frozen",
        "workflow": {
            "name": "same-model-vanilla-agent",
            "version": BINDING_VERSION,
            "adapter_name": "rtlflowbench-vanilla-provider-bridge",
            "adapter_version": BINDING_VERSION,
            "model": {"provider": PROVIDER_NAME, "name": model_id},
            "config_sha256": provider.canonical_sha256(projection),
        },
        "controller_sha256": provider.sha256(ROOT / "core.py"),
        "workflow_binding_schema_sha256": provider.sha256(BINDING_SCHEMA),
        "provider_runner_sha256": provider.sha256(provider_runner),
        "provider_response_schema_sha256": provider.sha256(
            ROOT / "provider_response.schema.json"
        ),
        "run_receipt_schema_sha256": provider.sha256(
            ROOT / "run_receipt.schema.json"
        ),
        "scan_submission_adapter_sha256": provider.sha256(
            ROOT.parents[1]
            / "conformance/adapters/scan_submission_adapter.py"
        ),
        "visible_runner_contract_schema_sha256": provider.sha256(
            ROOT.parents[1] / "schemas/visible_runner_contract.schema.json"
        ),
        "decoding_config_sha256": provider.decoding_config_sha256(),
        "maximum_iterations": maximum_iterations,
        "excluded_claims": [
            "This same-model DeepSeek binding is a development candidate, not frozen.",
            "Credential values are neither embedded nor hashed into this binding.",
            "No task, RTL, EDA, private evaluator, score, PPA, or ranking is reported.",
        ],
    }
    schema = _load_json(BINDING_SCHEMA)
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(binding)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("x", encoding="utf-8") as handle:
        json.dump(binding, handle, indent=2, sort_keys=True)
        handle.write("\n")
    output_path.chmod(0o600)
    return binding


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--credential-env-file", type=Path, required=True)
    parser.add_argument("--model-alias", required=True)
    parser.add_argument("--provider-runner", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--maximum-iterations", type=int, default=3)
    args = parser.parse_args()
    try:
        binding = build_binding(
            config_path=args.config,
            credential_env_file=args.credential_env_file,
            model_alias=args.model_alias,
            provider_runner=args.provider_runner,
            output_path=args.output,
            maximum_iterations=args.maximum_iterations,
        )
    except (OSError, TypeError, ValueError) as exc:
        print(
            json.dumps(
                {
                    "status": "binding_build_fail",
                    "exception_class": type(exc).__name__,
                },
                sort_keys=True,
            )
        )
        return 2
    print(
        json.dumps(
            {
                "status": binding["status"],
                "provider_runner_sha256": binding["provider_runner_sha256"],
                "config_sha256": binding["workflow"]["config_sha256"],
                "decoding_config_sha256": binding["decoding_config_sha256"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
