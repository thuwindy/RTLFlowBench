#!/usr/bin/env python3
"""Build one content-bound, task-neutral ChipFlow workflow binding."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
from typing import Any

from jsonschema import Draft202012Validator


HERE = Path(__file__).resolve().parent
SCHEMA = HERE / "workflow_binding.schema.json"
REPO_ROOT = HERE.parents[2]
CONTROLLER = HERE / "controller.py"
TASK_SCHEMA = REPO_ROOT / "benchmarks/golden12/schemas/task.schema.json"
WORKSPACE_SCHEMA = REPO_ROOT / "benchmarks/golden12/admission/public_trial_workspace_receipt.schema.json"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _sha256(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"binding source must be a regular file: {path}")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("binding schema must be a regular file")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("binding schema must contain one object")
    return value


def build_binding(
    *, status: str, workflow_version: str, adapter_version: str,
    model_provider: str | None, model_name: str | None,
    config_sha256: str, decoding_config_sha256: str,
    subagents: str, approval: str, public_python_runtime_sha256: str | None = None,
) -> dict[str, Any]:
    if status not in {"development_not_frozen", "frozen"}:
        raise ValueError("workflow binding status is invalid")
    if not workflow_version or not adapter_version:
        raise ValueError("workflow and adapter versions must be non-empty")
    if any(SHA256_RE.fullmatch(value) is None for value in (config_sha256, decoding_config_sha256)):
        raise ValueError("config and decoding digests must be lowercase SHA256")
    value = {
        "schema_version": "rtlflowbench.chipflow_workflow_binding.v1",
        "status": status,
        "workflow": {
            "name": "chipflow-native",
            "version": workflow_version,
            "adapter_name": "rtlflowbench-chipflow-public-bridge",
            "adapter_version": adapter_version,
            "model": {"provider": model_provider, "name": model_name},
            "config_sha256": config_sha256,
        },
        "runtime_policy": {
            "controller": "deerflow_official_chipflow_native_stategraph",
            "subagents": subagents,
            "approval": approval,
            "private_evaluator_reachable": False,
        },
        "controller_sha256": _sha256(CONTROLLER),
        "workflow_binding_schema_sha256": _sha256(SCHEMA),
        "task_schema_sha256": _sha256(TASK_SCHEMA),
        "workspace_receipt_schema_sha256": _sha256(WORKSPACE_SCHEMA),
        "decoding_config_sha256": decoding_config_sha256,
        "excluded_claims": [
            "A workflow binding does not prove AIRTL task execution or correctness.",
            "The public bridge cannot access the private evaluator or hidden oracle.",
            "Release status requires separate runtime, model, provider and independent review gates.",
        ],
    }
    if public_python_runtime_sha256 is not None:
        if type(public_python_runtime_sha256) is not str or SHA256_RE.fullmatch(public_python_runtime_sha256) is None:
            raise ValueError("public Python runtime selection digest is invalid")
        value["runtime_policy"]["public_python_runtime_sha256"] = public_python_runtime_sha256
    schema = _load(SCHEMA)
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(value)
    if status == "frozen" and (model_provider is None or model_name is None):
        raise ValueError("a frozen binding requires a concrete provider and model")
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--status", choices=("development_not_frozen", "frozen"), required=True)
    parser.add_argument("--workflow-version", required=True)
    parser.add_argument("--adapter-version", required=True)
    parser.add_argument("--model-provider")
    parser.add_argument("--model-name")
    parser.add_argument("--config-sha256", required=True)
    parser.add_argument("--decoding-config-sha256", required=True)
    parser.add_argument("--subagents", choices=("disabled_fail_closed", "enabled_frozen_runtime"), required=True)
    parser.add_argument("--approval", choices=("fail_closed_zero_intervention", "scope_hash_bound_controller_preapproval"), required=True)
    parser.add_argument("--public-python-runtime-sha256")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists() or args.output.is_symlink():
        raise FileExistsError("refusing to overwrite a workflow binding")
    value = build_binding(
        status=args.status, workflow_version=args.workflow_version,
        adapter_version=args.adapter_version, model_provider=args.model_provider,
        model_name=args.model_name, config_sha256=args.config_sha256,
        decoding_config_sha256=args.decoding_config_sha256,
        subagents=args.subagents, approval=args.approval,
        public_python_runtime_sha256=args.public_python_runtime_sha256,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(json.dumps({"status": value["status"], "workflow": value["workflow"]["name"], "private_evaluator_reachable": False}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
