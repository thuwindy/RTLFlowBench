#!/usr/bin/env python3
"""Export a neutral submission from a declared native workflow output.

The adapter uses only paths declared by the public bridge request.  It never
searches for a plausible alternative when the declared output is absent.
"""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import shutil
import sys
from typing import Any


HERE = Path(__file__).resolve().parent
PACKAGER = HERE / "package_submission.py"


def _load(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"expected regular JSON file: {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain one object")
    return value


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _safe_relative(value: str, label: str) -> Path:
    pure = PurePosixPath(value)
    if (
        pure.is_absolute()
        or not pure.parts
        or any(part in {"", ".", ".."} for part in pure.parts)
    ):
        raise ValueError(f"unsafe {label}: {value}")
    return Path(*pure.parts)


def _packager_module():
    spec = importlib.util.spec_from_file_location(
        "rtlflowbench_native_resource_packager", PACKAGER
    )
    if spec is None or spec.loader is None:
        raise ValueError("neutral submission packager unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _declared_native_output(
    *, bridge: dict[str, Any], scratch_root: Path
) -> tuple[Path | None, str, str]:
    work = scratch_root / "work"
    schema = bridge.get("schema_version")
    if schema == "rtlflowbench.mage_bridge_request.v1":
        expected = bridge.get("mage", {}).get("top_agent", {}).get(
            "expected_output_file"
        )
        if not isinstance(expected, str):
            raise ValueError("MAGE bridge lacks expected output filename")
        relative = _safe_relative(expected, "MAGE output filename")
        if len(relative.parts) != 1:
            raise ValueError("MAGE expected output must be one filename")
        output_root = work / "output"
        if output_root.is_symlink() or not output_root.is_dir():
            return None, expected, "expected_native_output_root_missing"
        matches = sorted(
            path
            for path in output_root.rglob(relative.name)
            if path.is_file() and not path.is_symlink()
        )
        if len(matches) > 1:
            raise ValueError("MAGE bridge output filename is ambiguous")
        return (
            matches[0] if matches else None,
            expected,
            "expected_native_output_missing",
        )
    if schema == "rtlflowbench.public_spec_bridge_request.v1":
        expected = bridge.get("execution", {}).get(
            "expected_output_path_relative_to_work_dir"
        )
        if not isinstance(expected, str):
            raise ValueError("public-spec bridge lacks expected output path")
        relative = _safe_relative(expected, "native output path")
        candidate = work / "attempt" / relative
        if candidate.is_symlink() or not candidate.is_file():
            return None, expected, "expected_native_output_missing"
        return candidate, expected, "expected_native_output_missing"
    raise ValueError("unsupported native bridge schema")


def _workflow_metadata(
    bridge: dict[str, Any], *, provider: str, model: str
) -> dict[str, Any]:
    if bridge["schema_version"] == "rtlflowbench.mage_bridge_request.v1":
        upstream = bridge["upstream"]
        name = upstream["name"]
        version = upstream["version"]
    else:
        upstream = bridge["workflow"]
        name = upstream["display_name"]
        version = upstream["commit"]
    return {
        "name": name,
        "version": version,
        "adapter_name": "rtlflowbench-declared-native-output-adapter",
        "adapter_version": "v1",
        "config_sha256": bridge["configuration_sha256"],
        "model": {"provider": provider, "name": model},
    }


def _resource_usage(
    receipt: dict[str, Any], ledger: dict[str, Any]
) -> dict[str, Any]:
    metrics = receipt.get("metrics", {})
    tokens = metrics.get("token_usage", {})
    if tokens.get("measurement_complete") is not True:
        raise ValueError("token measurement is incomplete")
    kinds = Counter(
        item.get("kind")
        for item in ledger.get("activities", [])
        if isinstance(item, dict)
    )
    return {
        "wall_time_seconds": metrics["wall_time_seconds"],
        "input_tokens": tokens["input_tokens"],
        "output_tokens": tokens["output_tokens"],
        "llm_calls": metrics["provider_call_count"],
        "eda_calls": {
            "compile_or_lint": kinds["eda_compile_or_lint"],
            "simulation": kinds["eda_simulation"],
            "formal": kinds["eda_formal"],
            "synthesis": kinds["eda_synthesis"],
        },
        "human_interventions": 0,
        "missing_measurements": [],
    }


def _attempt_metadata(
    request: dict[str, Any], *, workflow_id: str, task_id: str
) -> dict[str, Any]:
    binding = request["official_attempt_binding"]
    return {
        "attempt_id": request["attempt_id"],
        # Each independent seed starts a fresh one-attempt workflow slot.
        # The run index is not a retry count.
        "attempt_index": 1,
        "repeat_group_id": f"resource-calibration-{workflow_id}-{task_id}",
        "seed": binding["seed"],
    }


def build(
    *,
    task_path: Path,
    bridge_request_path: Path,
    resource_request_path: Path,
    resource_receipt_path: Path,
    activity_ledger_path: Path,
    scratch_root: Path,
    output_dir: Path,
    provider: str,
    model: str,
) -> dict[str, Any]:
    if output_dir.exists() or output_dir.is_symlink():
        raise FileExistsError("refusing to overwrite adapter output")
    scratch_root = scratch_root.expanduser().absolute()
    if scratch_root.is_symlink() or not scratch_root.is_dir():
        raise ValueError("scratch root must be a regular directory")
    task = _load(task_path)
    bridge = _load(bridge_request_path)
    request = _load(resource_request_path)
    receipt = _load(resource_receipt_path)
    ledger = _load(activity_ledger_path)
    identities = {
        (value.get("task_id"), value.get("workflow_id"))
        for value in (request, receipt, ledger)
    }
    expected_workflow = (
        bridge.get("upstream", {}).get("name", "").casefold()
        if bridge.get("schema_version") == "rtlflowbench.mage_bridge_request.v1"
        else bridge.get("workflow", {}).get("workflow_id")
    )
    if expected_workflow == "mage":
        expected_workflow = "mage"
    if identities != {(task.get("task_id"), expected_workflow)}:
        raise ValueError("task/workflow binding drift across adapter inputs")
    if receipt.get("status") != "full_workflow_resource_sample_complete":
        raise ValueError("resource sample is incomplete")
    native, declared_path, missing_reason = _declared_native_output(
        bridge=bridge, scratch_root=scratch_root
    )
    output_dir.mkdir(parents=True)
    common = {
        "schema_version": "rtlflowbench.native_resource_submission_export.v1",
        "task_id": task["task_id"],
        "workflow_id": expected_workflow,
        "input_sha256": {
            "task": _sha(task_path),
            "bridge_request": _sha(bridge_request_path),
            "resource_request": _sha(resource_request_path),
            "resource_receipt": _sha(resource_receipt_path),
            "activity_ledger": _sha(activity_ledger_path),
        },
        "declared_native_output_path": declared_path,
        "private_evaluator_calls": 0,
        "official_attempt_created": False,
    }
    if native is None:
        result = {
            **common,
            "status": "NO_SUBMISSION",
            "reason_code": missing_reason,
            "submission_available": False,
            "submission_sha256": None,
        }
        (output_dir / "export-receipt.json").write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return result

    submitted = bridge.get("submitted_output_path") or bridge.get("mage", {}).get(
        "submitted_output_path"
    )
    if not isinstance(submitted, str):
        raise ValueError("bridge lacks submitted output path")
    submitted_relative = _safe_relative(submitted, "submitted output path")
    bundle = output_dir / "bundle"
    target = bundle / submitted_relative
    target.parent.mkdir(parents=True)
    shutil.copyfile(native, target)
    metadata = {
        "schema_version": "rtlflowbench.submission_metadata.v1",
        "submission_id": f"submission-{request['attempt_id']}",
        "workflow": _workflow_metadata(bridge, provider=provider, model=model),
        "attempt": _attempt_metadata(
            request,
            workflow_id=expected_workflow,
            task_id=task["task_id"],
        ),
        "resource_usage": _resource_usage(receipt, ledger),
        "network_access_observed": False,
        "claims": [],
    }
    submission = _packager_module().package_submission(
        task=task, metadata=metadata, bundle_root=bundle
    )
    submission_path = output_dir / "submission.json"
    submission_path.write_text(
        json.dumps(submission, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    result = {
        **common,
        "status": "SUBMISSION_EXPORTED",
        "reason_code": None,
        "submission_available": True,
        "submission_sha256": _sha(submission_path),
        "artifact_sha256": _sha(target),
    }
    (output_dir / "export-receipt.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--task", type=Path, required=True)
    parser.add_argument("--bridge-request", type=Path, required=True)
    parser.add_argument("--resource-request", type=Path, required=True)
    parser.add_argument("--resource-receipt", type=Path, required=True)
    parser.add_argument("--activity-ledger", type=Path, required=True)
    parser.add_argument("--scratch-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--provider", required=True)
    parser.add_argument("--model", required=True)
    args = parser.parse_args()
    result = build(
        task_path=args.task,
        bridge_request_path=args.bridge_request,
        resource_request_path=args.resource_request,
        resource_receipt_path=args.resource_receipt,
        activity_ledger_path=args.activity_ledger,
        scratch_root=args.scratch_root,
        output_dir=args.output_dir,
        provider=args.provider,
        model=args.model,
    )
    print(
        json.dumps(
            {
                "status": result["status"],
                "reason_code": result["reason_code"],
                "submission_available": result["submission_available"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
