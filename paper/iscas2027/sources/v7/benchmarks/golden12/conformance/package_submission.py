#!/usr/bin/env python3
"""Build a workflow-neutral submission receipt from an artifact bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator


SCHEMA_ROOT = Path(__file__).resolve().parents[1] / "schemas"
METADATA_KEYS = {
    "schema_version",
    "submission_id",
    "workflow",
    "attempt",
    "resource_usage",
    "network_access_observed",
    "claims",
}


def _load(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain one JSON object")
    return payload


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical_json_sha256(value: dict[str, Any]) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _task_binding(task: dict[str, Any]) -> dict[str, Any]:
    return {
        "benchmark_id": task["benchmark_id"],
        "benchmark_version": task["benchmark_version"],
        "task_descriptor_sha256": _canonical_json_sha256(task),
        "public_packet_sha256": task["public_packet"]["sha256"],
    }


def _validate(name: str, payload: dict[str, Any]) -> None:
    schema = _load(SCHEMA_ROOT / f"{name}.schema.json")
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(payload)


def _bundle_files(bundle_root: Path) -> list[Path]:
    if (
        not bundle_root.is_dir()
        or bundle_root.is_symlink()
        or not bundle_root.exists()
    ):
        raise ValueError("bundle root must be a regular directory")
    files: list[Path] = []
    for path in sorted(bundle_root.rglob("*")):
        relative = path.relative_to(bundle_root)
        if path.is_symlink():
            raise ValueError(f"submission bundle contains symlink: {relative}")
        if path.is_dir():
            continue
        if not path.is_file():
            raise ValueError(
                f"submission bundle contains non-regular entry: {relative}"
            )
        if "__pycache__" in path.parts or path.suffix == ".pyc":
            raise ValueError(
                f"submission bundle contains generated cache: {relative}"
            )
        files.append(path)
    return files


def package_submission(
    *,
    task: dict[str, Any],
    metadata: dict[str, Any],
    bundle_root: Path,
) -> dict[str, Any]:
    _validate("task", task)
    if set(metadata) != METADATA_KEYS:
        raise ValueError(
            "submission metadata keys disagree with the neutral contract"
        )
    if metadata["schema_version"] != "rtlflowbench.submission_metadata.v1":
        raise ValueError("unsupported submission metadata schema version")

    files = _bundle_files(bundle_root)
    contract = task["submission_contract"]
    observed = {
        str(path.relative_to(bundle_root)): path
        for path in files
    }
    required = set(contract["required_files"])
    editable = set(contract["editable_paths"])
    if not required.issubset(observed):
        raise ValueError(
            "submission is missing required files: "
            + ", ".join(sorted(required - observed.keys()))
        )
    if not set(observed).issubset(editable):
        raise ValueError(
            "submission contains files outside editable_paths: "
            + ", ".join(sorted(set(observed) - editable))
        )
    if len(observed) > contract["max_files_changed"]:
        raise ValueError("submission exceeds max_files_changed")
    total_bytes = sum(path.stat().st_size for path in observed.values())
    if total_bytes > contract["max_submission_bytes"]:
        raise ValueError("submission exceeds max_submission_bytes")

    budget = task["budget"]
    usage = metadata["resource_usage"]
    if metadata["attempt"]["attempt_index"] > budget["workflow_attempts"]:
        raise ValueError("submission attempt exceeds workflow budget")
    if usage["wall_time_seconds"] > budget["wall_time_seconds"]:
        raise ValueError("submission wall time exceeds workflow budget")
    for key, limit in budget["eda_call_limits"].items():
        if usage["eda_calls"][key] > limit:
            raise ValueError(f"submission {key} calls exceed workflow budget")
    for key in ("llm_calls", "human_interventions"):
        limit = budget[key]["maximum"]
        if limit is not None and usage[key] > limit:
            raise ValueError(f"submission {key} exceed workflow budget")
    if budget["tokens"]["accounting_policy"] == "enforced_limits":
        for key, limit_key in (
            ("input_tokens", "maximum_input_tokens"),
            ("output_tokens", "maximum_output_tokens"),
        ):
            if usage[key] is None:
                raise ValueError(
                    f"submission {key} is required by workflow budget"
                )
            if usage[key] > budget["tokens"][limit_key]:
                raise ValueError(f"submission {key} exceed workflow budget")
    if (
        not task["public_packet"]["network_access"]
        and metadata["network_access_observed"]
    ):
        raise ValueError("offline task submission reports network access")

    submission = {
        "schema_version": "rtlflowbench.submission.v1",
        "submission_id": metadata["submission_id"],
        "task_id": task["task_id"],
        "task_binding": _task_binding(task),
        "workflow": metadata["workflow"],
        "attempt": metadata["attempt"],
        "artifact": {
            "format": "file_bundle",
            "files": [
                {
                    "path": relative,
                    "sha256": _sha256(path),
                    "bytes": path.stat().st_size,
                }
                for relative, path in sorted(observed.items())
            ],
        },
        "resource_usage": usage,
        "network_access_observed": metadata["network_access_observed"],
        "claims": metadata["claims"],
    }
    _validate("submission", submission)
    return submission


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--task", type=Path, required=True)
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--bundle-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        output = args.output.expanduser().resolve()
        if output.exists():
            raise FileExistsError(f"refusing to overwrite output: {output}")
        submission = package_submission(
            task=_load(args.task),
            metadata=_load(args.metadata),
            bundle_root=args.bundle_root.expanduser().absolute(),
        )
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(submission, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
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
    print(json.dumps(submission, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
