#!/usr/bin/env python3
"""Independent directory-scanning adapter for neutral submissions.

This implementation intentionally does not import the canonical
``package_submission.py`` packager.  It provides a second implementation of
the public task/submission contract for interoperability calibration.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator


SCHEMA_ROOT = Path(__file__).resolve().parents[2] / "schemas"
METADATA_KEYS = frozenset(
    {
        "schema_version",
        "submission_id",
        "workflow",
        "attempt",
        "resource_usage",
        "network_access_observed",
        "claims",
    }
)


def _load_schema(name: str) -> dict[str, Any]:
    payload = json.loads(
        (SCHEMA_ROOT / f"{name}.schema.json").read_text(encoding="utf-8")
    )
    if not isinstance(payload, dict):
        raise ValueError(f"{name} schema must be a JSON object")
    return payload


def _validate(name: str, payload: dict[str, Any]) -> None:
    schema = _load_schema(name)
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(payload)


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


def _scan_regular_files(root: Path) -> dict[str, Path]:
    if not root.exists() or not root.is_dir() or root.is_symlink():
        raise ValueError("bundle root must be a regular directory")
    observed: dict[str, Path] = {}
    pending = [root]
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as entries:
            for entry in sorted(entries, key=lambda item: item.name):
                path = Path(entry.path)
                relative = path.relative_to(root).as_posix()
                if entry.is_symlink():
                    raise ValueError(
                        f"submission bundle contains symlink: {relative}"
                    )
                if entry.is_dir(follow_symlinks=False):
                    pending.append(path)
                    continue
                if not entry.is_file(follow_symlinks=False):
                    raise ValueError(
                        "submission bundle contains non-regular entry: "
                        f"{relative}"
                    )
                if "__pycache__" in path.parts or path.suffix == ".pyc":
                    raise ValueError(
                        f"submission bundle contains generated cache: {relative}"
                    )
                observed[relative] = path
    return dict(sorted(observed.items()))


def _enforce_contract(
    *,
    task: dict[str, Any],
    metadata: dict[str, Any],
    observed: dict[str, Path],
) -> None:
    contract = task["submission_contract"]
    paths = set(observed)
    required = set(contract["required_files"])
    editable = set(contract["editable_paths"])
    missing = required - paths
    outside = paths - editable
    if missing:
        raise ValueError(
            "submission is missing required files: "
            + ", ".join(sorted(missing))
        )
    if outside:
        raise ValueError(
            "submission contains files outside editable_paths: "
            + ", ".join(sorted(outside))
        )
    if len(paths) > contract["max_files_changed"]:
        raise ValueError("submission exceeds max_files_changed")
    if sum(path.stat().st_size for path in observed.values()) > contract[
        "max_submission_bytes"
    ]:
        raise ValueError("submission exceeds max_submission_bytes")

    budget = task["budget"]
    usage = metadata["resource_usage"]
    if metadata["attempt"]["attempt_index"] > budget["workflow_attempts"]:
        raise ValueError("submission attempt exceeds workflow budget")
    if usage["wall_time_seconds"] > budget["wall_time_seconds"]:
        raise ValueError("submission wall time exceeds workflow budget")
    for tool, limit in budget["eda_call_limits"].items():
        if usage["eda_calls"][tool] > limit:
            raise ValueError(f"submission {tool} calls exceed workflow budget")
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


def package_submission(
    *,
    task: dict[str, Any],
    metadata: dict[str, Any],
    bundle_root: Path,
) -> dict[str, Any]:
    """Package one file bundle without using the canonical packager."""
    _validate("task", task)
    if set(metadata) != METADATA_KEYS:
        raise ValueError(
            "submission metadata keys disagree with the neutral contract"
        )
    if metadata["schema_version"] != "rtlflowbench.submission_metadata.v1":
        raise ValueError("unsupported submission metadata schema version")

    observed = _scan_regular_files(bundle_root)
    _enforce_contract(
        task=task,
        metadata=metadata,
        observed=observed,
    )
    files = []
    for relative, path in observed.items():
        content = path.read_bytes()
        files.append(
            {
                "path": relative,
                "sha256": hashlib.sha256(content).hexdigest(),
                "bytes": len(content),
            }
        )
    submission = {
        "schema_version": "rtlflowbench.submission.v1",
        "submission_id": metadata["submission_id"],
        "task_id": task["task_id"],
        "task_binding": _task_binding(task),
        "workflow": metadata["workflow"],
        "attempt": metadata["attempt"],
        "artifact": {"format": "file_bundle", "files": files},
        "resource_usage": metadata["resource_usage"],
        "network_access_observed": metadata["network_access_observed"],
        "claims": metadata["claims"],
    }
    _validate("submission", submission)
    return submission
