#!/usr/bin/env python3
"""Build five workflow-neutral, task-free OCI measurement requests.

The builder starts no container, loads no task packet, and creates no result.
It binds the already-audited OCI inventory to one uniform offline shell probe.
"""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


HERE = Path(__file__).resolve().parent
REQUEST_SCHEMA = HERE / "workflow_resource_measurement_request.schema.json"
INVENTORY_SCHEMA = HERE.parent / "evaluation" / "workflow_runtime_oci_inventory.schema.json"
SET_SCHEMA = HERE / "task_free_runtime_measurement_request_set.schema.json"
SOURCE_MANIFEST = Path("docs/chipflow/research/golden12/manifest.json")
EXPECTED_WORKFLOWS = [
    ("chipflow", "chipflow"),
    ("same_model_vanilla_agent", "same_model_vanilla_agent"),
    ("external_airtl_1", "mage"),
    ("external_airtl_2", "verilogcoder"),
    ("external_airtl_3", "hdlagent"),
]
PROBE = (
    "set -eu; "
    "i=0; { while [ \"$i\" -lt 32768 ]; do "
    "printf 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef; "
    "i=$((i+1)); done; } > payload.bin; "
    "i=0; while [ \"$i\" -lt 2000000 ]; do i=$((i+1)); done; "
    "printf TASK_FREE_OCI_PROBE_OK"
)


def _load(path: Path, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a regular non-symlink file")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{label} must contain one JSON object")
    return value


def _sha(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"expected regular non-symlink file: {path}")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_new(path: Path, value: Any) -> None:
    if path.exists() or path.is_symlink():
        raise FileExistsError(f"refusing to overwrite: {path}")
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def build_request_set(
    *,
    inventory_path: Path,
    source_root: Path,
    source_commit: str,
    podman_path: Path,
    output_root: Path,
    batch_id: str,
    observed_at: str,
) -> dict[str, Any]:
    parsed = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("observed_at must include a timezone")
    if not re.fullmatch(r"[0-9a-f]{40}", source_commit):
        raise ValueError("source_commit must be a lowercase 40-hex commit")
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", batch_id):
        raise ValueError("batch_id is invalid")
    source_root = source_root.expanduser()
    if source_root.is_symlink():
        raise ValueError("source root must not be a symlink")
    source_root = source_root.resolve(strict=True)
    manifest = source_root / SOURCE_MANIFEST
    inventory_path = inventory_path.expanduser()
    if inventory_path.is_symlink():
        raise ValueError("inventory must not be a symlink")
    inventory_path = inventory_path.resolve(strict=True)
    inventory = _load(inventory_path, "OCI inventory")
    inventory_schema = _load(INVENTORY_SCHEMA, "OCI inventory schema")
    request_schema = _load(REQUEST_SCHEMA, "measurement request schema")
    set_schema = _load(SET_SCHEMA, "measurement request set schema")
    for schema in (inventory_schema, request_schema, set_schema):
        Draft202012Validator.check_schema(schema)
    Draft202012Validator(
        inventory_schema, format_checker=FormatChecker()
    ).validate(inventory)
    if inventory["status"] != "task_free_oci_inventory_complete_not_resource_calibration":
        raise ValueError("all five OCI inventory rows must resolve uniquely")
    podman_path = podman_path.expanduser()
    if podman_path.is_symlink():
        raise ValueError("podman executable must not be a symlink")
    podman_path = podman_path.resolve(strict=True)
    if podman_path.name != "podman" or not podman_path.is_file() or not os.access(
        podman_path, os.X_OK
    ):
        raise ValueError("podman executable is unavailable")
    output_root = output_root.expanduser()
    if output_root.exists() or output_root.is_symlink():
        raise FileExistsError(f"refusing to overwrite output root: {output_root}")

    rows = inventory["workflows"]
    actual_pairs = [(row["workflow_slot_id"], row["workflow_id"]) for row in rows]
    if actual_pairs != EXPECTED_WORKFLOWS:
        raise ValueError("workflow inventory order or identities differ from the frozen set")
    source_binding = {
        "commit": source_commit,
        "manifest_sha256": _sha(manifest),
    }
    podman_sha = _sha(podman_path)
    built_requests = []
    for row in rows:
        if (
            row["inventory_status"] != "available_unique_digest_match"
            or row["matching_unique_image_id_count"] != 1
            or row["resolved_image_id"] is None
        ):
            raise ValueError("OCI inventory row is unavailable or ambiguous")
        workflow_measurement_name = row["workflow_id"].replace("_", "-")
        measurement_id = f"{workflow_measurement_name}-task-free-oci-{batch_id}"
        name_token = f"--name={measurement_id}"
        prefix = [
            "run",
            "--rm",
            name_token,
            "--pull=never",
            "--network=none",
            "--read-only",
            "--cap-drop=all",
            "--security-opt=no-new-privileges",
            "--pids-limit=64",
            "--entrypoint=/bin/sh",
            "--workdir=/work",
            "--volume=.:/work:rw",
        ]
        argv = [str(podman_path), *prefix, row["resolved_image_id"], "-c", PROBE]
        request = {
            "schema_version": "rtlflowbench.workflow_resource_measurement_request.v1",
            "measurement_id": measurement_id,
            "measurement_scope": "task_free_runtime_baseline",
            "workflow_slot_id": row["workflow_slot_id"],
            "workflow_id": row["workflow_id"],
            "task_id": None,
            "attempt_id": None,
            "argv": argv,
            "launcher_kind": "podman_oci",
            "launcher_executable_sha256": podman_sha,
            "runtime_image_argv_index": 1 + len(prefix),
            "working_directory": "work",
            "timeout_seconds": 30,
            "sampling_interval_ms": 25,
            "source_binding": source_binding,
            "runtime_binding": {
                "image_digest": row["expected_image_digest"],
                "image_id": row["resolved_image_id"],
            },
            "network_policy": "offline",
            "inherited_environment_keys": ["HOME", "XDG_RUNTIME_DIR"],
        }
        Draft202012Validator(request_schema).validate(request)
        filename = f"{row['workflow_slot_id']}.request.json"
        built_requests.append((filename, request, row))

    output_root.mkdir(parents=True)
    request_rows = []
    for filename, request, row in built_requests:
        path = output_root / filename
        _write_new(path, request)
        request_rows.append(
            {
                "workflow_slot_id": row["workflow_slot_id"],
                "workflow_id": row["workflow_id"],
                "request_path": filename,
                "request_sha256": _sha(path),
                "runtime_image_digest": row["expected_image_digest"],
                "runtime_image_id": row["resolved_image_id"],
            }
        )
    result = {
        "schema_version": "rtlflowbench.task_free_runtime_measurement_request_set.v1",
        "observed_at": observed_at,
        "status": "five_task_free_requests_built_not_resource_calibration",
        "batch_id": batch_id,
        "source_binding": source_binding,
        "oci_inventory_sha256": _sha(inventory_path),
        "launcher": {"kind": "podman_oci", "executable_sha256": podman_sha},
        "requests": request_rows,
        "summary": {"workflow_count": 5, "request_count": 5, "container_start_count": 0},
        "attempt_accounting": {
            "official_attempts_started": 0,
            "official_semantic_attempts_consumed": 0,
            "resource_calibration_attempts_consumed": 0,
            "benchmark_results_created": 0,
            "private_evaluator_calls": 0,
        },
        "readiness": {
            "task_free_request_set_complete": True,
            "full_workflow_resource_calibration_complete": False,
            "host_capacity_policy_derivation_permitted": False,
            "official_attempts_permitted": False,
        },
        "excluded_claims": [
            "The request set starts no container and is not resource calibration evidence.",
            "The uniform shell probe loads no task packet, model provider, EDA tool, or private evaluator.",
            "No request or future receipt is an RTL verdict, benchmark score, or QoR result.",
            "Full-workflow concurrency, capacity policy, and independent review remain pending.",
        ],
    }
    Draft202012Validator(set_schema, format_checker=FormatChecker()).validate(result)
    _write_new(output_root / "request-set.json", result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--podman", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--batch-id", required=True)
    parser.add_argument("--observed-at", required=True)
    args = parser.parse_args()
    try:
        result = build_request_set(
            inventory_path=args.inventory,
            source_root=args.source_root,
            source_commit=args.source_commit,
            podman_path=args.podman,
            output_root=args.output_root,
            batch_id=args.batch_id,
            observed_at=args.observed_at,
        )
    except Exception as exc:
        print(json.dumps({"status": "error", "error_class": type(exc).__name__}))
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
