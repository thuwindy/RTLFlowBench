#!/usr/bin/env python3
"""Build a fail-closed candidate for superseding resource-only measurements.

The candidate never rewrites an execution-time digest.  It classifies each
historical resource sample against the current public packet and runtime
identity, then leaves every reuse decision pending independent review.
"""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import tarfile
from typing import Any

from jsonschema import Draft202012Validator


HERE = Path(__file__).resolve().parent
SCHEMA = HERE / "resource_measurement_supersession_candidate.schema.json"
SUITE_ROOT = "rtlflowbench-golden12-development-candidate"
TASK_IDS = (
    "G01-common-fifo-spec",
    "G02-common-rr-arbiter-spec",
    "G03-axis-fifo-backpressure",
    "G04-wb2axip-split-bridge",
    "G05-picorv32-missing-irq",
    "G06-ibex-debug-csr-exception",
    "G07-ibex-ifetch-error-timing",
    "G08-common-fifo-dv",
    "G09-axis-fifo-dv",
    "G10-serv-area-qor",
    "G11-picorv32-qor",
    "G12-common-cdc-missing-contract",
)
WORKFLOW_SLOTS = (
    "chipflow",
    "same_model_vanilla_agent",
    "external_airtl_1",
    "external_airtl_2",
    "external_airtl_3",
)
RUNTIME_SEMANTIC_FIELDS = (
    "workflow_id",
    "source_commit",
    "source_manifest_sha256",
    "runtime_image_digest",
    "runtime_image_id",
    "runtime_source_manifest_sha256",
    "adapter_manifest_sha256",
    "adapter_source_sha256",
    "adapter_paths",
    "expected_provider_config_sha256",
    "observed_provider_config_sha256",
)


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _canonical_digest(value: Any) -> str:
    return _sha256_bytes(
        json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
    )


def _load(path: Path, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a regular non-symlink file")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{label} must contain one JSON object")
    return value


def _bind(path: Path, expected: str, label: str) -> str:
    if len(expected) != 64 or any(char not in "0123456789abcdef" for char in expected):
        raise ValueError(f"{label} expected SHA256 is invalid")
    observed = _sha256(path)
    if observed != expected:
        raise ValueError(f"{label} digest drift")
    return observed


def _validate_observed_at(value: str) -> None:
    try:
        observed_timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("observed-at must be an ISO-8601 timestamp") from error
    if observed_timestamp.tzinfo is None or observed_timestamp.utcoffset() is None:
        raise ValueError("observed-at must include a UTC offset")


def _expected_input_hashes(arguments: argparse.Namespace) -> dict[str, str]:
    return {
        key.removeprefix("expected_").removesuffix("_sha256"): value
        for key, value in vars(arguments).items()
        if key.startswith("expected_")
    }


def _safe_member(name: str) -> PurePosixPath:
    path = PurePosixPath(name)
    lowered = {part.lower() for part in path.parts}
    if (
        path.is_absolute()
        or not path.parts
        or any(part in {"", ".", ".."} for part in path.parts)
        or "\\" in name
        or name != path.as_posix()
        or "private" in lowered
        or "oracle" in lowered
    ):
        raise ValueError(f"unsafe public-suite member: {name}")
    return path


def _regular_members(archive: tarfile.TarFile) -> dict[str, bytes]:
    result: dict[str, bytes] = {}
    for member in archive.getmembers():
        _safe_member(member.name)
        if member.isdir():
            continue
        if not member.isfile() or member.issym() or member.islnk():
            raise ValueError(f"non-regular archive member: {member.name}")
        stream = archive.extractfile(member)
        if stream is None:
            raise ValueError(f"archive member cannot be read: {member.name}")
        payload = stream.read()
        if len(payload) != member.size:
            raise ValueError(f"archive member size drift: {member.name}")
        if member.name in result:
            raise ValueError(f"duplicate archive member: {member.name}")
        result[member.name] = payload
    return result


def _strip_single_root(payloads: dict[str, bytes]) -> dict[str, bytes]:
    roots = {PurePosixPath(name).parts[0] for name in payloads}
    if len(roots) != 1:
        raise ValueError("task public archive must contain one root directory")
    root = next(iter(roots))
    result: dict[str, bytes] = {}
    for name, payload in payloads.items():
        parts = PurePosixPath(name).parts
        if len(parts) < 2 or parts[0] != root:
            raise ValueError("task public archive root closure drift")
        relative = PurePosixPath(*parts[1:]).as_posix()
        _safe_member(relative)
        result[relative] = payload
    return result


def _tree_entries(payloads: dict[str, bytes]) -> list[dict[str, Any]]:
    return [
        {"path": path, "bytes": len(payload), "sha256": _sha256_bytes(payload)}
        for path, payload in sorted(payloads.items())
    ]


def _current_public_payloads(
    archive_path: Path,
    server_receipt: dict[str, Any],
) -> tuple[dict[str, dict[str, bytes]], dict[str, str]]:
    if server_receipt.get("reproduction", {}).get("archive_sha256") != _sha256(archive_path):
        raise ValueError("public-suite server receipt/archive drift")
    if server_receipt.get("suite", {}).get("private_file_count") != 0:
        raise ValueError("public-suite server receipt reports private files")
    with tarfile.open(archive_path, mode="r:gz") as outer:
        outer_payloads = _regular_members(outer)
    descriptor_name = f"{SUITE_ROOT}/suite.json"
    if descriptor_name not in outer_payloads:
        raise ValueError("public-suite descriptor is missing")
    descriptor = json.loads(outer_payloads[descriptor_name])
    rows = descriptor.get("tasks")
    if not isinstance(rows, list) or [row.get("task_id") for row in rows] != list(TASK_IDS):
        raise ValueError("public-suite task order/coverage drift")
    payloads: dict[str, dict[str, bytes]] = {}
    locks: dict[str, str] = {}
    receipt_locks = server_receipt.get("candidate_lock_sha256")
    if not isinstance(receipt_locks, dict) or set(receipt_locks) != set(TASK_IDS):
        raise ValueError("public-suite candidate-lock map drift")
    for row in rows:
        task_id = row["task_id"]
        archive_name = f"{SUITE_ROOT}/{row['public_archive_path']}"
        raw = outer_payloads.get(archive_name)
        if raw is None or _sha256_bytes(raw) != row.get("public_archive_sha256"):
            raise ValueError(f"task public archive drift: {task_id}")
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as inner:
            task_payloads = _strip_single_root(_regular_members(inner))
        if any("private" in PurePosixPath(path).parts for path in task_payloads):
            raise ValueError(f"private path in task public archive: {task_id}")
        payloads[task_id] = task_payloads
        lock = row.get("candidate_lock_sha256")
        if lock != receipt_locks[task_id]:
            raise ValueError(f"task/server candidate-lock drift: {task_id}")
        locks[task_id] = lock
    return payloads, locks


def _previous_public_payloads(
    workspace_set: dict[str, Any], workspace_root: Path
) -> dict[str, dict[str, bytes]]:
    rows = workspace_set.get("tasks")
    if not isinstance(rows, list) or [row.get("task_id") for row in rows] != list(TASK_IDS):
        raise ValueError("previous workspace-set task order/coverage drift")
    result: dict[str, dict[str, bytes]] = {}
    for row in rows:
        task_id = row["task_id"]
        public_root = workspace_root / task_id / "public"
        if public_root.is_symlink() or not public_root.is_dir():
            raise ValueError(f"previous public workspace is unavailable: {task_id}")
        payloads: dict[str, bytes] = {}
        for path in sorted(public_root.rglob("*")):
            if path.is_symlink():
                raise ValueError(f"symlink in previous public workspace: {task_id}")
            if path.is_dir():
                continue
            if not path.is_file():
                raise ValueError(f"non-regular previous public file: {task_id}")
            relative = path.relative_to(public_root).as_posix()
            _safe_member(relative)
            payloads[relative] = path.read_bytes()
        entries = _tree_entries(payloads)
        if len(entries) != row.get("public_file_count"):
            raise ValueError(f"previous public file-count drift: {task_id}")
        if _canonical_digest(entries) != row.get("public_tree_sha256"):
            raise ValueError(f"previous public tree digest drift: {task_id}")
        result[task_id] = payloads
    return result


def _runtime_semantics(release: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = release.get("workflows")
    if not isinstance(rows, list) or [row.get("workflow_slot_id") for row in rows] != list(WORKFLOW_SLOTS):
        raise ValueError("workflow release slot order/coverage drift")
    return {
        row["workflow_slot_id"]: {field: row.get(field) for field in RUNTIME_SEMANTIC_FIELDS}
        for row in rows
    }


def _sample_disposition(
    *, receipt_kind: str, public_stable: bool, runtime_stable: bool,
    model_stable: bool, launch_policy_stable: bool,
) -> tuple[str, list[str]]:
    reasons: list[str] = []
    if not public_stable:
        reasons.append("public_input_changed")
    if not runtime_stable:
        reasons.append("workflow_runtime_or_adapter_changed")
    if not model_stable:
        reasons.append("common_model_candidate_changed")
    if not launch_policy_stable:
        reasons.append("resource_launch_policy_changed")
    if receipt_kind == "controller_nonlaunch":
        return "controller_nonlaunch_regeneration_required", reasons or [
            "current_controller_projection_required"
        ]
    if receipt_kind != "measured_launch":
        raise ValueError(f"unsupported historical receipt kind: {receipt_kind}")
    if reasons:
        return "remeasurement_required", reasons
    return "candidate_reuse_pending_independent_review", [
        "execution_inputs_byte_bound_and_unchanged"
    ]


def build_candidate(
    *, repo_root: Path,
    previous_release_path: Path, current_release_path: Path,
    previous_workspace_set_path: Path, previous_workspace_root: Path,
    current_suite_archive_path: Path, current_suite_server_receipt_path: Path,
    historical_request_set_path: Path, historical_measurement_set_path: Path,
    historical_measurement_root: Path, current_model_path: Path,
    current_launch_policy_path: Path, current_provider_gate_path: Path,
    expected: dict[str, str], observed_at: str,
) -> dict[str, Any]:
    _validate_observed_at(observed_at)
    # Resolve every operator-supplied input before reading it.
    paths = {
        "previous_workflow_release_candidate": previous_release_path,
        "current_workflow_release_candidate": current_release_path,
        "previous_public_workspace_set": previous_workspace_set_path,
        "current_public_suite_archive": current_suite_archive_path,
        "current_public_suite_server_receipt": current_suite_server_receipt_path,
        "historical_resource_request_set": historical_request_set_path,
        "historical_resource_measurement_set": historical_measurement_set_path,
        "current_common_model_candidate": current_model_path,
        "current_resource_launch_policy": current_launch_policy_path,
        "current_common_provider_gate": current_provider_gate_path,
    }
    observed_hashes = {
        key: _bind(path.resolve(strict=True), expected[key], key)
        for key, path in paths.items()
    }
    previous_release = _load(previous_release_path, "previous workflow release")
    current_release = _load(current_release_path, "current workflow release")
    previous_workspace_set = _load(previous_workspace_set_path, "previous workspace set")
    server_receipt = _load(current_suite_server_receipt_path, "public-suite server receipt")
    request_set = _load(historical_request_set_path, "historical resource request set")
    measurement_set = _load(historical_measurement_set_path, "historical measurement set")
    provider_gate = _load(current_provider_gate_path, "current common provider gate")
    current_public, current_locks = _current_public_payloads(
        current_suite_archive_path, server_receipt
    )
    previous_public = _previous_public_payloads(
        previous_workspace_set, previous_workspace_root.resolve(strict=True)
    )
    for task_id in TASK_IDS:
        lock_path = repo_root / "benchmarks/golden12/tasks" / task_id / "private/admission/candidate.lock.json"
        if _sha256(lock_path) != current_locks[task_id]:
            raise ValueError(f"current task candidate-lock drift: {task_id}")
    old_release_sha = observed_hashes["previous_workflow_release_candidate"]
    if measurement_set.get("workflow_release_candidate_sha256") != old_release_sha:
        raise ValueError("historical measurement-set/release binding drift")
    request_inputs = request_set.get("input_sha256") or {}
    if request_inputs.get("workflow_release_candidate") != old_release_sha:
        raise ValueError("historical request-set/release binding drift")
    if request_inputs.get("public_workspace_set") != observed_hashes["previous_public_workspace_set"]:
        raise ValueError("historical request-set/workspace binding drift")
    model_stable = request_inputs.get("common_model_candidate") == observed_hashes[
        "current_common_model_candidate"
    ]
    launch_policy_stable = request_inputs.get("launch_policy") == observed_hashes[
        "current_resource_launch_policy"
    ]
    request_rows = request_set.get("requests")
    samples = measurement_set.get("samples")
    if not isinstance(request_rows, list) or len(request_rows) != 200:
        raise ValueError("historical resource request coverage drift")
    if not isinstance(samples, list) or len(samples) != 200:
        raise ValueError("historical resource measurement coverage drift")
    request_keys = {
        (row.get("workflow_slot_id"), row.get("task_id"), row.get("calibration_run_index"))
        for row in request_rows
    }
    sample_keys = {
        (row.get("workflow_slot_id"), row.get("task_id"), row.get("calibration_run_index"))
        for row in samples
    }
    if len(request_keys) != 200 or request_keys != sample_keys:
        raise ValueError("historical request/measurement slot closure drift")
    old_runtime = _runtime_semantics(previous_release)
    new_runtime = _runtime_semantics(current_release)
    runtime_stable = {
        slot: old_runtime[slot] == new_runtime[slot] for slot in WORKFLOW_SLOTS
    }
    task_deltas: list[dict[str, Any]] = []
    public_stable: dict[str, bool] = {}
    public_tree: dict[str, tuple[str, str]] = {}
    for task_id in TASK_IDS:
        old_entries = _tree_entries(previous_public[task_id])
        new_entries = _tree_entries(current_public[task_id])
        old_map = {row["path"]: row["sha256"] for row in old_entries}
        new_map = {row["path"]: row["sha256"] for row in new_entries}
        changed = sorted(path for path in set(old_map) | set(new_map) if old_map.get(path) != new_map.get(path))
        old_digest = _canonical_digest(old_entries)
        new_digest = _canonical_digest(new_entries)
        stable = not changed
        public_stable[task_id] = stable
        public_tree[task_id] = (old_digest, new_digest)
        task_deltas.append({
            "task_id": task_id,
            "current_candidate_lock_sha256": current_locks[task_id],
            "previous_public_tree_sha256": old_digest,
            "current_public_tree_sha256": new_digest,
            "public_payload_byte_identical": stable,
            "changed_public_paths": changed,
        })
    dispositions: list[dict[str, Any]] = []
    counts = {
        "candidate_reuse_pending_independent_review": 0,
        "remeasurement_required": 0,
        "controller_nonlaunch_regeneration_required": 0,
    }
    root = historical_measurement_root.resolve(strict=True)
    for sample in samples:
        relative = PurePosixPath(sample.get("receipt_relative_path", ""))
        if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
            raise ValueError("unsafe historical measurement receipt path")
        receipt_path = root.joinpath(*relative.parts)
        if _sha256(receipt_path) != sample.get("receipt_sha256"):
            raise ValueError(f"historical measurement receipt digest drift: {sample.get('sample_id')}")
        task_id = sample["task_id"]
        slot = sample["workflow_slot_id"]
        disposition, reasons = _sample_disposition(
            receipt_kind=sample["receipt_kind"],
            public_stable=public_stable[task_id],
            runtime_stable=runtime_stable[slot],
            model_stable=model_stable,
            launch_policy_stable=launch_policy_stable,
        )
        counts[disposition] += 1
        dispositions.append({
            "sample_id": sample["sample_id"],
            "workflow_slot_id": slot,
            "task_id": task_id,
            "calibration_run_index": sample["calibration_run_index"],
            "historical_receipt_kind": sample["receipt_kind"],
            "historical_receipt_sha256": sample["receipt_sha256"],
            "historical_execution_hash_preserved": True,
            "previous_public_tree_sha256": public_tree[task_id][0],
            "current_public_tree_sha256": public_tree[task_id][1],
            "runtime_semantics_byte_identical": runtime_stable[slot],
            "disposition": disposition,
            "reasons": reasons,
        })
    passed_routes = provider_gate.get("summary", {}).get("passed_route_count")
    provider_ready = passed_routes == 5 and provider_gate.get("summary", {}).get("infra_route_count") == 0
    result = {
        "schema_version": "rtlflowbench.resource_measurement_supersession_candidate.v1",
        "status": "technical_candidate_complete_reuse_not_authorized",
        "observed_at": observed_at,
        "input_sha256": observed_hashes,
        "source_sha256": {
            "builder": _sha256(Path(__file__)),
            "schema": _sha256(SCHEMA),
        },
        "runtime_semantic_fields": list(RUNTIME_SEMANTIC_FIELDS),
        "runtime_semantics": [
            {
                "workflow_slot_id": slot,
                "previous_sha256": _canonical_digest(old_runtime[slot]),
                "current_sha256": _canonical_digest(new_runtime[slot]),
                "byte_identical": runtime_stable[slot],
            }
            for slot in WORKFLOW_SLOTS
        ],
        "task_public_deltas": task_deltas,
        "sample_dispositions": dispositions,
        "summary": {
            "task_count": 12,
            "workflow_count": 5,
            "historical_sample_count": 200,
            "historical_measured_launch_count": measurement_set.get("launch_sample_count"),
            "historical_controller_nonlaunch_count": measurement_set.get("controller_nonlaunch_count"),
            "public_payload_byte_identical_task_count": sum(public_stable.values()),
            "public_payload_changed_task_count": sum(not value for value in public_stable.values()),
            "runtime_semantics_byte_identical_workflow_count": sum(runtime_stable.values()),
            "candidate_reuse_sample_count": counts["candidate_reuse_pending_independent_review"],
            "remeasurement_required_sample_count": counts["remeasurement_required"],
            "controller_nonlaunch_regeneration_count": counts["controller_nonlaunch_regeneration_required"],
        },
        "readiness": {
            "historical_execution_hashes_preserved": True,
            "silent_rebinding_permitted": False,
            "historical_receipt_reuse_authorized": False,
            "independent_review_complete": False,
            "current_provider_routes_5_of_5": provider_ready,
            "targeted_remeasurement_permitted": False,
            "resource_calibration_release_frozen": False,
            "official_attempts_permitted": False,
        },
        "attempt_accounting": {
            "official_attempts_started": 0,
            "official_semantic_attempts_consumed": 0,
            "resource_calibration_attempts_consumed_by_builder": 0,
            "provider_calls_by_builder": 0,
            "eda_calls_by_builder": 0,
        },
        "blockers": [
            "independent_resource_supersession_review_missing",
            "resource_supersession_release_receipt_missing",
            "remeasurement_required_samples_incomplete",
            *( [] if provider_ready else ["current_common_provider_gate_not_5_of_5_pass"] ),
        ],
        "excluded_claims": [
            "A technical supersession candidate does not authorize historical receipt reuse.",
            "Historical execution hashes are preserved and are never replaced with current-source hashes.",
            "Byte-identical inputs are reviewer evidence, not an independent semantic-equivalence signature.",
            "Required remeasurements remain incomplete and no resource freeze is claimed.",
            "No official attempt, RTL verdict, score, QoR, PPA, ranking, benchmark readiness, or adapter readiness is produced.",
        ],
    }
    schema = _load(SCHEMA, "resource supersession candidate schema")
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--previous-workflow-release-candidate", type=Path, required=True)
    parser.add_argument("--expected-previous-workflow-release-candidate-sha256", required=True)
    parser.add_argument("--current-workflow-release-candidate", type=Path, required=True)
    parser.add_argument("--expected-current-workflow-release-candidate-sha256", required=True)
    parser.add_argument("--previous-public-workspace-set", type=Path, required=True)
    parser.add_argument("--expected-previous-public-workspace-set-sha256", required=True)
    parser.add_argument("--previous-public-workspace-root", type=Path, required=True)
    parser.add_argument("--current-public-suite-archive", type=Path, required=True)
    parser.add_argument("--expected-current-public-suite-archive-sha256", required=True)
    parser.add_argument("--current-public-suite-server-receipt", type=Path, required=True)
    parser.add_argument("--expected-current-public-suite-server-receipt-sha256", required=True)
    parser.add_argument("--historical-resource-request-set", type=Path, required=True)
    parser.add_argument("--expected-historical-resource-request-set-sha256", required=True)
    parser.add_argument("--historical-resource-measurement-set", type=Path, required=True)
    parser.add_argument("--expected-historical-resource-measurement-set-sha256", required=True)
    parser.add_argument("--historical-resource-measurement-root", type=Path, required=True)
    parser.add_argument("--current-common-model-candidate", type=Path, required=True)
    parser.add_argument("--expected-current-common-model-candidate-sha256", required=True)
    parser.add_argument("--current-resource-launch-policy", type=Path, required=True)
    parser.add_argument("--expected-current-resource-launch-policy-sha256", required=True)
    parser.add_argument("--current-common-provider-gate", type=Path, required=True)
    parser.add_argument("--expected-current-common-provider-gate-sha256", required=True)
    parser.add_argument("--observed-at", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists() or args.output.is_symlink():
        raise FileExistsError("refusing to overwrite supersession candidate")
    expected = _expected_input_hashes(args)
    result = build_candidate(
        repo_root=args.repo_root.resolve(strict=True),
        previous_release_path=args.previous_workflow_release_candidate,
        current_release_path=args.current_workflow_release_candidate,
        previous_workspace_set_path=args.previous_public_workspace_set,
        previous_workspace_root=args.previous_public_workspace_root,
        current_suite_archive_path=args.current_public_suite_archive,
        current_suite_server_receipt_path=args.current_public_suite_server_receipt,
        historical_request_set_path=args.historical_resource_request_set,
        historical_measurement_set_path=args.historical_resource_measurement_set,
        historical_measurement_root=args.historical_resource_measurement_root,
        current_model_path=args.current_common_model_candidate,
        current_launch_policy_path=args.current_resource_launch_policy,
        current_provider_gate_path=args.current_common_provider_gate,
        expected=expected,
        observed_at=args.observed_at,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"status": result["status"], **result["summary"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
