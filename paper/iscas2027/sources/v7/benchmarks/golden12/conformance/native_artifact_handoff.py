"""Content-bound ChipFlow artifact snapshot, NOT a neutral result/export gate.

This read-only postprocessor never runs a model, grants approval, changes RTL or
infers usage. It preserves native failed outputs when their completed Safe
Executor and failed-verification bindings remain valid. Host observation and
the task's neutral schema/budget gates are still required for submission export.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat

MAX_DOCUMENT_BYTES = 32 * 1024 * 1024
MAX_OUTPUT_BYTES = 16 * 1024 * 1024


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return digest(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
    )


def lineage_digest(value):
    """Release lineage uses UTF-8 plus a newline, unlike approval scope hashes."""
    return digest(
        (
            json.dumps(
                value,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
            + "\n"
        ).encode()
    )


def relative(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9._/-]+", value):
        raise ValueError("unsafe_relative_path")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or not path.parts
        or any(p in {".", ".."} for p in value.split("/"))
        or path.as_posix() != value
    ):
        raise ValueError("noncanonical_relative_path")
    return path.as_posix()


def read_regular(root, name, limit=MAX_DOCUMENT_BYTES):
    parts = PurePosixPath(relative(name)).parts
    root = Path(root)
    if root.is_symlink():
        raise ValueError("symlink_root")
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for p in parts[:-1]:
            child = os.open(p, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        child = os.open(
            parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd
        )
        try:
            st = os.fstat(child)
            if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_size > limit:
                raise ValueError("unsafe_or_oversized_file")
            chunks = []
            remaining = limit + 1
            while remaining:
                block = os.read(child, min(65536, remaining))
                if not block:
                    break
                chunks.append(block)
                remaining -= len(block)
            data = b"".join(chunks)
            end = os.fstat(child)
            if (
                len(data) != st.st_size
                or len(data) > limit
                or (st.st_size, st.st_mtime_ns, st.st_ctime_ns)
                != (end.st_size, end.st_mtime_ns, end.st_ctime_ns)
            ):
                raise ValueError("file_changed_during_read")
            return data
        finally:
            os.close(child)
    finally:
        os.close(fd)


def decode(data):
    def pairs(items):
        answer = {}
        for k, v in items:
            if k in answer:
                raise ValueError("duplicate_json_key")
            answer[k] = v
        return answer

    def bad_constant(value):
        raise ValueError("nonfinite_json_number")

    result = json.loads(data, object_pairs_hook=pairs, parse_constant=bad_constant)
    if not isinstance(result, dict):
        raise ValueError("json_object_required")
    return result


def approval_payload(state):
    return {
        "approval_schema": "chipflow.research_design_unit_approval.v2",
        "gate": "research_design_unit_patch_plan",
        "design_unit_id": state["design_unit_contract"]["design_unit_id"],
        "repo_snapshot_id": state["repo_snapshot_id"],
        "design_unit_contract_sha256": canonical(state["design_unit_contract"]),
        "public_input_manifest_sha256": canonical(state["public_input_manifest"]),
        "runtime_manifest_hash": state["runtime_manifest_hash"],
        "dependency_artifact_refs_sha256": canonical(
            state.get("dependency_artifact_refs") or []
        ),
        "design_spec_sha256": canonical(state["design_spec"]),
        "patch_plan_sha256": canonical(state["patch_plan"]),
        "executor": state["patch_plan"]["executor"],
    }


def path_list(values):
    if not isinstance(values, list) or not values:
        raise ValueError("nonempty_path_list_required")
    paths = [relative(p) for p in values]
    if len(paths) != len(set(paths)):
        raise ValueError("duplicate_path")
    return paths


def capture(
    *,
    contract_path,
    work_root,
    state_relative,
    mounted_work_root,
    expected_state_sha256,
    output_dir,
):
    work_root = Path(work_root)
    output_dir = Path(output_dir).absolute()
    contract_path = Path(contract_path)
    if output_dir.exists() or output_dir.is_symlink():
        raise FileExistsError("fresh_output_required")
    if work_root.is_symlink() or output_dir.resolve().is_relative_to(
        work_root.resolve()
    ):
        raise ValueError("external_output_required")
    mount = PurePosixPath(mounted_work_root)
    if (
        not mount.is_absolute()
        or mount.as_posix() != mounted_work_root
        or ".." in mount.parts
    ):
        raise ValueError("canonical_mount_required")

    def relocate(path):
        p = PurePosixPath(path)
        if not p.is_absolute():
            raise ValueError("absolute_native_path_required")
        try:
            value = p.relative_to(mount).as_posix()
        except ValueError:
            raise ValueError("native_path_outside_mount") from None
        return relative(value)

    source_hashes = {}

    def read(path, expected=None):
        data = read_regular(work_root, path)
        hashed = digest(data)
        if expected is not None and hashed != expected:
            raise ValueError("evidence_content_drift")
        source_hashes[path] = hashed
        return data

    contract_bytes = read_regular(contract_path.parent, contract_path.name)
    contract = decode(contract_bytes)
    if (
        set(contract)
        != {
            "schema_version",
            "task_id",
            "public_input_manifest_sha256",
            "public_scope_relative",
            "required_files",
            "editable_paths",
            "max_files_changed",
            "transport_max_bytes",
        }
        or contract["schema_version"] != "chipflow.native_artifact_contract.v1"
    ):
        raise ValueError("unsupported_artifact_contract")
    required = set(path_list(contract["required_files"]))
    editable = set(path_list(contract["editable_paths"]))
    maximum = contract["transport_max_bytes"]
    max_files = contract["max_files_changed"]
    if (
        type(maximum) is not int
        or not 1 <= maximum <= MAX_OUTPUT_BYTES
        or type(max_files) is not int
        or max_files < 1
        or not required <= editable
    ):
        raise ValueError("invalid_transport_scope_limits")
    if not re.fullmatch("[0-9a-f]{64}", str(contract["public_input_manifest_sha256"])):
        raise ValueError("public_identity_missing")
    state = decode(read(relative(state_relative), expected_state_sha256))
    if (
        state.get("status") not in {"verified", "blocked"}
        or state.get("judge_decision") != "ACCEPT"
    ):
        raise ValueError("native_terminal_or_judge_missing")
    if state["status"] == "blocked" and state.get("current_stage") != "BLOCKED":
        raise ValueError("native_terminal_inconsistent")
    scope = approval_payload(state)
    if scope["design_unit_id"] != contract["task_id"]:
        raise ValueError("task_relabeling_forbidden")
    if (
        not isinstance(state.get("public_input_manifest"), list)
        or not state["public_input_manifest"]
    ):
        raise ValueError("public_input_binding_missing")
    if (
        canonical(state["public_input_manifest"])
        != contract["public_input_manifest_sha256"]
    ):
        raise ValueError("public_manifest_identity_drift")
    unit_root = relocate(state["unit_run_dir"])
    public_bytes = {}
    for item in state["public_input_manifest"]:
        path = relative(item["path"])
        if path in public_bytes:
            raise ValueError("duplicate_public_input")
        public_bytes[path] = read(unit_root + "/" + path, item["sha256"])
        if "size_bytes" in item and item["size_bytes"] != len(public_bytes[path]):
            raise ValueError("public_size_drift")
    allowed = decode(public_bytes[relative(contract["public_scope_relative"])])
    if (
        allowed.get("task_id") != contract["task_id"]
        or set(path_list(allowed.get("editable_paths"))) != editable
        or type(allowed.get("max_files_changed")) is not int
        or allowed["max_files_changed"] != max_files
    ):
        raise ValueError("declared_public_scope_drift")
    for key in [
        "repo_snapshot_id",
        "runtime_manifest_hash",
        "design_spec_sha256",
        "patch_plan_sha256",
    ]:
        if (
            not re.fullmatch("[0-9a-f]{64}", str(state.get(key)))
            or state[key] != scope[key]
        ):
            raise ValueError("native_identity_drift")
    request = state.get("approval_request", {})
    decision = state.get("approval_decision", {})
    generation = state.get("approval_generation")
    expected_request = {
        **scope,
        "scope_hash": canonical(scope),
        "generation": generation,
    }
    expected_request["request_id"] = canonical(
        {
            k: expected_request[k]
            for k in ["approval_schema", "design_unit_id", "scope_hash", "generation"]
        }
    )
    if type(generation) is not int or generation < 1 or request != expected_request:
        raise ValueError("approval_request_drift")
    if (
        decision.get("status") != "approved"
        or decision.get("scope_hash") != request["scope_hash"]
    ):
        raise ValueError("approval_decision_missing_or_stale")
    executor = state.get("executor_result", {})
    if (
        executor.get("status") != "pass"
        or executor.get("plan_sha256") != scope["patch_plan_sha256"]
        or executor.get("executor_id") != scope["executor"]
    ):
        raise ValueError("completed_executor_missing")
    receipt = decode(
        read(relocate(executor["receipt_path"]), executor["receipt_sha256"])
    )
    binding = receipt.get("binding", {})
    if (
        receipt.get("schema_version") != "chipflow.execution_receipt.v1"
        or receipt.get("status") != "completed"
    ):
        raise ValueError("executor_receipt_not_completed")
    for key, value in {
        "scope_hash": request["scope_hash"],
        "executor_id": scope["executor"],
        "plan_sha256": scope["patch_plan_sha256"],
        "repo_identity": scope["repo_snapshot_id"],
    }.items():
        if binding.get(key) != value:
            raise ValueError("executor_binding_drift")
    changed = set(path_list(executor.get("changed_files")))
    if changed != set(
        path_list(state["patch_plan"].get("changed_files"))
    ) or changed != set(path_list(receipt.get("target_files"))):
        raise ValueError("executor_target_mismatch")
    if not required <= changed or not changed <= editable or len(changed) > max_files:
        raise ValueError("public_output_scope_mismatch")
    post = receipt.get("post_images")
    if (
        not isinstance(post, list)
        or len(post) != len(changed)
        or {p.get("path") for p in post} != changed
    ):
        raise ValueError("post_image_inventory_mismatch")
    verification = state.get("verification_result", {})
    if verification.get("receipt_path") != executor["receipt_path"] or verification.get(
        "status"
    ) not in {"pass", "fail"}:
        raise ValueError("verification_binding_missing")
    evidence = decode(
        read(
            relocate(verification["immutable_evidence_path"]),
            verification["evidence_sha256"],
        )
    )
    if (
        evidence.get("design_unit_id") != contract["task_id"]
        or evidence.get("execution_receipt_sha256") != executor["receipt_sha256"]
        or evidence.get("execution_receipt_key") != receipt.get("receipt_key")
        or evidence.get("receipt_post_images") != post
        or evidence.get("visible_status") != verification["status"]
    ):
        raise ValueError("verification_evidence_drift")
    if state["status"] == "verified":
        if verification["status"] != "pass":
            raise ValueError("verified_state_requires_passing_evidence")
        release = decode(
            read(relocate(verification["release_path"]), verification["release_sha256"])
        )
        for key, value in {
            "schema": "chipflow.design_unit_release.v2",
            "contract_sha256": lineage_digest(state["design_unit_contract"]),
            "design_unit_id": contract["task_id"],
            "status": "verified",
            "visible_status": "pass",
            "receipt_sha256": executor["receipt_sha256"],
            "receipt_key": receipt["receipt_key"],
            "patch_plan_sha256": scope["patch_plan_sha256"],
            "repo_snapshot_id": scope["repo_snapshot_id"],
            "runtime_manifest_hash": scope["runtime_manifest_hash"],
            "verification_evidence_sha256": verification["evidence_sha256"],
        }.items():
            if release.get(key) != value:
                raise ValueError("native_release_drift")
        released = release.get("materialize")
        if (
            not isinstance(released, list)
            or len(released) != len(post)
            or {p.get("path"): p.get("sha256") for p in released}
            != {p["path"]: p.get("sha256") for p in post}
        ):
            raise ValueError("native_release_outputs_drift")
    elif (
        verification["status"] != "fail"
        or verification.get("release_path")
        or verification.get("release_sha256")
    ):
        raise ValueError("failed_output_must_not_claim_pass_release")
    workspace = relocate(state["workspace_root"])
    data_by_path = {}
    artifacts = []
    for image in sorted(post, key=lambda p: p["path"]):
        path = relative(image["path"])
        if image.get("exists") is not True or image.get("resolved_path") != path:
            raise ValueError("unsupported_deleted_or_aliased_post_image")
        data = read(workspace + "/" + path, image["sha256"])
        data_by_path[path] = data
        artifacts.append(
            {
                "submission_path": path,
                "source_path": "files/" + path,
                "sha256": digest(data),
                "bytes": len(data),
            }
        )
    total = sum(map(len, data_by_path.values()))
    if total > maximum:
        raise ValueError("snapshot_byte_limit")
    manifest = {
        "schema_version": "rtlflowbench.chipflow_output_manifest.v1",
        "artifact_count": len(artifacts),
        "total_bytes": total,
        "artifacts": artifacts,
    }
    result = {
        "schema_version": "chipflow.native_artifact_handoff.v1",
        "status": "native_artifacts_snapshotted",
        "task_id": contract["task_id"],
        "native_status": state["status"],
        "native_verification_status": verification["status"],
        "approved_generation": generation,
        "scope_sha256": request["scope_hash"],
        "plan_sha256": scope["patch_plan_sha256"],
        "runtime_manifest_hash": scope["runtime_manifest_hash"],
        "state_sha256": expected_state_sha256,
        "public_input_manifest_sha256": contract["public_input_manifest_sha256"],
        "contract_sha256": digest(contract_bytes),
        "evidence_manifest_sha256": canonical(source_hashes),
        "artifact_count": len(artifacts),
        "total_bytes": total,
        "resource_usage": None,
        "missing_measurements": ["canonical_controller_resource_chain"],
        "neutral_submission_exported": False,
        "benchmark_verdict": None,
        "adapter_ready": False,
        "benchmark_ready": False,
        "authority_note": "Content relationships verified; this does not authenticate the origin of caller-provided evidence.",
        "excluded_claims": [
            "No model, executor or evaluator was invoked by this snapshot.",
            "Native verification is not a benchmark verdict; missing resource data was not replaced with zero.",
            "Task descriptor/schema, run-resource observation and budget conformance still gate neutral export.",
        ],
    }
    # No old run mutation. Final publication follows a complete source recheck.
    output_dir.mkdir(mode=0o700, parents=True)
    candidate = output_dir / "candidate"
    candidate.mkdir(mode=0o700)
    for path, data in data_by_path.items():
        target = candidate / "files" / path
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as stream:
            stream.write(data)
    for path, value in [
        ("manifest.json", manifest),
        ("handoff.json", result),
        ("evidence-digests.json", source_hashes),
    ]:
        with (candidate / path).open("x") as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
    if digest(read_regular(contract_path.parent, contract_path.name)) != digest(
        contract_bytes
    ):
        raise ValueError("contract_changed_during_capture")
    for path, expected in source_hashes.items():
        if digest(read_regular(work_root, path)) != expected:
            raise ValueError("source_changed_during_capture")
    for path in sorted(candidate.rglob("*"), reverse=True):
        path.chmod(0o555 if path.is_dir() else 0o444)
    candidate.chmod(0o555)
    candidate.rename(output_dir / "ready")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["contract-path", "work-root", "output-dir"]:
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ["state-relative", "mounted-work-root", "expected-state-sha256"]:
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    try:
        result = capture(**vars(args))
    except (OSError, ValueError, KeyError, TypeError):
        print(
            json.dumps(
                {
                    "status": "blocked",
                    "reason": "native_artifact_binding_or_io_rejected",
                    "neutral_submission_exported": False,
                }
            )
        )
        return 2
    print(
        json.dumps(
            {
                k: result[k]
                for k in [
                    "status",
                    "task_id",
                    "native_status",
                    "artifact_count",
                    "neutral_submission_exported",
                ]
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
