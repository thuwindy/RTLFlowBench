#!/usr/bin/env python3
"""Verify one offline ChipFlow public-control probe and emit a path-free receipt."""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


HERE = Path(__file__).resolve().parent
SCHEMA = HERE / "runtime_probe_receipt.schema.json"
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
IMAGE_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
FORBIDDEN_PARTS = frozenset({"evaluator", "hidden", "oracle", "private"})
EXPECTED_COMMAND_PREFIX = (
    "/opt/native-preflight-env/bin/python",
    "/opt/rtlflowbench/run_chipflow_public.py",
    "--request-root", "/request", "--work-dir", "/work/run", "--model",
)
INPUTS = {
    "image_inspect": "image-inspect.json",
    "container_pre_inspect": "container-pre-inspect.json",
    "container_post_inspect": "container-post-inspect.json",
    "missing_container_pre_inspect": "missing-container-pre-inspect.json",
    "missing_container_post_inspect": "missing-container-post-inspect.json",
    "launch_request": "request/chipflow_request.json",
    "workflow_binding": "request/workflow_binding.json",
    "workspace_receipt": "request/workspace_receipt.json",
    "control_receipt": "run-output/run/chipflow_public_control_receipt.json",
    "checkpoint": "run-output/run/checkpoints.sqlite",
    "run_stdout": "run.stdout.log",
    "run_exit": "run.exit",
    "missing_stderr": "missing-run.stderr.log",
    "missing_exit": "missing-run.exit",
}


def _sha(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"expected a regular non-symlink file: {path.name}")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load(path: Path, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a regular non-symlink file")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{label} must contain one JSON object")
    return value


def _inspect(path: Path, label: str) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        raise ValueError(f"{label} must contain exactly one inspect object")
    return value[0]


def _normal_image_id(value: Any) -> str:
    text = str(value or "")
    if text.startswith("sha256:"):
        text = text[7:]
    normalized = "sha256:" + text
    if IMAGE_RE.fullmatch(normalized) is None:
        raise ValueError("runtime image id is invalid")
    return normalized


def _image_digest(value: dict[str, Any]) -> str:
    digests = value.get("RepoDigests")
    if not isinstance(digests, list):
        raise ValueError("runtime image has no repository digest")
    observed = {
        "sha256:" + item.rsplit("@sha256:", 1)[1]
        for item in digests
        if isinstance(item, str) and "@sha256:" in item
    }
    if len(observed) != 1 or IMAGE_RE.fullmatch(next(iter(observed))) is None:
        raise ValueError("runtime image repository digest is unavailable or ambiguous")
    return next(iter(observed))


def _manifest(root: Path, expected_sha256: str) -> tuple[Path, dict[Path, str]]:
    manifest = root / "SHA256SUMS"
    if SHA_RE.fullmatch(expected_sha256) is None or _sha(manifest) != expected_sha256:
        raise ValueError("evidence manifest differs from its out-of-band SHA256")
    entries: dict[Path, str] = {}
    for line in manifest.read_text(encoding="utf-8").splitlines():
        digest, raw_path = line.split(maxsplit=1)
        if SHA_RE.fullmatch(digest) is None:
            raise ValueError("evidence manifest contains an invalid digest")
        path = Path(raw_path.lstrip("*"))
        resolved = path.resolve(strict=True)
        if root != resolved and root not in resolved.parents:
            raise ValueError("evidence manifest path escapes its root")
        if resolved in entries or _sha(resolved) != digest:
            raise ValueError("evidence manifest entry drifted or duplicated")
        entries[resolved] = digest
    return manifest, entries


def _container(value: dict[str, Any], *, expected_image_id: str, model: str, exit_code: int | None) -> None:
    if _normal_image_id(value.get("Image")) != expected_image_id:
        raise ValueError("container image identity drifted")
    host = value.get("HostConfig")
    state = value.get("State")
    config = value.get("Config")
    if not isinstance(host, dict) or host.get("NetworkMode") != "none":
        raise ValueError("container network isolation is not none")
    expected_command = [*EXPECTED_COMMAND_PREFIX, model]
    if not isinstance(config, dict) or config.get("Cmd") != expected_command:
        raise ValueError("container command differs from the task-neutral entrypoint")
    mounts = value.get("Mounts")
    if not isinstance(mounts, list) or len(mounts) != 2:
        raise ValueError("container mount set is not closed")
    by_target = {item.get("Destination"): item for item in mounts if isinstance(item, dict)}
    if set(by_target) != {"/request", "/work"}:
        raise ValueError("container has an unexpected mount target")
    if not (
        by_target["/request"].get("Type") == "bind"
        and by_target["/request"].get("RW") is False
        and by_target["/work"].get("Type") == "bind"
        and by_target["/work"].get("RW") is True
    ):
        raise ValueError("container request/work mount policy drifted")
    if exit_code is not None:
        if not isinstance(state, dict) or state.get("Status") != "exited" or state.get("ExitCode") != exit_code:
            raise ValueError("container terminal status or exit code drifted")


def _exit(path: Path) -> int:
    text = path.read_text(encoding="utf-8").strip()
    if not text.isdigit():
        raise ValueError("container exit receipt is not an integer")
    return int(text)


def _single_json_line(path: Path, label: str) -> dict[str, Any]:
    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip().startswith("{")]
    if len(lines) != 1:
        raise ValueError(f"{label} does not contain one structured result")
    value = json.loads(lines[0])
    if not isinstance(value, dict):
        raise ValueError(f"{label} structured result is not an object")
    return value


def _request_tree(root: Path) -> None:
    for path in sorted((root / "request").rglob("*")):
        relative = path.relative_to(root / "request")
        if any(part.casefold() in FORBIDDEN_PARTS for part in relative.parts):
            raise ValueError("public request contains a private-control path")
        if path.is_symlink() or (not path.is_dir() and not path.is_file()):
            raise ValueError("public request contains a non-regular entry")


def build_receipt(*, evidence_root: Path, expected_evidence_manifest_sha256: str, observed_at: str) -> dict[str, Any]:
    parsed = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("observed_at must include timezone")
    unresolved = evidence_root.expanduser().absolute()
    if unresolved.is_symlink():
        raise ValueError("evidence root cannot be a symlink")
    root = unresolved.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("evidence root must be a directory")
    manifest, manifest_entries = _manifest(root, expected_evidence_manifest_sha256)
    paths = {name: root / relative for name, relative in INPUTS.items()}
    for path in paths.values():
        if path.resolve(strict=True) not in manifest_entries:
            raise ValueError("required probe input is missing from the evidence manifest")
    _request_tree(root)

    image = _inspect(paths["image_inspect"], "runtime image inspect")
    image_id = _normal_image_id(image.get("Id"))
    image_digest = _image_digest(image)
    size = image.get("Size")
    labels = image.get("Labels") or (image.get("Config") or {}).get("Labels")
    if not isinstance(size, int) or size <= 0 or not isinstance(labels, dict):
        raise ValueError("runtime image metadata is incomplete")
    source_commit = labels.get("org.rtlflowbench.source.commit")
    source_manifest = labels.get("org.rtlflowbench.runtime-component-manifest-sha256")
    if (
        not isinstance(source_commit, str) or not re.fullmatch(r"[0-9a-f]{40}", source_commit)
        or not isinstance(source_manifest, str) or SHA_RE.fullmatch(source_manifest) is None
        or labels.get("org.rtlflowbench.external-workflow") != "chipflow"
        or labels.get("org.rtlflowbench.runtime-role") != "public-task-neutral-workflow-runtime"
        or labels.get("org.rtlflowbench.private-evaluator-included") != "false"
    ):
        raise ValueError("runtime image labels do not bind a public ChipFlow runtime")

    request = _load(paths["launch_request"], "launch request")
    binding = _load(paths["workflow_binding"], "workflow binding")
    workspace = _load(paths["workspace_receipt"], "workspace receipt")
    control = _load(paths["control_receipt"], "native control receipt")
    workflow = binding.get("workflow")
    policy = binding.get("runtime_policy")
    layout = workspace.get("layout")
    model = request.get("model")
    if not (
        request.get("schema_version") == "rtlflowbench.chipflow_launch_request.v1"
        and request.get("mode") == "development"
        and request.get("public_input_only") is True
        and request.get("private_evaluator_mounted") is False
        and request.get("airtl_run_observed") is False
        and request.get("benchmark_verdict_produced") is False
        and request.get("benchmark_ready") is False
        and request.get("adapter_ready") is False
        and isinstance(model, str) and model
        and isinstance(layout, dict) and layout.get("private_file_count") == 0
        and binding.get("status") == "development_not_frozen"
        and isinstance(workflow, dict) and workflow.get("name") == "chipflow-native"
        and workflow.get("version") == source_commit
        and workflow.get("adapter_version") == source_manifest
        and isinstance(policy, dict)
        and policy.get("subagents") == "disabled_fail_closed"
        and policy.get("approval") == "fail_closed_zero_intervention"
        and policy.get("private_evaluator_reachable") is False
    ):
        raise ValueError("development request, binding, or isolation receipt drifted")
    if (workflow.get("model") or {}).get("name") != model:
        raise ValueError("request and workflow model bindings disagree")

    pre = _inspect(paths["container_pre_inspect"], "container pre-inspect")
    post = _inspect(paths["container_post_inspect"], "container post-inspect")
    missing_pre = _inspect(paths["missing_container_pre_inspect"], "missing-request pre-inspect")
    missing_post = _inspect(paths["missing_container_post_inspect"], "missing-request post-inspect")
    if pre.get("Id") != post.get("Id") or missing_pre.get("Id") != missing_post.get("Id"):
        raise ValueError("container identity changed across the probe")
    _container(pre, expected_image_id=image_id, model=model, exit_code=None)
    _container(post, expected_image_id=image_id, model=model, exit_code=5)
    _container(missing_pre, expected_image_id=image_id, model=model, exit_code=None)
    _container(missing_post, expected_image_id=image_id, model=model, exit_code=2)
    if _exit(paths["run_exit"]) != 5 or _exit(paths["missing_exit"]) != 2:
        raise ValueError("recorded container exit code drifted")

    run_result = _single_json_line(paths["run_stdout"], "native control stdout")
    missing_result = _single_json_line(paths["missing_stderr"], "missing-request stderr")
    common_control = (
        run_result.get("private_evaluator_run") is False
        and run_result.get("benchmark_verdict_produced") is False
        and control.get("schema_version") == "rtlflowbench.chipflow_public_control_receipt.v1"
        and control.get("workflow_id") == "chipflow"
        and control.get("task_id") == request.get("task_id")
        and control.get("model") == model
        and control.get("status") == run_result.get("status")
        and control.get("reason_code") == run_result.get("reason_code")
        and control.get("official_attempt") is False
        and control.get("submission_observed") is False
        and control.get("private_evaluator_run") is False
        and control.get("benchmark_verdict_produced") is False
        and control.get("checkpoint_sha256") == _sha(paths["checkpoint"])
        and isinstance(control.get("artifact_count"), int)
    )
    approval_block = (
        common_control
        and run_result.get("status") == "approval_required_block"
        and run_result.get("reason_code")
        == "zero_intervention_policy_stopped_at_native_approval_gate"
        and control.get("native_stage") == "DESIGN_BRIEF_APPROVAL"
        and control["artifact_count"] > 0
    )
    block_evidence = control.get("block_evidence")
    configuration_block = (
        common_control
        and run_result.get("status") == "workflow_capability_block"
        and run_result.get("reason_code") == "native_workflow_blocked"
        and control.get("native_stage") == "BLOCKED"
        and control.get("native_status") == "blocked"
        and control.get("design_unit_route") is True
        and control["artifact_count"] == 0
        and isinstance(block_evidence, dict)
        and block_evidence.get("schema_version")
        == "rtlflowbench.chipflow_public_block_evidence.v1"
        and block_evidence.get("categories")
        == ["runtime_configuration_unavailable"]
        and block_evidence.get("raw_reason_included") is False
    )
    if not (approval_block or configuration_block):
        raise ValueError("native control receipt is not an admitted structural BLOCK")
    if not (
        missing_result.get("status") == "control_plane_error"
        and isinstance(missing_result.get("exception_class"), str)
        and missing_result.get("raw_exception_text_recorded") is False
        and missing_result.get("private_evaluator_run") is False
        and missing_result.get("benchmark_verdict_produced") is False
    ):
        raise ValueError("missing-request control did not fail closed")

    input_sha256 = {name: _sha(path) for name, path in paths.items()}
    input_sha256["evidence_manifest"] = _sha(manifest)
    result = {
        "schema_version": "rtlflowbench.chipflow_runtime_probe.v1",
        "observed_at": observed_at,
        "decision": "PASS",
        "status": "task_neutral_runtime_probe_passed",
        "workflow_id": "chipflow",
        "scope": "development_public_control_plane_structural_probe",
        "source_commit": source_commit,
        "source_manifest_sha256": source_manifest,
        "runtime_image": {
            "image_id": image_id, "image_digest": image_digest,
            "stored_image_size_bytes": size, "private_evaluator_included": False,
        },
        "request": {
            "task_id": request["task_id"], "model": model, "mode": "development",
            "public_input_only": True, "private_evaluator_mounted": False,
            "repository_mounted": request["paths"]["repository_root"] is not None,
            "benchmark_ready": False, "adapter_ready": False,
        },
        "isolation": {
            "network_mode": "none", "request_mount_read_only": True,
            "work_mount_writable": True, "private_evaluator_mount_count": 0,
            "unexpected_mount_count": 0,
        },
        "native_control_plane": {
            "exit_code": 5, "status": control["status"],
            "reason_code": control["reason_code"], "native_stage": control["native_stage"],
            "native_status": control["native_status"],
            "checkpoint_sha256": control["checkpoint_sha256"],
            "artifact_count": control["artifact_count"],
            **(
                {"block_categories": block_evidence["categories"]}
                if configuration_block
                else {}
            ),
        },
        "fail_closed_control": {
            "exit_code": 2, "status": missing_result["status"],
            "exception_class": missing_result["exception_class"],
            "raw_exception_text_recorded": False,
        },
        "activity": {
            "task_packet_load_count": 1, "provider_call_count": 0,
            "eda_call_count": 0, "private_evaluator_call_count": 0,
            "task_mutation_count": 0, "benchmark_verdict_count": 0,
            "official_attempt_count": 0,
        },
        "readiness": {
            "binding_probe_passed": True, "fail_closed_probe_passed": True,
            "task_neutral_launch_candidate_bound": True,
            "runtime_release_frozen": False, "official_attempts_permitted": False,
        },
        "blockers": [
            "runtime_release_not_frozen", "common_model_and_provider_not_frozen",
            "independent_adapter_review_pending",
        ],
        "input_sha256": input_sha256,
        "source_sha256": {"builder": _sha(Path(__file__).resolve()), "schema": _sha(SCHEMA)},
        "excluded_claims": [
            "The PASS decision applies only to the task-neutral launcher structural probe.",
            "The native approval BLOCK is not a benchmark PASS, FAIL, or official attempt.",
            "No private evaluator, hidden oracle, provider, or EDA tool is invoked.",
            "The development runtime, model, provider, and adapter review are not release frozen.",
        ],
    }
    schema = _load(SCHEMA, "ChipFlow runtime probe receipt schema")
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(result)
    rendered = json.dumps(result, sort_keys=True)
    if any(token in rendered for token in ("/home/", "/Users/", "API_KEY")):
        raise ValueError("probe receipt exposes a private path or credential name")
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--expected-evidence-manifest-sha256", required=True)
    parser.add_argument("--observed-at", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.expanduser().absolute()
    if output.exists() or output.is_symlink():
        raise FileExistsError("refusing to overwrite a ChipFlow runtime probe receipt")
    value = build_receipt(
        evidence_root=args.evidence_root,
        expected_evidence_manifest_sha256=args.expected_evidence_manifest_sha256,
        observed_at=args.observed_at,
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(json.dumps({
        "status": value["status"], "decision": value["decision"],
        "task_packet_load_count": value["activity"]["task_packet_load_count"],
        "benchmark_verdict_count": value["activity"]["benchmark_verdict_count"],
        "official_attempt_count": value["activity"]["official_attempt_count"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
