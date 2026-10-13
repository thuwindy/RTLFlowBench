#!/usr/bin/env python3
"""Build one content-bound public launch request for ChipFlow native."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


HERE = Path(__file__).resolve().parent
REQUEST_SCHEMA = HERE / "chipflow_launch_request.schema.json"
BINDING_SCHEMA = HERE / "workflow_binding.schema.json"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _sha256(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"expected a regular non-symlink file: {path}")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load(path: Path, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a regular non-symlink file")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{label} must contain one JSON object")
    return value


def _validate(schema_path: Path, value: dict[str, Any], label: str) -> None:
    schema = _load(schema_path, f"{label} schema")
    Draft202012Validator.check_schema(schema)
    errors = sorted(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(value),
        key=lambda error: list(error.absolute_path),
    )
    if errors:
        first = errors[0]
        location = "/".join(str(part) for part in first.absolute_path)
        raise ValueError(f"{label} schema error at {location or '<root>'}")


def _root(path: Path) -> Path:
    unresolved = path.expanduser().absolute()
    if unresolved.is_symlink():
        raise ValueError("request root cannot be a symlink")
    root = unresolved.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("request root must be a directory")
    return root


def _require_digest(path: Path, expected: str, label: str) -> str:
    if SHA256_RE.fullmatch(expected) is None or _sha256(path) != expected:
        raise ValueError(f"{label} differs from its out-of-band SHA256")
    return expected


def _write_new(path: Path, payload: bytes) -> None:
    if path.exists() or path.is_symlink():
        raise FileExistsError(f"refusing to overwrite request input: {path}")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(payload)


def _release_gate(task: dict[str, Any], receipt: dict[str, Any], binding: dict[str, Any]) -> None:
    public = task.get("public_packet")
    rights = task.get("rights")
    budget = task.get("budget")
    readiness = receipt.get("readiness")
    if (
        task.get("packet_status") != "frozen"
        or not isinstance(public, dict)
        or public.get("digest_status") != "frozen"
        or public.get("sha256") is None
        or not isinstance(budget, dict)
        or budget.get("status") != "frozen"
    ):
        raise ValueError("release request requires frozen packet and budget")
    if (
        not isinstance(rights, dict)
        or rights.get("status") != "approved"
        or rights.get("redistribution_review_complete") is not True
    ):
        raise ValueError("release request requires independent rights approval")
    if (
        not isinstance(readiness, dict)
        or readiness.get("benchmark_ready") is not True
        or readiness.get("publishable_score_permitted") is not True
    ):
        raise ValueError("release request requires an admitted trial workspace")
    if binding.get("status") != "frozen":
        raise ValueError("release request requires a frozen workflow binding")


def build_request(
    *, request_root: Path, workspace_receipt_sha256: str,
    workflow_binding_path: Path, workflow_binding_sha256: str,
    expected_model: str, mode: str, attempt_id: str, attempt_index: int,
    repeat_group_id: str, seed: int | None, submission_id: str,
    maximum_public_text_bytes: int, maximum_repository_text_bytes: int,
) -> dict[str, Any]:
    if mode not in {"development", "release"}:
        raise ValueError("mode must be development or release")
    root = _root(request_root)
    public = root / "public"
    worktree = root / "worktree"
    if public.is_symlink() or not public.is_dir():
        raise ValueError("trial workspace has no regular public directory")
    if worktree.is_symlink() or not worktree.is_dir():
        raise ValueError("trial workspace has no regular worktree directory")
    task_path = public / "external_task.json"
    repo_lock_path = public / "repo.lock"
    receipt_path = root / "workspace_receipt.json"
    binding_source = workflow_binding_path.expanduser()
    _require_digest(receipt_path, workspace_receipt_sha256, "workspace receipt")
    _require_digest(binding_source, workflow_binding_sha256, "workflow binding")
    task = _load(task_path, "task descriptor")
    repo_lock = _load(repo_lock_path, "public repository lock")
    receipt = _load(receipt_path, "workspace receipt")
    binding = _load(binding_source, "workflow binding")
    _validate(BINDING_SCHEMA, binding, "ChipFlow workflow binding")
    if task.get("task_id") != receipt.get("task_id"):
        raise ValueError("task and workspace receipt identities disagree")
    layout = receipt.get("layout")
    if (
        not isinstance(layout, dict)
        or layout.get("public_root") != "public"
        or layout.get("worktree_root") != "worktree"
        or layout.get("private_file_count") != 0
    ):
        raise ValueError("trial workspace does not prove public/private isolation")
    workflow = binding.get("workflow")
    model = workflow.get("model") if isinstance(workflow, dict) else None
    if (
        not isinstance(workflow, dict)
        or workflow.get("name") != "chipflow-native"
        or not isinstance(model, dict)
        or model.get("name") != expected_model
    ):
        raise ValueError("workflow binding differs from the expected ChipFlow model")
    expected_status = {"development": "development_not_frozen", "release": "frozen"}[mode]
    if binding.get("status") != expected_status:
        raise ValueError("workflow binding status disagrees with request mode")
    if mode == "release":
        _release_gate(task, receipt, binding)
    projection = repo_lock.get("source_snapshot_exposed_to_workflow")
    if not isinstance(projection, bool):
        raise ValueError("public repository lock has no projection decision")
    _write_new(root / "workflow_binding.json", binding_source.read_bytes())
    request = {
        "schema_version": "rtlflowbench.chipflow_launch_request.v1",
        "mode": mode,
        "status": {"development": "development_request_prepared_not_run", "release": "release_request_prepared_not_run"}[mode],
        "workflow_id": "chipflow",
        "task_id": task["task_id"],
        "model": expected_model,
        "paths": {
            "public_root": "public", "task": "public/external_task.json",
            "repository_root": "worktree" if projection else None,
            "workspace_receipt": "workspace_receipt.json",
            "workflow_binding": "workflow_binding.json",
        },
        "sha256": {
            "task": _sha256(task_path), "workspace_receipt": workspace_receipt_sha256,
            "workflow_binding": workflow_binding_sha256,
        },
        "attempt": {"attempt_id": attempt_id, "attempt_index": attempt_index, "repeat_group_id": repeat_group_id, "seed": seed},
        "submission_id": submission_id,
        "limits": {"maximum_public_text_bytes": maximum_public_text_bytes, "maximum_repository_text_bytes": maximum_repository_text_bytes},
        "public_input_only": True,
        "private_evaluator_mounted": False,
        "airtl_run_observed": False,
        "benchmark_verdict_produced": False,
        "adapter_ready": False,
        "benchmark_ready": False,
        "excluded_claims": [
            "The request contains only the admitted public trial workspace.",
            "No private evaluator, hidden oracle, or reference solution is mounted.",
            "Preparing a request is not an AIRTL run or benchmark verdict.",
        ],
    }
    _validate(REQUEST_SCHEMA, request, "ChipFlow launch request")
    _write_new(root / "chipflow_request.json", (json.dumps(request, indent=2, sort_keys=True) + "\n").encode())
    return request


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--request-root", type=Path, required=True)
    parser.add_argument("--workspace-receipt-sha256", required=True)
    parser.add_argument("--workflow-binding", type=Path, required=True)
    parser.add_argument("--workflow-binding-sha256", required=True)
    parser.add_argument("--expected-model", required=True)
    parser.add_argument("--mode", choices=("development", "release"), required=True)
    parser.add_argument("--attempt-id", required=True)
    parser.add_argument("--attempt-index", type=int, required=True)
    parser.add_argument("--repeat-group-id", required=True)
    parser.add_argument("--seed", type=int)
    parser.add_argument("--submission-id", required=True)
    parser.add_argument("--maximum-public-text-bytes", type=int, default=1048576)
    parser.add_argument("--maximum-repository-text-bytes", type=int, default=4194304)
    args = parser.parse_args()
    try:
        request = build_request(
            request_root=args.request_root, workspace_receipt_sha256=args.workspace_receipt_sha256,
            workflow_binding_path=args.workflow_binding, workflow_binding_sha256=args.workflow_binding_sha256,
            expected_model=args.expected_model, mode=args.mode, attempt_id=args.attempt_id,
            attempt_index=args.attempt_index, repeat_group_id=args.repeat_group_id, seed=args.seed,
            submission_id=args.submission_id, maximum_public_text_bytes=args.maximum_public_text_bytes,
            maximum_repository_text_bytes=args.maximum_repository_text_bytes,
        )
    except (OSError, TypeError, ValueError) as exc:
        print(json.dumps({"status": "chipflow_launch_request_build_fail", "exception_class": type(exc).__name__, "benchmark_verdict_produced": False}, sort_keys=True))
        return 2
    print(json.dumps({"status": request["status"], "task_id": request["task_id"], "benchmark_verdict_produced": False}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
