#!/usr/bin/env python3
"""Opt-in v2 export with bound, complete controller EDA accounting.

This adapter consumes only controller-observed resource evidence, the public
launch binding, and a content-bound output manifest emitted by ChipFlow.  It
does not run an RTL evaluator or infer PASS from workflow completion.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import sys
import tempfile
from typing import Any


HERE = Path(__file__).resolve().parent
PACKAGER_PATH = HERE / "package_submission.py"


def _load(path: Path, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a regular non-symlink file")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{label} must contain one JSON object")
    return value


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_packager():
    spec = importlib.util.spec_from_file_location(
        "rtlflowbench_chipflow_neutral_packager", PACKAGER_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load the neutral submission packager")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _write_new(path: Path, value: dict[str, Any]) -> None:
    if path.exists() or path.is_symlink():
        raise FileExistsError(f"refusing to overwrite output: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def _safe_relative(value: Any, label: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value:
        raise ValueError(f"{label} is not a safe POSIX relative path")
    relative = PurePosixPath(value)
    if relative.is_absolute() or ".." in relative.parts or "." in relative.parts:
        raise ValueError(f"{label} escapes the run root")
    return relative


def _source_file(work_root: Path, relative_value: Any) -> Path:
    relative = _safe_relative(relative_value, "manifest source path")
    candidate = work_root.joinpath(*relative.parts)
    if candidate.is_symlink():
        raise ValueError("manifest source is a symlink")
    source = candidate.resolve(strict=True)
    if not source.is_file() or not source.is_relative_to(work_root):
        raise ValueError("manifest source escapes the ChipFlow work root")
    current = work_root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError("manifest source path contains a symlink")
    return source


def _eda_counts(activity_ledger: dict[str, Any]) -> dict[str, int]:
    """Count observed invocations, including failures; never infer correctness.

    This is a narrow projection of controller v1, not full ledger schema
    validation or an attestation that the host controller is trustworthy.
    Legacy aliases need their own audited version, not silent normalization.
    """
    if (
        activity_ledger.get("schema_version")
        != "rtlflowbench.workflow_activity_ledger.v1"
    ):
        raise ValueError("EDA measurement requires controller activity ledger v1")
    expected = {
        "provider_gateway_observation_complete": True,
        "eda_broker_observation_complete": True,
        "all_provider_calls_routed_through_observer": True,
        "all_eda_invocations_routed_through_observer": True,
        "raw_provider_response_exposed": False,
        "credentials_exposed": False,
        "private_evaluator_instrumented": False,
        "task_workspace_can_write_ledger": False,
    }
    complete = activity_ledger.get("completeness")
    if not isinstance(complete, dict) or any(
        complete.get(key) is not value for key, value in expected.items()
    ):
        raise ValueError("EDA measurement is incomplete or unsafe; counts unavailable")
    activities = activity_ledger.get("activities")
    if not isinstance(activities, list):
        raise ValueError("EDA activity list missing; counts unavailable")
    kinds = {
        "eda_compile_or_lint": "compile_or_lint",
        "eda_simulation": "simulation",
        "eda_formal": "formal",
        "eda_synthesis": "synthesis",
    }
    counts = dict.fromkeys(kinds.values(), 0)
    seen: set[str] = set()
    for row in activities:
        if not isinstance(row, dict):
            raise ValueError("resource activity entry is invalid")
        identity = row.get("activity_id")
        if (
            not isinstance(identity, str)
            or re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,159}", identity) is None
            or identity in seen
        ):
            raise ValueError(
                "resource activity identity missing, invalid or duplicated"
            )
        seen.add(identity)
        kind = row.get("kind")
        if kind not in (*kinds, "llm_call"):
            raise ValueError("unknown controller activity kind")
        owner = "provider_gateway" if kind == "llm_call" else "eda_broker"
        start, stop = row.get("started_offset_ns"), row.get("completed_offset_ns")
        binding = row.get("event_binding_sha256")
        if (
            row.get("controller") != owner
            or row.get("outcome") not in {"completed", "failed", "timed_out"}
            or type(start) is not int
            or type(stop) is not int
            or not 0 <= start < stop
            or row.get("raw_content_embedded") is not False
            or not isinstance(binding, str)
            or re.fullmatch(r"[0-9a-f]{64}", binding) is None
        ):
            raise ValueError(
                "resource activity lacks valid terminal controller evidence"
            )
        if kind in kinds:
            counts[kinds[kind]] += 1
    return counts


def _validate_activity_binding(
    *,
    activity,
    resource,
    resource_request,
    process,
    concurrency,
    activity_path,
    resource_request_path,
    process_path,
    concurrency_path,
):
    """Verify existing content links; no historical receipt is rewritten."""
    identities = (
        "measurement_id",
        "workflow_slot_id",
        "workflow_id",
        "task_id",
        "attempt_id",
        "source_binding",
        "runtime_binding",
    )
    for key in identities:
        value = resource_request.get(key)
        if not value or any(
            item.get(key) != value
            for item in (activity, resource, process, concurrency)
        ):
            raise ValueError("resource/activity run identity drifted")
    process_sha = _sha256(process_path)
    summary_bindings = resource.get("input_sha256") or {}
    if (
        process.get("request_sha256") != _sha256(resource_request_path)
        or activity.get("process_measurement_receipt_sha256") != process_sha
        or concurrency.get("process_measurement_receipt_sha256") != process_sha
        or concurrency.get("ledger_sha256") != _sha256(activity_path)
        or summary_bindings.get("process_measurement_receipt") != process_sha
        or summary_bindings.get("activity_concurrency_receipt")
        != _sha256(concurrency_path)
    ):
        raise ValueError("resource/activity content binding drifted")
    forced = (resource.get("metrics") or {}).get("forced_eda_activity_closure_count")
    if type(forced) is not int or forced != 0:
        raise ValueError("forced or unknown EDA closure; counts unavailable")


def _token_usage(metrics: dict[str, Any]) -> tuple[int | None, int | None, list[str]]:
    observed = metrics.get("token_usage") or {}
    complete = observed.get("measurement_complete") is True
    values: list[int | None] = []
    missing: list[str] = []
    for key in ("input_tokens", "output_tokens"):
        value = observed.get(key)
        if complete and type(value) is int and value >= 0:
            values.append(value)
        else:
            values.append(None)
            missing.append(key)
    return values[0], values[1], missing


def collect_chipflow_submission(
    *,
    task_path: Path,
    request_path: Path,
    workflow_binding_path: Path,
    control_receipt_path: Path,
    work_root: Path,
    resource_summary_path: Path,
    activity_ledger_path: Path,
    resource_request_path: Path,
    process_receipt_path: Path,
    activity_concurrency_path: Path,
    bundle_output: Path,
    submission_output: Path,
    receipt_output: Path,
    observed_at: str,
) -> dict[str, Any]:
    task = _load(task_path, "public task descriptor")
    request = _load(request_path, "ChipFlow launch request")
    binding = _load(workflow_binding_path, "ChipFlow workflow binding")
    control = _load(control_receipt_path, "ChipFlow control receipt")
    resource = _load(resource_summary_path, "resource summary")
    activity = _load(activity_ledger_path, "resource activity ledger")
    resource_request = _load(resource_request_path, "resource request")
    process = _load(process_receipt_path, "process receipt")
    concurrency = _load(activity_concurrency_path, "activity concurrency receipt")
    _validate_activity_binding(
        activity=activity,
        resource=resource,
        resource_request=resource_request,
        process=process,
        concurrency=concurrency,
        activity_path=activity_ledger_path,
        resource_request_path=resource_request_path,
        process_path=process_receipt_path,
        concurrency_path=activity_concurrency_path,
    )
    eda_counts = _eda_counts(activity)

    task_id = task.get("task_id")
    if any(
        item.get("task_id") != task_id
        for item in (request, control, resource, resource_request)
    ):
        raise ValueError("ChipFlow submission evidence task identity drifted")
    if activity.get("workflow_id") != "chipflow" or activity.get("task_id") != task_id:
        raise ValueError("resource activity ledger identity drifted")
    request_hashes = request.get("sha256") or {}
    public_binding = resource_request.get("public_input_binding") or {}
    task_sha256 = _sha256(task_path)
    if (
        request_hashes.get("task") != task_sha256
        or request_hashes.get("workflow_binding") != _sha256(workflow_binding_path)
        or public_binding.get("external_task_sha256") != task_sha256
    ):
        raise ValueError("ChipFlow public or resource content binding drifted")
    if (
        control.get("schema_version")
        != "rtlflowbench.chipflow_public_control_receipt.v1"
    ):
        raise ValueError("unsupported ChipFlow control receipt")
    if (
        control.get("status") != "workflow_completed_neutral_export_ready"
        or control.get("submission_observed") is not True
        or control.get("benchmark_verdict_produced") is not False
        or control.get("private_evaluator_run") is not False
    ):
        raise ValueError("ChipFlow run is not eligible for neutral export")
    if request.get("workflow_id") != "chipflow" or request.get("model") != control.get(
        "model"
    ):
        raise ValueError("ChipFlow launch binding drifted")
    workflow = binding.get("workflow")
    if not isinstance(workflow, dict) or workflow.get("name") != "chipflow-native":
        raise ValueError("ChipFlow workflow identity is invalid")
    if (workflow.get("model") or {}).get("name") != request.get("model"):
        raise ValueError("ChipFlow model binding drifted")
    controller_binding = resource_request.get("controller_binding") or {}
    if (
        controller_binding.get("network_policy") != "offline"
        or controller_binding.get("private_evaluator_reachable") is not False
    ):
        raise ValueError("resource controller did not enforce offline isolation")
    official = resource_request.get("official_attempt_binding") or {}
    attempt = request.get("attempt") or {}
    if resource_request.get("attempt_id") != attempt.get("attempt_id"):
        raise ValueError("resource attempt differs from the public launch request")
    if official.get("seed") != attempt.get("seed"):
        raise ValueError("resource seed differs from the public launch request")
    activities = activity.get("activities")
    metrics = resource.get("metrics") or {}
    if not isinstance(activities, list) or metrics.get("activity_count") != len(
        activities
    ):
        raise ValueError("resource activity count is incomplete or inconsistent")

    manifest = control.get("submission_manifest")
    if (
        not isinstance(manifest, dict)
        or manifest.get("schema_version") != "rtlflowbench.chipflow_output_manifest.v1"
        or type(manifest.get("artifact_count")) is not int
        or not isinstance(manifest.get("artifacts"), list)
        or manifest["artifact_count"] != len(manifest["artifacts"])
    ):
        raise ValueError("ChipFlow output manifest is invalid")
    work = work_root.expanduser().resolve(strict=True)
    if not work.is_dir() or work_root.is_symlink():
        raise ValueError("ChipFlow work root must be a regular directory")
    for output in (bundle_output, submission_output, receipt_output):
        if output.exists() or output.is_symlink():
            raise FileExistsError(f"refusing to overwrite output: {output}")

    bundle_output.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(
        tempfile.mkdtemp(prefix=".chipflow-submission-", dir=bundle_output.parent)
    )
    observed_total = 0
    observed_paths: set[str] = set()
    try:
        for item in manifest["artifacts"]:
            if not isinstance(item, dict):
                raise ValueError("ChipFlow artifact manifest entry is invalid")
            submission_path = _safe_relative(
                item.get("submission_path"), "submission artifact path"
            ).as_posix()
            if submission_path in observed_paths:
                raise ValueError("ChipFlow artifact manifest path is duplicated")
            observed_paths.add(submission_path)
            source = _source_file(work, item.get("source_path"))
            size = source.stat().st_size
            if _sha256(source) != item.get("sha256") or size != item.get("bytes"):
                raise ValueError(
                    "ChipFlow output bytes differ from the terminal manifest"
                )
            target = stage / submission_path
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
            observed_total += size
        if observed_total != manifest.get("total_bytes"):
            raise ValueError("ChipFlow output manifest byte total drifted")

        input_tokens, output_tokens, missing = _token_usage(metrics)
        resource_usage = {
            "wall_time_seconds": metrics.get("wall_time_seconds"),
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "llm_calls": metrics.get("provider_call_count"),
            "eda_calls": eda_counts,
            "human_interventions": control.get("human_intervention_count"),
            "missing_measurements": missing,
        }
        if (
            not isinstance(resource_usage["wall_time_seconds"], (int, float))
            or type(resource_usage["llm_calls"]) is not int
            or type(resource_usage["human_interventions"]) is not int
        ):
            raise ValueError("controller resource measurements are incomplete")
        metadata = {
            "schema_version": "rtlflowbench.submission_metadata.v1",
            "submission_id": request["submission_id"],
            "workflow": {
                "name": "ChipFlow",
                "version": workflow["version"],
                "adapter_name": workflow["adapter_name"],
                "adapter_version": workflow["adapter_version"],
                "model": workflow["model"],
                "config_sha256": workflow["config_sha256"],
            },
            "attempt": attempt,
            "resource_usage": resource_usage,
            "network_access_observed": False,
            "claims": [],
        }
        packager = _load_packager()
        submission = packager.package_submission(
            task=task,
            metadata=metadata,
            bundle_root=stage,
        )
        os.replace(stage, bundle_output)
    finally:
        if stage.exists():
            shutil.rmtree(stage)
    for path in sorted(bundle_output.rglob("*"), reverse=True):
        path.chmod(0o555 if path.is_dir() else 0o444)
    _write_new(submission_output, submission)
    receipt = {
        "schema_version": "rtlflowbench.chipflow_submission_bridge_receipt.v2",
        "observed_at": observed_at,
        "status": "neutral_submission_exported",
        "task_id": task_id,
        "workflow_id": "chipflow",
        "control_receipt_sha256": _sha256(control_receipt_path),
        "resource_summary_sha256": _sha256(resource_summary_path),
        "activity_ledger_sha256": _sha256(activity_ledger_path),
        "process_receipt_sha256": _sha256(process_receipt_path),
        "activity_concurrency_receipt_sha256": _sha256(activity_concurrency_path),
        "exporter_sha256": _sha256(Path(__file__).resolve()),
        "packager_sha256": _sha256(PACKAGER_PATH),
        "eda_accounting_policy": "complete_controller_invocations_v2",
        "eda_calls": eda_counts,
        "submission_sha256": _sha256(submission_output),
        "artifact_count": len(submission["artifact"]["files"]),
        "private_evaluator_run": False,
        "benchmark_verdict_produced": False,
        "benchmark_ready": False,
        "excluded_claims": [
            "Neutral export is not an RTL evaluator verdict or benchmark PASS.",
            "No private evaluator, reference implementation, or hidden oracle was used.",
        ],
    }
    _write_new(receipt_output, receipt)
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--task", type=Path, required=True)
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--workflow-binding", type=Path, required=True)
    parser.add_argument("--control-receipt", type=Path, required=True)
    parser.add_argument("--work-root", type=Path, required=True)
    parser.add_argument("--resource-summary", type=Path, required=True)
    parser.add_argument("--activity-ledger", type=Path, required=True)
    parser.add_argument("--resource-request", type=Path, required=True)
    parser.add_argument("--process-receipt", type=Path, required=True)
    parser.add_argument("--activity-concurrency-receipt", type=Path, required=True)
    parser.add_argument("--bundle-output", type=Path, required=True)
    parser.add_argument("--submission-output", type=Path, required=True)
    parser.add_argument("--receipt-output", type=Path, required=True)
    parser.add_argument("--observed-at", required=True)
    args = parser.parse_args()
    try:
        receipt = collect_chipflow_submission(
            task_path=args.task,
            request_path=args.request,
            workflow_binding_path=args.workflow_binding,
            control_receipt_path=args.control_receipt,
            work_root=args.work_root,
            resource_summary_path=args.resource_summary,
            activity_ledger_path=args.activity_ledger,
            resource_request_path=args.resource_request,
            process_receipt_path=args.process_receipt,
            activity_concurrency_path=args.activity_concurrency_receipt,
            bundle_output=args.bundle_output,
            submission_output=args.submission_output,
            receipt_output=args.receipt_output,
            observed_at=args.observed_at,
        )
    except Exception as exc:
        print(
            json.dumps(
                {"status": "fail", "error": f"{type(exc).__name__}: {exc}"},
                sort_keys=True,
            )
        )
        return 2
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
