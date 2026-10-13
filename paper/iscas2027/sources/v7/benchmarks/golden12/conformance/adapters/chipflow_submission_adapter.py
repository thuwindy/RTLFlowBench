#!/usr/bin/env python3
"""Convert an evidence-backed ChipFlow run into a neutral submission."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator


ADAPTER_ROOT = Path(__file__).resolve().parent
SCHEMA_ROOT = ADAPTER_ROOT.parents[1] / "schemas"
EXPORT_SCHEMA_PATH = ADAPTER_ROOT / "chipflow_export.schema.json"
USAGE_SCHEMA_PATH = ADAPTER_ROOT / "chipflow_usage_receipt.schema.json"
EVENT_SCHEMA_PATH = ADAPTER_ROOT / "chipflow_usage_events.schema.json"
TASK_SCHEMA_PATH = SCHEMA_ROOT / "task.schema.json"
SUBMISSION_SCHEMA_PATH = SCHEMA_ROOT / "submission.schema.json"


def _load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} must contain one JSON object")
    return value


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


def _validate(
    *,
    schema: dict[str, Any],
    instance: dict[str, Any],
    name: str,
) -> None:
    errors = sorted(
        Draft202012Validator(schema).iter_errors(instance),
        key=lambda error: list(error.absolute_path),
    )
    if errors:
        first = errors[0]
        location = "/".join(str(part) for part in first.absolute_path)
        raise ValueError(f"{name} schema error at {location or '<root>'}: {first.message}")


def _resolve_member(root: Path, relative: str) -> Path:
    member = Path(relative)
    if member.is_absolute() or ".." in member.parts or "\\" in relative:
        raise ValueError(f"unsafe ChipFlow run path: {relative}")
    candidate = root / member
    current = root
    for part in member.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError(f"ChipFlow run path contains a symlink: {relative}")
    if not candidate.is_file():
        raise ValueError(f"ChipFlow run path is not a regular file: {relative}")
    resolved = candidate.resolve(strict=True)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"ChipFlow run path escapes its root: {relative}") from exc
    return resolved


def _parse_time(value: str, *, field: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError(f"{field} must include a timezone")
    return parsed


def _validate_usage_evidence(
    *,
    run_root: Path,
    usage: dict[str, Any],
    event_schema: dict[str, Any],
) -> None:
    started = _parse_time(usage["started_at"], field="started_at")
    completed = _parse_time(usage["completed_at"], field="completed_at")
    elapsed = (completed - started).total_seconds()
    if elapsed < 0:
        raise ValueError("usage receipt completed_at precedes started_at")
    reported = float(usage["resource_usage"]["wall_time_seconds"])
    if abs(reported - elapsed) > 0.001:
        raise ValueError(
            "usage receipt wall_time_seconds does not match its timestamps"
        )
    evidence_paths: set[str] = set()
    for evidence in usage["evidence_manifest"]:
        relative = evidence["path"]
        if relative in evidence_paths:
            raise ValueError(f"duplicate usage evidence path: {relative}")
        evidence_paths.add(relative)
        path = _resolve_member(run_root, relative)
        if path.stat().st_size != evidence["bytes"]:
            raise ValueError(f"usage evidence byte count drift: {relative}")
        if _sha256(path) != evidence["sha256"]:
            raise ValueError(f"usage evidence digest drift: {relative}")

    ledger_relative = usage["event_ledger"]["path"]
    if ledger_relative not in evidence_paths:
        raise ValueError("usage event ledger is absent from evidence_manifest")
    ledger_path = _resolve_member(run_root, ledger_relative)
    if _sha256(ledger_path) != usage["event_ledger"]["sha256"]:
        raise ValueError("usage event ledger digest drift")
    ledger = _load_object(ledger_path)
    _validate(
        schema=event_schema,
        instance=ledger,
        name="ChipFlow usage event ledger",
    )
    if ledger["chipflow_run_id"] != usage["chipflow_run_id"]:
        raise ValueError("usage event ledger run ID disagrees with its receipt")
    event_ids = [event["event_id"] for event in ledger["events"]]
    if len(event_ids) != len(set(event_ids)):
        raise ValueError("usage event IDs are not unique")
    for event in ledger["events"]:
        missing_refs = set(event["evidence_refs"]) - evidence_paths
        if missing_refs:
            raise ValueError(
                f"usage event {event['event_id']} cites unmanifested evidence: "
                f"{sorted(missing_refs)}"
            )

    counts = {
        "llm_call": 0,
        "eda_compile_or_lint": 0,
        "eda_simulation": 0,
        "eda_formal": 0,
        "eda_synthesis": 0,
        "human_intervention": 0,
        "network_attempt": 0,
    }
    llm_inputs: list[int | None] = []
    llm_outputs: list[int | None] = []
    for event in ledger["events"]:
        counts[event["event_type"]] += 1
        if event["event_type"] == "llm_call":
            llm_inputs.append(event["input_tokens"])
            llm_outputs.append(event["output_tokens"])
    resource = usage["resource_usage"]
    if resource["llm_calls"] != counts["llm_call"]:
        raise ValueError("usage llm_calls disagrees with the event ledger")
    if resource["human_interventions"] != counts["human_intervention"]:
        raise ValueError(
            "usage human_interventions disagrees with the event ledger"
        )
    expected_eda = {
        "compile_or_lint": counts["eda_compile_or_lint"],
        "simulation": counts["eda_simulation"],
        "formal": counts["eda_formal"],
        "synthesis": counts["eda_synthesis"],
    }
    if resource["eda_calls"] != expected_eda:
        raise ValueError("usage eda_calls disagrees with the event ledger")
    expected_input = (
        sum(value for value in llm_inputs if value is not None)
        if all(value is not None for value in llm_inputs)
        else None
    )
    expected_output = (
        sum(value for value in llm_outputs if value is not None)
        if all(value is not None for value in llm_outputs)
        else None
    )
    if resource["input_tokens"] != expected_input:
        raise ValueError("usage input_tokens disagrees with the event ledger")
    if resource["output_tokens"] != expected_output:
        raise ValueError("usage output_tokens disagrees with the event ledger")
    expected_missing = []
    if expected_input is None:
        expected_missing.append("input_tokens")
    if expected_output is None:
        expected_missing.append("output_tokens")
    if resource["missing_measurements"] != expected_missing:
        raise ValueError(
            "usage missing_measurements disagrees with the event ledger"
        )
    network = usage["network_monitor"]
    if network["attempt_count"] != counts["network_attempt"]:
        raise ValueError(
            "network monitor attempt_count disagrees with the event ledger"
        )


def _check_task_contract(
    *,
    task: dict[str, Any],
    export: dict[str, Any],
    artifacts: dict[str, Path],
    usage: dict[str, Any],
) -> None:
    if export["task_id"] != task["task_id"]:
        raise ValueError("ChipFlow export task_id does not match the task")
    if export["chipflow_run_id"] != usage["chipflow_run_id"]:
        raise ValueError("ChipFlow export and usage receipt run IDs disagree")
    contract = task["submission_contract"]
    paths = set(artifacts)
    required = set(contract["required_files"])
    editable = set(contract["editable_paths"])
    if not required.issubset(paths):
        raise ValueError(
            "ChipFlow export is missing required files: "
            + ", ".join(sorted(required - paths))
        )
    if not paths.issubset(editable):
        raise ValueError(
            "ChipFlow export contains files outside editable_paths: "
            + ", ".join(sorted(paths - editable))
        )
    if len(paths) > contract["max_files_changed"]:
        raise ValueError("ChipFlow export exceeds max_files_changed")
    total_bytes = sum(path.stat().st_size for path in artifacts.values())
    if total_bytes > contract["max_submission_bytes"]:
        raise ValueError("ChipFlow export exceeds max_submission_bytes")

    budget = task["budget"]
    resource_usage = usage["resource_usage"]
    if export["attempt"]["attempt_index"] > budget["workflow_attempts"]:
        raise ValueError("ChipFlow export attempt exceeds workflow budget")
    if resource_usage["wall_time_seconds"] > budget["wall_time_seconds"]:
        raise ValueError("ChipFlow export wall time exceeds workflow budget")
    for tool, limit in budget["eda_call_limits"].items():
        if resource_usage["eda_calls"][tool] > limit:
            raise ValueError(f"ChipFlow export {tool} calls exceed workflow budget")
    monitored = usage["network_monitor"]
    if monitored["network_access_observed"] != (
        monitored["attempt_count"] > 0
    ):
        raise ValueError(
            "network monitor access flag disagrees with attempt_count"
        )
    if not task["public_packet"]["network_access"] and monitored[
        "network_access_observed"
    ]:
        raise ValueError("offline task ChipFlow run observed network access")


def adapt_chipflow_run(
    *,
    task: dict[str, Any],
    export: dict[str, Any],
    run_root: Path,
    bundle_output: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Validate one ChipFlow export and atomically materialize its bundle."""
    if run_root.is_symlink():
        raise ValueError("ChipFlow run root must not be a symlink")
    run_root = run_root.expanduser().resolve(strict=True)
    if not run_root.is_dir():
        raise ValueError("ChipFlow run root must be a directory")
    task_schema = _load_object(TASK_SCHEMA_PATH)
    submission_schema = _load_object(SUBMISSION_SCHEMA_PATH)
    export_schema = _load_object(EXPORT_SCHEMA_PATH)
    usage_schema = _load_object(USAGE_SCHEMA_PATH)
    event_schema = _load_object(EVENT_SCHEMA_PATH)
    _validate(schema=task_schema, instance=task, name="task")
    _validate(
        schema=export_schema,
        instance=export,
        name="ChipFlow export",
    )

    usage_path = _resolve_member(run_root, export["usage_receipt"]["path"])
    if _sha256(usage_path) != export["usage_receipt"]["sha256"]:
        raise ValueError("ChipFlow usage receipt digest drift")
    usage = _load_object(usage_path)
    _validate(
        schema=usage_schema,
        instance=usage,
        name="ChipFlow usage receipt",
    )
    _validate_usage_evidence(
        run_root=run_root,
        usage=usage,
        event_schema=event_schema,
    )

    artifacts: dict[str, Path] = {}
    artifact_meta: dict[str, dict[str, Any]] = {}
    source_paths: set[str] = set()
    for item in export["artifacts"]:
        source_relative = item["source_path"]
        submission_relative = item["submission_path"]
        if source_relative in source_paths:
            raise ValueError(f"duplicate ChipFlow artifact source: {source_relative}")
        if submission_relative in artifacts:
            raise ValueError(
                f"duplicate neutral submission path: {submission_relative}"
            )
        source_paths.add(source_relative)
        source = _resolve_member(run_root, source_relative)
        if source.stat().st_size != item["bytes"]:
            raise ValueError(f"ChipFlow artifact byte count drift: {source_relative}")
        if _sha256(source) != item["sha256"]:
            raise ValueError(f"ChipFlow artifact digest drift: {source_relative}")
        artifacts[submission_relative] = source
        artifact_meta[submission_relative] = item

    _check_task_contract(
        task=task,
        export=export,
        artifacts=artifacts,
        usage=usage,
    )
    resource_usage = usage["resource_usage"]
    submission = {
        "schema_version": "rtlflowbench.submission.v1",
        "submission_id": export["submission_id"],
        "task_id": task["task_id"],
        "task_binding": _task_binding(task),
        "workflow": export["workflow"],
        "attempt": export["attempt"],
        "artifact": {
            "format": "file_bundle",
            "files": [
                {
                    "path": relative,
                    "sha256": artifact_meta[relative]["sha256"],
                    "bytes": artifact_meta[relative]["bytes"],
                }
                for relative in sorted(artifacts)
            ],
        },
        "resource_usage": resource_usage,
        "network_access_observed": usage["network_monitor"][
            "network_access_observed"
        ],
        "claims": export["claims"],
    }
    _validate(
        schema=submission_schema,
        instance=submission,
        name="neutral submission",
    )

    bundle_output = bundle_output.expanduser().resolve()
    if bundle_output.exists() or bundle_output.is_symlink():
        raise FileExistsError(f"refusing to overwrite bundle: {bundle_output}")
    bundle_output.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(
        tempfile.mkdtemp(
            prefix=f".{bundle_output.name}.",
            dir=bundle_output.parent,
        )
    )
    committed = False
    try:
        for relative, source in sorted(artifacts.items()):
            target = stage / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(source.read_bytes())
            target.chmod(0o444)
        os.replace(stage, bundle_output)
        committed = True
    finally:
        if not committed and stage.exists():
            shutil.rmtree(stage)

    adapter_receipt = {
        "schema_version": "rtlflowbench.chipflow_adapter_receipt.v1",
        "status": "submission_materialized",
        "task_id": task["task_id"],
        "chipflow_run_id": export["chipflow_run_id"],
        "submission_id": submission["submission_id"],
        "source_sha256": {
            "task": hashlib.sha256(
                json.dumps(
                    task,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest(),
            "export": hashlib.sha256(
                json.dumps(export, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
            "usage_receipt": _sha256(usage_path),
        },
        "artifact_count": len(artifacts),
        "artifact_bytes": sum(
            item["bytes"] for item in submission["artifact"]["files"]
        ),
        "network_monitor_status": usage["network_monitor"]["status"],
        "excluded_claims": [
            "Adapter success is not RTL correctness or benchmark PASS.",
            "The adapter validates receipts but does not independently attest model-provider accounting.",
            "The private evaluator has not run.",
        ],
    }
    return submission, adapter_receipt


def _write_new_json(path: Path, value: dict[str, Any]) -> None:
    path = path.expanduser().resolve()
    if path.exists() or path.is_symlink():
        raise FileExistsError(f"refusing to overwrite output: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    stage = path.with_name(f".{path.name}.tmp")
    if stage.exists() or stage.is_symlink():
        raise FileExistsError(f"temporary output already exists: {stage}")
    stage.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.replace(stage, path)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--task", type=Path, required=True)
    parser.add_argument("--export", type=Path, required=True)
    parser.add_argument("--run-root", type=Path, required=True)
    parser.add_argument("--bundle-output", type=Path, required=True)
    parser.add_argument("--submission-output", type=Path, required=True)
    parser.add_argument("--adapter-receipt-output", type=Path, required=True)
    args = parser.parse_args()
    try:
        submission_output = args.submission_output.expanduser().resolve()
        adapter_output = args.adapter_receipt_output.expanduser().resolve()
        for output in (submission_output, adapter_output):
            if output.exists() or output.is_symlink():
                raise FileExistsError(f"refusing to overwrite output: {output}")
        submission, adapter_receipt = adapt_chipflow_run(
            task=_load_object(args.task),
            export=_load_object(args.export),
            run_root=args.run_root,
            bundle_output=args.bundle_output,
        )
        _write_new_json(submission_output, submission)
        _write_new_json(adapter_output, adapter_receipt)
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
    print(
        json.dumps(
            {
                "status": "pass",
                "submission": submission,
                "adapter_receipt": adapter_receipt,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
