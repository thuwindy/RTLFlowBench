#!/usr/bin/env python3
"""Build a ChipFlow benchmark usage receipt from a typed event ledger."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator


CONFORMANCE_ROOT = Path(__file__).resolve().parent
ADAPTER_ROOT = CONFORMANCE_ROOT / "adapters"
EVENT_SCHEMA_PATH = ADAPTER_ROOT / "chipflow_usage_events.schema.json"
USAGE_SCHEMA_PATH = ADAPTER_ROOT / "chipflow_usage_receipt.schema.json"


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} must contain one JSON object")
    return value


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _parse_time(value: str, *, field: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError(f"{field} must include a timezone")
    return parsed


def _relative_member(root: Path, path: Path) -> tuple[str, Path]:
    if path.is_symlink():
        raise ValueError(f"usage evidence must not be a symlink: {path}")
    resolved = path.expanduser().resolve(strict=True)
    if not resolved.is_file():
        raise ValueError(f"usage evidence must be a regular file: {path}")
    try:
        relative = resolved.relative_to(root).as_posix()
    except ValueError as exc:
        raise ValueError(f"usage evidence escapes run root: {path}") from exc
    current = root
    for part in Path(relative).parts:
        current = current / part
        if current.is_symlink():
            raise ValueError(
                f"usage evidence path contains a symlink: {relative}"
            )
    return relative, resolved


def _summarize_events(events: list[dict[str, Any]]) -> tuple[dict[str, Any], int]:
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
    event_ids: set[str] = set()
    for event in events:
        if event["event_id"] in event_ids:
            raise ValueError(f"duplicate usage event_id: {event['event_id']}")
        event_ids.add(event["event_id"])
        counts[event["event_type"]] += 1
        if event["event_type"] == "llm_call":
            llm_inputs.append(event["input_tokens"])
            llm_outputs.append(event["output_tokens"])
    input_tokens = (
        sum(value for value in llm_inputs if value is not None)
        if all(value is not None for value in llm_inputs)
        else None
    )
    output_tokens = (
        sum(value for value in llm_outputs if value is not None)
        if all(value is not None for value in llm_outputs)
        else None
    )
    missing = []
    if input_tokens is None:
        missing.append("input_tokens")
    if output_tokens is None:
        missing.append("output_tokens")
    return (
        {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "llm_calls": counts["llm_call"],
            "eda_calls": {
                "compile_or_lint": counts["eda_compile_or_lint"],
                "simulation": counts["eda_simulation"],
                "formal": counts["eda_formal"],
                "synthesis": counts["eda_synthesis"],
            },
            "human_interventions": counts["human_intervention"],
            "missing_measurements": missing,
        },
        counts["network_attempt"],
    )


def build_usage_receipt(
    *,
    run_root: Path,
    event_ledger_path: Path,
    chipflow_run_id: str,
    started_at: str,
    completed_at: str,
    network_method: str | None = None,
) -> dict[str, Any]:
    if run_root.is_symlink():
        raise ValueError("ChipFlow run root must not be a symlink")
    run_root = run_root.expanduser().resolve(strict=True)
    if not run_root.is_dir():
        raise ValueError("ChipFlow run root must be a directory")
    if not chipflow_run_id:
        raise ValueError("run id must be non-empty")
    ledger_relative, ledger_path = _relative_member(
        run_root,
        event_ledger_path,
    )
    ledger = _load(ledger_path)
    event_schema = _load(EVENT_SCHEMA_PATH)
    Draft202012Validator(event_schema).validate(ledger)
    if ledger["chipflow_run_id"] != chipflow_run_id:
        raise ValueError("event ledger run ID does not match --run-id")
    ledger_network_method = ledger["network_monitor"]["method"]
    if (
        network_method is not None
        and network_method != ledger_network_method
    ):
        raise ValueError(
            "network monitor method disagrees with the event ledger"
        )

    evidence_relatives = {
        relative
        for event in ledger["events"]
        for relative in event["evidence_refs"]
    }
    evidence_relatives.update(ledger["collection_evidence_refs"])
    network_evidence_ref = ledger["network_monitor"]["evidence_ref"]
    if network_evidence_ref not in ledger["collection_evidence_refs"]:
        raise ValueError(
            "network monitor evidence must be collection evidence"
        )
    evidence: dict[str, Path] = {ledger_relative: ledger_path}
    for relative in sorted(evidence_relatives):
        normalized, path = _relative_member(run_root, run_root / relative)
        if normalized != relative:
            raise ValueError(f"non-canonical usage evidence path: {relative}")
        evidence[relative] = path

    started = _parse_time(started_at, field="started_at")
    completed = _parse_time(completed_at, field="completed_at")
    wall_time_seconds = (completed - started).total_seconds()
    if wall_time_seconds < 0:
        raise ValueError("completed_at precedes started_at")
    summary, network_attempt_count = _summarize_events(ledger["events"])
    receipt = {
        "schema_version": "rtlflowbench.chipflow_usage_receipt.v1",
        "chipflow_run_id": chipflow_run_id,
        "started_at": started_at,
        "completed_at": completed_at,
        "collection_status": {
            "wall_time": "complete",
            "llm_calls": "complete",
            "eda_calls": "complete",
            "human_interventions": "complete",
        },
        "resource_usage": {
            "wall_time_seconds": wall_time_seconds,
            **summary,
        },
        "network_monitor": {
            "status": "complete",
            "network_access_observed": network_attempt_count > 0,
            "attempt_count": network_attempt_count,
            "method": ledger_network_method,
        },
        "event_ledger": {
            "path": ledger_relative,
            "sha256": _sha256(ledger_path),
        },
        "evidence_manifest": [
            {
                "path": relative,
                "sha256": _sha256(path),
                "bytes": path.stat().st_size,
            }
            for relative, path in sorted(evidence.items())
        ],
    }
    usage_schema = _load(USAGE_SCHEMA_PATH)
    Draft202012Validator(usage_schema).validate(receipt)
    return receipt


def _write_new(path: Path, value: dict[str, Any]) -> None:
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
    parser.add_argument("--run-root", type=Path, required=True)
    parser.add_argument("--event-ledger", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--started-at", required=True)
    parser.add_argument("--completed-at", required=True)
    parser.add_argument("--network-method")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        receipt = build_usage_receipt(
            run_root=args.run_root,
            event_ledger_path=args.event_ledger,
            chipflow_run_id=args.run_id,
            started_at=args.started_at,
            completed_at=args.completed_at,
            network_method=args.network_method,
        )
        _write_new(args.output, receipt)
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
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
