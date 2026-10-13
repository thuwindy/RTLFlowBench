#!/usr/bin/env python3
"""Build an external all-task development relock candidate.

The command delegates lock construction to each task's existing builder,
validates the resulting component closure against the current source tree,
and rebinds only unsigned review packets.  It never applies the generated
files, reuses a signature, admits a task, or exposes its output to a workflow.
"""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from benchmarks.golden12.conformance.package_public import (
    public_archive_sha256,
)


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
DATE_ONLY_TASKS = {
    "G04-wb2axip-split-bridge",
    "G09-axis-fifo-dv",
}
ADMISSION_RELATIVE = Path("benchmarks/golden12/admission")
RECEIPT_SCHEMA_RELATIVE = (
    ADMISSION_RELATIVE / "current_development_relock_candidate.schema.json"
)
REBINDER_RELATIVE = ADMISSION_RELATIVE / "rebind_pending_review_packet.py"
PACKAGER_RELATIVE = Path("benchmarks/golden12/conformance/package_public.py")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load(path: Path, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a regular non-symlink file: {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{label} must contain one JSON object")
    return value


def _write_new(path: Path, value: dict[str, Any]) -> None:
    if path.exists() or path.is_symlink():
        raise FileExistsError(f"refusing to overwrite output: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _external(repo_root: Path, path: Path) -> Path:
    resolved = path.expanduser().resolve()
    try:
        resolved.relative_to(repo_root)
    except ValueError:
        return resolved
    raise ValueError("development relock output must remain outside the repository")


def _parse_observed_at(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("--observed-at must include a timezone")
    return parsed


def _task_observed_at(task_id: str, observed_at: str) -> str:
    parsed = _parse_observed_at(observed_at)
    if task_id in DATE_ONLY_TASKS:
        return parsed.date().isoformat()
    return observed_at


def _run(
    *,
    argv: list[str],
    repo_root: Path,
    log_path: Path,
) -> None:
    environment = os.environ.copy()
    python_path = str(repo_root)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONPATH"] = (
        python_path
        if not environment.get("PYTHONPATH")
        else python_path + os.pathsep + environment["PYTHONPATH"]
    )
    completed = subprocess.run(
        argv,
        cwd=repo_root,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    _write_new(
        log_path,
        {
            "argv": argv,
            "exit_code": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
        },
    )
    if completed.returncode != 0:
        raise ValueError(
            f"command failed with exit {completed.returncode}; see {log_path}"
        )


def _validate_lock_schema(lock: dict[str, Any], schema_path: Path) -> None:
    if not schema_path.exists():
        return
    schema = _load(schema_path, "candidate lock schema")
    Draft202012Validator.check_schema(schema)
    errors = sorted(
        Draft202012Validator(
            schema,
            format_checker=FormatChecker(),
        ).iter_errors(lock),
        key=lambda error: tuple(str(part) for part in error.absolute_path),
    )
    if errors:
        first = errors[0]
        location = "/".join(str(part) for part in first.absolute_path)
        raise ValueError(
            "candidate lock schema error at "
            f"{location or '<root>'}: {first.message}"
        )


def _validate_components(
    *, repo_root: Path, task_id: str, lock: dict[str, Any]
) -> tuple[int, int]:
    components = lock.get("component_sha256")
    if not isinstance(components, dict) or not components:
        raise ValueError(f"candidate lock has no components: {task_id}")
    for relative, expected in sorted(components.items()):
        if not isinstance(relative, str) or not isinstance(expected, str):
            raise ValueError(f"invalid component entry: {task_id}")
        pure = PurePosixPath(relative)
        if pure.is_absolute() or ".." in pure.parts:
            raise ValueError(f"unsafe component path: {task_id}:{relative}")
        path = (repo_root / Path(*pure.parts)).resolve()
        if (
            not path.is_relative_to(repo_root)
            or path.is_symlink()
            or not path.is_file()
            or _sha256(path) != expected
        ):
            raise ValueError(f"component digest drift: {task_id}:{relative}")
    runner_contract = (
        f"benchmarks/golden12/tasks/{task_id}/"
        "public/visible/runner_contract.json"
    )
    if runner_contract not in components:
        raise ValueError(f"visible runner contract is not locked: {task_id}")
    public_root = (
        repo_root / "benchmarks/golden12/tasks" / task_id / "public"
    )
    public_files = [
        path
        for path in sorted(public_root.rglob("*"))
        if path.is_file() and "__pycache__" not in path.parts
        and path.suffix != ".pyc"
    ]
    for path in public_files:
        relative = path.relative_to(repo_root).as_posix()
        if relative not in components:
            raise ValueError(
                f"public file is not component-bound: {task_id}:{relative}"
            )
    return len(components), len(public_files)


def _review_items_pending(packet: dict[str, Any]) -> bool:
    lists = [packet.get("review_items")]
    if "reviews" in packet:
        lists.append(packet.get("reviews"))
    for items in lists:
        if not isinstance(items, list) or not items:
            return False
        for item in items:
            if not isinstance(item, dict) or item.get("status") != "pending":
                return False
            for field in (
                "reviewer",
                "independent_reviewer",
                "signed_at",
                "signed_candidate_lock_sha256",
                "signature_sha256",
            ):
                if item.get(field) is not None:
                    return False
    return True


def build_current_development_relock_candidate(
    *, repo_root: Path, output_dir: Path, observed_at: str
) -> dict[str, Any]:
    _parse_observed_at(observed_at)
    repo_root = repo_root.expanduser().resolve(strict=True)
    output_dir = _external(repo_root, output_dir)
    if output_dir.exists() or output_dir.is_symlink():
        raise FileExistsError(f"refusing to overwrite output: {output_dir}")
    output_dir.mkdir(parents=True)
    files_root = output_dir / "files"
    logs_root = output_dir / "logs"
    files_root.mkdir()
    logs_root.mkdir()

    records: list[dict[str, Any]] = []
    builder_sha256: dict[str, str] = {}
    for task_id in TASK_IDS:
        task_root = repo_root / "benchmarks/golden12/tasks" / task_id
        admission = task_root / "private/admission"
        builder = admission / "build_candidate_lock.py"
        old_lock = admission / "candidate.lock.json"
        old_packet = admission / "review_packet.json"
        task_output = files_root / task_id
        task_output.mkdir()
        new_lock = task_output / "candidate.lock.json"
        new_packet = task_output / "review_packet.json"
        task_observed_at = _task_observed_at(task_id, observed_at)
        builder_sha256[task_id] = _sha256(builder)
        _run(
            argv=[
                sys.executable,
                str(builder),
                "--repo-root",
                str(repo_root),
                "--observed-at",
                task_observed_at,
                "--output",
                str(new_lock),
            ],
            repo_root=repo_root,
            log_path=logs_root / f"{task_id}-lock.json",
        )
        _run(
            argv=[
                sys.executable,
                str(repo_root / REBINDER_RELATIVE),
                "--packet",
                str(old_packet),
                "--candidate-lock",
                str(new_lock),
                "--observed-at",
                task_observed_at,
                "--output",
                str(new_packet),
            ],
            repo_root=repo_root,
            log_path=logs_root / f"{task_id}-review-packet.json",
        )
        lock = _load(new_lock, f"{task_id} candidate lock")
        packet = _load(new_packet, f"{task_id} review packet")
        if lock.get("task_id") != task_id:
            raise ValueError(f"candidate task id mismatch: {task_id}")
        if lock.get("benchmark_ready") is not False:
            raise ValueError(f"candidate claims benchmark readiness: {task_id}")
        if lock.get("chipflow_adapter_ready") not in (None, False):
            raise ValueError(f"candidate claims adapter readiness: {task_id}")
        _validate_lock_schema(
            lock, admission / "candidate.lock.schema.json"
        )
        component_count, public_file_count = _validate_components(
            repo_root=repo_root,
            task_id=task_id,
            lock=lock,
        )
        current_public_archive = public_archive_sha256(task_root)
        candidate_public_archive = lock.get("public_archive_sha256")
        if candidate_public_archive not in (None, current_public_archive):
            raise ValueError(f"public archive digest drift: {task_id}")
        if (
            packet.get("task_id") != task_id
            or packet.get("candidate_lock_sha256") != _sha256(new_lock)
            or not _review_items_pending(packet)
        ):
            raise ValueError(f"review packet is not safely rebound: {task_id}")
        records.append(
            {
                "task_id": task_id,
                "task_observed_at": task_observed_at,
                "pretransition_candidate_lock_sha256": _sha256(old_lock),
                "pretransition_review_packet_sha256": _sha256(old_packet),
                "candidate_lock_sha256": _sha256(new_lock),
                "review_packet_sha256": _sha256(new_packet),
                "public_archive_sha256": current_public_archive,
                "candidate_public_archive_sha256": candidate_public_archive,
                "component_count": component_count,
                "public_file_count": public_file_count,
                "public_tree_component_bound": True,
                "visible_runner_contract_bound": True,
                "all_review_items_pending": True,
                "benchmark_ready": False,
                "chipflow_adapter_ready": False,
            }
        )

    result = {
        "schema_version": (
            "rtlflowbench.current_development_relock_candidate.v1"
        ),
        "observed_at": observed_at,
        "status": "verified_development_relock_candidate_pending_apply",
        "classification": "release_authority_only",
        "task_count": len(records),
        "benchmark_ready_task_count": 0,
        "chipflow_adapter_ready_task_count": 0,
        "apply_permitted": False,
        "pretransition_signature_reuse_permitted": False,
        "workflow_workspace_exposure_permitted": False,
        "source": {
            "builder_sha256": _sha256(Path(__file__).resolve()),
            "schema_sha256": _sha256(repo_root / RECEIPT_SCHEMA_RELATIVE),
            "rebinder_sha256": _sha256(repo_root / REBINDER_RELATIVE),
            "packager_sha256": _sha256(repo_root / PACKAGER_RELATIVE),
            "task_builder_sha256": dict(sorted(builder_sha256.items())),
        },
        "tasks": records,
        "excluded_claims": [
            "Candidate generation is not benchmark admission or release freeze.",
            "Generated locks and packets are external and have not been applied.",
            "No prior signature may be reused for a generated candidate digest.",
            "No AIRTL, EDA, QoR, PPA, performance, or benchmark PASS is claimed.",
        ],
    }
    schema_path = repo_root / RECEIPT_SCHEMA_RELATIVE
    schema = _load(schema_path, "development relock receipt schema")
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(
        schema,
        format_checker=FormatChecker(),
    ).validate(result)
    _write_new(output_dir / "candidate-receipt.json", result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--observed-at", required=True)
    args = parser.parse_args()
    try:
        result = build_current_development_relock_candidate(
            repo_root=args.repo_root,
            output_dir=args.output_dir,
            observed_at=args.observed_at,
        )
    except Exception as exc:
        print(
            json.dumps(
                {
                    "status": "invalid_evidence",
                    "error": f"{type(exc).__name__}: {exc}",
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
