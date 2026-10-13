#!/usr/bin/env python3
"""Summarize a fail-closed external workflow runtime environment candidate."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


HERE = Path(__file__).resolve().parent
SCHEMA = HERE / "runtime_environment_receipt.schema.json"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
IMAGE_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

WORKFLOWS = {
    "verilogcoder": {
        "display_name": "VerilogCoder",
        "commit": "8b13108869f276c7b644dd88beabcb401a5cfa92",
        "tracked_manifest_sha256": "01ac57a9e5bdb79d12055554fc5646d2b6451602f982377f48f35505d2328d69",
        "source_entry_count": 1268,
        "image_id": "c94231c94fee83b5ee6ace21846cde18e841abc38d9deac581e021c9b9ceda53",
        "image_digest": "sha256:702a5aebe52854489199657e076eb974425688119dc65bd163616601a6b25a81",
        "image_size_bytes": 653164045,
        "overlay_file_count": 21199,
        "source_tracked_pyc_count": 24,
    },
    "hdlagent": {
        "display_name": "HDLAgent",
        "commit": "bd2321e03d1d60b0656d7ff0992f35f5906a824d",
        "tracked_manifest_sha256": "843ccf62106d6ae2e953f5d5b5a8fd7ea4160c969084d010acc59d4e7ba6d91f",
        "source_entry_count": 145,
        "image_id": "fcb29e8f0f7a83518af91379996b8c328cedb47226cd1fc7c87a81c809acb14c",
        "image_digest": "sha256:b285ad074fe59fe4a958fc50b43189d98f55cd26014801dc25f258ad7bd2f835",
        "image_size_bytes": 389396452,
        "overlay_file_count": 7959,
        "source_tracked_pyc_count": 0,
    },
}

PUBLIC_BASE = {
    "image_id": "4168e7cb461aa2852ff9446a85fdf6bee4ace23830388c49b1d02413d50a38bf",
    "image_digest": "sha256:d6ed5a579d8ad959963079292b0d895107e0ba44ac2c91e636417a47f7a4b207",
}


def _sha256(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"expected regular evidence file: {path.name}")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _require_zero(path: Path) -> int:
    value = path.read_text(encoding="utf-8").strip()
    if value != "0":
        raise ValueError(f"non-zero or invalid evidence exit code: {path.name}")
    return 0


def _require_empty(path: Path) -> str:
    if path.read_bytes():
        raise ValueError(f"expected empty evidence artifact: {path.name}")
    return _sha256(path)


def _receipt(directory: Path, *artifacts: str) -> dict[str, Any]:
    values = []
    for artifact in artifacts:
        path = directory / artifact
        values.append({"artifact": artifact, "sha256": _sha256(path)})
    return {"evidence_id": directory.name, "artifacts": values}


def _identity(path: Path) -> dict[str, Any]:
    fields = path.read_text(encoding="utf-8").strip().split()
    if len(fields) != 3 or not SHA256_RE.fullmatch(fields[0]):
        raise ValueError("invalid image identity evidence")
    if not IMAGE_DIGEST_RE.fullmatch(fields[1]) or not fields[2].isdigit():
        raise ValueError("invalid image identity evidence")
    return {
        "image_id": fields[0],
        "image_digest": fields[1],
        "size_bytes": int(fields[2]),
    }


def _version_line(path: Path) -> str:
    lines = [line.strip() for line in path.read_text(errors="replace").splitlines() if line.strip()]
    if not lines:
        raise ValueError(f"missing tool version output: {path.name}")
    return lines[0]


def build_receipt(
    *,
    workflow_id: str,
    source_snapshot_root: Path,
    source_snapshot_evidence: Path,
    wheelhouse_acquisition_evidence: Path,
    wheelhouse_evidence: Path,
    offline_rebuild_evidence: Path,
    offline_validation_evidence: Path | None,
    overlay_evidence: Path,
    system_runtime_evidence: Path,
    image_context_evidence: Path,
    image_build_evidence: Path,
    preflight_evidence: Path,
    observed_at: str,
) -> dict[str, Any]:
    if workflow_id not in WORKFLOWS:
        raise ValueError("unsupported workflow id")
    expected = WORKFLOWS[workflow_id]
    snapshot = json.loads(
        (source_snapshot_root / "source_snapshot.json").read_text(encoding="utf-8")
    )
    if (
        snapshot.get("commit") != expected["commit"]
        or snapshot.get("tracked_manifest_sha256")
        != expected["tracked_manifest_sha256"]
        or snapshot.get("entry_count") != expected["source_entry_count"]
    ):
        raise ValueError("source snapshot identity drift")
    source_manifest_sha = _sha256(source_snapshot_root / "source_snapshot.json")
    evidence_manifest_line = (
        source_snapshot_evidence / "snapshot-manifest.sha256"
    ).read_text(encoding="utf-8").split()[0]
    if evidence_manifest_line != source_manifest_sha:
        raise ValueError("source snapshot evidence digest drift")
    _require_zero(source_snapshot_evidence / "export.exit-code.txt")

    _require_zero(wheelhouse_acquisition_evidence / "download.exit-code.txt")
    wheel_files = (wheelhouse_evidence / "wheelhouse.files.txt").read_text(
        encoding="utf-8"
    ).splitlines()
    if not wheel_files:
        raise ValueError("wheelhouse evidence is empty")

    for repeat in (1, 2):
        for gate in ("install", "pip-check", "import", "freeze"):
            _require_zero(
                offline_rebuild_evidence
                / f"rebuild-{repeat}.{gate}.exit-code.txt"
            )
        lock_match = offline_rebuild_evidence / f"rebuild-{repeat}.lock-match.exit-code.txt"
        if offline_validation_evidence is None:
            _require_zero(lock_match)
        else:
            _require_zero(
                offline_validation_evidence
                / f"rebuild-{repeat}.normalized-lock-match.exit-code.txt"
            )

    for repeat in ("a", "b"):
        _require_zero(overlay_evidence / f"install-{repeat}.exit-code.txt")
    _require_zero(overlay_evidence / "files-match.exit-code.txt")
    _require_zero(overlay_evidence / "symlinks-match.exit-code.txt")
    overlay_files = (
        overlay_evidence / "overlay-a.files.sha256"
    ).read_text(encoding="utf-8").splitlines()
    if len(overlay_files) != expected["overlay_file_count"]:
        raise ValueError("deterministic overlay file count drift")

    required_system_libs = (
        system_runtime_evidence / "required-libs.txt"
    ).read_text(encoding="utf-8").splitlines()
    if len(required_system_libs) != 3:
        raise ValueError("minimal system runtime evidence drift")

    context_files = (
        image_context_evidence / "context-files.sha256"
    ).read_text(encoding="utf-8").splitlines()
    if not context_files:
        raise ValueError("image context evidence is empty")
    for repeat in ("a", "b"):
        _require_zero(image_build_evidence / f"build-{repeat}.exit-code.txt")
    _require_zero(image_build_evidence / "identity-match.exit-code.txt")
    identity_a = _identity(image_build_evidence / "identity-a.txt")
    identity_b = _identity(image_build_evidence / "identity-b.txt")
    if identity_a != identity_b or identity_a != {
        "image_id": expected["image_id"],
        "image_digest": expected["image_digest"],
        "size_bytes": expected["image_size_bytes"],
    }:
        raise ValueError("deterministic runtime image identity drift")

    for gate in (
        "runtime-smoke",
        "launcher-help",
        "iverilog-version",
        "yosys-version",
        "benchmark-sensitive-path-scan",
    ):
        _require_zero(preflight_evidence / f"{gate}.exit-code.txt")
    sensitive_sha = _require_empty(
        preflight_evidence / "benchmark-sensitive-path-matches.txt"
    )

    evidence = [
        _receipt(source_snapshot_evidence, "export.exit-code.txt", "snapshot-manifest.sha256"),
        _receipt(wheelhouse_acquisition_evidence, "download.exit-code.txt", "wheelhouse.sha256"),
        _receipt(wheelhouse_evidence, "requirements.lock.txt", "wheelhouse.sha256"),
        _receipt(offline_rebuild_evidence, "evidence-files.sha256"),
        _receipt(overlay_evidence, "overlay-a.files.sha256", "overlay-b.files.sha256"),
        _receipt(system_runtime_evidence, "files.sha256", "source-packages.sha256"),
        _receipt(image_context_evidence, "context-files.sha256", "context-symlinks.txt"),
        _receipt(image_build_evidence, "identity-a.txt", "identity-b.txt"),
        _receipt(preflight_evidence, "image-inspect.json", "evidence-files.sha256"),
    ]
    if offline_validation_evidence is not None:
        evidence.append(_receipt(offline_validation_evidence, "evidence-files.sha256"))

    result = {
        "schema_version": "rtlflowbench.external_runtime_environment_receipt.v1",
        "status": "same_server_deterministic_runtime_reproduced_not_release_frozen",
        "observed_at": observed_at,
        "workflow": {
            "workflow_id": workflow_id,
            "display_name": expected["display_name"],
            "commit": expected["commit"],
            "tracked_manifest_sha256": expected["tracked_manifest_sha256"],
        },
        "source_snapshot": {
            "entry_count": expected["source_entry_count"],
            "manifest_sha256": source_manifest_sha,
            "tracked_python_cache_count": expected["source_tracked_pyc_count"],
            "tracked_python_cache_execution": False,
        },
        "dependency_environment": {
            "requirements_lock_sha256": _sha256(wheelhouse_evidence / "requirements.lock.txt"),
            "wheelhouse_manifest_sha256": _sha256(wheelhouse_evidence / "wheelhouse.sha256"),
            "wheelhouse_distribution_count": len(wheel_files),
            "two_offline_rebuilds_passed": True,
            "two_deterministic_overlay_trees_equal": True,
            "overlay_file_count": len(overlay_files),
            "overlay_python_cache_count": 0,
        },
        "container": {
            "public_base": PUBLIC_BASE,
            "system_runtime_source_bound": True,
            "build_network": "none",
            "build_no_cache": True,
            "build_omit_history": True,
            "build_timestamp": 0,
            **identity_a,
            "two_build_identity_equal": True,
            "context_file_count": len(context_files),
        },
        "preflight": {
            "status": "pass",
            "source_binding": True,
            "core_import": True,
            "launcher_help": True,
            "network": "none",
            "iverilog_version": _version_line(preflight_evidence / "iverilog-version.stdout.log"),
            "yosys_version": _version_line(preflight_evidence / "yosys-version.stdout.log"),
            "benchmark_sensitive_path_scan_empty": True,
            "benchmark_sensitive_path_matches_sha256": sensitive_sha,
        },
        "evidence": evidence,
        "claims": {
            "environment_reproducible_same_server": True,
            "cross_host_reproduced": False,
            "release_frozen": False,
            "provider_call_observed": False,
            "airtl_run_observed": False,
            "hidden_evaluator_run": False,
            "rtl_verdict_produced": False,
            "adapter_ready": False,
            "benchmark_ready": False,
        },
        "remaining_gates": [
            "provider configuration and minimal provider preflight",
            "public request construction bound to frozen budget/model/seed",
            "network-separated workflow attempt and exact output collection",
            "private evaluator execution outside the workflow container",
            "repeatability across the complete all-task schedule",
            "cross-host reproduction and independent release review",
        ],
    }
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workflow", choices=sorted(WORKFLOWS), required=True)
    parser.add_argument("--source-snapshot-root", type=Path, required=True)
    parser.add_argument("--source-snapshot-evidence", type=Path, required=True)
    parser.add_argument("--wheelhouse-acquisition-evidence", type=Path, required=True)
    parser.add_argument("--wheelhouse-evidence", type=Path, required=True)
    parser.add_argument("--offline-rebuild-evidence", type=Path, required=True)
    parser.add_argument("--offline-validation-evidence", type=Path)
    parser.add_argument("--overlay-evidence", type=Path, required=True)
    parser.add_argument("--system-runtime-evidence", type=Path, required=True)
    parser.add_argument("--image-context-evidence", type=Path, required=True)
    parser.add_argument("--image-build-evidence", type=Path, required=True)
    parser.add_argument("--preflight-evidence", type=Path, required=True)
    parser.add_argument("--observed-at", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists() or args.output.is_symlink():
        raise FileExistsError("refusing to overwrite runtime environment receipt")
    result = build_receipt(
        workflow_id=args.workflow,
        source_snapshot_root=args.source_snapshot_root,
        source_snapshot_evidence=args.source_snapshot_evidence,
        wheelhouse_acquisition_evidence=args.wheelhouse_acquisition_evidence,
        wheelhouse_evidence=args.wheelhouse_evidence,
        offline_rebuild_evidence=args.offline_rebuild_evidence,
        offline_validation_evidence=args.offline_validation_evidence,
        overlay_evidence=args.overlay_evidence,
        system_runtime_evidence=args.system_runtime_evidence,
        image_context_evidence=args.image_context_evidence,
        image_build_evidence=args.image_build_evidence,
        preflight_evidence=args.preflight_evidence,
        observed_at=args.observed_at,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"status": result["status"], "workflow": args.workflow, "image_digest": result["container"]["image_digest"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
