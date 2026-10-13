#!/usr/bin/env python3
"""Fail-closed public-only bridge from MAGE output to a neutral submission.

The bridge never invokes MAGE, a model provider, an EDA tool, or a private
evaluator.  It prepares a public-only request and maps an already-produced
``rtl.sv`` byte-for-byte into one single-file Spec-to-RTL submission.  A
separate runner and isolation receipt are still required for an actual AIRTL
attempt.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
from typing import Any


HERE = Path(__file__).resolve().parent
CONFORMANCE_ROOT = HERE.parent
PROFILE_PATH = HERE / "mage_profile.json"
PUBLIC_SPEC_PATHS = (
    "spec/design_spec.md",
    "spec/acceptance_spec.json",
    "spec/interface_spec.json",
)
BRIDGE_NAME = "rtlflowbench-mage-submission-bridge"
BRIDGE_VERSION = "1"
SUPPORTED_FAMILY = "spec_to_rtl"


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ValueError(f"could not load module: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _load_object(path: Path, label: str) -> dict[str, Any]:
    if not path.exists() or not path.is_file() or path.is_symlink():
        raise ValueError(f"{label} must be a regular non-symlink file")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{label} must contain one JSON object")
    return payload


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _canonical_sha256(value: dict[str, Any]) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return _sha256_bytes(encoded)


def _write_new_json(path: Path, payload: dict[str, Any]) -> None:
    if path.exists():
        raise FileExistsError(f"refusing to overwrite output: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _resolve_public_root(path: Path) -> Path:
    unresolved = path.expanduser().absolute()
    if unresolved.is_symlink():
        raise ValueError("task public root must be a regular non-symlink directory")
    root = unresolved.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("task public root must be a regular non-symlink directory")
    if (root / "private").exists():
        raise ValueError("task public root contains a private directory")
    return root


def _read_public_file(root: Path, relative: str) -> tuple[bytes, Path]:
    path = root / relative
    resolved = path.resolve(strict=True)
    if root not in resolved.parents or not path.is_file() or path.is_symlink():
        raise ValueError(f"public input is not a regular in-root file: {relative}")
    return path.read_bytes(), path


def _profile() -> dict[str, Any]:
    return _load_object(PROFILE_PATH, "MAGE profile")


def _task(root: Path) -> tuple[dict[str, Any], Any]:
    packager = _load_module(
        "rtlflowbench_mage_bridge_packager",
        CONFORMANCE_ROOT / "package_submission.py",
    )
    task = _load_object(root / "external_task.json", "task descriptor")
    packager._validate("task", task)
    return task, packager


def classify_public_task_shape(task: dict[str, Any]) -> dict[str, Any]:
    """Classify support using public shape fields, never a Golden-12 task id."""
    if task["family"] != SUPPORTED_FAMILY:
        return {
            "supported": False,
            "reason_code": "unsupported_capability",
            "reason": (
                "MAGE exposes only the public spec_to_rtl (Spec-to-RTL) "
                "workflow contract."
            ),
        }
    if task["public_packet"]["contains_evaluator_assets"]:
        return {
            "supported": False,
            "reason_code": "security_policy_block",
            "reason": "The public packet reports evaluator assets.",
        }
    if task["public_packet"]["network_access"]:
        return {
            "supported": False,
            "reason_code": "missing_required_public_contract",
            "reason": "The MAGE bridge requires an offline workflow workspace.",
        }
    contract = task["submission_contract"]
    required = contract["required_files"]
    editable = contract["editable_paths"]
    if len(required) != 1 or editable != required:
        return {
            "supported": False,
            "reason_code": "unsupported_submission_shape",
            "reason": (
                "MAGE emits one RTL file and cannot neutrally represent this "
                "multi-file or non-identical editable contract."
            ),
        }
    target = required[0]
    if not target.endswith((".sv", ".v")):
        return {
            "supported": False,
            "reason_code": "unsupported_submission_shape",
            "reason": "The single required output is not a Verilog source file.",
        }
    return {
        "supported": True,
        "reason_code": None,
        "reason": None,
        "target_output_path": target,
    }


def _check_single_file_spec_task(task: dict[str, Any]) -> str:
    classification = classify_public_task_shape(task)
    if not classification["supported"]:
        raise ValueError(
            f"MAGE bridge {classification['reason_code']}: "
            f"{classification['reason']}"
        )
    return classification["target_output_path"]


def _check_release_task(
    task: dict[str, Any], isolation_receipt_path: Path | None
) -> dict[str, Any]:
    if (
        task["packet_status"] != "frozen"
        or task["public_packet"]["digest_status"] != "frozen"
        or task["public_packet"]["sha256"] is None
        or task["budget"]["status"] != "frozen"
    ):
        raise ValueError("release mode requires a frozen packet, digest and budget")
    if (
        task["rights"]["status"] != "approved"
        or not task["rights"]["redistribution_review_complete"]
    ):
        raise ValueError("release mode requires completed independent rights review")
    if isolation_receipt_path is None:
        raise ValueError("release mode requires an isolation receipt")
    receipt = _load_object(isolation_receipt_path, "isolation receipt")
    required = {
        "status": "pass",
        "provider_egress_separated": True,
        "workspace_network_disabled": True,
        "eda_subprocess_network_disabled": True,
    }
    if any(receipt.get(key) != value for key, value in required.items()):
        raise ValueError("isolation receipt does not prove separated offline EDA")
    evidence_sha256 = receipt.get("evidence_sha256")
    if not isinstance(evidence_sha256, str) or len(evidence_sha256) != 64:
        raise ValueError("isolation receipt evidence_sha256 is invalid")
    return {
        "status": "pass",
        "receipt_sha256": _sha256(isolation_receipt_path),
        "evidence_sha256": evidence_sha256,
    }


def _configuration(
    *,
    task: dict[str, Any],
    profile: dict[str, Any],
    mode: str,
    prompt_bytes: bytes,
    target: str,
    isolation: dict[str, Any],
) -> dict[str, Any]:
    return {
        "adapter_name": BRIDGE_NAME,
        "adapter_version": BRIDGE_VERSION,
        "mode": mode,
        "upstream_commit": profile["upstream"]["commit"],
        "source_manifest_sha256": profile["source_intake"]["manifest_sha256"],
        "task_descriptor_sha256": _canonical_sha256(task),
        "prompt_sha256": _sha256_bytes(prompt_bytes),
        "golden_tb_path": None,
        "golden_rtl_blackbox_path": None,
        "target_output_path": target,
        "isolation": isolation,
    }


def _build_prompt(root: Path) -> tuple[str, list[dict[str, Any]]]:
    sections: list[str] = []
    sources: list[dict[str, Any]] = []
    for relative in PUBLIC_SPEC_PATHS:
        content, path = _read_public_file(root, relative)
        if len(content) > 1_048_576:
            raise ValueError(f"public specification is unexpectedly large: {relative}")
        text = content.decode("utf-8")
        sections.append(f"## {relative}\n\n{text.rstrip()}\n")
        sources.append(
            {
                "path": relative,
                "sha256": _sha256(path),
                "bytes": len(content),
            }
        )
    return "\n".join(sections), sources


def prepare_request(
    *,
    task_public_root: Path,
    output_dir: Path,
    observed_at: str,
    mode: str,
    upstream_commit: str,
    source_manifest_sha256: str,
    isolation_receipt_path: Path | None = None,
) -> dict[str, Any]:
    if mode not in {"development", "release"}:
        raise ValueError("mode must be development or release")
    output_dir = output_dir.expanduser().absolute()
    if output_dir.exists():
        raise FileExistsError(f"refusing to overwrite output: {output_dir}")
    root = _resolve_public_root(task_public_root)
    task, _ = _task(root)
    target = _check_single_file_spec_task(task)
    profile = _profile()
    if upstream_commit != profile["upstream"]["commit"]:
        raise ValueError("upstream MAGE commit disagrees with the reviewed profile")
    if source_manifest_sha256 != profile["source_intake"]["manifest_sha256"]:
        raise ValueError("MAGE source manifest disagrees with the reviewed profile")

    isolation = (
        _check_release_task(task, isolation_receipt_path)
        if mode == "release"
        else {"status": "unproven_development_only"}
    )
    prompt, public_sources = _build_prompt(root)
    prompt_bytes = prompt.encode("utf-8")
    task_descriptor_sha256 = _canonical_sha256(task)
    configuration = _configuration(
        task=task,
        profile=profile,
        mode=mode,
        prompt_bytes=prompt_bytes,
        target=target,
        isolation=isolation,
    )
    request = {
        "schema_version": "rtlflowbench.mage_bridge_request.v1",
        "observed_at": observed_at,
        "status": (
            "release_request_prepared_not_run"
            if mode == "release"
            else "development_only_not_run"
        ),
        "mode": mode,
        "task_id": task["task_id"],
        "task_binding": {
            "benchmark_id": task["benchmark_id"],
            "benchmark_version": task["benchmark_version"],
            "task_descriptor_sha256": task_descriptor_sha256,
            "public_packet_sha256": task["public_packet"]["sha256"],
        },
        "upstream": {
            "name": "MAGE",
            "version": profile["upstream"]["version"],
            "commit": upstream_commit,
            "source_manifest_sha256": source_manifest_sha256,
        },
        "prompt": {
            "path": "public_prompt.txt",
            "sha256": _sha256_bytes(prompt_bytes),
            "bytes": len(prompt_bytes),
            "public_sources": public_sources,
        },
        "mage": {
            "top_agent": {
                "golden_tb_path": None,
                "golden_rtl_blackbox_path": None,
                "expected_output_file": "rtl.sv",
            },
            "submitted_output_path": target,
        },
        "isolation": isolation,
        "configuration_sha256": _canonical_sha256(configuration),
        "airtl_run_observed": False,
        "rtl_verdict_produced": False,
        "adapter_ready": False,
        "benchmark_ready": False,
        "excluded_claims": [
            "Preparing a public prompt is not a MAGE or AIRTL workflow run.",
            "No private evaluator, golden testbench or golden RTL is provided.",
            "No RTL PASS, score, PPA, QoR or readiness is claimed.",
        ],
    }
    output_dir.mkdir(parents=True)
    (output_dir / "public_prompt.txt").write_bytes(prompt_bytes)
    _write_new_json(output_dir / "mage_request.json", request)
    return request


def collect_output(
    *,
    task_public_root: Path,
    request_path: Path,
    metadata_path: Path,
    mage_output_dir: Path,
    bundle_root: Path,
    submission_path: Path,
    receipt_path: Path,
    observed_at: str,
    isolation_receipt_path: Path | None = None,
) -> dict[str, Any]:
    root = _resolve_public_root(task_public_root)
    task, packager = _task(root)
    target = _check_single_file_spec_task(task)
    request = _load_object(request_path, "MAGE bridge request")
    metadata = _load_object(metadata_path, "submission metadata")
    if request.get("schema_version") != "rtlflowbench.mage_bridge_request.v1":
        raise ValueError("unsupported MAGE bridge request")
    mode = request.get("mode")
    if mode not in {"development", "release"}:
        raise ValueError("MAGE bridge request mode is invalid")
    expected_status = (
        "release_request_prepared_not_run"
        if mode == "release"
        else "development_only_not_run"
    )
    if request.get("status") != expected_status:
        raise ValueError("MAGE bridge request status drift")
    if request.get("task_id") != task["task_id"]:
        raise ValueError("MAGE bridge request task_id drift")
    task_binding = request.get("task_binding")
    if not isinstance(task_binding, dict):
        raise ValueError("MAGE bridge request task binding is missing")
    if task_binding.get("benchmark_id") != task["benchmark_id"]:
        raise ValueError("MAGE bridge request benchmark_id drift")
    if task_binding.get("benchmark_version") != task["benchmark_version"]:
        raise ValueError("MAGE bridge request benchmark_version drift")
    if task_binding.get("task_descriptor_sha256") != _canonical_sha256(task):
        raise ValueError("MAGE bridge request task descriptor drift")
    if task_binding.get("public_packet_sha256") != task["public_packet"]["sha256"]:
        raise ValueError("MAGE bridge request public packet digest drift")

    profile = _profile()
    upstream = request.get("upstream")
    if not isinstance(upstream, dict) or upstream.get("name") != "MAGE":
        raise ValueError("MAGE bridge request upstream identity drift")
    if upstream.get("version") != profile["upstream"]["version"]:
        raise ValueError("upstream MAGE version drift")
    if upstream.get("commit") != profile["upstream"]["commit"]:
        raise ValueError("upstream MAGE commit drift")
    if (
        upstream.get("source_manifest_sha256")
        != profile["source_intake"]["manifest_sha256"]
    ):
        raise ValueError("upstream MAGE source manifest drift")

    mage = request.get("mage")
    if not isinstance(mage, dict) or mage.get("submitted_output_path") != target:
        raise ValueError("MAGE bridge target output drift")
    top_agent = mage.get("top_agent")
    if not isinstance(top_agent, dict):
        raise ValueError("MAGE bridge top-agent binding is missing")
    if top_agent.get("expected_output_file") != "rtl.sv":
        raise ValueError("MAGE bridge expected output drift")
    if top_agent.get("golden_tb_path") is not None:
        raise ValueError("MAGE bridge request exposes a golden testbench")
    if top_agent.get("golden_rtl_blackbox_path") is not None:
        raise ValueError("MAGE bridge request exposes golden RTL")

    prompt, public_sources = _build_prompt(root)
    prompt_bytes = prompt.encode("utf-8")
    prompt_binding = request.get("prompt")
    if not isinstance(prompt_binding, dict):
        raise ValueError("MAGE bridge public prompt binding is missing")
    if prompt_binding.get("path") != "public_prompt.txt":
        raise ValueError("MAGE bridge public prompt path drift")
    if prompt_binding.get("sha256") != _sha256_bytes(prompt_bytes):
        raise ValueError("MAGE bridge public prompt digest drift")
    if prompt_binding.get("bytes") != len(prompt_bytes):
        raise ValueError("MAGE bridge public prompt size drift")
    if prompt_binding.get("public_sources") != public_sources:
        raise ValueError("MAGE bridge public prompt source drift")
    request_root = request_path.expanduser().resolve(strict=True).parent
    prompt_path = request_root / "public_prompt.txt"
    if (
        not prompt_path.exists()
        or not prompt_path.is_file()
        or prompt_path.is_symlink()
        or prompt_path.read_bytes() != prompt_bytes
    ):
        raise ValueError("MAGE bridge public prompt file drift")

    if mode == "release":
        if isolation_receipt_path is None:
            raise ValueError("release collect requires an isolation receipt")
        isolation = _check_release_task(task, isolation_receipt_path)
        if request.get("isolation") != isolation:
            raise ValueError("MAGE bridge isolation receipt drift")
    else:
        if isolation_receipt_path is not None:
            raise ValueError("development collect must not accept an isolation receipt")
        isolation = {"status": "unproven_development_only"}
        if request.get("isolation") != isolation:
            raise ValueError("MAGE bridge development isolation status drift")

    configuration = _configuration(
        task=task,
        profile=profile,
        mode=mode,
        prompt_bytes=prompt_bytes,
        target=target,
        isolation=isolation,
    )
    if request.get("configuration_sha256") != _canonical_sha256(configuration):
        raise ValueError("MAGE bridge request configuration drift")
    if any(
        request.get(key) is not False
        for key in (
            "airtl_run_observed",
            "rtl_verdict_produced",
            "adapter_ready",
            "benchmark_ready",
        )
    ):
        raise ValueError("MAGE bridge request contains an unsupported success claim")
    workflow = metadata.get("workflow")
    if not isinstance(workflow, dict):
        raise ValueError("submission workflow metadata is missing")
    if (
        workflow.get("name") != "MAGE"
        or workflow.get("adapter_name") != BRIDGE_NAME
        or workflow.get("adapter_version") != BRIDGE_VERSION
    ):
        raise ValueError("submission workflow metadata is not the MAGE bridge")
    if workflow.get("config_sha256") != request["configuration_sha256"]:
        raise ValueError("submission configuration_sha256 disagrees with request")

    mage_output_dir = mage_output_dir.expanduser().resolve(strict=True)
    if not mage_output_dir.is_dir() or mage_output_dir.is_symlink():
        raise ValueError("MAGE output root must be a regular directory")
    rtl_path = mage_output_dir / top_agent["expected_output_file"]
    if not rtl_path.exists() or not rtl_path.is_file() or rtl_path.is_symlink():
        raise ValueError("MAGE rtl.sv must be a regular non-symlink file")
    rtl_bytes = rtl_path.read_bytes()
    if len(rtl_bytes) > task["submission_contract"]["max_submission_bytes"]:
        raise ValueError("MAGE rtl.sv exceeds the submission byte budget")

    bundle_root = bundle_root.expanduser().absolute()
    submission_path = submission_path.expanduser().absolute()
    receipt_path = receipt_path.expanduser().absolute()
    for path in (bundle_root, submission_path, receipt_path):
        if path.exists():
            raise FileExistsError(f"refusing to overwrite output: {path}")
    bundle_root.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(
        tempfile.mkdtemp(prefix=".mage-bridge-", dir=bundle_root.parent)
    )
    try:
        staged_target = stage / target
        staged_target.parent.mkdir(parents=True, exist_ok=True)
        staged_target.write_bytes(rtl_bytes)
        submission = packager.package_submission(
            task=task,
            metadata=metadata,
            bundle_root=stage,
        )
        os.replace(stage, bundle_root)
    finally:
        if stage.exists():
            shutil.rmtree(stage)

    _write_new_json(submission_path, submission)
    receipt = {
        "schema_version": "rtlflowbench.mage_bridge_receipt.v1",
        "observed_at": observed_at,
        "status": (
            "release_candidate_conformant_submission_only"
            if mode == "release"
            else "development_conformant_submission_only"
        ),
        "task_id": task["task_id"],
        "mode": mode,
        "request_sha256": _sha256(request_path),
        "metadata_sha256": _sha256(metadata_path),
        "submission_sha256": _sha256(submission_path),
        "mapping": {
            "source_file": "rtl.sv",
            "source_sha256": _sha256_bytes(rtl_bytes),
            "target_file": target,
            "target_sha256": _sha256(bundle_root / target),
            "bytes_preserved_exactly": True,
            "unsubmitted_mage_files_ignored": True,
        },
        "airtl_run_observed": False,
        "rtl_verdict_produced": False,
        "hidden_evaluator_run": False,
        "adapter_ready": False,
        "benchmark_ready": False,
        "excluded_claims": [
            "An output-file mapping does not prove that MAGE produced the file.",
            "Submission conformance is not private evaluation or RTL PASS.",
            "No score, PPA, QoR, workflow success rate or readiness is claimed.",
        ],
    }
    _write_new_json(receipt_path, receipt)
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    prepare = subparsers.add_parser("prepare")
    prepare.add_argument("--task-public-root", type=Path, required=True)
    prepare.add_argument("--output-dir", type=Path, required=True)
    prepare.add_argument("--observed-at", required=True)
    prepare.add_argument("--mode", choices=("development", "release"), required=True)
    prepare.add_argument("--upstream-commit", required=True)
    prepare.add_argument("--source-manifest-sha256", required=True)
    prepare.add_argument("--isolation-receipt", type=Path)
    collect = subparsers.add_parser("collect")
    collect.add_argument("--task-public-root", type=Path, required=True)
    collect.add_argument("--request", type=Path, required=True)
    collect.add_argument("--metadata", type=Path, required=True)
    collect.add_argument("--mage-output-dir", type=Path, required=True)
    collect.add_argument("--bundle-root", type=Path, required=True)
    collect.add_argument("--submission", type=Path, required=True)
    collect.add_argument("--receipt", type=Path, required=True)
    collect.add_argument("--observed-at", required=True)
    collect.add_argument("--isolation-receipt", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "prepare":
            result = prepare_request(
                task_public_root=args.task_public_root,
                output_dir=args.output_dir,
                observed_at=args.observed_at,
                mode=args.mode,
                upstream_commit=args.upstream_commit,
                source_manifest_sha256=args.source_manifest_sha256,
                isolation_receipt_path=args.isolation_receipt,
            )
        else:
            result = collect_output(
                task_public_root=args.task_public_root,
                request_path=args.request,
                metadata_path=args.metadata,
                mage_output_dir=args.mage_output_dir,
                bundle_root=args.bundle_root,
                submission_path=args.submission,
                receipt_path=args.receipt,
                observed_at=args.observed_at,
                isolation_receipt_path=args.isolation_receipt,
            )
    except Exception as exc:
        print(
            json.dumps(
                {"status": "fail", "error": f"{type(exc).__name__}: {exc}"},
                indent=2,
                sort_keys=True,
            )
        )
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
