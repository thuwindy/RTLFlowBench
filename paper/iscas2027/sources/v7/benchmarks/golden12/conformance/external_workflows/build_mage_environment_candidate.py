#!/usr/bin/env python3
"""Build a fail-closed, source-bound MAGE development environment candidate."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


SOURCE_COMMIT = "90c96366c518d32bd7b81703bdef3cc46eeaeaf9"
SOURCE_MANIFEST_SHA256 = (
    "4e1fb9f4d2f0719667cf4bbcbca46b8ff3a1ba22fb495a11617905ba2ebcac85"
)
PUBLIC_BASE_DIGEST = (
    "sha256:d6ed5a579d8ad959963079292b0d895107e0ba44ac2c91e636417a47f7a4b207"
)
EXPECTED_IMAGE_DIGEST = (
    "sha256:b5ce2db9b94f790e447871d73e0cfc0b819d58e770911045d3ed09f65d0f18af"
)
EXPECTED_IMAGE_ID = (
    "3c6f6c0fb154972bcae1d20cf4dd898cbf9f227b97949f9913660a4e0638e0c1"
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
IMAGE_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

EVIDENCE_IDS = {
    "download": "mage-environment-download-20260811cj",
    "overlay": "mage-environment-overlay-20260811ck",
    "invalid_private_base": "mage-environment-image-20260811cl",
    "public_image": "mage-environment-public-image-20260811cn",
    "rebuild": "mage-environment-rebuild-20260811co",
    "preflight": "mage-environment-preflight-20260811cp",
    "base_audit": "mage-environment-base-audit-20260811ct",
    "package_source": "protocol-package-source-snapshot-server-20260803d",
}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical_sha256(value: Any) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def summarize_tree(root: Path) -> dict[str, Any]:
    if not root.is_dir():
        raise ValueError(f"tree root is not a directory: {root.name}")
    entries: list[dict[str, Any]] = []
    total_regular_bytes = 0
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            target = os.readlink(path)
            if Path(target).is_absolute() or ".." in Path(target).parts:
                raise ValueError(f"unsafe symlink in content tree: {relative}")
            entries.append(
                {"path": relative, "type": "symlink", "target": target}
            )
        elif path.is_file():
            size = path.stat().st_size
            total_regular_bytes += size
            entries.append(
                {
                    "path": relative,
                    "type": "file",
                    "bytes": size,
                    "sha256": _sha256(path),
                }
            )
        elif not path.is_dir():
            raise ValueError(f"unsupported filesystem entry: {relative}")
    return {
        "entry_count": len(entries),
        "regular_file_count": sum(item["type"] == "file" for item in entries),
        "symlink_count": sum(item["type"] == "symlink" for item in entries),
        "total_regular_bytes": total_regular_bytes,
        "manifest_sha256": _canonical_sha256(entries),
    }


def require_same_tree(
    left: dict[str, Any],
    right: dict[str, Any],
    *,
    label: str,
) -> None:
    if left != right:
        raise ValueError(f"{label} trees differ")


def _exit_code(path: Path) -> int:
    rendered = path.read_text(encoding="utf-8").strip()
    if not rendered.isdigit():
        raise ValueError(f"invalid exit-code evidence: {path.name}")
    return int(rendered)


def _require_zero(path: Path) -> int:
    result = _exit_code(path)
    if result != 0:
        raise ValueError(f"non-zero evidence exit code: {path.name}")
    return result


def _identity(path: Path) -> dict[str, Any]:
    fields = path.read_text(encoding="utf-8").strip().split()
    if len(fields) != 3:
        raise ValueError(f"invalid image identity: {path.name}")
    image_id, digest, size_text = fields
    if not SHA256_RE.fullmatch(image_id):
        raise ValueError(f"invalid image id: {path.name}")
    if not IMAGE_DIGEST_RE.fullmatch(digest):
        raise ValueError(f"invalid image digest: {path.name}")
    if not size_text.isdigit():
        raise ValueError(f"invalid image size: {path.name}")
    return {
        "image_id": image_id,
        "image_digest": digest,
        "size_bytes": int(size_text),
    }


def _receipt(
    evidence_root: Path,
    evidence_key: str,
    artifact: str,
) -> dict[str, str]:
    evidence_id = EVIDENCE_IDS[evidence_key]
    path = evidence_root / evidence_id / artifact
    if not path.is_file():
        raise ValueError(f"missing evidence artifact: {evidence_id}/{artifact}")
    return {
        "evidence_id": evidence_id,
        "artifact": artifact,
        "sha256": _sha256(path),
    }


def _assert_asset_equal(left: Path, right: Path, label: str) -> str:
    left_sha = _sha256(left)
    right_sha = _sha256(right)
    if left_sha != right_sha:
        raise ValueError(f"{label} source/build asset differs")
    return left_sha


def build_candidate(
    *,
    external_root: Path,
    evidence_root: Path,
    package_source_root: Path,
    source_root: Path,
    observed_at: str,
) -> dict[str, Any]:
    download = evidence_root / EVIDENCE_IDS["download"]
    overlay_evidence = evidence_root / EVIDENCE_IDS["overlay"]
    rebuild = evidence_root / EVIDENCE_IDS["rebuild"]
    preflight_dir = evidence_root / EVIDENCE_IDS["preflight"]
    base_audit = evidence_root / EVIDENCE_IDS["base_audit"]

    source_containerfile = source_root / "MageEnvironment.Containerfile"
    source_probe = source_root / "mage_runtime_probe.py"
    source_probe_schema = source_root / "mage_runtime_probe.schema.json"
    containerfile_sha = _assert_asset_equal(
        source_containerfile,
        external_root / "build-context/Containerfile",
        "Containerfile",
    )
    probe_sha = _assert_asset_equal(
        source_probe,
        external_root / "probe/mage_runtime_probe.py",
        "runtime probe",
    )
    probe_schema_sha = _assert_asset_equal(
        source_probe_schema,
        external_root / "probe/mage_runtime_probe.schema.json",
        "runtime probe schema",
    )
    rendered_containerfile = source_containerfile.read_text(encoding="utf-8")
    if not rendered_containerfile.startswith(
        f"FROM localhost/rtlflowbench-protocol-cli@{PUBLIC_BASE_DIGEST}\n"
    ):
        raise ValueError("Containerfile public base digest differs")
    if "g01-evaluator" in rendered_containerfile or "private" in rendered_containerfile.lower():
        raise ValueError("Containerfile references a private evaluator base")

    wheelhouse = summarize_tree(external_root / "wheelhouse")
    if wheelhouse["regular_file_count"] != wheelhouse["entry_count"]:
        raise ValueError("wheelhouse contains non-regular entries")
    wheel_log_lines = [
        line
        for line in (download / "wheel-files.sha256").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    if len(wheel_log_lines) != wheelhouse["regular_file_count"]:
        raise ValueError("wheelhouse evidence count differs")

    overlay_a = summarize_tree(external_root / "overlay-a")
    overlay_b = summarize_tree(external_root / "overlay-b")
    require_same_tree(overlay_a, overlay_b, label="overlay")
    build_overlay = summarize_tree(external_root / "build-context/overlay")
    require_same_tree(overlay_a, build_overlay, label="overlay build context")

    system_runtime = summarize_tree(external_root / "system-runtime/minimal")
    build_system_runtime = summarize_tree(
        external_root / "build-context/system-runtime"
    )
    require_same_tree(
        system_runtime,
        build_system_runtime,
        label="system runtime build context",
    )

    libc_deb = package_source_root / "libc6_2.39-0ubuntu8.7_amd64.deb"
    zlib_deb = (
        package_source_root
        / "zlib1g_1%3a1.3.dfsg-3.1ubuntu2.1_amd64.deb"
    )
    for package in (libc_deb, zlib_deb):
        if not package.is_file():
            raise ValueError(f"missing package-source artifact: {package.name}")

    identity_a = _identity(rebuild / "identity-a.txt")
    identity_b = _identity(rebuild / "identity-b.txt")
    if identity_a != identity_b:
        raise ValueError("deterministic image identities differ")
    if (
        identity_a["image_id"] != EXPECTED_IMAGE_ID
        or identity_a["image_digest"] != EXPECTED_IMAGE_DIGEST
    ):
        raise ValueError("deterministic image identity is unexpected")

    preflight_path = preflight_dir / "preflight.json"
    preflight = json.loads(preflight_path.read_text(encoding="utf-8"))
    probe_schema = json.loads(source_probe_schema.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(probe_schema)
    Draft202012Validator(
        probe_schema,
        format_checker=FormatChecker(),
    ).validate(preflight)
    if (
        preflight["status"] != "pass"
        or not all(preflight["checks"].values())
        or preflight["source_binding"]["commit"] != SOURCE_COMMIT
        or preflight["source_binding"]["manifest_sha256"]
        != SOURCE_MANIFEST_SHA256
        or preflight["image_digest"] != EXPECTED_IMAGE_DIGEST
        or preflight["airtl_run_observed"] is not False
        or preflight["provider_call_observed"] is not False
        or preflight["provider_eda_network_separation_proven"] is not False
        or preflight["private_evaluator_run"] is not False
        or preflight["adapter_ready"] is not False
        or preflight["benchmark_ready"] is not False
    ):
        raise ValueError("preflight receipt is not a fail-closed environment probe")

    base_inspect = json.loads((base_audit / "base-inspect.json").read_text())[0]
    base_files = base_audit / "base-files.txt"
    leakage_matches = base_audit / "base-leakage.matches.log"
    _require_zero(base_audit / "base-files.exit_code")
    _require_zero(base_audit / "base-leakage.exit_code")
    if leakage_matches.read_bytes():
        raise ValueError("public base sensitive-path scan is non-empty")
    if (
        base_inspect.get("Digest") != PUBLIC_BASE_DIGEST
        or not SHA256_RE.fullmatch(base_inspect.get("Id", ""))
    ):
        raise ValueError("public base identity differs")

    evidence_receipts = [
        _receipt(evidence_root, "download", "wheel-files.sha256"),
        _receipt(evidence_root, "overlay", "overlay-a.sha256"),
        _receipt(evidence_root, "overlay", "overlay-b.sha256"),
        _receipt(evidence_root, "rebuild", "identity-a.txt"),
        _receipt(evidence_root, "rebuild", "identity-b.txt"),
        _receipt(evidence_root, "preflight", "preflight.json"),
        _receipt(evidence_root, "base_audit", "base-inspect.json"),
        _receipt(evidence_root, "base_audit", "base-files.txt"),
        _receipt(evidence_root, "base_audit", "base-leakage.matches.log"),
    ]

    return {
        "schema_version": "rtlflowbench.mage_environment_candidate.v1",
        "status": "same_server_development_environment_reproduced_not_frozen",
        "observed_at": observed_at,
        "source_binding": {
            "name": "MAGE",
            "version": "1.0.1",
            "commit": SOURCE_COMMIT,
            "manifest_sha256": SOURCE_MANIFEST_SHA256,
        },
        "source_assets": {
            "containerfile_sha256": containerfile_sha,
            "runtime_probe_sha256": probe_sha,
            "runtime_probe_schema_sha256": probe_schema_sha,
        },
        "public_base": {
            "classification": "public_protocol_cli_no_private_evaluator",
            "image_id": base_inspect["Id"],
            "image_digest": base_inspect["Digest"],
            "size_bytes": base_inspect["Size"],
            "regular_file_count": sum(1 for _ in base_files.open(encoding="utf-8")),
            "file_listing_sha256": _sha256(base_files),
            "sensitive_path_scan_empty": True,
        },
        "dependency_inputs": {
            "wheelhouse": {
                **wheelhouse,
                "download_exit_code": _require_zero(download / "pip-download.exit_code"),
                "wheel_build_exit_code": _require_zero(download / "pip-wheel.exit_code"),
                "network_acquisition_observed": True,
                "frozen_build_network_access": False,
            },
            "overlay": {
                "first": overlay_a,
                "second": overlay_b,
                "two_install_trees_equal": True,
                "install_exit_codes": [
                    _require_zero(overlay_evidence / "install-a.exit_code"),
                    _require_zero(overlay_evidence / "install-b.exit_code"),
                ],
                "install_network_access": False,
            },
            "system_runtime": {
                "tree": system_runtime,
                "source_packages": [
                    {"name": libc_deb.name, "sha256": _sha256(libc_deb)},
                    {"name": zlib_deb.name, "sha256": _sha256(zlib_deb)},
                ],
            },
        },
        "deterministic_build": {
            **identity_a,
            "build_exit_codes": [
                _require_zero(rebuild / "build-a.exit_code"),
                _require_zero(rebuild / "build-b.exit_code"),
            ],
            "two_build_identity_equal": True,
            "declared_build_policy": {
                "network": "none",
                "no_cache": True,
                "omit_history": True,
                "timestamp": 0,
            },
        },
        "preflight": {
            "status": preflight["status"],
            "receipt_sha256": _sha256(preflight_path),
            "schema_valid": True,
            "checks": preflight["checks"],
            "observed_sandbox": {
                "network_only_loopback": preflight["checks"]["network_only_loopback"],
                "root_filesystem_read_only": preflight["checks"]["root_filesystem_read_only"],
                "tmpfs_writable": preflight["checks"]["tmpfs_writable"],
                "forbidden_private_roots_absent": preflight["checks"]["forbidden_private_roots_absent"],
                "provider_credentials_absent": preflight["checks"]["provider_credentials_absent"],
            },
            "airtl_run_observed": False,
            "provider_call_observed": False,
            "provider_eda_network_separation_proven": False,
            "private_evaluator_run": False,
            "rtl_verdict_produced": False,
        },
        "evidence_receipts": evidence_receipts,
        "failed_or_excluded_attempts": [
            {
                "evidence_id": EVIDENCE_IDS["invalid_private_base"],
                "classification": "BLOCKED_PRIVATE_BASE_IMAGE",
                "eligible": False,
                "reason": "An evaluator-derived base is outside the external workflow trust boundary.",
            },
            {
                "evidence_id": EVIDENCE_IDS["invalid_private_base"],
                "classification": "FAILED_MISSING_RUNTIME_LIBRARY",
                "eligible": False,
                "reason": "The first development image build failed because librt.so.1 was absent.",
            },
        ],
        "rights": {
            "status": "pending_independent_review",
            "license_declarations_consistent": False,
            "redistribution_permitted": None,
        },
        "readiness": {
            "dependency_environment_ready": False,
            "environment_release_frozen": False,
            "cross_host_reproduced": False,
            "provider_eda_isolation_ready": False,
            "submission_adapter_ready": False,
            "airtl_run_observed": False,
            "benchmark_ready": False,
            "publishable_cohort_eligible": False,
        },
        "blockers": [
            "The deterministic image is reproduced only twice on one SERVER26 host.",
            "The image and dependency inputs are not independently mirrored or release-signed.",
            "Provider egress is not yet separated from offline workspace and EDA execution.",
            "MAGE license declarations remain inconsistent and pending independent review.",
            "No actual MAGE AIRTL run or Golden-12 RTL verdict has been observed.",
        ],
        "excluded_claims": [
            "This development environment candidate is not a frozen release environment.",
            "A provider-free import/tool probe is not an AIRTL workflow run.",
            "No adapter readiness, benchmark PASS, score, PPA or QoR is claimed.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--external-root", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--package-source-root", type=Path, required=True)
    parser.add_argument("--observed-at", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source_root = Path(__file__).resolve().parent
    candidate = build_candidate(
        external_root=args.external_root.resolve(),
        evidence_root=args.evidence_root.resolve(),
        package_source_root=args.package_source_root.resolve(),
        source_root=source_root,
        observed_at=args.observed_at,
    )
    schema = json.loads(
        (source_root / "mage_environment_candidate.schema.json").read_text(
            encoding="utf-8"
        )
    )
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(
        schema,
        format_checker=FormatChecker(),
    ).validate(candidate)
    args.output.write_text(
        json.dumps(candidate, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
