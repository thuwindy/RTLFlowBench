#!/usr/bin/env python3
"""Public-only, provider-free runtime probe for the MAGE OCI candidate."""

from __future__ import annotations

import argparse
import errno
import importlib
from importlib import metadata
import json
import os
from pathlib import Path
import re
import subprocess
from typing import Any


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GIT_RE = re.compile(r"^[0-9a-f]{40}$")
PROVIDER_ENV_NAMES = (
    "ANTHROPIC_API_KEY",
    "OPENAI_API_BASE_URL",
    "OPENAI_API_KEY",
    "OPENROUTER_API_KEY",
    "VERTEX_REGION",
    "VERTEX_SERVICE_ACCOUNT_PATH",
)
REQUIRED_MODULES = (
    "mage",
    "mage.agent",
    "mage.gen_config",
    "llama_index.core",
    "llama_index.llms.anthropic",
    "llama_index.llms.openai",
    "llama_index.llms.vertex",
)
PACKAGE_NAMES = (
    "mage",
    "llama-index-core",
    "llama-index-llms-anthropic",
    "llama-index-llms-openai",
    "llama-index-llms-vertex",
    "pydantic",
    "tiktoken",
)
FORBIDDEN_ROOTS = (
    "/evaluator",
    "/hidden",
    "/private",
    "/reference",
    "/workspace/private",
)


def _tool(command: list[str]) -> dict[str, Any]:
    completed = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    lines = [
        line.strip()
        for line in (completed.stdout + "\n" + completed.stderr).splitlines()
        if line.strip()
    ]
    return {
        "command": command,
        "exit_code": completed.returncode,
        "version_line": lines[0] if lines else None,
    }


def _network_interfaces() -> list[str]:
    lines = Path("/proc/net/dev").read_text(encoding="utf-8").splitlines()[2:]
    return sorted(line.split(":", 1)[0].strip() for line in lines)


def _rootfs_is_read_only() -> bool:
    path = Path("/rtlflowbench-rootfs-write-probe")
    try:
        path.write_text("must not be written\n", encoding="utf-8")
    except OSError as exc:
        return exc.errno in {errno.EROFS, errno.EACCES, errno.EPERM}
    else:
        path.unlink(missing_ok=True)
        return False


def _tmpfs_is_writable() -> bool:
    path = Path("/tmp/rtlflowbench-mage-probe")
    try:
        path.write_text("probe\n", encoding="utf-8")
        return path.read_text(encoding="utf-8") == "probe\n"
    finally:
        path.unlink(missing_ok=True)


def build_probe(
    *,
    observed_at: str,
    source_commit: str,
    source_manifest_sha256: str,
    image_digest: str,
) -> dict[str, Any]:
    if not GIT_RE.fullmatch(source_commit):
        raise ValueError("source commit must be a 40-character Git digest")
    if not SHA256_RE.fullmatch(source_manifest_sha256):
        raise ValueError("source manifest must be SHA256")
    if not image_digest.startswith("sha256:") or not SHA256_RE.fullmatch(
        image_digest.removeprefix("sha256:")
    ):
        raise ValueError("image digest must be sha256:<digest>")

    imported = []
    for name in REQUIRED_MODULES:
        importlib.import_module(name)
        imported.append(name)
    versions = {name: metadata.version(name) for name in PACKAGE_NAMES}
    tools = {
        "iverilog": _tool(["/usr/bin/iverilog", "-V"]),
        "vvp": _tool(["/usr/bin/vvp", "-V"]),
        "yosys": _tool(["/usr/bin/yosys", "-V"]),
    }
    interfaces = _network_interfaces()
    rootfs_read_only = _rootfs_is_read_only()
    tmpfs_writable = _tmpfs_is_writable()
    provider_env_present = sorted(
        name for name in PROVIDER_ENV_NAMES if name in os.environ
    )
    forbidden_present = sorted(
        path for path in FORBIDDEN_ROOTS if Path(path).exists()
    )
    checks = {
        "required_modules_imported": imported == list(REQUIRED_MODULES),
        "eda_tools_exit_zero": all(item["exit_code"] == 0 for item in tools.values()),
        "network_only_loopback": interfaces == ["lo"],
        "root_filesystem_read_only": rootfs_read_only,
        "tmpfs_writable": tmpfs_writable,
        "provider_credentials_absent": provider_env_present == [],
        "forbidden_private_roots_absent": forbidden_present == [],
    }
    passed = all(checks.values())
    return {
        "schema_version": "rtlflowbench.mage_runtime_probe.v1",
        "observed_at": observed_at,
        "status": "pass" if passed else "fail",
        "source_binding": {
            "commit": source_commit,
            "manifest_sha256": source_manifest_sha256,
        },
        "image_digest": image_digest,
        "checks": checks,
        "python": {
            "implementation": os.sys.implementation.name,
            "version": os.sys.version.split()[0],
        },
        "package_versions": versions,
        "imported_modules": imported,
        "tools": tools,
        "network_interfaces": interfaces,
        "provider_environment_names_present": provider_env_present,
        "forbidden_roots_present": forbidden_present,
        "airtl_run_observed": False,
        "provider_call_observed": False,
        "provider_eda_network_separation_proven": False,
        "private_evaluator_run": False,
        "rtl_verdict_produced": False,
        "benchmark_ready": False,
        "adapter_ready": False,
        "excluded_claims": [
            "A provider-free import and tool probe is not an AIRTL workflow run.",
            "Network-none preflight does not prove provider/EDA separation for an actual MAGE run.",
            "No RTL PASS, benchmark score, QoR, PPA, or readiness is claimed.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--observed-at", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--source-manifest-sha256", required=True)
    parser.add_argument("--image-digest", required=True)
    args = parser.parse_args()
    try:
        result = build_probe(
            observed_at=args.observed_at,
            source_commit=args.source_commit,
            source_manifest_sha256=args.source_manifest_sha256,
            image_digest=args.image_digest,
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
    return 0 if result["status"] == "pass" else 2


if __name__ == "__main__":
    raise SystemExit(main())
