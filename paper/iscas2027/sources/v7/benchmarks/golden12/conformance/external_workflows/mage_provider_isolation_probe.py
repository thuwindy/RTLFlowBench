#!/usr/bin/python3
"""Provider-image isolation probe that reports booleans, never secret values."""

from __future__ import annotations

import errno
import hashlib
import json
import os
from pathlib import Path
import shutil


SCHEMA_VERSION = "rtlflowbench.mage_provider_isolation_probe.v1"
SENSITIVE_ENVIRONMENT_NAMES = {
    "ANTHROPIC_API_KEY",
    "DEEPSEEK_API_KEY",
    "GOOGLE_API_KEY",
    "OPENAI_API_KEY",
    "OPENROUTER_API_KEY",
}
SHIM_PATHS = (Path("/usr/bin/iverilog"), Path("/usr/bin/vvp"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _network_interfaces() -> list[str]:
    lines = Path("/proc/net/dev").read_text(encoding="utf-8").splitlines()[2:]
    return sorted(line.split(":", 1)[0].strip() for line in lines if ":" in line)


def _root_filesystem_is_read_only() -> bool:
    path = Path("/rtlflowbench-provider-rootfs-write-probe")
    try:
        path.write_bytes(b"write-must-fail")
    except OSError as exc:
        return exc.errno in {errno.EACCES, errno.EROFS}
    path.unlink(missing_ok=True)
    return False


def main() -> int:
    sensitive_names_present = sorted(SENSITIVE_ENVIRONMENT_NAMES & set(os.environ))
    interfaces = _network_interfaces()
    shim_text = [path.read_text(encoding="utf-8") for path in SHIM_PATHS]
    try:
        from mage.agent import TopAgent

        mage_top_agent = TopAgent.__name__
        mage_importable = mage_top_agent == "TopAgent"
    except Exception:
        mage_top_agent = None
        mage_importable = False
    checks = {
        "forbidden_private_roots_absent": all(
            not Path(root).exists()
            for root in ("/evaluator", "/hidden", "/private", "/reference")
        ),
        "mage_importable": mage_importable,
        "native_eda_absent": (
            shutil.which("yosys") is None
            and not Path("/usr/bin/yosys").exists()
            and all("rtlflowbench.mage_eda_request.v1" in text for text in shim_text)
        ),
        "network_only_loopback": interfaces == ["lo"],
        "provider_credentials_absent": not sensitive_names_present,
        "root_filesystem_read_only": _root_filesystem_is_read_only(),
        "shim_paths_fixed": tuple(shutil.which(path.name) for path in SHIM_PATHS)
        == tuple(str(path) for path in SHIM_PATHS),
    }
    result = {
        "schema_version": SCHEMA_VERSION,
        "status": "pass" if all(checks.values()) else "fail",
        "checks": checks,
        "observations": {
            "mage_top_agent": mage_top_agent,
            "network_interfaces": interfaces,
            "sensitive_environment_names_present": sensitive_names_present,
            "shim_sha256": {path.name: _sha256(path) for path in SHIM_PATHS},
        },
        "airtl_run_observed": False,
        "provider_call_observed": False,
        "benchmark_verdict_produced": False,
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "pass" else 2


if __name__ == "__main__":
    raise SystemExit(main())
