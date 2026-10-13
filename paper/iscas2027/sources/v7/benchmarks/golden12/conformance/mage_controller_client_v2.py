"""MAGE accounting route: actual broker tools count once, never at both layers."""

import os
from pathlib import Path
import subprocess
import sys

from native_complete_public_launcher_v2 import pinned_module


def socket_exists(path):
    return bool(path) and Path(path).is_socket()


def install_accounting_route(client):
    original = client._run_eda_shim

    def run(tool):
        if tool not in {"iverilog", "vvp"}:
            return original(tool)
        if not (
            os.environ.get("RTLFLOWBENCH_MAGE_EDA_ACCOUNTING") == "host-broker-v2"
            and os.environ.get("RTLFLOWBENCH_MAGE_EDA_SESSION_ID")
            and os.environ.get("RTLFLOWBENCH_MAGE_EDA_SESSION_ID")
            == os.environ.get("RTLFLOWBENCH_CONTROLLER_SESSION")
            and socket_exists(os.environ.get("RTLFLOWBENCH_MAGE_EDA_SOCKET"))
        ):
            raise ValueError("host broker accounting owner/session/socket unavailable")
        actual = os.environ.get("RTLFLOWBENCH_REAL_" + tool.upper())
        if actual != "/usr/bin/" + tool:
            raise ValueError("unexpected native MAGE shim")
        # /usr/bin/{iverilog,vvp} is the pinned MAGE socket shim, not a host EDA
        # executable. The broker records start/finish around the actual tool.
        return subprocess.run([actual, *sys.argv[1:]], check=False).returncode

    client._run_eda_shim = run
    client.__file__ = str(Path(__file__).resolve())
    return client


def main():
    client = pinned_module(Path(__file__).resolve().parent, "controller_client.py")
    return install_accounting_route(client).main()


if __name__ == "__main__":
    raise SystemExit(main())
