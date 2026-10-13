#!/usr/bin/python3
"""Run the reviewed HDLAgent launcher behind a loopback provider relay."""

from __future__ import annotations

import argparse
from pathlib import Path
import runpy
import sys

from provider_tcp_shim import start_relay


def main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--provider-socket", type=Path, required=True)
    parser.add_argument("--provider-port", type=int, default=18080)
    args, workflow_args = parser.parse_known_args()
    relay, thread = start_relay(args.provider_socket, args.provider_port)
    try:
        sys.argv = ["run_hdlagent_public.py", *workflow_args]
        runpy.run_path(
            "/opt/rtlflowbench/run_hdlagent_public.py",
            run_name="__main__",
        )
    finally:
        relay.shutdown()
        relay.server_close()
        thread.join(timeout=5)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
