#!/usr/bin/python3
"""Drop-in yosys/iverilog shim for a networkless HDLAgent container."""

from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import struct
import sys


REQUEST_SCHEMA_VERSION = "rtlflowbench.hdlagent_eda_request.v1"
RESPONSE_SCHEMA_VERSION = "rtlflowbench.hdlagent_eda_response.v1"
MAX_RESPONSE_BYTES = 4 * 1024 * 1024


def _required_setting(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise ValueError(f"required broker setting is missing: {name}")
    return value


def _receive(connection: socket.socket) -> dict[str, object]:
    header = connection.recv(4)
    if len(header) != 4:
        raise ValueError("broker response header is incomplete")
    size = struct.unpack("!I", header)[0]
    if size < 2 or size > MAX_RESPONSE_BYTES:
        raise ValueError("broker response size is invalid")
    payload = bytearray()
    while len(payload) < size:
        chunk = connection.recv(size - len(payload))
        if not chunk:
            raise ValueError("broker response body is incomplete")
        payload.extend(chunk)
    value = json.loads(payload.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("broker response must be one JSON object")
    return value


def main() -> int:
    tool = Path(sys.argv[0]).name
    if tool not in {"yosys", "iverilog", "vvp"}:
        raise ValueError("shim executable name is not an allowed HDLAgent EDA tool")
    socket_path = _required_setting("RTLFLOWBENCH_HDLAGENT_EDA_SOCKET")
    session_id = _required_setting("RTLFLOWBENCH_HDLAGENT_EDA_SESSION_ID")
    control_root = Path(
        _required_setting("RTLFLOWBENCH_HDLAGENT_EDA_CONTROL_ROOT")
    ).resolve(strict=True)
    cwd = Path.cwd().resolve(strict=True)
    if not cwd.is_relative_to(control_root):
        raise ValueError("shim cwd is outside the control root")
    request = {
        "schema_version": REQUEST_SCHEMA_VERSION,
        "session_id": session_id,
        "tool": tool,
        "cwd": cwd.relative_to(control_root).as_posix() or ".",
        "argv": sys.argv[1:],
    }
    payload = json.dumps(request, sort_keys=True).encode("utf-8")
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        connection.connect(socket_path)
        connection.sendall(struct.pack("!I", len(payload)) + payload)
        response = _receive(connection)
    finally:
        connection.close()
    if response.get("schema_version") != RESPONSE_SCHEMA_VERSION:
        raise ValueError("broker response schema version is invalid")
    stdout = response.get("stdout")
    stderr = response.get("stderr")
    exit_code = response.get("exit_code")
    if not isinstance(stdout, str) or not isinstance(stderr, str):
        raise ValueError("broker response output fields are invalid")
    if not isinstance(exit_code, int) or not 0 <= exit_code <= 255:
        raise ValueError("broker response exit code is invalid")
    sys.stdout.write(stdout)
    sys.stderr.write(stderr)
    return exit_code


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        sys.stderr.write(
            f"offline EDA shim failed closed: {type(exc).__name__}: {exc}\n"
        )
        raise SystemExit(127)
