#!/usr/bin/env python3
"""Container-side bridge for the host-owned observed controller transport."""

from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import shlex
import socket
import struct
import subprocess
import sys
import threading
from typing import Any


PROTOCOL_VERSION = "rtlflowbench.observed_controller_transport.v1"
MAX_FRAME_BYTES = 32 * 1024 * 1024
MAX_HTTP_BODY_BYTES = 24 * 1024 * 1024
TOOLS = {"iverilog", "vvp", "yosys"}
PROVIDER_CONFIG_PATH = "/run/rtlflowbench-provider/config.yaml"
VANILLA_MODEL_ALIAS = "rtlflowbench-common-provider"
PROVIDER_SENTINEL = "rtlflowbench-observed-host-gateway"
CONTROLLER_REJECTION_CODES = {
    "authorization_rejected",
    "request_policy_rejected",
    "controller_state_rejected",
}
CONTROLLER_REQUEST_POLICY_DETAIL_CODES = {
    "provider_body_invalid_or_too_large",
    "provider_body_not_hexadecimal",
    "provider_body_not_json",
    "provider_credential_header_forbidden",
    "provider_get_body_forbidden",
    "provider_headers_invalid",
    "provider_model_mismatch",
    "provider_output_token_bound_invalid",
    "provider_request_fields_invalid",
    "provider_route_outside_frozen_set",
    "provider_sampling_mismatch",
    "provider_thinking_mode_mismatch",
    "request_policy_rejected_unspecified",
}


class ControllerRejected(RuntimeError):
    def __init__(self, code: str, detail_code: str | None = None):
        super().__init__("controller rejected the bounded request")
        self.code = code
        self.detail_code = detail_code


def _recv_exact(connection: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = connection.recv(remaining)
        if not chunk:
            raise ConnectionError("unexpected EOF")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _rpc(socket_path: str, request: dict[str, Any]) -> dict[str, Any]:
    payload = json.dumps(
        request, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    if not payload or len(payload) > MAX_FRAME_BYTES:
        raise ValueError("controller request frame size is invalid")
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.settimeout(900)
    try:
        connection.connect(socket_path)
        connection.sendall(struct.pack("!I", len(payload)) + payload)
        length = struct.unpack("!I", _recv_exact(connection, 4))[0]
        if length <= 0 or length > MAX_FRAME_BYTES:
            raise ValueError("controller response frame size is invalid")
        response = json.loads(_recv_exact(connection, length).decode("utf-8"))
    finally:
        connection.close()
    if not isinstance(response, dict):
        raise RuntimeError("controller rejected the bounded request")
    if response.get("status") == "error":
        code = response.get("error_code")
        if code in CONTROLLER_REJECTION_CODES:
            detail_code = response.get("error_detail_code")
            if detail_code is not None and detail_code not in CONTROLLER_REQUEST_POLICY_DETAIL_CODES:
                raise RuntimeError("controller returned an invalid policy detail code")
            raise ControllerRejected(code, detail_code)
        raise RuntimeError("controller rejected the bounded request")
    return response


class _ProviderProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "RTLFlowBenchObservedBridge/1"

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _forward(self) -> None:
        length_value = self.headers.get("Content-Length", "0")
        try:
            length = int(length_value)
        except ValueError:
            self.send_error(400)
            return
        if length < 0 or length > MAX_HTTP_BODY_BYTES:
            self.send_error(413)
            return
        body = self.rfile.read(length)
        headers = {
            key.lower(): value
            for key, value in self.headers.items()
            if key.lower() in {"accept", "content-type"}
        }
        request = {
            "schema_version": PROTOCOL_VERSION,
            "session_id": self.server.session_id,  # type: ignore[attr-defined]
            "operation": "provider_http",
            "method": self.command,
            "path": self.path.split("?", 1)[0],
            "headers": headers,
            "body_hex": body.hex(),
        }
        try:
            response = _rpc(self.server.socket_path, request)  # type: ignore[attr-defined]
            response_body = bytes.fromhex(response["body_hex"])
            self.send_response(response["http_status"])
            for key, value in response["headers"].items():
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(response_body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(response_body)
        except ControllerRejected as exc:
            status = {
                "authorization_rejected": 403,
                "request_policy_rejected": 422,
                "controller_state_rejected": 409,
            }[exc.code]
            error = {"code": f"observed_controller_{exc.code}"}
            if exc.detail_code is not None:
                error["detail_code"] = exc.detail_code
            response_body = json.dumps(
                {"error": error},
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response_body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(response_body)
        except Exception:
            response_body = b'{"error":{"message":"observed controller unavailable"}}'
            self.send_response(502)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response_body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(response_body)

    do_GET = _forward
    do_POST = _forward


class ProviderProxy:
    def __init__(self, *, socket_path: str, session_id: str):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _ProviderProxyHandler)
        self.server.socket_path = socket_path  # type: ignore[attr-defined]
        self.server.session_id = session_id  # type: ignore[attr-defined]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_port}/v1"

    def __enter__(self) -> "ProviderProxy":
        self.thread.start()
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        if self.thread.is_alive():
            raise RuntimeError("provider proxy thread did not stop")


def _run_eda_shim(tool: str) -> int:
    socket_path = os.environ["RTLFLOWBENCH_CONTROLLER_SOCKET"]
    session_id = os.environ["RTLFLOWBENCH_CONTROLLER_SESSION"]
    real = os.environ[f"RTLFLOWBENCH_REAL_{tool.upper()}"]
    invocation_id = f"{tool}.{os.getpid()}.{secrets.token_hex(8)}"
    _rpc(
        socket_path,
        {
            "schema_version": PROTOCOL_VERSION,
            "session_id": session_id,
            "operation": "eda_start",
            "invocation_id": invocation_id,
            "tool": tool,
        },
    )
    outcome = "failed"
    try:
        completed = subprocess.run([real, *sys.argv[1:]], check=False)
        outcome = "completed" if completed.returncode == 0 else "failed"
        return completed.returncode
    finally:
        _rpc(
            socket_path,
            {
                "schema_version": PROTOCOL_VERSION,
                "session_id": session_id,
                "operation": "eda_finish",
                "invocation_id": invocation_id,
                "outcome": outcome,
            },
        )


def _install_shims(
    shim_root: Path, *, socket_path: str, session_id: str
) -> None:
    if shim_root.exists() or shim_root.is_symlink():
        raise FileExistsError("refusing to overwrite EDA shim root")
    shim_root.mkdir(parents=True, mode=0o700)
    source = Path(__file__).resolve(strict=True)
    for tool in sorted(TOOLS):
        wrapper = shim_root / tool
        real_tool = f"/usr/bin/{tool}"
        wrapper.write_text(
            "#!/bin/sh\n"
            f"RTLFLOWBENCH_CONTROLLER_SOCKET={shlex.quote(socket_path)} "
            f"RTLFLOWBENCH_CONTROLLER_SESSION={shlex.quote(session_id)} "
            f"RTLFLOWBENCH_REAL_{tool.upper()}={shlex.quote(real_tool)} "
            f"RTLFLOWBENCH_EDA_TOOL={shlex.quote(tool)} exec "
            f"{shlex.quote(sys.executable)} {shlex.quote(str(source))} \"$@\"\n",
            encoding="utf-8",
        )
        wrapper.chmod(0o700)


def run_wrapped(args: argparse.Namespace) -> int:
    if not args.command:
        raise ValueError("wrapped workflow command is empty")
    socket_path = str(Path(args.socket).resolve(strict=True))
    health = _rpc(
        socket_path,
        {
            "schema_version": PROTOCOL_VERSION,
            "session_id": args.session,
            "operation": "health",
        },
    )
    if health.get("status") != "ready":
        raise RuntimeError("controller health check failed")
    provider_runtime = health.get("provider_runtime")
    if not (
        isinstance(provider_runtime, dict)
        and isinstance(provider_runtime.get("model"), str)
        and provider_runtime.get("thinking") == {"type": "disabled"}
        and provider_runtime.get("temperature") == 0
        and provider_runtime.get("top_p") == 1
        and provider_runtime.get("maximum_output_tokens") == 8192
        and provider_runtime.get("maximum_calls_per_measurement") == 4
        and provider_runtime.get("maximum_input_tokens_per_measurement")
        == 163840
        and provider_runtime.get("maximum_output_tokens_per_measurement")
        == 16384
        and provider_runtime.get("maximum_consecutive_identical_requests") == 2
        and provider_runtime.get("maximum_consecutive_identical_errors") == 2
    ):
        raise RuntimeError("controller provider runtime binding is invalid")
    shim_root = Path(args.shim_root)
    _install_shims(
        shim_root, socket_path=socket_path, session_id=args.session
    )
    with ProviderProxy(socket_path=socket_path, session_id=args.session) as proxy:
        environment = dict(os.environ)
        environment.update(
            {
                "OPENAI_BASE_URL": proxy.base_url,
                "OPENAI_API_BASE": proxy.base_url,
                "OPENAI_API_KEY": PROVIDER_SENTINEL,
                "DEEPSEEK_API_KEY": PROVIDER_SENTINEL,
                "DEER_FLOW_CONFIG_PATH": PROVIDER_CONFIG_PATH,
                "RTLFLOWBENCH_VANILLA_CONFIG_PATH": PROVIDER_CONFIG_PATH,
                "RTLFLOWBENCH_VANILLA_MODEL_ALIAS": VANILLA_MODEL_ALIAS,
                "RTLFLOWBENCH_PROVIDER_PROXY_BASE_URL": proxy.base_url,
                "OAI_CONFIG_LIST": json.dumps(
                    [
                        {
                            "model": provider_runtime["model"],
                            "api_key": PROVIDER_SENTINEL,
                            "base_url": proxy.base_url,
                            "temperature": provider_runtime["temperature"],
                            "top_p": provider_runtime["top_p"],
                            "max_tokens": provider_runtime[
                                "maximum_output_tokens"
                            ],
                            "extra_body": {
                                "thinking": provider_runtime["thinking"]
                            },
                        }
                    ],
                    sort_keys=True,
                ),
                "RTLFLOWBENCH_CONTROLLER_SOCKET": socket_path,
                "RTLFLOWBENCH_CONTROLLER_SESSION": args.session,
                "RTLFLOWBENCH_REAL_IVERILOG": "/usr/bin/iverilog",
                "RTLFLOWBENCH_REAL_VVP": "/usr/bin/vvp",
                "RTLFLOWBENCH_REAL_YOSYS": "/usr/bin/yosys",
                "PATH": f"{shim_root}:{environment.get('PATH', '/usr/bin:/bin')}",
            }
        )
        completed = subprocess.run(args.command, env=environment, check=False)
        return completed.returncode


def main() -> int:
    invoked = os.environ.get("RTLFLOWBENCH_EDA_TOOL") or Path(sys.argv[0]).name
    if invoked in TOOLS:
        return _run_eda_shim(invoked)
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", required=True)
    parser.add_argument("--session", required=True)
    parser.add_argument("--shim-root", required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.command and args.command[0] == "--":
        args.command = args.command[1:]
    return run_wrapped(args)


if __name__ == "__main__":
    raise SystemExit(main())
