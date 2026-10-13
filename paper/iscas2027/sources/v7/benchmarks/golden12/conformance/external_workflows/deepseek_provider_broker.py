#!/usr/bin/env python3
"""Content-redacting DeepSeek chat-completions broker over a Unix socket."""
from __future__ import annotations

import argparse
import hashlib
import http.client
import http.server
import json
import os
from pathlib import Path
import signal
import socketserver
import threading
import time
from typing import Any


MAX_REQUEST_BYTES = 8 * 1024 * 1024
MAX_RESPONSE_BYTES = 32 * 1024 * 1024


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def write_new_json(path: Path, value: dict[str, Any]) -> None:
    if path.exists() or path.is_symlink():
        raise FileExistsError(f"refusing to overwrite provider evidence: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


class UnixHTTPServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(
        self,
        socket_path: str,
        handler: type[http.server.BaseHTTPRequestHandler],
        *,
        evidence_root: Path,
        api_key: str,
        expected_model: str,
        max_requests: int,
    ) -> None:
        self.evidence_root = evidence_root
        self.api_key = api_key
        self.expected_model = expected_model
        self.max_requests = max_requests
        self.request_count = 0
        self.counter_lock = threading.Lock()
        super().__init__(socket_path, handler)

    def next_request_index(self) -> int:
        with self.counter_lock:
            if self.request_count >= self.max_requests:
                raise RuntimeError("provider broker request budget exhausted")
            self.request_count += 1
            return self.request_count


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server: UnixHTTPServer

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def _send_json_error(self, status: int, code: str) -> None:
        body = json.dumps(
            {"error": {"message": code, "type": "broker_error", "code": code}},
            separators=(",", ":"),
        ).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        if self.path != "/health":
            self._send_json_error(404, "unsupported_endpoint")
            return
        body = b'{"status":"ok"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        started = time.monotonic()
        try:
            index = self.server.next_request_index()
        except RuntimeError:
            self._send_json_error(429, "broker_request_budget_exhausted")
            return
        if self.path not in {"/chat/completions", "/v1/chat/completions"}:
            self._send_json_error(404, "unsupported_endpoint")
            return
        try:
            length = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            self._send_json_error(400, "invalid_content_length")
            return
        if length < 1 or length > MAX_REQUEST_BYTES:
            self._send_json_error(413, "request_size_out_of_bounds")
            return
        request_body = self.rfile.read(length)
        try:
            request = json.loads(request_body)
        except json.JSONDecodeError:
            self._send_json_error(400, "invalid_json")
            return
        if not isinstance(request, dict):
            self._send_json_error(400, "request_must_be_object")
            return
        if (
            request.get("model") != self.server.expected_model
            or request.get("stream", False) is not False
            or request.get("temperature") not in (0, 0.0)
            or request.get("top_p", 1) not in (1, 1.0)
            or request.get("thinking") != {"type": "disabled"}
        ):
            self._send_json_error(400, "decoding_contract_violation")
            return

        upstream_status: int | None = None
        response_body = b""
        response_type = "application/json"
        error_class: str | None = None
        try:
            connection = http.client.HTTPSConnection("api.deepseek.com", timeout=180)
            connection.request(
                "POST",
                "/chat/completions",
                body=request_body,
                headers={
                    "Authorization": f"Bearer {self.server.api_key}",
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "User-Agent": "rtlflowbench-provider-broker/1",
                },
            )
            upstream = connection.getresponse()
            upstream_status = upstream.status
            response_type = upstream.getheader("Content-Type", "application/json")
            response_body = upstream.read(MAX_RESPONSE_BYTES + 1)
            connection.close()
            if len(response_body) > MAX_RESPONSE_BYTES:
                raise ValueError("upstream response exceeds broker limit")
        except Exception as exc:  # keep provider exception content private
            error_class = type(exc).__name__
            response_body = json.dumps(
                {
                    "error": {
                        "message": "provider_broker_upstream_error",
                        "type": "broker_error",
                        "code": "provider_broker_upstream_error",
                    }
                },
                separators=(",", ":"),
            ).encode("utf-8")
            upstream_status = 502
            response_type = "application/json"

        usage = {"input_tokens": None, "output_tokens": None, "total_tokens": None}
        if upstream_status == 200:
            try:
                parsed = json.loads(response_body)
                raw_usage = parsed.get("usage", {}) if isinstance(parsed, dict) else {}
                if isinstance(raw_usage, dict):
                    usage = {
                        "input_tokens": raw_usage.get("prompt_tokens"),
                        "output_tokens": raw_usage.get("completion_tokens"),
                        "total_tokens": raw_usage.get("total_tokens"),
                    }
            except json.JSONDecodeError:
                error_class = "InvalidProviderJSON"

        receipt = {
            "schema_version": "rtlflowbench.provider_broker_call.v1",
            "request_index": index,
            "provider": "deepseek",
            "model": self.server.expected_model,
            "endpoint_allowlist_match": True,
            "decoding_contract_match": True,
            "request": {
                "sha256": sha256_bytes(request_body),
                "bytes": len(request_body),
                "raw_content_recorded": False,
            },
            "response": {
                "http_status": upstream_status,
                "sha256": sha256_bytes(response_body),
                "bytes": len(response_body),
                "raw_content_recorded": False,
                "error_class": error_class,
            },
            "usage": usage,
            "wall_time_seconds": round(time.monotonic() - started, 6),
            "credential_recorded": False,
        }
        write_new_json(
            self.server.evidence_root / f"call-{index:04d}" / "receipt.json",
            receipt,
        )
        self.send_response(upstream_status)
        self.send_header("Content-Type", response_type)
        self.send_header("Content-Length", str(len(response_body)))
        self.end_headers()
        self.wfile.write(response_body)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--model", default="deepseek-v4-pro")
    parser.add_argument("--max-requests", type=int, default=64)
    args = parser.parse_args()
    if args.max_requests < 1:
        raise ValueError("max requests must be positive")
    api_key = os.environ.pop("DEEPSEEK_API_KEY", "")
    if not api_key:
        raise ValueError("DEEPSEEK_API_KEY is unavailable")
    if args.socket.exists() or args.socket.is_symlink():
        raise FileExistsError(f"refusing to reuse provider socket: {args.socket}")
    if args.evidence_root.exists() or args.evidence_root.is_symlink():
        raise FileExistsError(
            f"refusing to reuse provider evidence: {args.evidence_root}"
        )
    args.socket.parent.mkdir(parents=True, exist_ok=True)
    args.evidence_root.mkdir(parents=True)
    server = UnixHTTPServer(
        str(args.socket),
        Handler,
        evidence_root=args.evidence_root,
        api_key=api_key,
        expected_model=args.model,
        max_requests=args.max_requests,
    )
    os.chmod(args.socket, 0o600)
    del api_key

    def stop(_signum: int, _frame: object) -> None:
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        server.serve_forever(poll_interval=0.1)
    finally:
        server.server_close()
        args.socket.unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
