#!/usr/bin/env python3
"""Host-owned provider/EDA observation transport for resource calibration.

The workflow container has no network and receives no provider credential.  A
small client bridge sends bounded requests over a Unix socket.  This module
forwards only the frozen OpenAI-compatible provider paths and records a
content-free activity timeline.  It never writes prompt/response bodies,
credentials, RTL verdicts, or private-evaluator data.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import socket
import socketserver
import ssl
import struct
import threading
import time
from typing import Any, Protocol


PROTOCOL_VERSION = "rtlflowbench.observed_controller_transport.v1"
CONTROLLER_ID = "rtlflowbench.observed-controller-transport"
CONTROLLER_VERSION = "3"
MAX_FRAME_BYTES = 32 * 1024 * 1024
MAX_PROVIDER_BODY_BYTES = 24 * 1024 * 1024
MAX_PROVIDER_RESPONSE_BYTES = 32 * 1024 * 1024
# macOS exposes a 104-byte ``sun_path`` while Linux commonly exposes 108.
# Keep the pathname itself within the smaller portable payload budget.
UNIX_SOCKET_PATH_MAX_BYTES = 103
SESSION_RE = re.compile(r"^[a-z0-9][a-z0-9-]{15,127}$")
ACTIVITY_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,159}$")
MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
EDA_TO_KIND = {
    "iverilog": "eda_compile_or_lint",
    "vvp": "eda_simulation",
    "yosys": "eda_synthesis",
    "verilator": "eda_compile_or_lint",
    "native_sim": "eda_simulation",
}
ALLOWED_PROVIDER_PATHS = {"/v1/chat/completions", "/v1/models"}
TOKEN_ACCOUNTING_POLICY = "controller_observed_openai_compatible_usage_v2"
PROVIDER_FINISH_REASONS = (
    "stop",
    "length",
    "tool_calls",
    "content_filter",
    "function_call",
    "unknown",
)


def _canonical_sha256(value: Any) -> str:
    payload = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _normalized_provider_token_usage(value: Any) -> dict[str, int | bool | None] | None:
    """Return content-free OpenAI-compatible usage totals when complete."""
    if not isinstance(value, dict):
        return None
    names = ("prompt_tokens", "completion_tokens", "total_tokens")
    if any(
        isinstance(value.get(name), bool)
        or not isinstance(value.get(name), int)
        or value[name] < 0
        for name in names
    ):
        return None
    if value["total_tokens"] != value["prompt_tokens"] + value["completion_tokens"]:
        return None
    cache_names = ("prompt_cache_hit_tokens", "prompt_cache_miss_tokens")
    cache_complete = all(
        not isinstance(value.get(name), bool)
        and isinstance(value.get(name), int)
        and value[name] >= 0
        for name in cache_names
    )
    if (
        cache_complete
        and sum(value[name] for name in cache_names) != value["prompt_tokens"]
    ):
        cache_complete = False
    return {
        "input_tokens": value["prompt_tokens"],
        "output_tokens": value["completion_tokens"],
        "total_tokens": value["total_tokens"],
        "cache_measurement_complete": cache_complete,
        "cache_hit_input_tokens": (
            value["prompt_cache_hit_tokens"] if cache_complete else None
        ),
        "cache_miss_input_tokens": (
            value["prompt_cache_miss_tokens"] if cache_complete else None
        ),
    }


def _extract_provider_token_usage(
    *, response_headers: dict[str, str], response_body: bytes
) -> dict[str, int | bool | None] | None:
    """Parse JSON or SSE usage without retaining any response content."""
    candidates: list[dict[str, int | bool | None]] = []
    content_type = response_headers.get("content-type", "").casefold()
    if "text/event-stream" in content_type or response_body.lstrip().startswith(b"data:"):
        for line in response_body.splitlines():
            stripped = line.strip()
            if not stripped.startswith(b"data:"):
                continue
            payload = stripped.removeprefix(b"data:").strip()
            if not payload or payload == b"[DONE]":
                continue
            try:
                value = json.loads(payload.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue
            usage = _normalized_provider_token_usage(
                value.get("usage") if isinstance(value, dict) else None
            )
            if usage is not None:
                candidates.append(usage)
    else:
        try:
            value = json.loads(response_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            value = None
        usage = _normalized_provider_token_usage(
            value.get("usage") if isinstance(value, dict) else None
        )
        if usage is not None:
            candidates.append(usage)
    return candidates[-1] if candidates else None


def _normalized_provider_finish_reason(value: Any) -> str | None:
    """Return one bounded finish-reason enum without retaining response text."""
    if not isinstance(value, dict) or not isinstance(value.get("choices"), list):
        return None
    observed: list[str] = []
    for choice in value["choices"]:
        if not isinstance(choice, dict) or "finish_reason" not in choice:
            continue
        reason = choice["finish_reason"]
        if reason is None:
            continue
        if isinstance(reason, str) and reason in PROVIDER_FINISH_REASONS[:-1]:
            observed.append(reason)
        else:
            observed.append("unknown")
    if not observed:
        return None
    return observed[0] if len(set(observed)) == 1 else "unknown"


def _extract_provider_finish_reason(
    *, response_headers: dict[str, str], response_body: bytes
) -> str | None:
    """Parse JSON or SSE finish metadata and discard all response content."""
    candidates: list[str] = []
    content_type = response_headers.get("content-type", "").casefold()
    if "text/event-stream" in content_type or response_body.lstrip().startswith(b"data:"):
        payloads = []
        for line in response_body.splitlines():
            stripped = line.strip()
            if stripped.startswith(b"data:"):
                payload = stripped.removeprefix(b"data:").strip()
                if payload and payload != b"[DONE]":
                    payloads.append(payload)
    else:
        payloads = [response_body]
    for payload in payloads:
        try:
            value = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        reason = _normalized_provider_finish_reason(value)
        if reason is not None:
            candidates.append(reason)
    return candidates[-1] if candidates else None


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


def recv_frame(connection: socket.socket) -> dict[str, Any]:
    length = struct.unpack("!I", _recv_exact(connection, 4))[0]
    if length <= 0 or length > MAX_FRAME_BYTES:
        raise ValueError("controller frame size is invalid")
    value = json.loads(_recv_exact(connection, length).decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("controller frame must contain one JSON object")
    return value


def send_frame(connection: socket.socket, value: dict[str, Any]) -> None:
    payload = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    if not payload or len(payload) > MAX_FRAME_BYTES:
        raise ValueError("controller response frame size is invalid")
    connection.sendall(struct.pack("!I", len(payload)) + payload)


class ProviderForwarder(Protocol):
    def __call__(
        self, *, method: str, path: str, headers: dict[str, str], body: bytes
    ) -> tuple[int, dict[str, str], bytes]: ...


class ProviderRequestPolicyRejected(ValueError):
    """A content-free, stable reason for rejecting a provider HTTP request."""

    def __init__(self, detail_code: str, message: str):
        super().__init__(message)
        self.detail_code = detail_code


class DeepSeekForwarder:
    """Fixed-destination HTTPS forwarder; the credential stays host-side."""

    def __init__(self, *, api_key: str, timeout_seconds: int = 600):
        if not api_key or any(character.isspace() for character in api_key):
            raise ValueError("provider credential is unavailable or malformed")
        if not 1 <= timeout_seconds <= 3600:
            raise ValueError("provider timeout is outside the reviewed range")
        self._api_key = api_key
        self._timeout_seconds = timeout_seconds

    def __call__(
        self, *, method: str, path: str, headers: dict[str, str], body: bytes
    ) -> tuple[int, dict[str, str], bytes]:
        upstream_path = path.removeprefix("/v1")
        safe_headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Accept": headers.get("accept", "application/json"),
            "Content-Type": headers.get("content-type", "application/json"),
            "User-Agent": "rtlflowbench-observed-provider-gateway/1",
            "Content-Length": str(len(body)),
        }
        connection = http.client.HTTPSConnection(
            "api.deepseek.com",
            443,
            timeout=self._timeout_seconds,
            context=ssl.create_default_context(),
        )
        try:
            connection.request(method, upstream_path, body=body, headers=safe_headers)
            response = connection.getresponse()
            response_body = response.read(MAX_PROVIDER_RESPONSE_BYTES + 1)
            if len(response_body) > MAX_PROVIDER_RESPONSE_BYTES:
                raise ValueError("provider response exceeds transport limit")
            response_headers = {
                key.lower(): value
                for key, value in response.getheaders()
                if key.lower()
                in {"content-type", "content-encoding", "x-request-id"}
            }
            return response.status, response_headers, response_body
        finally:
            connection.close()


@dataclass
class _OpenEdaActivity:
    activity_id: str
    kind: str
    started_offset_ns: int
    tool: str


class ControllerState:
    def __init__(
        self,
        *,
        session_id: str,
        measurement: dict[str, Any],
        expected_model: str,
        maximum_provider_calls: int,
        maximum_output_tokens_per_call: int,
        maximum_input_tokens: int,
        maximum_output_tokens: int,
        maximum_consecutive_identical_requests: int,
        maximum_consecutive_identical_errors: int,
        provider_forwarder: ProviderForwarder,
        provider_config_sha256: str,
        provider_source_sha256: str,
        eda_config_sha256: str,
        eda_source_sha256: str,
        public_command_broker=None,
    ):
        if SESSION_RE.fullmatch(session_id) is None:
            raise ValueError("session id is invalid")
        if MODEL_RE.fullmatch(expected_model) is None:
            raise ValueError("expected model is invalid")
        if (
            isinstance(maximum_provider_calls, bool)
            or not isinstance(maximum_provider_calls, int)
            or not 1 <= maximum_provider_calls <= 4096
        ):
            raise ValueError("maximum provider calls is invalid")
        for value, label in (
            (maximum_output_tokens_per_call, "maximum output tokens per call"),
            (maximum_input_tokens, "maximum input tokens"),
            (maximum_output_tokens, "maximum output tokens"),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"{label} is invalid")
        if maximum_output_tokens_per_call > maximum_output_tokens:
            raise ValueError("per-call output-token limit exceeds cumulative limit")
        for value, label in (
            (
                maximum_consecutive_identical_requests,
                "maximum consecutive identical requests",
            ),
            (
                maximum_consecutive_identical_errors,
                "maximum consecutive identical errors",
            ),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not 1 <= value <= 64
            ):
                raise ValueError(f"{label} is invalid")
        required = {
            "measurement_id",
            "measurement_scope",
            "workflow_slot_id",
            "workflow_id",
            "task_id",
            "attempt_id",
            "source_binding",
            "runtime_binding",
        }
        if set(measurement) != required:
            raise ValueError("measurement identity fields are invalid")
        if measurement["measurement_scope"] != "full_workflow_calibration":
            raise ValueError("controller is only valid for full workflow calibration")
        for digest in (
            provider_config_sha256,
            provider_source_sha256,
            eda_config_sha256,
            eda_source_sha256,
        ):
            if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
                raise ValueError("controller binding SHA256 is malformed")
        self.session_id = session_id
        if public_command_broker is not None:
            from deerflow.chipflow.research.public_command_broker import PublicCommandBroker

            if type(public_command_broker) is not PublicCommandBroker or public_command_broker.session_id != session_id:
                raise ValueError("public command broker must be host-constructed for this session")
        self.public_command_broker = public_command_broker
        self.measurement = measurement
        self.expected_model = expected_model
        self.maximum_provider_calls = maximum_provider_calls
        self.maximum_output_tokens_per_call = maximum_output_tokens_per_call
        self.maximum_input_tokens = maximum_input_tokens
        self.maximum_output_tokens = maximum_output_tokens
        self.maximum_consecutive_identical_requests = (
            maximum_consecutive_identical_requests
        )
        self.maximum_consecutive_identical_errors = (
            maximum_consecutive_identical_errors
        )
        self.provider_forwarder = provider_forwarder
        self.controller_bindings = {
            "provider_gateway": {
                "controller_id": CONTROLLER_ID + ".provider-gateway",
                "version": CONTROLLER_VERSION,
                "config_sha256": provider_config_sha256,
                "source_sha256": provider_source_sha256,
            },
            "eda_broker": {
                "controller_id": CONTROLLER_ID + ".eda-observer",
                "version": CONTROLLER_VERSION,
                "config_sha256": eda_config_sha256,
                "source_sha256": eda_source_sha256,
            },
        }
        self._origin_ns: int | None = None
        self._activities: list[dict[str, Any]] = []
        self._open_eda: dict[str, _OpenEdaActivity] = {}
        self._ids: set[str] = set()
        self._provider_sequence = 0
        self._provider_output_token_bound_clamp_count = 0
        self._provider_budget_rejection_count = 0
        self._provider_budget_rejection_counts = {
            "call_limit": 0,
            "input_token_limit": 0,
            "output_token_limit": 0,
            "token_accounting_incomplete": 0,
            "repeated_request": 0,
            "repeated_error": 0,
        }
        self._terminal_guard_reason: str | None = None
        self._provider_token_usage_expected_count = 0
        self._provider_token_usage_observed_count = 0
        self._provider_input_tokens = 0
        self._provider_output_tokens = 0
        self._provider_total_tokens = 0
        self._provider_cache_usage_observed_count = 0
        self._provider_cache_hit_input_tokens = 0
        self._provider_cache_miss_input_tokens = 0
        self._provider_finish_reason_observed_count = 0
        self._provider_finish_reason_counts = {
            reason: 0 for reason in PROVIDER_FINISH_REASONS
        }
        self._provider_output_cap_reached_call_count = 0
        self._provider_output_cap_with_length_finish_count = 0
        self._last_request_sha256: str | None = None
        self._consecutive_identical_request_count = 0
        self._highest_consecutive_identical_request_count = 0
        self._last_error_sha256: str | None = None
        self._consecutive_identical_error_count = 0
        self._highest_consecutive_identical_error_count = 0
        self._lock = threading.Lock()
        # Settle actual usage before another request can spend the same balance.
        # Do not hold the general state lock across network I/O: health/EDA and
        # close checks must remain responsive while the forwarder is pending.
        self._provider_dispatch_lock = threading.Lock()
        self._open_provider: set[str] = set()
        self._closed = False
        self._provider_admission_closed = False

    def set_origin(self, origin_ns: int) -> None:
        if not isinstance(origin_ns, int) or origin_ns <= 0:
            raise ValueError("measurement origin is invalid")
        with self._lock:
            if self._origin_ns is not None:
                raise RuntimeError("measurement origin is already set")
            if self._activities or self._open_eda:
                raise RuntimeError("activity exists before measurement origin")
            self._origin_ns = origin_ns

    def _offset(self) -> int:
        if self._origin_ns is None:
            raise RuntimeError("measurement origin is not set")
        return max(0, time.monotonic_ns() - self._origin_ns)

    def _new_id(self, prefix: str, sequence: int) -> str:
        activity_id = f"{self.measurement['measurement_id']}.{prefix}.{sequence}"
        if ACTIVITY_RE.fullmatch(activity_id) is None or activity_id in self._ids:
            raise RuntimeError("controller activity id is invalid or duplicated")
        self._ids.add(activity_id)
        return activity_id

    def _append(
        self,
        *,
        activity_id: str,
        kind: str,
        controller: str,
        started_offset_ns: int,
        completed_offset_ns: int,
        outcome: str,
        binding_context: dict[str, Any],
    ) -> None:
        completed_offset_ns = max(completed_offset_ns, started_offset_ns + 1)
        event_binding_sha256 = _canonical_sha256(
            {
                "measurement_id": self.measurement["measurement_id"],
                "activity_id": activity_id,
                "kind": kind,
                "controller": controller,
                "started_offset_ns": started_offset_ns,
                "completed_offset_ns": completed_offset_ns,
                "outcome": outcome,
                "context": binding_context,
                "raw_content_embedded": False,
            }
        )
        self._activities.append(
            {
                "activity_id": activity_id,
                "kind": kind,
                "controller": controller,
                "started_offset_ns": started_offset_ns,
                "completed_offset_ns": completed_offset_ns,
                "outcome": outcome,
                "event_binding_sha256": event_binding_sha256,
                "raw_content_embedded": False,
            }
        )

    def _validate_provider_request(
        self, request: dict[str, Any]
    ) -> tuple[str, str, dict[str, str], bytes, int | None]:
        expected = {
            "schema_version",
            "session_id",
            "operation",
            "method",
            "path",
            "headers",
            "body_hex",
        }
        if set(request) != expected:
            raise ProviderRequestPolicyRejected(
                "provider_request_fields_invalid",
                "provider request fields are invalid",
            )
        method = request["method"]
        path = request["path"]
        if method not in {"GET", "POST"} or path not in ALLOWED_PROVIDER_PATHS:
            raise ProviderRequestPolicyRejected(
                "provider_route_outside_frozen_set",
                "provider method or path is outside the frozen route",
            )
        headers = request["headers"]
        if not isinstance(headers, dict) or any(
            not isinstance(key, str) or not isinstance(value, str)
            for key, value in headers.items()
        ):
            raise ProviderRequestPolicyRejected(
                "provider_headers_invalid",
                "provider headers are invalid",
            )
        lowered = {key.lower(): value for key, value in headers.items()}
        forbidden = {"authorization", "x-api-key", "proxy-authorization"}
        if forbidden.intersection(lowered):
            raise ProviderRequestPolicyRejected(
                "provider_credential_header_forbidden",
                "container attempted to send a credential header",
            )
        body_hex = request["body_hex"]
        if not isinstance(body_hex, str) or len(body_hex) > MAX_PROVIDER_BODY_BYTES * 2:
            raise ProviderRequestPolicyRejected(
                "provider_body_invalid_or_too_large",
                "provider body is invalid or too large",
            )
        try:
            body = bytes.fromhex(body_hex)
        except ValueError as exc:
            raise ProviderRequestPolicyRejected(
                "provider_body_not_hexadecimal",
                "provider body is not valid hexadecimal",
            ) from exc
        if method == "GET":
            if body:
                raise ProviderRequestPolicyRejected(
                    "provider_get_body_forbidden",
                    "GET provider request must not contain a body",
                )
            max_tokens = None
        else:
            try:
                payload = json.loads(body.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ProviderRequestPolicyRejected(
                    "provider_body_not_json",
                    "provider request body is not JSON",
                ) from exc
            if not isinstance(payload, dict) or payload.get("model") != self.expected_model:
                raise ProviderRequestPolicyRejected(
                    "provider_model_mismatch",
                    "provider model differs from the frozen model",
                )
            if payload.get("thinking") != {"type": "disabled"}:
                raise ProviderRequestPolicyRejected(
                    "provider_thinking_mode_mismatch",
                    "provider thinking mode differs from the frozen mode",
                )
            if payload.get("temperature") != 0 or payload.get("top_p") != 1:
                raise ProviderRequestPolicyRejected(
                    "provider_sampling_mismatch",
                    "provider sampling differs from the frozen decoding",
                )
            candidate_count = payload.get("n", 1)
            if (
                isinstance(candidate_count, bool)
                or not isinstance(candidate_count, int)
                or candidate_count != 1
            ):
                raise ProviderRequestPolicyRejected(
                    "provider_candidate_count_invalid",
                    "provider requests must produce exactly one candidate",
                )
            token_fields = [
                name
                for name in ("max_tokens", "max_completion_tokens")
                if name in payload
            ]
            max_tokens = payload.get(token_fields[0]) if len(token_fields) == 1 else None
            if (
                len(token_fields) != 1
                or isinstance(max_tokens, bool)
                or not isinstance(max_tokens, int)
                or not 1 <= max_tokens <= self.maximum_output_tokens_per_call
            ):
                raise ProviderRequestPolicyRejected(
                    "provider_output_token_bound_invalid",
                    "provider output-token bound is invalid",
                )
        return method, path, lowered, body, max_tokens

    def _provider_budget_rejected(self, detail_code: str) -> dict[str, Any]:
        if detail_code not in self._provider_budget_rejection_counts:
            raise RuntimeError("unknown provider budget rejection code")
        self._provider_budget_rejection_count += 1
        self._provider_budget_rejection_counts[detail_code] += 1
        if self._terminal_guard_reason is None:
            self._terminal_guard_reason = detail_code
        return {
            "schema_version": PROTOCOL_VERSION,
            "status": "ok",
            "http_status": 429,
            "headers": {"content-type": "application/json"},
            "body_hex": json.dumps(
                {"error": {"code": f"provider_budget_{detail_code}"}},
                separators=(",", ":"),
            ).encode("utf-8").hex(),
        }

    def close_provider_admission(self) -> dict[str, Any]:
        """Host-only shutdown: cancel queued calls without erasing live usage."""
        with self._lock:
            already_closed = self._provider_admission_closed
            self._provider_admission_closed = True
            return {
                "already_closed": already_closed,
                "unfinished_provider_count": len(self._open_provider),
                "raw_content_embedded": False,
            }

    def provider_http(self, request: dict[str, Any]) -> dict[str, Any]:
        """One in-flight forward per controller; waiting calls recheck all gates.

        This is a versioned execution policy, not a change to token limits. Queue
        time remains part of total wall time, outside the actual-call interval.
        The forwarder still owns its bounded network timeout. Closing before a
        waiting call acquires this lock prevents that call from being forwarded.
        """
        with self._provider_dispatch_lock:
            return self._settled_provider_http(request)

    def _settled_provider_http(self, request: dict[str, Any]) -> dict[str, Any]:
        method, path, headers, body, requested_output_tokens = (
            self._validate_provider_request(request)
        )
        request_sha256 = _canonical_sha256(
            {
                "method": method,
                "path": path,
                "body_sha256": hashlib.sha256(body).hexdigest(),
            }
        )
        output_token_bound_was_clamped = False
        with self._lock:
            if self._closed:
                raise RuntimeError("controller is closed")
            if self._provider_admission_closed:
                raise RuntimeError("provider admission closed after workflow exit")
            if self._provider_sequence >= self.maximum_provider_calls:
                return self._provider_budget_rejected("call_limit")
            if (
                self._provider_token_usage_expected_count
                != self._provider_token_usage_observed_count
            ):
                return self._provider_budget_rejected("token_accounting_incomplete")
            if self._provider_input_tokens >= self.maximum_input_tokens:
                return self._provider_budget_rejected("input_token_limit")
            if self._provider_output_tokens >= self.maximum_output_tokens:
                return self._provider_budget_rejected("output_token_limit")
            if method == "POST" and path == "/v1/chat/completions":
                remaining_input = self.maximum_input_tokens - self._provider_input_tokens
                remaining_output = (
                    self.maximum_output_tokens - self._provider_output_tokens
                )
                # The UTF-8 JSON byte count is a conservative upper bound on
                # prompt tokens and therefore prevents a cumulative overshoot.
                if len(body) > remaining_input:
                    return self._provider_budget_rejected("input_token_limit")
                if requested_output_tokens is None:
                    return self._provider_budget_rejected("output_token_limit")
                if requested_output_tokens > remaining_output:
                    payload = json.loads(body.decode("utf-8"))
                    token_field = next(
                        name
                        for name in ("max_tokens", "max_completion_tokens")
                        if name in payload
                    )
                    payload[token_field] = remaining_output
                    body = json.dumps(
                        payload,
                        separators=(",", ":"),
                        ensure_ascii=False,
                    ).encode("utf-8")
                    if "content-length" in headers:
                        headers = dict(headers)
                        headers["content-length"] = str(len(body))
                    requested_output_tokens = remaining_output
                    output_token_bound_was_clamped = True
            next_identical_request_count = (
                self._consecutive_identical_request_count + 1
                if request_sha256 == self._last_request_sha256
                else 1
            )
            if (
                next_identical_request_count
                > self.maximum_consecutive_identical_requests
            ):
                return self._provider_budget_rejected("repeated_request")
            if (
                self._consecutive_identical_error_count
                >= self.maximum_consecutive_identical_errors
            ):
                return self._provider_budget_rejected("repeated_error")
            self._last_request_sha256 = request_sha256
            self._consecutive_identical_request_count = next_identical_request_count
            self._highest_consecutive_identical_request_count = max(
                self._highest_consecutive_identical_request_count,
                next_identical_request_count,
            )
            if output_token_bound_was_clamped:
                self._provider_output_token_bound_clamp_count += 1
            self._provider_sequence += 1
            activity_id = self._new_id("llm", self._provider_sequence)
            started = self._offset()
            self._open_provider.add(activity_id)
        status = 502
        response_headers: dict[str, str] = {"content-type": "application/json"}
        response_body = b'{"error":{"message":"observed provider transport failed"}}'
        outcome = "failed"
        try:
            status, response_headers, response_body = self.provider_forwarder(
                method=method, path=path, headers=headers, body=body
            )
            if (
                not isinstance(status, int)
                or not 100 <= status <= 599
                or not isinstance(response_headers, dict)
                or not isinstance(response_body, bytes)
                or len(response_body) > MAX_PROVIDER_RESPONSE_BYTES
            ):
                raise ValueError("provider forwarder returned an invalid response")
            outcome = "completed" if status < 500 else "failed"
        except TimeoutError:
            outcome = "timed_out"
            status = 504
            response_body = b'{"error":{"message":"observed provider transport timed out"}}'
        except Exception:
            outcome = "failed"
        completed = self._offset()
        token_usage = (
            _extract_provider_token_usage(
                response_headers=response_headers,
                response_body=response_body,
            )
            if method == "POST" and path == "/v1/chat/completions"
            else None
        )
        finish_reason = (
            _extract_provider_finish_reason(
                response_headers=response_headers,
                response_body=response_body,
            )
            if method == "POST" and path == "/v1/chat/completions"
            else None
        )
        with self._lock:
            if method == "POST" and path == "/v1/chat/completions":
                self._provider_token_usage_expected_count += 1
                if finish_reason is not None:
                    self._provider_finish_reason_observed_count += 1
                    self._provider_finish_reason_counts[finish_reason] += 1
                if token_usage is not None:
                    self._provider_token_usage_observed_count += 1
                    self._provider_input_tokens += token_usage["input_tokens"]
                    self._provider_output_tokens += token_usage["output_tokens"]
                    self._provider_total_tokens += token_usage["total_tokens"]
                    if token_usage["cache_measurement_complete"]:
                        self._provider_cache_usage_observed_count += 1
                        self._provider_cache_hit_input_tokens += int(
                            token_usage["cache_hit_input_tokens"]
                        )
                        self._provider_cache_miss_input_tokens += int(
                            token_usage["cache_miss_input_tokens"]
                        )
                    output_cap_reached = (
                        requested_output_tokens is not None
                        and token_usage["output_tokens"] >= requested_output_tokens
                    )
                    if output_cap_reached:
                        self._provider_output_cap_reached_call_count += 1
                        if finish_reason == "length":
                            self._provider_output_cap_with_length_finish_count += 1
            if outcome != "completed" or status >= 400:
                error_sha256 = _canonical_sha256(
                    {
                        "http_status": status,
                        "outcome": outcome,
                        "response_sha256": hashlib.sha256(response_body).hexdigest(),
                    }
                )
                self._consecutive_identical_error_count = (
                    self._consecutive_identical_error_count + 1
                    if error_sha256 == self._last_error_sha256
                    else 1
                )
                self._last_error_sha256 = error_sha256
                self._highest_consecutive_identical_error_count = max(
                    self._highest_consecutive_identical_error_count,
                    self._consecutive_identical_error_count,
                )
                if (
                    self._consecutive_identical_error_count
                    >= self.maximum_consecutive_identical_errors
                    and self._terminal_guard_reason is None
                ):
                    self._terminal_guard_reason = "repeated_error"
            else:
                self._last_error_sha256 = None
                self._consecutive_identical_error_count = 0
            self._append(
                activity_id=activity_id,
                kind="llm_call",
                controller="provider_gateway",
                started_offset_ns=started,
                completed_offset_ns=completed,
                outcome=outcome,
                binding_context={"method": method, "path": path, "http_status": status},
            )
            self._open_provider.remove(activity_id)
        safe_response_headers = {
            key.lower(): value
            for key, value in response_headers.items()
            if key.lower() in {"content-type", "content-encoding", "x-request-id"}
            and isinstance(value, str)
            and len(value) <= 1024
        }
        return {
            "schema_version": PROTOCOL_VERSION,
            "status": "ok",
            "http_status": status,
            "headers": safe_response_headers,
            "body_hex": response_body.hex(),
        }

    def eda_start(self, request: dict[str, Any]) -> dict[str, Any]:
        expected = {
            "schema_version",
            "session_id",
            "operation",
            "invocation_id",
            "tool",
        }
        if set(request) != expected:
            raise ValueError("EDA start fields are invalid")
        invocation_id = request["invocation_id"]
        tool = request["tool"]
        if ACTIVITY_RE.fullmatch(str(invocation_id)) is None or tool not in EDA_TO_KIND:
            raise ValueError("EDA invocation id or tool is invalid")
        with self._lock:
            if self._closed or invocation_id in self._open_eda:
                raise RuntimeError("EDA invocation is duplicated or controller is closed")
            activity_id = self._new_id("eda", len(self._ids) + 1)
            self._open_eda[invocation_id] = _OpenEdaActivity(
                activity_id=activity_id,
                kind=EDA_TO_KIND[tool],
                started_offset_ns=self._offset(),
                tool=tool,
            )
        return {"schema_version": PROTOCOL_VERSION, "status": "accepted"}

    def eda_finish(self, request: dict[str, Any]) -> dict[str, Any]:
        expected = {
            "schema_version",
            "session_id",
            "operation",
            "invocation_id",
            "outcome",
        }
        if set(request) != expected:
            raise ValueError("EDA finish fields are invalid")
        invocation_id = request["invocation_id"]
        outcome = request["outcome"]
        if outcome not in {"completed", "failed", "timed_out"}:
            raise ValueError("EDA outcome is invalid")
        with self._lock:
            opened = self._open_eda.pop(invocation_id, None)
            if opened is None:
                raise ValueError("EDA invocation was not opened")
            self._append(
                activity_id=opened.activity_id,
                kind=opened.kind,
                controller="eda_broker",
                started_offset_ns=opened.started_offset_ns,
                completed_offset_ns=self._offset(),
                outcome=outcome,
                binding_context={"tool": opened.tool},
            )
        return {"schema_version": PROTOCOL_VERSION, "status": "accepted"}

    def close_unfinished_eda_on_process_exit(self, *, outcome: str) -> int:
        """Conservatively close EDA activities orphaned by workflow exit.

        An EDA shim normally sends ``eda_finish`` from a ``finally`` block. A
        parent-side timeout can terminate the shim before Python gets that
        chance, which must not erase the rest of the resource sample. The
        returned count is recorded in process and merged receipts.
        """
        if outcome not in {"failed", "timed_out"}:
            raise ValueError("forced EDA outcome is invalid")
        with self._lock:
            if self._closed:
                raise RuntimeError("controller is already closed")
            completed_offset_ns = self._offset()
            opened = sorted(
                self._open_eda.values(), key=lambda row: row.activity_id
            )
            self._open_eda.clear()
            for row in opened:
                self._append(
                    activity_id=row.activity_id,
                    kind=row.kind,
                    controller="eda_broker",
                    started_offset_ns=row.started_offset_ns,
                    completed_offset_ns=completed_offset_ns,
                    outcome=outcome,
                    binding_context={
                        "tool": row.tool,
                        "completion": "forced_on_workflow_process_exit",
                    },
                )
            return len(opened)

    def dispatch(self, request: dict[str, Any]) -> dict[str, Any]:
        if request.get("schema_version") != PROTOCOL_VERSION:
            raise ValueError("controller protocol version is invalid")
        if request.get("session_id") != self.session_id:
            raise PermissionError("controller session id does not match")
        operation = request.get("operation")
        if operation == "health":
            if set(request) != {"schema_version", "session_id", "operation"}:
                raise ValueError("health request fields are invalid")
            response = {
                "schema_version": PROTOCOL_VERSION,
                "status": "ready",
                "provider_runtime": {
                    "model": self.expected_model,
                    "thinking": {"type": "disabled"},
                    "temperature": 0,
                    "top_p": 1,
                    "maximum_output_tokens": self.maximum_output_tokens_per_call,
                    "maximum_calls_per_measurement": self.maximum_provider_calls,
                    "maximum_input_tokens_per_measurement": (
                        self.maximum_input_tokens
                    ),
                    "maximum_output_tokens_per_measurement": (
                        self.maximum_output_tokens
                    ),
                    "maximum_consecutive_identical_requests": (
                        self.maximum_consecutive_identical_requests
                    ),
                    "maximum_consecutive_identical_errors": (
                        self.maximum_consecutive_identical_errors
                    ),
                },
            }
            if self.public_command_broker is not None:
                response["public_command_runtime"] = self.public_command_broker.capability()
            return response
        if operation == "public_command":
            if self.public_command_broker is None:
                raise ValueError("public command broker is not enabled")
            with self._lock:
                if self._closed or self._origin_ns is None:
                    raise RuntimeError("public command requires an active measurement")
            return self.public_command_broker.dispatch(request)
        if operation == "provider_http":
            return self.provider_http(request)
        if operation == "eda_start":
            return self.eda_start(request)
        if operation == "eda_finish":
            return self.eda_finish(request)
        raise ValueError("controller operation is unsupported")

    def activity_summary(self) -> dict[str, Any]:
        """Return content-free live counts for transport-only OCI probes."""
        with self._lock:
            return {
                "activity_count": len(self._activities),
                "llm_activity_count": sum(
                    row["kind"] == "llm_call" for row in self._activities
                ),
                "eda_activity_count": sum(
                    row["kind"] != "llm_call" for row in self._activities
                ),
                "unfinished_eda_activity_count": len(self._open_eda),
                "raw_content_embedded": False,
            }

    def terminal_guard_reason(self) -> str | None:
        """Return the content-free reason that requires process termination."""
        with self._lock:
            return self._terminal_guard_reason

    def snapshot_ledger(
        self, *, observed_at: str, process_measurement_receipt_sha256: str
    ) -> dict[str, Any]:
        """Detached mid-attempt telemetry, never final settlement or an RPC grant."""
        ledger = self._project_ledger(
            observed_at=observed_at,
            process_measurement_receipt_sha256=process_measurement_receipt_sha256,
            finalize=False,
        )
        return {
            "schema_version": "rtlflowbench.workflow_activity_snapshot.v1",
            "finalized": False,
            "ledger": ledger,
        }

    def build_ledger(
        self, *, observed_at: str, process_measurement_receipt_sha256: str
    ) -> dict[str, Any]:
        """Final settlement retains the existing close-before-export contract."""
        return self._project_ledger(
            observed_at=observed_at,
            process_measurement_receipt_sha256=process_measurement_receipt_sha256,
            finalize=True,
        )

    def _project_ledger(
        self, *, observed_at: str, process_measurement_receipt_sha256: str,
        finalize: bool,
    ) -> dict[str, Any]:
        if self.public_command_broker is not None:
            raise RuntimeError("public capsule resource aggregation is not integrated; legacy whole-workflow ledger is unavailable")
        if re.fullmatch(r"[0-9a-f]{64}", process_measurement_receipt_sha256) is None:
            raise ValueError("process measurement receipt SHA256 is malformed")
        with self._lock:
            if not finalize and self._closed:
                raise RuntimeError("cannot snapshot a closed controller")
            if self._origin_ns is None:
                raise RuntimeError("measurement origin was never established")
            if self._open_eda:
                raise RuntimeError("cannot close ledger with unfinished EDA activities")
            if self._open_provider:
                raise RuntimeError(
                    "cannot close ledger with unfinished provider activities"
                )
            if finalize:
                self._closed = True
            activities = sorted(
                self._activities,
                key=lambda row: (row["started_offset_ns"], row["activity_id"]),
            )
            provider_budget = {
                "maximum_forwarded_calls": self.maximum_provider_calls,
                "maximum_output_tokens_per_call": self.maximum_output_tokens_per_call,
                "maximum_input_tokens": self.maximum_input_tokens,
                "maximum_output_tokens": self.maximum_output_tokens,
                "maximum_consecutive_identical_requests": (
                    self.maximum_consecutive_identical_requests
                ),
                "maximum_consecutive_identical_errors": (
                    self.maximum_consecutive_identical_errors
                ),
                "forwarded_call_count": self._provider_sequence,
                "output_token_bound_clamp_count": (
                    self._provider_output_token_bound_clamp_count
                ),
                "rejected_call_count": self._provider_budget_rejection_count,
                "rejection_counts": dict(self._provider_budget_rejection_counts),
                "highest_consecutive_identical_request_count": (
                    self._highest_consecutive_identical_request_count
                ),
                "highest_consecutive_identical_error_count": (
                    self._highest_consecutive_identical_error_count
                ),
                "exhausted": self._provider_budget_rejection_count > 0,
            }
            token_measurement_complete = (
                self._provider_token_usage_expected_count
                == self._provider_token_usage_observed_count
            )
            provider_budget["token_usage"] = {
                "accounting_policy": TOKEN_ACCOUNTING_POLICY,
                "measurement_complete": token_measurement_complete,
                "expected_call_count": self._provider_token_usage_expected_count,
                "observed_call_count": self._provider_token_usage_observed_count,
                "unobserved_call_count": (
                    self._provider_token_usage_expected_count
                    - self._provider_token_usage_observed_count
                ),
                "input_tokens": (
                    self._provider_input_tokens
                    if token_measurement_complete
                    else None
                ),
                "output_tokens": (
                    self._provider_output_tokens
                    if token_measurement_complete
                    else None
                ),
                "total_tokens": (
                    self._provider_total_tokens
                    if token_measurement_complete
                    else None
                ),
                "observed_input_tokens": self._provider_input_tokens,
                "observed_output_tokens": self._provider_output_tokens,
                "observed_total_tokens": self._provider_total_tokens,
                "cache_measurement_complete": (
                    token_measurement_complete
                    and self._provider_cache_usage_observed_count
                    == self._provider_token_usage_expected_count
                ),
                "cache_observed_call_count": self._provider_cache_usage_observed_count,
                "cache_unobserved_call_count": (
                    self._provider_token_usage_expected_count
                    - self._provider_cache_usage_observed_count
                ),
                "cache_hit_input_tokens": (
                    self._provider_cache_hit_input_tokens
                    if token_measurement_complete
                    and self._provider_cache_usage_observed_count
                    == self._provider_token_usage_expected_count
                    else None
                ),
                "cache_miss_input_tokens": (
                    self._provider_cache_miss_input_tokens
                    if token_measurement_complete
                    and self._provider_cache_usage_observed_count
                    == self._provider_token_usage_expected_count
                    else None
                ),
                "observed_cache_hit_input_tokens": (
                    self._provider_cache_hit_input_tokens
                ),
                "observed_cache_miss_input_tokens": (
                    self._provider_cache_miss_input_tokens
                ),
                "finish_reason_measurement_complete": (
                    self._provider_finish_reason_observed_count
                    == self._provider_token_usage_expected_count
                ),
                "finish_reason_observed_call_count": (
                    self._provider_finish_reason_observed_count
                ),
                "finish_reason_unobserved_call_count": (
                    self._provider_token_usage_expected_count
                    - self._provider_finish_reason_observed_count
                ),
                "finish_reason_counts": dict(self._provider_finish_reason_counts),
                "output_cap_reached_call_count": (
                    self._provider_output_cap_reached_call_count
                ),
                "output_cap_with_length_finish_count": (
                    self._provider_output_cap_with_length_finish_count
                ),
                "raw_content_embedded": False,
            }
            if finalize:
                measurement, controller_bindings = self.measurement, self.controller_bindings
            else:
                activities = json.loads(json.dumps(activities))
                measurement = json.loads(json.dumps(self.measurement))
                controller_bindings = json.loads(json.dumps(self.controller_bindings))
        return {
            "schema_version": "rtlflowbench.workflow_activity_ledger.v1",
            "observed_at": observed_at,
            **measurement,
            "process_measurement_receipt_sha256": process_measurement_receipt_sha256,
            "timing": {
                "clock": "monotonic_ns",
                "origin": "measurement_envelope_process_start",
                "interval_semantics": (
                    "half_open_started_inclusive_completed_exclusive"
                ),
            },
            "controllers": controller_bindings,
            "provider_budget": provider_budget,
            "completeness": {
                "provider_gateway_observation_complete": True,
                "eda_broker_observation_complete": True,
                "all_provider_calls_routed_through_observer": True,
                "all_eda_invocations_routed_through_observer": True,
                "raw_provider_response_exposed": False,
                "credentials_exposed": False,
                "private_evaluator_instrumented": False,
                "task_workspace_can_write_ledger": False,
            },
            "activities": activities,
            "attempt_accounting": {
                "official_attempt_started": False,
                "official_semantic_attempt_consumed": False,
                "resource_calibration_attempt_consumed": True,
                "benchmark_result_created": False,
                "private_evaluator_calls": 0,
            },
            "excluded_claims": [
                "The controller activity ledger is resource-calibration telemetry and is not an RTL correctness, QoR, or benchmark verdict.",
                "Provider prompts, provider responses, credentials, user identifiers, and request bodies are neither embedded nor persisted in this ledger.",
                "The private evaluator is not mounted, instrumented, invoked, or reachable from the workflow calibration workspace.",
                "No official Golden-12 semantic attempt is started or consumed by this resource-only controller session.",
            ],
        }


class _UnixControllerHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        try:
            request = recv_frame(self.request)
            response = self.server.controller_state.dispatch(request)  # type: ignore[attr-defined]
        except Exception as exc:
            if isinstance(exc, PermissionError):
                error_code = "authorization_rejected"
                error_detail_code = None
            elif isinstance(exc, ProviderRequestPolicyRejected):
                error_code = "request_policy_rejected"
                error_detail_code = exc.detail_code
            elif isinstance(exc, ValueError):
                error_code = "request_policy_rejected"
                error_detail_code = "request_policy_rejected_unspecified"
            else:
                error_code = "controller_state_rejected"
                error_detail_code = None
            response = {
                "schema_version": PROTOCOL_VERSION,
                "status": "error",
                "error_class": type(exc).__name__,
                "error_code": error_code,
            }
            if error_detail_code is not None:
                response["error_detail_code"] = error_detail_code
        send_frame(self.request, response)


class _ThreadingUnixServer(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True
    allow_reuse_address = False


class ControllerServer:
    def __init__(self, *, socket_path: Path, state: ControllerState):
        self.socket_path = socket_path.expanduser().absolute()
        if len(os.fsencode(self.socket_path)) > UNIX_SOCKET_PATH_MAX_BYTES:
            raise ValueError("controller socket path is too long for portable AF_UNIX")
        if self.socket_path.exists() or self.socket_path.is_symlink():
            raise FileExistsError("refusing to replace controller socket path")
        parent = self.socket_path.parent
        if parent.exists():
            if parent.is_symlink() or not parent.is_dir() or any(parent.iterdir()):
                raise ValueError("controller socket root must be an empty directory")
        else:
            parent.mkdir(parents=True, mode=0o700)
        os.chmod(parent, 0o700)
        self.server = _ThreadingUnixServer(str(self.socket_path), _UnixControllerHandler)
        self.server.controller_state = state  # type: ignore[attr-defined]
        os.chmod(self.socket_path, 0o600)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self) -> "ControllerServer":
        self.thread.start()
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.socket_path.unlink(missing_ok=True)
        if self.thread.is_alive():
            raise RuntimeError("controller server thread did not stop")


def rpc(socket_path: Path, request: dict[str, Any], timeout: float = 30.0) -> dict[str, Any]:
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.settimeout(timeout)
    try:
        connection.connect(str(socket_path))
        send_frame(connection, request)
        return recv_frame(connection)
    finally:
        connection.close()
