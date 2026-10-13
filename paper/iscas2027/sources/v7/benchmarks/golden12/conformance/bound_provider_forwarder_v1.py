"""Opt-in, host-only fixed route for the existing observed provider controller.

This is not a provider selector or a budget authority. The trusted caller pins
the reviewed route and gives this callable to ControllerState, which still owns
all call/token/stop accounting. Credentials never come from a workload request.
Historical official-DeepSeek forwarding and launchers remain unchanged.
"""

import hashlib
import http.client
import json
import re
import ssl
from urllib.parse import urlsplit


ALLOWED_HOSTS = frozenset({"api.deepseek.com", "llmapi.paratera.com"})
SHA = re.compile(r"[0-9a-f]{64}")
MODEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}")
MAX_REQUEST = 24 * 1024 * 1024


def canonical(value):
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
    ).hexdigest()


def _object(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate provider request field")
            result[key] = value
        return result

    def nonfinite(_):
        raise ValueError("nonfinite provider request field")

    result = json.loads(raw, object_pairs_hook=unique, parse_constant=nonfinite)
    if type(result) is not dict:
        raise ValueError("provider request must be an object")
    return result


class BoundProviderForwarder:
    def __init__(self, *, route, expected_route_sha256, api_key):
        if type(route) is not dict or set(route) != {
            "schema",
            "base_url",
            "model",
            "native_model_config_sha256",
            "timeout_seconds",
            "maximum_response_bytes",
        }:
            raise ValueError("invalid bound provider route fields")
        if route["schema"] != "chipflow.bound_openai_provider_route.v1":
            raise ValueError("invalid bound provider route schema")
        if (
            type(expected_route_sha256) is not str
            or not SHA.fullmatch(expected_route_sha256)
            or canonical(route) != expected_route_sha256
        ):
            raise ValueError("bound provider route hash mismatch")
        base = route["base_url"]
        if type(base) is not str or any(ord(c) <= 32 or ord(c) >= 127 for c in base):
            raise ValueError("invalid provider URL")
        parsed = urlsplit(base)
        if (
            parsed.scheme != "https"
            or parsed.hostname not in ALLOWED_HOSTS
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or "?" in base
            or "#" in base
            or parsed.port not in (None, 443)
            or parsed.path.rstrip("/") not in {"", "/v1"}
        ):
            raise ValueError("provider URL outside reviewed fixed routes")
        if type(route["model"]) is not str or not MODEL.fullmatch(route["model"]):
            raise ValueError("invalid bound provider model")
        if type(route["native_model_config_sha256"]) is not str or not SHA.fullmatch(
            route["native_model_config_sha256"]
        ):
            raise ValueError("missing native model configuration binding")
        if (
            type(route["timeout_seconds"]) is not int
            or not 1 <= route["timeout_seconds"] <= 600
        ):
            raise ValueError("invalid provider timeout")
        if (
            type(route["maximum_response_bytes"]) is not int
            or not 1 <= route["maximum_response_bytes"] <= 32 * 1024 * 1024
        ):
            raise ValueError("invalid provider response limit")
        if (
            type(api_key) is not str
            or not api_key
            or any(ord(c) <= 32 or ord(c) >= 127 for c in api_key)
        ):
            raise ValueError("provider credential unavailable or malformed")
        self._route = dict(route)
        self._route_hash = expected_route_sha256
        self._host = parsed.hostname
        self._prefix = parsed.path.rstrip("/")
        self._api_key = api_key

    @property
    def binding(self):
        return {
            "schema": self._route["schema"],
            "route_sha256": self._route_hash,
            "endpoint_sha256": hashlib.sha256(
                self._route["base_url"].encode()
            ).hexdigest(),
            "model": self._route["model"],
            "native_model_config_sha256": self._route["native_model_config_sha256"],
            "credential_recorded": False,
        }

    def __call__(self, *, method, path, headers, body):
        if (method, path) not in {
            ("POST", "/v1/chat/completions"),
            ("GET", "/v1/models"),
        }:
            raise ValueError("provider operation outside reviewed route")
        if type(body) is not bytes or len(body) > MAX_REQUEST:
            raise ValueError("invalid provider request body")
        if type(headers) is not dict or any(
            k not in {"content-type", "accept"} for k in headers
        ):
            raise ValueError("workload provider headers forbidden")
        if any(
            v not in {"application/json", "text/event-stream"} for v in headers.values()
        ):
            raise ValueError("invalid provider content negotiation")
        if method == "POST":
            value = _object(body)
            if value.get("model") != self._route["model"]:
                raise ValueError("provider model differs from bound route")
        elif body:
            raise ValueError("model-list request cannot contain a body")
        # No proxy/env destination, redirect following or retry. The existing
        # controller enforces cumulative spend before it calls this transport.
        connection = http.client.HTTPSConnection(
            self._host,
            443,
            timeout=self._route["timeout_seconds"],
            context=ssl.create_default_context(),
        )
        safe_headers = {
            "Authorization": "Bearer " + self._api_key,
            "Accept": headers.get("accept", "application/json"),
            "Content-Type": "application/json",
            "Content-Length": str(len(body)),
            "User-Agent": "rtlflowbench-bound-provider-gateway/1",
        }
        try:
            connection.request(
                method,
                self._prefix + path.removeprefix("/v1"),
                body=body,
                headers=safe_headers,
            )
            response = connection.getresponse()
            content = response.read(self._route["maximum_response_bytes"] + 1)
            if len(content) > self._route["maximum_response_bytes"]:
                raise ValueError("provider response exceeds bound limit")
            selected_headers = {
                k.lower(): v
                for k, v in response.getheaders()
                if k.lower() in {"content-type", "content-encoding"}
            }
            return response.status, selected_headers, content
        finally:
            connection.close()
