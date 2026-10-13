"""Opt-in host-only, content-bound translation of one model identifier.

The workflow speaks the frozen workload model alias. The trusted host changes
only the JSON `model` field to the pinned upstream provider spelling; all
workflows must use the same route identity for a comparable cohort. This
module has no budget or task authority and must sit behind ControllerState.
"""

from __future__ import annotations

import json

import bound_provider_forwarder_v1 as base

canonical = base.canonical


class AliasBoundProviderForwarder:
    def __init__(self, *, route: dict, expected_route_sha256: str, api_key: str):
        if type(route) is not dict or set(route) != {
            "schema",
            "base_url",
            "workload_model",
            "upstream_model",
            "native_model_config_sha256",
            "timeout_seconds",
            "maximum_response_bytes",
        }:
            raise ValueError("invalid alias route fields")
        if route["schema"] != "chipflow.bound_openai_provider_route.v2":
            raise ValueError("invalid alias route schema")
        if (
            type(expected_route_sha256) is not str
            or base.SHA.fullmatch(expected_route_sha256) is None
            or canonical(route) != expected_route_sha256
        ):
            raise ValueError("alias route content hash mismatch")
        workload = route["workload_model"]
        upstream = route["upstream_model"]
        if (
            type(workload) is not str
            or type(upstream) is not str
            or base.MODEL.fullmatch(workload) is None
            or base.MODEL.fullmatch(upstream) is None
            or workload == upstream
        ):
            raise ValueError("a distinct exact model alias is required")
        inner_route = {
            "schema": "chipflow.bound_openai_provider_route.v1",
            "base_url": route["base_url"],
            "model": upstream,
            "native_model_config_sha256": route["native_model_config_sha256"],
            "timeout_seconds": route["timeout_seconds"],
            "maximum_response_bytes": route["maximum_response_bytes"],
        }
        self._inner = base.BoundProviderForwarder(
            route=inner_route,
            expected_route_sha256=canonical(inner_route),
            api_key=api_key,
        )
        self._route_sha256 = expected_route_sha256
        self._workload_model = workload
        self._upstream_model = upstream

    @property
    def binding(self) -> dict:
        inner = self._inner.binding
        return {
            "schema": "chipflow.bound_openai_provider_route.v2",
            "route_sha256": self._route_sha256,
            "endpoint_sha256": inner["endpoint_sha256"],
            "workload_model": self._workload_model,
            "upstream_model": self._upstream_model,
            "native_model_config_sha256": inner["native_model_config_sha256"],
            "request_model_field_reencoded": True,
            "credential_recorded": False,
        }

    def __call__(self, *, method: str, path: str, headers: dict, body: bytes):
        if method == "POST":
            if type(body) is not bytes or len(body) > base.MAX_REQUEST:
                raise ValueError("invalid provider request body")
            value = base._object(body)
            if value.get("model") != self._workload_model:
                raise ValueError("workload model differs from bound alias")
            value["model"] = self._upstream_model
            body = json.dumps(
                value, sort_keys=True, separators=(",", ":"), allow_nan=False
            ).encode("utf-8")
        return self._inner(method=method, path=path, headers=headers, body=body)
