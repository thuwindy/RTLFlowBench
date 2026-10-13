#!/usr/bin/env python3
"""Register reviewed OpenAI-compatible chat models for the pinned MAGE runtime.

The LlamaIndex version used by upstream MAGE rejects model identifiers that are
not in its bundled OpenAI model table before an HTTP request is attempted.  This
module adds one explicit, caller-reviewed model/context binding without changing
the upstream source tree or serialising provider credentials.
"""

from __future__ import annotations

import re
from types import ModuleType
from typing import Any


SCHEMA_VERSION = "rtlflowbench.mage_openai_compat_binding.v3"
MODEL_ID_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9._:/+\-]{0,253}[A-Za-z0-9])?$"
)
FROZEN_TEMPERATURE = 0.0
FROZEN_TOP_P = 1.0
MIN_CONTEXT_WINDOW = 1_024
MAX_CONTEXT_WINDOW = 16_777_216


def _frozen_call_kwargs(kwargs: dict[str, Any]) -> dict[str, Any]:
    """Apply the campaign-wide decoding lock to MAGE per-call overrides.

    Upstream MAGE supplies its own sampling values on individual ``chat``
    calls. Those values would otherwise override the reviewed constructor
    binding and make MAGE incomparable with the other workflows. Normalizing
    these generic launch parameters adds no task or solution knowledge.
    """

    frozen = dict(kwargs)
    frozen["temperature"] = FROZEN_TEMPERATURE
    frozen["top_p"] = FROZEN_TOP_P
    if "additional_kwargs" in frozen:
        additional = frozen["additional_kwargs"]
        if not isinstance(additional, dict):
            raise TypeError("MAGE per-call additional_kwargs must be a dictionary")
        normalized_additional = dict(additional)
        normalized_additional["top_p"] = FROZEN_TOP_P
        frozen["additional_kwargs"] = normalized_additional
    return frozen


class OpenAICompatibleLLMProxy:
    """Delegate LLM calls while preventing false tiktoken model detection.

    Upstream MAGE treats every LlamaIndex ``OpenAI`` instance as if its model
    identifier were present in tiktoken.  Third-party OpenAI-compatible model
    identifiers are not.  The proxy preserves the LLM API while making MAGE use
    its explicit no-tokenizer branch; external receipts therefore report token
    accounting as unavailable rather than the zero values produced internally.
    """

    __slots__ = ("_call_count", "_delegate")

    def __init__(self, delegate: Any) -> None:
        self._delegate = delegate
        self._call_count = 0

    def __getattr__(self, name: str) -> Any:
        return getattr(self._delegate, name)

    @property
    def observed_call_count(self) -> int:
        return self._call_count

    def chat(self, *args: Any, **kwargs: Any) -> Any:
        self._call_count += 1
        return self._delegate.chat(*args, **_frozen_call_kwargs(kwargs))

    async def achat(self, *args: Any, **kwargs: Any) -> Any:
        self._call_count += 1
        return await self._delegate.achat(*args, **_frozen_call_kwargs(kwargs))

    def complete(self, *args: Any, **kwargs: Any) -> Any:
        self._call_count += 1
        return self._delegate.complete(*args, **_frozen_call_kwargs(kwargs))

    async def acomplete(self, *args: Any, **kwargs: Any) -> Any:
        self._call_count += 1
        return await self._delegate.acomplete(
            *args, **_frozen_call_kwargs(kwargs)
        )


def _validate_model_binding(model: str, context_window: int) -> None:
    if not isinstance(model, str) or not MODEL_ID_RE.fullmatch(model):
        raise ValueError("model must be a bounded OpenAI-compatible model identifier")
    if isinstance(context_window, bool) or not isinstance(context_window, int):
        raise ValueError("context_window must be an integer")
    if not MIN_CONTEXT_WINDOW <= context_window <= MAX_CONTEXT_WINDOW:
        raise ValueError("context_window is outside the reviewed safety bounds")


def _load_openai_utils() -> ModuleType:
    import llama_index.llms.openai.utils as openai_utils

    return openai_utils


def register_openai_compatible_chat_model(
    *,
    model: str,
    context_window: int,
    openai_utils: ModuleType | Any | None = None,
) -> dict[str, Any]:
    """Register exactly one chat model, refusing conflicting built-in metadata."""

    _validate_model_binding(model, context_window)
    utils = openai_utils if openai_utils is not None else _load_openai_utils()
    all_models = getattr(utils, "ALL_AVAILABLE_MODELS", None)
    chat_models = getattr(utils, "CHAT_MODELS", None)
    if not isinstance(all_models, dict) or not isinstance(chat_models, dict):
        raise TypeError("pinned LlamaIndex model registries are not dictionaries")
    context_lookup = getattr(utils, "openai_modelname_to_contextsize", None)
    chat_lookup = getattr(utils, "is_chat_model", None)
    if not callable(context_lookup) or not callable(chat_lookup):
        raise TypeError("pinned LlamaIndex model lookup functions are unavailable")

    present_in_all = model in all_models
    present_in_chat = model in chat_models
    added = False
    if present_in_all or present_in_chat:
        if not (
            present_in_all
            and present_in_chat
            and all_models[model] == context_window
            and chat_models[model] == context_window
        ):
            raise ValueError("model already has conflicting or partial metadata")
        registration = "already_registered_same_binding"
    else:
        all_models[model] = context_window
        try:
            chat_models[model] = context_window
            added = True
        except BaseException:
            all_models.pop(model, None)
            chat_models.pop(model, None)
            raise
        registration = "registered_explicit_binding"

    try:
        if context_lookup(model) != context_window or chat_lookup(model) is not True:
            raise RuntimeError("registered model metadata did not round-trip")
    except BaseException:
        if added:
            all_models.pop(model, None)
            chat_models.pop(model, None)
        raise

    return {
        "schema_version": SCHEMA_VERSION,
        "status": "pass",
        "model": model,
        "context_window": context_window,
        "token_accounting": {
            "status": "not_available",
            "exact": False,
            "provider_usage_accounting": False,
            "reason": "external model tokenizer is not available in pinned MAGE",
        },
        "registration": registration,
        "chat_model": True,
        "provider_call_observed": False,
        "provider_credentials_recorded": False,
    }


def build_mage_openai_compatible_llm(
    *,
    model: str,
    context_window: int,
    max_tokens: int,
    max_retries: int,
    timeout_seconds: float,
    thinking_mode: str | None = None,
    cfg_path: str | None = None,
    openai_utils: ModuleType | Any | None = None,
    mage_gen_config: ModuleType | Any | None = None,
) -> tuple[Any, dict[str, Any]]:
    """Build MAGE's LLM through its public factory with bounded client settings.

    Upstream ``get_llm`` performs one completion as its provider preflight.  A
    successful return therefore proves a completion was observed; response text
    is deliberately not returned or included in the receipt.
    """

    registration = register_openai_compatible_chat_model(
        model=model,
        context_window=context_window,
        openai_utils=openai_utils,
    )
    if isinstance(max_tokens, bool) or not isinstance(max_tokens, int):
        raise ValueError("max_tokens must be an integer")
    if not 1 <= max_tokens < context_window:
        raise ValueError("max_tokens must be positive and smaller than context_window")
    if isinstance(max_retries, bool) or not isinstance(max_retries, int):
        raise ValueError("max_retries must be an integer")
    if not 0 <= max_retries <= 10:
        raise ValueError("max_retries is outside the reviewed safety bounds")
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)):
        raise ValueError("timeout_seconds must be numeric")
    if not 1.0 <= float(timeout_seconds) <= 600.0:
        raise ValueError("timeout_seconds is outside the reviewed safety bounds")
    if thinking_mode not in {None, "disabled"}:
        raise ValueError("thinking_mode must be absent or explicitly disabled")

    if mage_gen_config is None:
        import mage.gen_config as imported_gen_config

        mage_gen_config = imported_gen_config
    original_openai = getattr(mage_gen_config, "OpenAI", None)
    get_llm = getattr(mage_gen_config, "get_llm", None)
    if not callable(original_openai) or not callable(get_llm):
        raise TypeError("pinned MAGE OpenAI factory is unavailable")

    def configured_openai(*args: Any, **kwargs: Any) -> Any:
        kwargs["max_retries"] = max_retries
        kwargs["timeout"] = float(timeout_seconds)
        supplied_temperature = kwargs.get("temperature", FROZEN_TEMPERATURE)
        if isinstance(supplied_temperature, bool) or supplied_temperature not in (
            0,
            0.0,
        ):
            raise ValueError("MAGE OpenAI factory defines conflicting temperature")
        kwargs["temperature"] = FROZEN_TEMPERATURE
        if "top_p" in kwargs:
            supplied_top_p = kwargs.pop("top_p")
            if isinstance(supplied_top_p, bool) or supplied_top_p not in (1, 1.0):
                raise ValueError("MAGE OpenAI factory defines conflicting top_p")
        additional = dict(kwargs.get("additional_kwargs") or {})
        supplied_top_p = additional.get("top_p", FROZEN_TOP_P)
        if isinstance(supplied_top_p, bool) or supplied_top_p not in (1, 1.0):
            raise ValueError("MAGE OpenAI factory defines conflicting top_p")
        additional["top_p"] = FROZEN_TOP_P
        if thinking_mode is not None:
            if "extra_body" in additional:
                raise ValueError("MAGE OpenAI factory already defines extra_body")
            additional["extra_body"] = {"thinking": {"type": thinking_mode}}
        kwargs["additional_kwargs"] = additional
        return original_openai(*args, **kwargs)

    mage_gen_config.OpenAI = configured_openai
    try:
        delegate = get_llm(
            provider="openai",
            model=model,
            max_token=max_tokens,
            cfg_path=cfg_path,
        )
    finally:
        mage_gen_config.OpenAI = original_openai

    llm = OpenAICompatibleLLMProxy(delegate)

    receipt = {
        **registration,
        "max_tokens": max_tokens,
        "max_retries": max_retries,
        "timeout_seconds": float(timeout_seconds),
        "config_file_used": cfg_path is not None,
        "provider_call_observed": True,
        "completion_observed": True,
        "response_body_recorded": False,
        "provider_credentials_recorded": False,
        "llm_proxy_class": type(llm).__name__,
        "provider_delegate_class": type(delegate).__name__,
        "provider_preflight_llm_calls": 1,
        "provider_options": {
            "temperature": FROZEN_TEMPERATURE,
            "top_p": FROZEN_TOP_P,
            "thinking_mode": thinking_mode or "default",
        },
    }
    return llm, receipt
