#!/usr/bin/env python3
"""Thin launcher for HDLAgent's native public spec-build path."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
from urllib.parse import urlsplit

from source_snapshot_binding import bind_source


PROVIDER_SENTINEL = "rtlflowbench-observed-host-gateway"
PROVIDER_PROXY_BASE_URL_ENV = "RTLFLOWBENCH_PROVIDER_PROXY_BASE_URL"
TASK_FREE_PREFLIGHT_BASE_URL = "http://127.0.0.1:18080/v1"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _validated_provider_base_url() -> str:
    endpoint = os.environ.get("OPENAI_BASE_URL")
    controller_endpoint = os.environ.get(PROVIDER_PROXY_BASE_URL_ENV)
    if controller_endpoint is None:
        if endpoint != TASK_FREE_PREFLIGHT_BASE_URL:
            raise ValueError("workflow provider endpoint must be the loopback relay")
    elif endpoint != controller_endpoint:
        raise ValueError("workflow provider endpoint must match the controller relay")
    try:
        parsed = urlsplit(endpoint or "")
        port = parsed.port
    except ValueError as exc:
        raise ValueError("workflow provider endpoint is malformed") from exc
    if not (
        parsed.scheme == "http"
        and parsed.hostname == "127.0.0.1"
        and parsed.username is None
        and parsed.password is None
        and port is not None
        and 1 <= port <= 65535
        and parsed.path == "/v1"
        and not parsed.query
        and not parsed.fragment
    ):
        raise ValueError("workflow provider endpoint must be a bounded loopback relay")
    return endpoint


def _configure_networkless_deepseek(agent_module: object, model: str) -> None:
    if model != "deepseek-v4-pro":
        raise ValueError("networkless HDLAgent provider mode requires the common model")
    if os.environ.get("OPENAI_API_KEY") != PROVIDER_SENTINEL:
        raise ValueError("workflow container must receive only the broker placeholder")
    _validated_provider_base_url()

    def reviewed_models(_warn: bool = True) -> list[str]:
        return [model]

    def fixed_chat_completion(self: object, conversation: list[dict[str, str]], compile_convo: bool = False) -> str:
        del compile_convo
        completion = self.client.chat.completions.create(
            model=self.model,
            messages=conversation,
            temperature=0.0,
            top_p=1.0,
            max_tokens=8192,
            extra_body={"thinking": {"type": "disabled"}},
        )
        self.prompt_tokens += completion.usage.prompt_tokens
        self.completion_tokens += completion.usage.completion_tokens
        content = completion.choices[0].message.content
        if not isinstance(content, str):
            raise ValueError("provider returned no text completion")
        return content

    agent_module.list_openai_models = reviewed_models
    agent_module.Agent.openai_chat_completion = fixed_chat_completion


def _prepare_work_directory(work: Path) -> None:
    if work.is_symlink():
        raise FileExistsError("refusing a symlink HDLAgent work directory")
    if work.exists():
        if not work.is_dir() or any(work.iterdir()):
            raise FileExistsError("refusing to reuse a non-empty HDLAgent work directory")
        return
    work.mkdir(parents=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--request-root", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--compile-limit", type=int, required=True)
    parser.add_argument("--source-manifest", type=Path)
    parser.add_argument(
        "--provider-mode",
        choices=("upstream", "networkless-deepseek-v4-pro"),
        default="upstream",
    )
    args = parser.parse_args()
    if args.compile_limit < 1:
        raise ValueError("compile limit must be positive")
    request_root = args.request_root.resolve(strict=True)
    request = json.loads(
        (request_root / "bridge_request.json").read_text(encoding="utf-8")
    )
    if request.get("workflow", {}).get("workflow_id") != "hdlagent":
        raise ValueError("request is not bound to HDLAgent")
    expected_commit = request["workflow"].get("commit")
    if len(expected_commit or "") != 40:
        raise ValueError("request has no reviewed HDLAgent commit")
    source = bind_source(
        args.source_root,
        expected_commit=expected_commit,
        expected_manifest_sha256=request["workflow"]["tracked_manifest_sha256"],
        snapshot_manifest=args.source_manifest,
    )
    native = request.get("native_input", {})
    if native.get("bench_response") is not None or native.get("external_hdeval_alias") is not None:
        raise ValueError("HDLAgent request attempts to provide a private or external oracle")
    spec_path = request_root / native["spec_path"]
    manifest = {item["path"]: item for item in request["input_files"]}
    relative = spec_path.relative_to(request_root).as_posix()
    if spec_path.is_symlink() or not spec_path.is_file() or _sha256(spec_path) != manifest[relative]["sha256"]:
        raise ValueError("HDLAgent public spec digest drift")
    work = args.work_dir.absolute()
    _prepare_work_directory(work)
    sys.path.insert(0, str(source / "hdlagent"))
    import agent as agent_module

    if args.provider_mode == "networkless-deepseek-v4-pro":
        _configure_networkless_deepseek(agent_module, args.model)
    from handler import Handler

    handler = Handler()
    handler.set_comp_iter(args.compile_limit)
    handler.create_agents(
        spath=str(source / "hdlagent/resources"),
        llms=[args.model],
        lang="Verilog",
        use_spec=True,
        temperature=None,
        w_dir=str(work),
        init_context=[],
        supp_context=False,
        short_context=False,
    )
    handler.spec_run(
        target_spec=str(spec_path),
        lec_iterations=0,
        comp_iterations=args.compile_limit,
        w_dir=str(work),
        skip_completed=False,
        skip_successful=False,
    )
    expected = work / request["execution"]["expected_output_path_relative_to_work_dir"]
    if not expected.is_file() or expected.is_symlink():
        raise ValueError("HDLAgent did not materialize the declared RTL output")
    print(json.dumps({"workflow_completed": True, "output_sha256": _sha256(expected)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
