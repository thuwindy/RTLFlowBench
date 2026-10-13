#!/usr/bin/env python3
"""Thin, task-generic launcher for the reviewed VerilogCoder core workflow."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

from source_snapshot_binding import bind_source


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--request-root", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--source-manifest", type=Path)
    args = parser.parse_args()
    request_root = args.request_root.resolve(strict=True)
    request_path = request_root / "bridge_request.json"
    request = json.loads(request_path.read_text(encoding="utf-8"))
    workflow = request.get("workflow", {})
    if workflow.get("workflow_id") != "verilogcoder":
        raise ValueError("request is not bound to VerilogCoder")
    expected_commit = workflow.get("commit")
    if len(expected_commit or "") != 40:
        raise ValueError("request has no reviewed VerilogCoder commit")
    source = bind_source(
        args.source_root,
        expected_commit=expected_commit,
        expected_manifest_sha256=workflow["tracked_manifest_sha256"],
        snapshot_manifest=args.source_manifest,
    )
    files = {item["path"]: item for item in request["input_files"]}
    prompt = request_root / "input/public_prompt.txt"
    testbench = request_root / "input/public_visible_tb.sv"
    for path in (prompt, testbench):
        relative = path.relative_to(request_root).as_posix()
        if path.is_symlink() or not path.is_file() or _sha256(path) != files[relative]["sha256"]:
            raise ValueError("public input digest drift")
    work = args.work_dir.absolute()
    if work.exists() or work.is_symlink():
        raise FileExistsError("refusing to reuse VerilogCoder work directory")
    plan_dir = work / "generated_plans"
    output_dir = work / "generated_verilog"
    tool_dir = work / "tool_tmp"
    knowledge_graph_dir = work / "tmp"
    for path in (plan_dir, output_dir, tool_dir, knowledge_graph_dir):
        path.mkdir(parents=True)
    sys.path.insert(0, str(source))
    from autogen import config_list_from_json
    from hardware_agent.examples.VerilogCoder.verilogcoder import VerilogCoder

    configs = config_list_from_json(env_or_file="OAI_CONFIG_LIST")
    if not configs:
        raise ValueError("VerilogCoder provider configuration is unavailable")
    llm_configs = {
        key: configs
        for key in (
            "task_planner_llm",
            "kg_llm",
            "graph_retrieval_llm",
            "verilog_writing_llm",
            "verilog_debug_llm",
        )
    }
    llm_types = {
        key: ("llama3" if "llama3" in configs[0].get("model", "") else "gpt")
        for key in llm_configs
    }
    # VerilogCoder prepends os.getcwd() to verilog_tmp_dir and treats all three
    # output arguments as string paths.  Run from the fresh attempt root and
    # pass relative directory names so its unmodified upstream path handling
    # remains confined to that root.
    previous_cwd = Path.cwd()
    os.chdir(work)
    agent = VerilogCoder(
        task_planner_llm_config=llm_configs["task_planner_llm"],
        kg_llm_config=llm_configs["kg_llm"],
        graph_retrieval_llm_config=llm_configs["graph_retrieval_llm"],
        verilog_writing_llm_config=llm_configs["verilog_writing_llm"],
        debug_llm_config=llm_configs["verilog_debug_llm"],
        llm_types=llm_types,
        generate_plan_dir="generated_plans/",
        generate_verilog_dir="generated_verilog/",
        verilog_tmp_dir="tool_tmp/",
    )
    try:
        success = agent.write_Verilog_module(
            cur_task_id=request["task_id"],
            spec=prompt.read_text(encoding="utf-8"),
            golden_test_bench=testbench.read_text(encoding="utf-8"),
        )
    finally:
        os.chdir(previous_cwd)
    expected = work / request["execution"]["expected_output_path_relative_to_work_dir"]
    if not expected.is_file() or expected.is_symlink():
        raise ValueError("VerilogCoder did not materialize the declared RTL output")
    print(json.dumps({"workflow_completed": bool(success), "output_sha256": _sha256(expected)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
