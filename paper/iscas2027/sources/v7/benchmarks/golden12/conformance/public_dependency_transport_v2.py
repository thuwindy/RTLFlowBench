"""Map explicit public dependencies to compiler inputs, never infer a solution."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from public_input_bundle_v2 import safe_relative


def declared_dependency_plan(loaded: dict[str, Any]) -> dict[str, Any]:
    files = {row["path"]: row for row in loaded["context"]["files"]}
    interface = files.get("public/spec/interface_spec.json")
    declared = (
        json.loads(interface["text"]).get("dependency_bindings", [])
        if interface
        else []
    )
    if not isinstance(declared, list) or len(declared) > 64:
        raise ValueError("explicit dependency list is missing or excessive")
    dependencies = []
    paths, modules = set(), set()
    for binding in declared:
        if not isinstance(binding, dict):
            raise ValueError("dependency must be an object")
        path, module = binding.get("source_path"), binding.get("module")
        safe_relative(path)
        if not isinstance(module, str) or not re.fullmatch(
            r"[A-Za-z_][A-Za-z0-9_$]*", module
        ):
            raise ValueError("explicit dependency module identifier required")
        if Path(path).suffix not in {".v", ".sv"} or path in paths or module in modules:
            raise ValueError("unsupported or duplicate dependency declaration")
        source = files.get("repository/" + path)
        if source is None or source.get("role") != "read_only_repository_input":
            raise ValueError(
                "declared dependency is not a pinned read-only repository input"
            )
        paths.add(path)
        modules.add(module)
        dependencies.append(
            {
                "source_path": path,
                "module": module,
                "sha256": source["sha256"],
                "bytes": source["bytes"],
            }
        )
    readonly_hdl = {
        name.removeprefix("repository/")
        for name, row in files.items()
        if name.startswith("repository/")
        and row.get("role") == "read_only_repository_input"
        and Path(name).suffix in {".v", ".sv", ".vh", ".svh"}
    }
    if readonly_hdl != paths:
        raise ValueError(
            "read-only HDL lacks an explicit complete dependency contract; do not infer build inputs"
        )
    return {
        "schema_version": "rtlflowbench.explicit_public_dependency_plan.v2",
        "task_id": loaded["receipt"]["task_id"],
        "context_sha256": loaded["receipt"]["context_sha256"],
        "interface_source_sha256": interface["sha256"] if interface else None,
        "dependencies": dependencies,
        "source_order_policy": "exact_public_dependency_bindings_order_no_inference",
        "workflow_verified": False,
    }


def extend_iverilog_command(command: list[str], plan: dict[str, Any]) -> list[str]:
    return [
        *command,
        *["/public-repository/" + row["source_path"] for row in plan["dependencies"]],
    ]
