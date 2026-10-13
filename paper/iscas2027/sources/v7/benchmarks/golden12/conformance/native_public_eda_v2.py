"""Narrow argument projection for explicitly declared, pinned public dependencies."""

import re
from pathlib import Path

from public_input_bundle_v2 import safe_relative

YOSYS_READ = re.compile(
    r"\Alogger -nowarn assigned; read_verilog -sv (?P<source>[A-Za-z0-9_./-]+);\Z"
)


def project_argv(
    tool: str, argv: list[str], plan: dict, repository_root: Path
) -> list[str]:
    if tool not in {"iverilog", "yosys", "vvp"}:
        raise ValueError("unsupported native EDA tool")
    if not isinstance(argv, list) or not all(isinstance(value, str) for value in argv):
        raise ValueError("native tool arguments must be strings")
    dependencies = []
    for row in plan["dependencies"]:
        relative = safe_relative(row["source_path"])
        dependencies.append(str(repository_root / relative))
    if not dependencies or tool == "vvp":
        return list(argv)
    if tool == "iverilog":
        return [*argv, *[path for path in dependencies if path not in argv]]
    if len(argv) != 2 or argv[0] != "-p":
        raise ValueError(
            "dependency projection requires the reviewed Yosys read-only shape"
        )
    match = YOSYS_READ.fullmatch(argv[1])
    if match is None or any(
        not re.fullmatch(r"[A-Za-z0-9_./-]+", path) for path in dependencies
    ):
        raise ValueError("unsafe or unsupported Yosys dependency command")
    # Full source units, no -lib/blackbox and no inferred compilation order.
    sources = " ".join([*dependencies, match.group("source")])
    return ["-p", f"logger -nowarn assigned; read_verilog -sv {sources};"]
