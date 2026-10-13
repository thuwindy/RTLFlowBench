#!/usr/bin/env python3
"""Strict task-neutral EDA broker for a networkless HDLAgent container.

HDLAgent's reviewed Verilog compile script invokes only a fixed Yosys
``read_verilog`` command followed by Icarus compilation.  This adapter accepts
exactly those two shapes, snapshots only provider-owned HDL, and delegates the
tool process to a separate no-network container through the generic broker.
"""

from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path
import re
import sys
from typing import Any


BROKER_SOURCE = Path(__file__).with_name("mage_eda_broker.py")
PROVIDER_CONTROL_ROOT = Path("/attempt/work")
YOSYS_SCRIPT_RE = re.compile(
    r"\Alogger -nowarn assigned; read_verilog -sv "
    r"(?P<input>[A-Za-z0-9_./-]+);\Z"
)
HDLAGENT_LOG_OUTPUT_RE = re.compile(
    r"\Acheck_verilog\.[A-Za-z0-9]+icarus_exe\Z"
)
HDLAGENT_TB_OUTPUT_RE = re.compile(r"\A[A-Za-z0-9_.-]+_iverilog-tb\Z")


def _load_broker():
    spec = importlib.util.spec_from_file_location(
        "rtlflowbench_hdlagent_eda_broker_base", BROKER_SOURCE
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("base EDA broker cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def configure_broker():
    broker = _load_broker()
    broker.REQUEST_SCHEMA_VERSION = "rtlflowbench.hdlagent_eda_request.v1"
    broker.RESPONSE_SCHEMA_VERSION = "rtlflowbench.hdlagent_eda_response.v1"
    broker.RECEIPT_SCHEMA_VERSION = "rtlflowbench.hdlagent_eda_call_receipt.v1"
    broker.PUBLIC_EDA_IMAGE = "localhost/rtlflowbench-hdlagent-runtime"
    broker.NO_VALUE_IVERILOG_FLAGS = set(broker.NO_VALUE_IVERILOG_FLAGS) | {
        "-g2005-sv"
    }

    def provider_relative(value: str, *, cwd: Path) -> Path:
        candidate = Path(value)
        if candidate.is_absolute():
            try:
                relative = candidate.relative_to(PROVIDER_CONTROL_ROOT)
            except ValueError as exc:
                raise ValueError(
                    "absolute EDA path escapes provider control root"
                ) from exc
        else:
            relative = Path(os.path.normpath((cwd / candidate).as_posix()))
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("EDA path escapes provider control root")
        broker._safe_relative(relative.as_posix(), label="EDA path")
        return relative

    def resolve_input(control_root: Path, cwd: Path, value: str) -> Path:
        relative = provider_relative(value, cwd=cwd)
        path = control_root / relative
        if path.is_symlink() or not path.is_file():
            raise ValueError("EDA input is not a regular control-root file")
        if path.suffix.casefold() not in {".sv", ".v", ".vh"}:
            raise ValueError("HDLAgent EDA input suffix is unsupported")
        return relative

    def resolve_output(
        control_root: Path, cwd: Path, value: str
    ) -> Path | None:
        if value == "/dev/null":
            return None
        relative = provider_relative(value, cwd=cwd)
        target = control_root / relative
        if target.is_symlink() or target.parent.is_symlink():
            raise ValueError("EDA output path cannot use a symlink")
        if not target.parent.is_dir():
            raise ValueError("HDLAgent EDA output parent must exist")
        reviewed_name = (
            relative.name == "a.out"
            or HDLAGENT_TB_OUTPUT_RE.fullmatch(relative.name) is not None
            or (
                relative.parent.name == "logs"
                and HDLAGENT_LOG_OUTPUT_RE.fullmatch(relative.name) is not None
            )
        )
        if not reviewed_name:
            raise ValueError("HDLAgent Icarus output name is outside the reviewed shape")
        return relative

    def validate_yosys(
        argv: list[str], *, control_root: Path, cwd: Path
    ) -> tuple[Path, ...]:
        if len(argv) != 2 or argv[0] != "-p":
            raise ValueError("Yosys requires the reviewed two-argument command")
        match = YOSYS_SCRIPT_RE.fullmatch(argv[1])
        if match is None:
            raise ValueError("Yosys script is outside the reviewed read-only shape")
        return (resolve_input(control_root, cwd, match.group("input")),)

    def validate_iverilog(
        argv: list[str], *, control_root: Path, cwd: Path
    ) -> tuple[tuple[Path, ...], Path | None]:
        if "-o" in argv:
            return broker._validate_iverilog(
                argv, control_root=control_root, cwd=cwd
            )
        synthetic = ["-o", "a.out", *argv]
        return broker._validate_iverilog(
            synthetic, control_root=control_root, cwd=cwd
        )

    def validate_vvp(
        argv: list[str], *, control_root: Path, cwd: Path
    ) -> tuple[Path, ...]:
        if len(argv) == 1:
            value = argv[0]
        elif len(argv) == 2 and argv[0] in {"-n", "-N"}:
            value = argv[1]
        else:
            raise ValueError("vvp requires one input with an optional -n/-N flag")
        relative = provider_relative(value, cwd=cwd)
        path = control_root / relative
        if path.is_symlink() or not path.is_file():
            raise ValueError("vvp input is not a regular control-root file")
        if not (
            relative.name == "a.out"
            or HDLAGENT_TB_OUTPUT_RE.fullmatch(relative.name) is not None
            or (
                relative.parent.name == "logs"
                and HDLAGENT_LOG_OUTPUT_RE.fullmatch(relative.name) is not None
            )
        ):
            raise ValueError("vvp input name is outside the reviewed HDLAgent shape")
        return (relative,)

    def validate_request(
        request: dict[str, Any],
        *,
        expected_session_id: str,
        control_root: Path,
    ):
        if not isinstance(request, dict) or set(request) != {
            "schema_version",
            "session_id",
            "tool",
            "cwd",
            "argv",
        }:
            raise ValueError("request fields are invalid")
        if request["schema_version"] != broker.REQUEST_SCHEMA_VERSION:
            raise ValueError("request schema version is invalid")
        if request["session_id"] != expected_session_id:
            raise ValueError("session id does not match broker")
        if not broker.SESSION_RE.fullmatch(expected_session_id):
            raise ValueError("expected session id is invalid")
        tool = request["tool"]
        if tool not in {"yosys", "iverilog", "vvp"}:
            raise ValueError(f"unsupported HDLAgent EDA tool: {tool}")
        argv = request["argv"]
        if (
            not isinstance(argv, list)
            or not argv
            or len(argv) > 16
            or any(
                not isinstance(item, str) or len(item) > 4096 for item in argv
            )
        ):
            raise ValueError("argv is invalid")
        root = control_root.expanduser().resolve(strict=True)
        cwd_value = request["cwd"]
        if not isinstance(cwd_value, str):
            raise ValueError("cwd is invalid")
        cwd = broker._safe_relative(cwd_value, label="cwd")
        cwd_path = root / cwd
        if cwd_path.is_symlink() or not cwd_path.is_dir():
            raise ValueError("cwd is not a regular directory")
        if tool == "yosys":
            inputs = validate_yosys(argv, control_root=root, cwd=cwd)
            output = None
        elif tool == "iverilog":
            inputs, output = validate_iverilog(
                argv, control_root=root, cwd=cwd
            )
        else:
            inputs = validate_vvp(argv, control_root=root, cwd=cwd)
            output = None
        return broker.ValidatedRequest(
            session_id=expected_session_id,
            tool=tool,
            cwd_relative=cwd,
            argv=tuple(argv),
            input_relatives=inputs,
            output_relative=output,
        )

    def tree_entries(root: Path) -> list[dict[str, object]]:
        entries: list[dict[str, object]] = []
        total_bytes = 0
        for path in sorted(
            root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()
        ):
            if path.is_symlink():
                raise ValueError("provider control tree contains a symlink")
            if not path.is_file():
                continue
            relative = path.relative_to(root)
            reviewed_tool_artifact = (
                relative.name == "a.out"
                or HDLAGENT_TB_OUTPUT_RE.fullmatch(relative.name) is not None
                or (
                    relative.parent.name == "logs"
                    and HDLAGENT_LOG_OUTPUT_RE.fullmatch(relative.name) is not None
                )
            )
            if (
                path.suffix.casefold() not in {".sv", ".v", ".vh"}
                and not reviewed_tool_artifact
            ):
                continue
            if any(
                part.casefold() in broker.FORBIDDEN_PARTS for part in relative.parts
            ):
                raise ValueError("provider HDL path uses a forbidden component")
            size = path.stat().st_size
            total_bytes += size
            if len(entries) + 1 > broker.MAX_SNAPSHOT_FILES:
                raise ValueError("provider HDL file count exceeds broker limit")
            if total_bytes > broker.MAX_SNAPSHOT_BYTES:
                raise ValueError("provider HDL bytes exceed broker limit")
            entries.append(
                {
                    "path": relative.as_posix(),
                    "bytes": size,
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                }
            )
        if not entries:
            raise ValueError("provider control tree contains no HDL snapshot files")
        return entries

    def mapped_argv(request: Any) -> list[str]:
        input_map = {
            relative.as_posix(): f"/workspace/{relative.as_posix()}"
            for relative in request.input_relatives
        }
        if request.tool == "yosys":
            only_input = request.input_relatives[0].as_posix()
            return [
                "-p",
                "logger -nowarn assigned; read_verilog -sv "
                f"{input_map[only_input]};",
            ]
        if request.tool == "vvp":
            prefix = list(request.argv[:-1])
            relative = provider_relative(
                request.argv[-1], cwd=request.cwd_relative
            ).as_posix()
            return [*prefix, input_map[relative]]
        result: list[str] = []
        output_next = False
        for argument in request.argv:
            if output_next:
                result.append(
                    "/dev/null"
                    if request.output_relative is None
                    else f"/output/{request.output_relative.as_posix()}"
                )
                output_next = False
            elif argument == "-o":
                result.append(argument)
                output_next = True
            elif argument.startswith("-"):
                result.append(argument)
            else:
                relative = provider_relative(
                    argument, cwd=request.cwd_relative
                ).as_posix()
                result.append(input_map.get(relative, argument))
        if "-o" not in request.argv:
            if request.output_relative is None:
                raise ValueError("implicit Icarus output binding is missing")
            return [
                "-o",
                f"/output/{request.output_relative.as_posix()}",
                *result,
            ]
        return result

    base_execute_request = broker.execute_request

    def execute_request(*args: Any, **kwargs: Any) -> dict[str, Any]:
        response = base_execute_request(*args, **kwargs)
        request_payload = args[0] if args else kwargs["request_payload"]
        if request_payload.get("tool") != "iverilog" or response.get("exit_code") != 0:
            return response
        validated = validate_request(
            request_payload,
            expected_session_id=kwargs["expected_session_id"],
            control_root=kwargs["control_root"],
        )
        if validated.output_relative is not None:
            output = Path(kwargs["control_root"]).resolve() / validated.output_relative
            if output.is_symlink() or not output.is_file():
                raise ValueError("copied Icarus artifact is unavailable")
            output.chmod(0o700)
        return response

    broker._resolve_input = resolve_input
    broker._resolve_output = resolve_output
    broker.validate_request = validate_request
    broker._tree_entries = tree_entries
    broker._mapped_argv = mapped_argv
    broker.execute_request = execute_request
    return broker


def main() -> int:
    return configure_broker().main()


if __name__ == "__main__":
    raise SystemExit(main())
