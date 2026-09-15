#!/usr/bin/env python3
"""Development public preflight for the G11 PicoRV32 QoR task."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
from typing import Any

sys.dont_write_bytecode = True

_VERDICT_PATH = Path(__file__).resolve().parent / "verdict.py"
_VERDICT_SPEC = importlib.util.spec_from_file_location(
    "rtlflowbench_g11_visible_verdict", _VERDICT_PATH
)
if _VERDICT_SPEC is None or _VERDICT_SPEC.loader is None:
    raise ImportError(f"could not load verdict helper: {_VERDICT_PATH}")
_VERDICT_MODULE = importlib.util.module_from_spec(_VERDICT_SPEC)
sys.modules[_VERDICT_SPEC.name] = _VERDICT_MODULE
_VERDICT_SPEC.loader.exec_module(_VERDICT_MODULE)
VisibleVerdict = _VERDICT_MODULE.VisibleVerdict
classify_build = _VERDICT_MODULE.classify_build
classify_simulation = _VERDICT_MODULE.classify_simulation


TASK_ID = "G11-picorv32-qor"
TOP = "picorv32"
REQUIRED_FILE = Path("picorv32.v")
MAX_SUBMISSION_BYTES = 524_288
SMOKE_TOP = "g11_visible_firmware_smoke_tb"
SMOKE_SENTINEL = "GOLDEN12_G11_VISIBLE_SMOKE_PASS"
SMOKE_TB = Path(__file__).resolve().parent / "firmware_smoke_tb.sv"
NOTICE_MARKERS = (
    b"PicoRV32 -- A Small RISC-V (RV32I) Processor Core",
    b"Copyright (C) 2015  Claire Xenia Wolf <claire@yosyshq.com>",
    b"Permission to use, copy, modify, and/or distribute this software",
)
REQUIRED_MODULES = (
    "picorv32",
    "picorv32_regs",
    "picorv32_pcpi_mul",
    "picorv32_pcpi_fast_mul",
    "picorv32_pcpi_div",
    "picorv32_axi",
    "picorv32_axi_adapter",
    "picorv32_wb",
)
FROZEN_PARAMETERS = {
    "ENABLE_COUNTERS": "1",
    "ENABLE_COUNTERS64": "1",
    "ENABLE_REGS_16_31": "1",
    "ENABLE_REGS_DUALPORT": "1",
    "LATCHED_MEM_RDATA": "0",
    "TWO_STAGE_SHIFT": "1",
    "BARREL_SHIFTER": "1",
    "TWO_CYCLE_COMPARE": "0",
    "TWO_CYCLE_ALU": "0",
    "COMPRESSED_ISA": "1",
    "CATCH_MISALIGN": "1",
    "CATCH_ILLINSN": "1",
    "ENABLE_PCPI": "1",
    "ENABLE_MUL": "1",
    "ENABLE_FAST_MUL": "0",
    "ENABLE_DIV": "0",
    "ENABLE_IRQ": "1",
    "ENABLE_IRQ_QREGS": "1",
    "ENABLE_IRQ_TIMER": "1",
    "ENABLE_TRACE": "0",
    "REGS_INIT_ZERO": "0",
    "MASKED_IRQ": "32'h00000000",
    "LATCHED_IRQ": "32'hffffffff",
    "PROGADDR_RESET": "32'h00000000",
    "PROGADDR_IRQ": "32'h00000010",
    "STACKADDR": "32'hffffffff",
}
EXPECTED_PORTS = {
    "clk": ("input", 1),
    "resetn": ("input", 1),
    "trap": ("output", 1),
    "mem_valid": ("output", 1),
    "mem_instr": ("output", 1),
    "mem_ready": ("input", 1),
    "mem_addr": ("output", 32),
    "mem_wdata": ("output", 32),
    "mem_wstrb": ("output", 4),
    "mem_rdata": ("input", 32),
    "mem_la_read": ("output", 1),
    "mem_la_write": ("output", 1),
    "mem_la_addr": ("output", 32),
    "mem_la_wdata": ("output", 32),
    "mem_la_wstrb": ("output", 4),
    "pcpi_valid": ("output", 1),
    "pcpi_insn": ("output", 32),
    "pcpi_rs1": ("output", 32),
    "pcpi_rs2": ("output", 32),
    "pcpi_wr": ("input", 1),
    "pcpi_rd": ("input", 32),
    "pcpi_wait": ("input", 1),
    "pcpi_ready": ("input", 1),
    "irq": ("input", 32),
    "eoi": ("output", 32),
    "trace_valid": ("output", 1),
    "trace_data": ("output", 36),
}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _subprocess_environment(locale: str = "C.UTF-8") -> dict[str, str]:
    environment = {"PATH": os.environ.get("PATH", ""), "LANG": locale, "LC_ALL": locale}
    for name in ("RTLFLOWBENCH_PORTABLE_MOUNT_ROOTS", "RTLFLOWBENCH_PORTABLE_RUNTIME_CONFIG"):
        value = os.environ.get(name)
        if value:
            environment[name] = value
    return environment


def _yosys_quote(path: Path) -> str:
    return '"' + str(path).replace("\\", "\\\\").replace('"', '\\"') + '"'


def _execute(
    argv: list[str],
    *,
    cwd: Path,
    timeout: int,
    stdout_path: Path,
    stderr_path: Path,
) -> dict[str, Any]:
    started = time.monotonic()
    try:
        completed = subprocess.run(
            argv,
            cwd=cwd,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=_subprocess_environment(),
        )
        stdout, stderr = completed.stdout, completed.stderr
        process_status, exit_code = "completed", completed.returncode
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode(errors="replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode(errors="replace")
        process_status, exit_code = "timeout", None
    except OSError as exc:
        stdout, stderr = "", f"{type(exc).__name__}: {exc}\n"
        process_status, exit_code = "infra_error", None
    stdout_path.write_text(stdout, encoding="utf-8")
    stderr_path.write_text(stderr, encoding="utf-8")
    return {
        "process_status": process_status,
        "exit_code": exit_code,
        "wall_time_seconds": round(time.monotonic() - started, 6),
        "stdout_path": stdout_path.name,
        "stderr_path": stderr_path.name,
        "stdout_sha256": _sha256(stdout_path),
        "stderr_sha256": _sha256(stderr_path),
    }


def _preflight(
    submission_root: Path, output_root: Path
) -> tuple[VisibleVerdict, str, dict[str, Any]]:
    if not submission_root.is_dir() or submission_root.is_symlink():
        return VisibleVerdict.INVALID_SUBMISSION, "submission root must be a regular directory", {}
    if output_root == submission_root or output_root.is_relative_to(submission_root):
        return VisibleVerdict.INVALID_SUBMISSION, "output directory must be outside the submission", {}
    observed_files: list[str] = []
    for path in sorted(submission_root.rglob("*")):
        if path.is_symlink():
            return (
                VisibleVerdict.SCOPE_VIOLATION,
                f"submission contains a symlink: {path.relative_to(submission_root)}",
                {},
            )
        if path.is_file():
            observed_files.append(path.relative_to(submission_root).as_posix())
    if observed_files != [REQUIRED_FILE.as_posix()]:
        return (
            VisibleVerdict.SCOPE_VIOLATION,
            "submission must contain exactly picorv32.v",
            {"observed_files": observed_files, "expected_files": [REQUIRED_FILE.as_posix()]},
        )
    source = submission_root / REQUIRED_FILE
    source_bytes = source.read_bytes()
    if len(source_bytes) > MAX_SUBMISSION_BYTES:
        return (
            VisibleVerdict.SCOPE_VIOLATION,
            "picorv32.v exceeds the public byte budget",
            {"submission_bytes": len(source_bytes)},
        )
    if any(marker not in source_bytes for marker in NOTICE_MARKERS):
        return (
            VisibleVerdict.SCOPE_VIOLATION,
            "picorv32.v does not retain every required upstream notice marker",
            {"submission_bytes": len(source_bytes)},
        )
    try:
        source_text = source_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return VisibleVerdict.INVALID_SUBMISSION, "picorv32.v must be UTF-8 text", {}
    observed_modules = sorted(
        set(re.findall(r"(?m)^\s*module\s+([A-Za-z_][A-Za-z0-9_$]*)\b", source_text))
    )
    missing_modules = sorted(set(REQUIRED_MODULES) - set(observed_modules))
    if missing_modules:
        return (
            VisibleVerdict.STRUCTURAL_FAIL,
            "required PicoRV32 module declarations are missing",
            {"observed_modules": observed_modules, "missing_modules": missing_modules},
        )
    return (
        VisibleVerdict.PASS,
        "exact one-file scope, byte budget, notices, and module declarations validated",
        {
            "observed_files": observed_files,
            "submission_bytes": len(source_bytes),
            "submission_sha256": {REQUIRED_FILE.as_posix(): _sha256(source)},
            "observed_modules": observed_modules,
            "required_notice_markers_present": True,
        },
    )


def _write_yosys_script(*, submission_root: Path, output_root: Path) -> Path:
    parameter_args = " ".join(
        f"-set {name} {value}" for name, value in FROZEN_PARAMETERS.items()
    )
    netlist = output_root / "generic-netlist.json"
    lines = [
        f"read_verilog -defer {_yosys_quote(submission_root / REQUIRED_FILE)}",
        f"chparam {parameter_args} {TOP}",
        f"hierarchy -check -top {TOP}",
        f"synth -top {TOP} -flatten -noabc",
        "check",
        f"write_json {_yosys_quote(netlist)}",
    ]
    path = output_root / "structural-preflight.ys"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _inspect_netlist(path: Path) -> tuple[VisibleVerdict, str, dict[str, Any] | None]:
    if not path.is_file() or path.is_symlink():
        return VisibleVerdict.STRUCTURAL_FAIL, "Yosys did not produce a regular JSON netlist", None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        module = payload["modules"][TOP]
        ports = {
            name: (entry["direction"], len(entry["bits"]))
            for name, entry in module["ports"].items()
        }
        cells = module["cells"]
        netnames = module["netnames"]
    except Exception as exc:
        return (
            VisibleVerdict.STRUCTURAL_FAIL,
            f"could not parse Yosys netlist: {type(exc).__name__}: {exc}",
            None,
        )
    if ports != EXPECTED_PORTS:
        return VisibleVerdict.STRUCTURAL_FAIL, "synthesized top interface differs from CPUInterfaceSpec", None
    if not cells or not netnames:
        return VisibleVerdict.STRUCTURAL_FAIL, "synthesized top is empty or structurally pruned", None
    return (
        VisibleVerdict.PASS,
        "frozen ordinary-build interface and non-empty generic structure validated",
        {
            "unit": "generic_yosys_cells_not_area",
            "top_port_count": len(ports),
            "generic_cell_count": len(cells),
            "netname_count": len(netnames),
        },
    )


def run(args: argparse.Namespace) -> dict[str, Any]:
    started = time.monotonic()
    submission_root = args.submission_root.expanduser().resolve()
    output_root = args.output_dir.expanduser().resolve()
    output_root.mkdir(parents=True, exist_ok=False)
    verdict, reason, scope = _preflight(submission_root, output_root)
    checks: list[dict[str, Any]] = [
        {"check_id": "submission_scope", "stage": "scope", "verdict": verdict.value, "reason": reason}
    ]
    yosys = shutil.which(args.yosys) or args.yosys
    iverilog = shutil.which(args.iverilog) or args.iverilog
    vvp = shutil.which(args.vvp) or args.vvp
    statistics = None
    if verdict == VisibleVerdict.PASS:
        execution_root = output_root / "work"
        execution_root.mkdir()
        shutil.copyfile(
            submission_root / REQUIRED_FILE, execution_root / REQUIRED_FILE
        )
        script = _write_yosys_script(
            submission_root=execution_root, output_root=output_root
        )
        process = _execute(
            [yosys, "-q", "-l", str(output_root / "yosys.log"), str(script)],
            cwd=execution_root,
            timeout=args.command_timeout_seconds,
            stdout_path=output_root / "yosys.stdout.log",
            stderr_path=output_root / "yosys.stderr.log",
        )
        verdict, reason = classify_build(
            process_status=process["process_status"], exit_code=process["exit_code"], stage="Yosys frozen-configuration synthesis"
        )
        checks.append({"check_id": "elaboration_synthesis", "stage": "elaboration_synthesis", "verdict": verdict.value, "reason": reason, "process": process})
    if verdict == VisibleVerdict.PASS:
        verdict, reason, statistics = _inspect_netlist(output_root / "generic-netlist.json")
        checks.append({"check_id": "frozen_interface", "stage": "interface", "verdict": verdict.value, "reason": reason})
    simulation = output_root / "firmware-smoke.vvp"
    if verdict == VisibleVerdict.PASS:
        process = _execute(
            [iverilog, "-g2012", "-s", SMOKE_TOP, "-o", str(simulation), str(execution_root / REQUIRED_FILE), str(SMOKE_TB)],
            cwd=execution_root,
            timeout=args.command_timeout_seconds,
            stdout_path=output_root / "firmware-smoke-compile.stdout.log",
            stderr_path=output_root / "firmware-smoke-compile.stderr.log",
        )
        verdict, reason = classify_build(
            process_status=process["process_status"], exit_code=process["exit_code"], stage="visible firmware smoke compilation"
        )
        checks.append({"check_id": "firmware_smoke_compile", "stage": "firmware_smoke_compile", "verdict": verdict.value, "reason": reason, "process": process})
    if verdict == VisibleVerdict.PASS:
        stdout_path = output_root / "firmware-smoke.stdout.log"
        process = _execute(
            [vvp, str(simulation)],
            cwd=execution_root,
            timeout=args.command_timeout_seconds,
            stdout_path=stdout_path,
            stderr_path=output_root / "firmware-smoke.stderr.log",
        )
        verdict, reason = classify_simulation(
            process_status=process["process_status"],
            exit_code=process["exit_code"],
            stdout=stdout_path.read_text(encoding="utf-8"),
            sentinel=SMOKE_SENTINEL,
        )
        checks.append({"check_id": "short_firmware_smoke", "stage": "firmware_smoke", "verdict": verdict.value, "reason": reason, "process": process})
    evidence = [
        {"path": path.name, "bytes": path.stat().st_size, "sha256": _sha256(path)}
        for path in sorted(output_root.iterdir())
        if path.is_file() and path.name != "result.json"
    ]
    return {
        "schema_version": "chipflow.golden12.g11_visible_result.v1",
        "task_id": TASK_ID,
        "suite_status": "development_structural_and_firmware_smoke_not_frozen",
        "verdict": verdict.value,
        "pass": verdict == VisibleVerdict.PASS,
        "wall_time_seconds": round(time.monotonic() - started, 6),
        "tool_paths": {"yosys": yosys, "iverilog": iverilog, "vvp": vvp},
        "scope_receipt": scope,
        "checks": checks,
        "diagnostic_structural_statistics": statistics,
        "evidence_manifest": evidence,
        "excluded_claims": [
            "Visible PASS covers exact scope, frozen ordinary-build elaboration, generic synthesis, and one public four-instruction smoke only; it is not hidden F2P/P2P, ISA compliance, complete equivalence, timing, PPA, QoR, score, or benchmark PASS.",
            "Generic Yosys cell counts are diagnostic structure, not an area unit or optimization result.",
            "The runner, tools, environment, limits, and verdict parser remain development-only until calibration and independent admission.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--submission-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--yosys", default="yosys")
    parser.add_argument("--iverilog", default="iverilog")
    parser.add_argument("--vvp", default="vvp")
    parser.add_argument("--command-timeout-seconds", type=int, default=120)
    args = parser.parse_args()
    output = args.output_dir.expanduser().resolve()
    try:
        result = run(args)
    except Exception as exc:
        output.mkdir(parents=True, exist_ok=True)
        result = {
            "schema_version": "chipflow.golden12.g11_visible_result.v1",
            "task_id": TASK_ID,
            "suite_status": "development_structural_and_firmware_smoke_not_frozen",
            "verdict": "infra_error",
            "pass": False,
            "wall_time_seconds": None,
            "tool_paths": {},
            "scope_receipt": {},
            "checks": [{"check_id": "runner_exception", "stage": "scope", "verdict": "infra_error", "reason": f"{type(exc).__name__}: {exc}"}],
            "diagnostic_structural_statistics": None,
            "evidence_manifest": [],
            "excluded_claims": ["The visible runner raised before completing its checks."],
            "error": f"{type(exc).__name__}: {exc}",
        }
    (output / "result.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["pass"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
