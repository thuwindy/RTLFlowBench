#!/usr/bin/env python3
"""Public structural/synthesis preflight for the G10 SERV QoR task."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from typing import Any

sys.dont_write_bytecode = True

_VERDICT_PATH = Path(__file__).resolve().parent / "verdict.py"
_VERDICT_SPEC = importlib.util.spec_from_file_location(
    "rtlflowbench_g10_visible_verdict",
    _VERDICT_PATH,
)
if _VERDICT_SPEC is None or _VERDICT_SPEC.loader is None:
    raise ImportError(f"could not load verdict helper: {_VERDICT_PATH}")
_VERDICT_MODULE = importlib.util.module_from_spec(_VERDICT_SPEC)
sys.modules[_VERDICT_SPEC.name] = _VERDICT_MODULE
_VERDICT_SPEC.loader.exec_module(_VERDICT_MODULE)
VisibleVerdict = _VERDICT_MODULE.VisibleVerdict
classify_compile = _VERDICT_MODULE.classify_compile
classify_process = _VERDICT_MODULE.classify_process
classify_simulation = _VERDICT_MODULE.classify_simulation


TASK_ID = "G10-serv-area-qor"
TOP = "serv_synth_wrapper"
SMOKE_TOP = "g10_visible_software_smoke_tb"
SMOKE_SENTINEL = "GOLDEN12_G10_VISIBLE_SMOKE_PASS"
SMOKE_TB = Path(__file__).resolve().parent / "software_smoke_tb.sv"
MAX_SUBMISSION_BYTES = 1_048_576
REQUIRED_FILES = tuple(
    Path(path)
    for path in (
        "rtl/serv_aligner.v",
        "rtl/serv_alu.v",
        "rtl/serv_bufreg.v",
        "rtl/serv_bufreg2.v",
        "rtl/serv_compdec.v",
        "rtl/serv_csr.v",
        "rtl/serv_ctrl.v",
        "rtl/serv_decode.v",
        "rtl/serv_immdec.v",
        "rtl/serv_mem_if.v",
        "rtl/serv_rf_if.v",
        "rtl/serv_rf_ram.v",
        "rtl/serv_rf_ram_if.v",
        "rtl/serv_rf_top.v",
        "rtl/serv_state.v",
        "rtl/serv_synth_wrapper.v",
        "rtl/serv_top.v",
    )
)
EXPECTED_PORTS = {
    "clk": ("input", 1),
    "i_rst": ("input", 1),
    "i_timer_irq": ("input", 1),
    "o_ibus_adr": ("output", 32),
    "o_ibus_cyc": ("output", 1),
    "i_ibus_rdt": ("input", 32),
    "i_ibus_ack": ("input", 1),
    "o_dbus_adr": ("output", 32),
    "o_dbus_dat": ("output", 32),
    "o_dbus_sel": ("output", 4),
    "o_dbus_we": ("output", 1),
    "o_dbus_cyc": ("output", 1),
    "i_dbus_rdt": ("input", 32),
    "i_dbus_ack": ("input", 1),
    "o_waddr": ("output", 10),
    "o_wdata": ("output", 2),
    "o_wen": ("output", 1),
    "o_raddr": ("output", 10),
    "i_rdata": ("input", 2),
}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _yosys_quote(path: Path) -> str:
    return '"' + str(path).replace("\\", "\\\\").replace('"', '\\"') + '"'


def _subprocess_environment() -> dict[str, str]:
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }
    for name in (
        "RTLFLOWBENCH_PORTABLE_MOUNT_ROOTS",
        "RTLFLOWBENCH_PORTABLE_RUNTIME_CONFIG",
    ):
        value = os.environ.get(name)
        if value:
            environment[name] = value
    return environment


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
        "argv": list(argv),
        "cwd": str(cwd),
        "process_status": process_status,
        "exit_code": exit_code,
        "wall_time_seconds": round(time.monotonic() - started, 6),
        "stdout_path": stdout_path.name,
        "stderr_path": stderr_path.name,
        "stdout_sha256": _sha256(stdout_path),
        "stderr_sha256": _sha256(stderr_path),
    }


def _preflight(
    submission_root: Path,
    output_root: Path,
) -> tuple[VisibleVerdict, str, dict[str, Any]]:
    if not submission_root.is_dir() or submission_root.is_symlink():
        return (
            VisibleVerdict.INVALID_SUBMISSION,
            "submission root must be a regular directory",
            {},
        )
    if output_root == submission_root or output_root.is_relative_to(
        submission_root
    ):
        return (
            VisibleVerdict.INVALID_SUBMISSION,
            "output directory must be outside the submission",
            {},
        )
    observed_files: list[str] = []
    digests: dict[str, str] = {}
    total_bytes = 0
    for path in sorted(submission_root.rglob("*")):
        if path.is_symlink():
            return (
                VisibleVerdict.SCOPE_VIOLATION,
                f"submission contains a symlink: {path.relative_to(submission_root)}",
                {},
            )
        if path.is_file():
            relative = path.relative_to(submission_root).as_posix()
            observed_files.append(relative)
            total_bytes += path.stat().st_size
            digests[relative] = _sha256(path)
    expected_files = sorted(path.as_posix() for path in REQUIRED_FILES)
    if observed_files != expected_files:
        return (
            VisibleVerdict.SCOPE_VIOLATION,
            "submission must contain exactly the seventeen required RTL files",
            {
                "observed_files": observed_files,
                "expected_files": expected_files,
            },
        )
    if total_bytes > MAX_SUBMISSION_BYTES:
        return (
            VisibleVerdict.SCOPE_VIOLATION,
            "submission exceeds the byte budget",
            {"submission_bytes": total_bytes},
        )
    return (
        VisibleVerdict.PASS,
        "exact seventeen-file RTL scope validated",
        {
            "observed_files": observed_files,
            "submission_bytes": total_bytes,
            "submission_sha256": digests,
        },
    )


def _write_yosys_script(
    *,
    submission_root: Path,
    output_root: Path,
) -> Path:
    netlist = output_root / "generic-netlist.json"
    lines = [
        *(
            f"read_verilog -defer {_yosys_quote(submission_root / relative)}"
            for relative in REQUIRED_FILES
        ),
        (
            "chparam -set PRE_REGISTER 1 "
            '-set RESET_STRATEGY "MINI" '
            "-set WITH_CSR 1 -set RF_WIDTH 2 -set RF_L2D 10 "
            f"{TOP}"
        ),
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
        return (
            VisibleVerdict.STRUCTURAL_FAIL,
            "Yosys did not produce a regular JSON netlist",
            None,
        )
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
        return (
            VisibleVerdict.STRUCTURAL_FAIL,
            "synthesized top-level interface differs from the frozen contract",
            None,
        )
    if not cells or not netnames:
        return (
            VisibleVerdict.STRUCTURAL_FAIL,
            "synthesized top is empty or structurally pruned",
            None,
        )
    return (
        VisibleVerdict.PASS,
        "frozen top-level interface and non-empty generic structure validated",
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
        {
            "check_id": "submission_scope",
            "stage": "scope",
            "verdict": verdict.value,
            "reason": reason,
        }
    ]
    yosys = shutil.which(args.yosys) or args.yosys
    iverilog_name = getattr(args, "iverilog", "iverilog")
    vvp_name = getattr(args, "vvp", "vvp")
    iverilog = shutil.which(iverilog_name) or iverilog_name
    vvp = shutil.which(vvp_name) or vvp_name
    statistics = None
    if verdict == VisibleVerdict.PASS:
        script = _write_yosys_script(
            submission_root=submission_root,
            output_root=output_root,
        )
        process = _execute(
            [yosys, "-q", "-l", str(output_root / "yosys.log"), str(script)],
            cwd=submission_root,
            timeout=args.command_timeout_seconds,
            stdout_path=output_root / "yosys.stdout.log",
            stderr_path=output_root / "yosys.stderr.log",
        )
        verdict, reason = classify_process(
            process_status=process["process_status"],
            exit_code=process["exit_code"],
        )
        checks.append(
            {
                "check_id": "elaboration_synthesis",
                "stage": "elaboration_synthesis",
                "verdict": verdict.value,
                "reason": reason,
                "process": process,
            }
        )
    if verdict == VisibleVerdict.PASS:
        verdict, reason, statistics = _inspect_netlist(
            output_root / "generic-netlist.json"
        )
        checks.append(
            {
                "check_id": "frozen_interface",
                "stage": "interface",
                "verdict": verdict.value,
                "reason": reason,
            }
        )

    simulation = output_root / "software-smoke.vvp"
    if verdict == VisibleVerdict.PASS:
        process = _execute(
            [
                iverilog,
                "-g2012",
                "-s",
                SMOKE_TOP,
                "-o",
                str(simulation),
                *(str(submission_root / relative) for relative in REQUIRED_FILES),
                str(SMOKE_TB),
            ],
            cwd=submission_root,
            timeout=args.command_timeout_seconds,
            stdout_path=output_root / "software-smoke-compile.stdout.log",
            stderr_path=output_root / "software-smoke-compile.stderr.log",
        )
        verdict, reason = classify_compile(
            process_status=process["process_status"],
            exit_code=process["exit_code"],
        )
        checks.append(
            {
                "check_id": "software_smoke_compile",
                "stage": "software_smoke_compile",
                "verdict": verdict.value,
                "reason": reason,
                "process": process,
            }
        )
    if verdict == VisibleVerdict.PASS:
        smoke_stdout = output_root / "software-smoke.stdout.log"
        process = _execute(
            [vvp, str(simulation)],
            cwd=submission_root,
            timeout=args.command_timeout_seconds,
            stdout_path=smoke_stdout,
            stderr_path=output_root / "software-smoke.stderr.log",
        )
        verdict, reason = classify_simulation(
            process_status=process["process_status"],
            exit_code=process["exit_code"],
            stdout=smoke_stdout.read_text(encoding="utf-8"),
            sentinel=SMOKE_SENTINEL,
        )
        checks.append(
            {
                "check_id": "short_software_smoke",
                "stage": "software_smoke",
                "verdict": verdict.value,
                "reason": reason,
                "process": process,
            }
        )
    evidence = []
    for path in sorted(output_root.iterdir()):
        if path.is_file() and path.name != "result.json":
            evidence.append(
                {
                    "path": path.name,
                    "bytes": path.stat().st_size,
                    "sha256": _sha256(path),
                }
            )
    return {
        "schema_version": "chipflow.golden12.g10_visible_result.v1",
        "task_id": TASK_ID,
        "suite_status": (
            "development_structural_and_software_smoke_not_frozen"
        ),
        "verdict": verdict.value,
        "pass": verdict == VisibleVerdict.PASS,
        "wall_time_seconds": round(time.monotonic() - started, 6),
        "tool_paths": {
            "yosys": yosys,
            "iverilog": iverilog,
            "vvp": vvp,
        },
        "scope_receipt": scope,
        "checks": checks,
        "diagnostic_structural_statistics": statistics,
        "evidence_manifest": evidence,
        "excluded_claims": [
            "Visible PASS covers structural checks and one public four-instruction smoke only; it is not hidden F2P/P2P, ISA compliance, timing, PPA, QoR, score, or benchmark PASS.",
            "Generic Yosys cell counts are diagnostic structure, not an area unit or optimization result.",
            "The runner, tool versions, environment, limits, and verdict parser are development-only and not frozen.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--submission-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--yosys", default="yosys")
    parser.add_argument("--iverilog", default="iverilog")
    parser.add_argument("--vvp", default="vvp")
    parser.add_argument(
        "--command-timeout-seconds",
        type=int,
        default=120,
    )
    args = parser.parse_args()
    output = args.output_dir.expanduser().resolve()
    try:
        result = run(args)
    except Exception as exc:
        if not output.exists():
            output.mkdir(parents=True, exist_ok=False)
        result = {
            "schema_version": "chipflow.golden12.g10_visible_result.v1",
            "task_id": TASK_ID,
            "suite_status": (
                "development_structural_and_software_smoke_not_frozen"
            ),
            "verdict": "infra_error",
            "pass": False,
            "wall_time_seconds": None,
            "tool_paths": {},
            "scope_receipt": {},
            "checks": [
                {
                    "check_id": "runner_exception",
                    "stage": "scope",
                    "verdict": "infra_error",
                    "reason": f"{type(exc).__name__}: {exc}",
                }
            ],
            "diagnostic_structural_statistics": None,
            "evidence_manifest": [],
            "excluded_claims": [
                "The visible runner raised before completing its checks."
            ],
            "error": f"{type(exc).__name__}: {exc}",
        }
    (output / "result.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["pass"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
