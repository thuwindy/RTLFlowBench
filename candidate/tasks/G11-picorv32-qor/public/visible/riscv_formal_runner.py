#!/usr/bin/env python3
"""Development RISCV_FORMAL structural projection gate for G11."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import time
from typing import Any

sys.dont_write_bytecode = True

_VISIBLE_DIR = Path(__file__).resolve().parent
_RUNNER_PATH = _VISIBLE_DIR / "runner.py"
_RUNNER_SPEC = importlib.util.spec_from_file_location(
    "rtlflowbench_g11_visible_runner_for_rvfi", _RUNNER_PATH
)
if _RUNNER_SPEC is None or _RUNNER_SPEC.loader is None:
    raise ImportError(f"could not load visible runner: {_RUNNER_PATH}")
_RUNNER = importlib.util.module_from_spec(_RUNNER_SPEC)
sys.modules[_RUNNER_SPEC.name] = _RUNNER
_RUNNER_SPEC.loader.exec_module(_RUNNER)

TASK_ID = "G11-picorv32-qor"
PROJECTION_PATH = _VISIBLE_DIR / "riscv_formal_projection.json"
RESULT_SCHEMA_PATH = _VISIBLE_DIR / "riscv_formal_result.schema.json"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_projection() -> dict[str, Any]:
    projection = json.loads(PROJECTION_PATH.read_text(encoding="utf-8"))
    if projection.get("schema_version") != "rtlflowbench.g11_riscv_formal_projection.v1":
        raise ValueError("unsupported RISCV_FORMAL projection schema")
    if projection.get("task_id") != TASK_ID or projection.get("top_module") != _RUNNER.TOP:
        raise ValueError("RISCV_FORMAL projection is bound to another task or top")
    if projection.get("compile_defines") != ["RISCV_FORMAL"]:
        raise ValueError("RISCV_FORMAL projection must use the one frozen public define")
    rvfi_ports = projection.get("rvfi_ports")
    if not isinstance(rvfi_ports, list) or len(rvfi_ports) != 29:
        raise ValueError("RISCV_FORMAL projection must list exactly 29 RVFI ports")
    names = [item.get("name") for item in rvfi_ports]
    if len(names) != len(set(names)):
        raise ValueError("RISCV_FORMAL projection contains duplicate RVFI ports")
    return projection


def _expected_ports(projection: dict[str, Any]) -> dict[str, tuple[str, int]]:
    rvfi = {
        str(item["name"]): (str(item["direction"]), int(item["width"]))
        for item in projection["rvfi_ports"]
    }
    overlap = set(_RUNNER.EXPECTED_PORTS).intersection(rvfi)
    if overlap:
        raise ValueError(f"ordinary/RVFI port overlap: {sorted(overlap)}")
    expected = {**_RUNNER.EXPECTED_PORTS, **rvfi}
    if len(expected) != projection["expected_total_top_port_count"]:
        raise ValueError("RISCV_FORMAL expected port count is internally inconsistent")
    return expected


def _write_yosys_script(*, submission_root: Path, output_root: Path) -> Path:
    parameter_args = " ".join(
        f"-set {name} {value}" for name, value in _RUNNER.FROZEN_PARAMETERS.items()
    )
    netlist = output_root / "riscv-formal-netlist.json"
    lines = [
        f"read_verilog -DRISCV_FORMAL -defer {_RUNNER._yosys_quote(submission_root / _RUNNER.REQUIRED_FILE)}",
        f"chparam {parameter_args} {_RUNNER.TOP}",
        f"hierarchy -check -top {_RUNNER.TOP}",
        f"synth -top {_RUNNER.TOP} -flatten -noabc",
        "check",
        f"write_json {_RUNNER._yosys_quote(netlist)}",
    ]
    path = output_root / "riscv-formal-structural.ys"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _inspect_netlist(
    path: Path, projection: dict[str, Any]
) -> tuple[Any, str, dict[str, Any] | None]:
    if not path.is_file() or path.is_symlink():
        return (
            _RUNNER.VisibleVerdict.STRUCTURAL_FAIL,
            "Yosys did not produce a regular RISCV_FORMAL JSON netlist",
            None,
        )
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        module = payload["modules"][_RUNNER.TOP]
        ports = {
            name: (entry["direction"], len(entry["bits"]))
            for name, entry in module["ports"].items()
        }
        cells = module["cells"]
        netnames = module["netnames"]
    except Exception as exc:
        return (
            _RUNNER.VisibleVerdict.STRUCTURAL_FAIL,
            f"could not parse RISCV_FORMAL netlist: {type(exc).__name__}: {exc}",
            None,
        )
    expected = _expected_ports(projection)
    if ports != expected:
        missing = sorted(set(expected) - set(ports))
        extra = sorted(set(ports) - set(expected))
        mismatched = sorted(
            name
            for name in set(ports).intersection(expected)
            if ports[name] != expected[name]
        )
        return (
            _RUNNER.VisibleVerdict.STRUCTURAL_FAIL,
            "RISCV_FORMAL top interface differs from the public projection",
            {"missing_ports": missing, "extra_ports": extra, "mismatched_ports": mismatched},
        )
    if not cells or not netnames:
        return (
            _RUNNER.VisibleVerdict.STRUCTURAL_FAIL,
            "RISCV_FORMAL synthesis is empty or structurally pruned",
            None,
        )
    return (
        _RUNNER.VisibleVerdict.PASS,
        "ordinary and RVFI top ports exactly match the public RISCV_FORMAL projection",
        {
            "ordinary_port_count": projection["ordinary_port_count"],
            "rvfi_port_count": projection["rvfi_port_count"],
            "total_top_port_count": len(ports),
            "generic_cell_count_not_area": len(cells),
            "netname_count": len(netnames),
        },
    )


def run(args: argparse.Namespace) -> dict[str, Any]:
    started = time.monotonic()
    submission_root = args.submission_root.expanduser().resolve()
    output_root = args.output_dir.expanduser().resolve()
    output_root.mkdir(parents=True, exist_ok=False)
    projection = _load_projection()
    verdict, reason, scope = _RUNNER._preflight(submission_root, output_root)
    checks: list[dict[str, Any]] = [
        {"check_id": "submission_scope", "stage": "scope", "verdict": verdict.value, "reason": reason}
    ]
    yosys = shutil.which(args.yosys) or args.yosys
    interface_observation = None
    if verdict == _RUNNER.VisibleVerdict.PASS:
        execution_root = output_root / "work"
        execution_root.mkdir()
        shutil.copyfile(
            submission_root / _RUNNER.REQUIRED_FILE,
            execution_root / _RUNNER.REQUIRED_FILE,
        )
        script = _write_yosys_script(
            submission_root=execution_root,
            output_root=output_root,
        )
        process = _RUNNER._execute(
            [yosys, "-q", "-l", str(output_root / "riscv-formal-yosys.log"), str(script)],
            cwd=execution_root,
            timeout=args.command_timeout_seconds,
            stdout_path=output_root / "riscv-formal-yosys.stdout.log",
            stderr_path=output_root / "riscv-formal-yosys.stderr.log",
        )
        verdict, reason = _RUNNER.classify_build(
            process_status=process["process_status"],
            exit_code=process["exit_code"],
            stage="Yosys RISCV_FORMAL elaboration and synthesis",
        )
        checks.append(
            {
                "check_id": "riscv_formal_elaboration",
                "stage": "riscv_formal_elaboration",
                "verdict": verdict.value,
                "reason": reason,
                "process": process,
            }
        )
    if verdict == _RUNNER.VisibleVerdict.PASS:
        verdict, reason, interface_observation = _inspect_netlist(
            output_root / "riscv-formal-netlist.json", projection
        )
        checks.append(
            {
                "check_id": "riscv_formal_interface",
                "stage": "riscv_formal_interface",
                "verdict": verdict.value,
                "reason": reason,
            }
        )
    evidence = [
        {"path": path.name, "bytes": path.stat().st_size, "sha256": _sha256(path)}
        for path in sorted(output_root.iterdir())
        if path.is_file() and path.name != "result.json"
    ]
    return {
        "schema_version": "rtlflowbench.g11_riscv_formal_result.v1",
        "task_id": TASK_ID,
        "suite_status": "development_structural_projection_not_frozen",
        "verdict": verdict.value,
        "pass": verdict == _RUNNER.VisibleVerdict.PASS,
        "wall_time_seconds": round(time.monotonic() - started, 6),
        "tool_paths": {"yosys": yosys},
        "contract_sha256": _sha256(PROJECTION_PATH),
        "scope_receipt": scope,
        "checks": checks,
        "interface_observation": interface_observation,
        "evidence_manifest": evidence,
        "excluded_claims": [
            "A structural RISCV_FORMAL PASS establishes only exact ordinary/RVFI port projection and non-empty generic synthesis.",
            "It does not prove RVFI observation semantics, hidden F2P/P2P, complete equivalence, ISA compliance, physical PPA, QoR improvement, score, benchmark readiness, or adapter readiness.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--submission-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--yosys", default="yosys")
    parser.add_argument("--command-timeout-seconds", type=int, default=120)
    args = parser.parse_args()
    output = args.output_dir.expanduser().resolve()
    try:
        result = run(args)
    except Exception as exc:
        output.mkdir(parents=True, exist_ok=True)
        result = {
            "schema_version": "rtlflowbench.g11_riscv_formal_result.v1",
            "task_id": TASK_ID,
            "suite_status": "development_structural_projection_not_frozen",
            "verdict": "infra_error",
            "pass": False,
            "wall_time_seconds": None,
            "tool_paths": {},
            "contract_sha256": _sha256(PROJECTION_PATH) if PROJECTION_PATH.is_file() else None,
            "scope_receipt": {},
            "checks": [{"check_id": "runner_exception", "stage": "scope", "verdict": "infra_error", "reason": f"{type(exc).__name__}: {exc}"}],
            "interface_observation": None,
            "evidence_manifest": [],
            "excluded_claims": ["The RISCV_FORMAL runner raised before completing its checks."],
            "error": f"{type(exc).__name__}: {exc}",
        }
    (output / "result.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["pass"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
