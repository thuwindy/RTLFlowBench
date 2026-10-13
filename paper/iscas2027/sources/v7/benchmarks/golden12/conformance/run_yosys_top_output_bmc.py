#!/usr/bin/env python3
"""Fail-closed public top-output bounded equivalence runner.

This runner deliberately compares only the configured top-level outputs.  It
is intended for QoR transformations that may change implementation-private
signals while preserving externally observable behavior.  The proof starts
from a declared zero-state/reset projection and is bounded; a PASS is not a
complete sequential- or ISA-equivalence claim.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from typing import Any

sys.dont_write_bytecode = True

_BASE_PATH = Path(__file__).with_name("run_yosys_sequential_equivalence.py")
_BASE_SPEC = importlib.util.spec_from_file_location(
    "rtlflowbench_yosys_equivalence_helpers", _BASE_PATH
)
if _BASE_SPEC is None or _BASE_SPEC.loader is None:
    raise ImportError(f"could not load equivalence helpers: {_BASE_PATH}")
_BASE = importlib.util.module_from_spec(_BASE_SPEC)
sys.modules[_BASE_SPEC.name] = _BASE
_BASE_SPEC.loader.exec_module(_BASE)

CONTRACT_SCHEMA_VERSION = "rtlflowbench.yosys_top_output_bmc_contract.v1"
RESULT_SCHEMA_VERSION = "rtlflowbench.yosys_top_output_bmc_result.v1"
_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_$]*$")
_SUCCESS_SENTINEL = "SAT proof finished - no model found: SUCCESS!"
_FAIL_SENTINEL = "Called with -verify and proof did fail!"


class InputError(ValueError):
    """The public contract or source projection is invalid."""


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_contract(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InputError(f"cannot parse top-output BMC contract: {exc}") from exc
    if not isinstance(payload, dict):
        raise InputError("top-output BMC contract must be a JSON object")
    required = {
        "schema_version",
        "task_id",
        "top_module",
        "language",
        "source_paths",
        "parameters",
        "sequential_depth",
        "max_source_bytes",
        "reset_signal",
        "reset_active_level",
        "reset_cycles",
        "initial_state_policy",
        "ignore_baseline_x_outputs",
    }
    if set(payload) != required:
        raise InputError(
            "top-output BMC contract fields must exactly equal: "
            + ", ".join(sorted(required))
        )
    if payload.get("schema_version") != CONTRACT_SCHEMA_VERSION:
        raise InputError("unsupported top-output BMC contract schema_version")
    if not isinstance(payload.get("task_id"), str) or not payload["task_id"]:
        raise InputError("top-output BMC contract requires a non-empty task_id")
    top = payload.get("top_module")
    if not isinstance(top, str) or not _IDENTIFIER_RE.fullmatch(top):
        raise InputError("top-output BMC top_module is invalid")
    if top in {"gold", "gate", "miter"}:
        raise InputError("top-output BMC top_module uses a reserved name")
    if payload.get("language") not in {"verilog_2005", "systemverilog"}:
        raise InputError("top-output BMC language is unsupported")
    sources = payload.get("source_paths")
    if (
        not isinstance(sources, list)
        or not 1 <= len(sources) <= 64
        or not all(isinstance(item, str) for item in sources)
        or len(sources) != len(set(sources))
    ):
        raise InputError("source_paths must contain 1..64 unique paths")
    for item in sources:
        try:
            _BASE._safe_relative(item)
        except _BASE.InputError as exc:
            raise InputError(str(exc)) from exc
    parameters = payload.get("parameters")
    if not isinstance(parameters, dict) or not parameters:
        raise InputError("parameters must be a non-empty object")
    for name, value in parameters.items():
        if not isinstance(name, str) or not _IDENTIFIER_RE.fullmatch(name):
            raise InputError(f"invalid parameter name: {name!r}")
        if isinstance(value, bool) or not isinstance(value, (int, str)):
            raise InputError(f"invalid parameter value for {name}")
        if isinstance(value, str) and (
            not value or any(ch in value for ch in "\n\r\"\\")
        ):
            raise InputError(f"unsafe string parameter value for {name}")
    depth = payload.get("sequential_depth")
    if isinstance(depth, bool) or not isinstance(depth, int) or not 2 <= depth <= 32:
        raise InputError("sequential_depth must be an integer from 2 to 32")
    limit = payload.get("max_source_bytes")
    if (
        isinstance(limit, bool)
        or not isinstance(limit, int)
        or not 1 <= limit <= 16_777_216
    ):
        raise InputError("max_source_bytes must be an integer from 1 to 16777216")
    reset = payload.get("reset_signal")
    if not isinstance(reset, str) or not _IDENTIFIER_RE.fullmatch(reset):
        raise InputError("reset_signal must be an identifier")
    if payload.get("reset_active_level") not in {0, 1}:
        raise InputError("reset_active_level must be 0 or 1")
    reset_cycles = payload.get("reset_cycles")
    if (
        isinstance(reset_cycles, bool)
        or not isinstance(reset_cycles, int)
        or not 1 <= reset_cycles < depth
    ):
        raise InputError("reset_cycles must be from 1 to sequential_depth - 1")
    if payload.get("initial_state_policy") != "zero":
        raise InputError("initial_state_policy must be zero")
    if not isinstance(payload.get("ignore_baseline_x_outputs"), bool):
        raise InputError("ignore_baseline_x_outputs must be boolean")
    return payload


def _build_script(
    baseline_sources: list[Path],
    candidate_sources: list[Path],
    contract: dict[str, Any],
) -> str:
    top = contract["top_module"]
    depth = contract["sequential_depth"]
    reset_cycles = contract["reset_cycles"]
    active = contract["reset_active_level"]
    inactive = 1 - active
    reset_port = f"in_{contract['reset_signal']}"
    reset_constraints = " ".join(
        f"-set-at {cycle} {reset_port} {active if cycle <= reset_cycles else inactive}"
        for cycle in range(1, depth + 1)
    )
    ignore_x = " -ignore_gold_x" if contract["ignore_baseline_x_outputs"] else ""
    return "\n".join(
        [
            *_BASE._design_commands(
                baseline_sources,
                language=contract["language"],
                top=top,
                parameters=contract["parameters"],
                renamed_top="gold",
            ),
            *_BASE._design_commands(
                candidate_sources,
                language=contract["language"],
                top=top,
                parameters=contract["parameters"],
                renamed_top="gate",
            ),
            "design -copy-from gold -as gold gold",
            "design -copy-from gate -as gate gate",
            f"miter -equiv{ignore_x} -make_outputs -flatten gold gate miter",
            "hierarchy -top miter",
            "memory_map",
            "opt_clean",
            (
                f"sat -verify -seq {depth} -set-init-zero {reset_constraints} "
                f"-prove-skip {reset_cycles} -prove trigger 0"
            ),
            "",
        ]
    )


def _empty_result(*, task_id: str = "") -> dict[str, Any]:
    return {
        "schema_version": RESULT_SCHEMA_VERSION,
        "task_id": task_id,
        "verdict": "invalid_input",
        "pass": False,
        "reason": "top-output BMC runner did not start",
        "contract_sha256": None,
        "baseline_manifest_sha256": None,
        "candidate_manifest_sha256": None,
        "compared_source_count": 0,
        "proof": {
            "method": "yosys_miter_sat_reset_bmc",
            "sequential_depth": None,
            "reset_signal": None,
            "reset_active_level": None,
            "reset_cycles": None,
            "initial_state_policy": None,
            "ignore_baseline_x_outputs": None,
            "proof_obligation_discharged": False,
            "complete_equivalence_claimed": False,
        },
        "tool": {"name": "yosys", "path": None, "sha256": None, "version": None},
        "process": {
            "status": "not_started",
            "exit_code": None,
            "wall_time_seconds": None,
            "command": [],
        },
        "evidence": {
            "script_path": None,
            "script_sha256": None,
            "stdout_path": None,
            "stdout_sha256": None,
            "stderr_path": None,
            "stderr_sha256": None,
            "stdout_tail": "",
            "stderr_tail": "",
        },
        "excluded_claims": [
            "This public gate is a reset-constrained bounded top-output proof, not a complete sequential-equivalence or ISA-compliance claim.",
            "Zero-state initialization is a declared proof projection and not a claim about arbitrary uninitialized register-file contents.",
            "A successful proof does not establish hidden benchmark PASS, P2P, physical QoR, score, adapter readiness, or benchmark readiness.",
        ],
    }


def run(
    *,
    baseline_root: Path,
    candidate_root: Path,
    output_root: Path,
    contract_path: Path,
    yosys: str,
    timeout_seconds: int,
) -> tuple[int, dict[str, Any]]:
    result = _empty_result()
    try:
        contract = _load_contract(contract_path)
        result["task_id"] = contract["task_id"]
        result["contract_sha256"] = _sha256(contract_path)
        result["proof"].update(
            {
                key: contract[key]
                for key in (
                    "sequential_depth",
                    "reset_signal",
                    "reset_active_level",
                    "reset_cycles",
                    "initial_state_policy",
                    "ignore_baseline_x_outputs",
                )
            }
        )
        if timeout_seconds < 1 or timeout_seconds > 3600:
            raise InputError("timeout_seconds must be from 1 to 3600")
        try:
            baseline = _BASE._source_root(baseline_root.expanduser())
            candidate = _BASE._source_root(candidate_root.expanduser())
            output = _BASE._safe_output_root(
                output_root,
                baseline_root=baseline,
                candidate_root=candidate,
            )
            relative_paths = [_BASE._safe_relative(item) for item in contract["source_paths"]]
            baseline_manifest, baseline_sources = _BASE._source_manifest(
                baseline,
                relative_paths,
                max_source_bytes=contract["max_source_bytes"],
            )
            candidate_manifest, candidate_sources = _BASE._source_manifest(
                candidate,
                relative_paths,
                max_source_bytes=contract["max_source_bytes"],
            )
        except _BASE.InputError as exc:
            raise InputError(str(exc)) from exc
        result["baseline_manifest_sha256"] = _BASE._sha256_json(baseline_manifest)
        result["candidate_manifest_sha256"] = _BASE._sha256_json(candidate_manifest)
        result["compared_source_count"] = len(relative_paths)

        script_path = output / "top-output-bmc.ys"
        stdout_path = output / "yosys.stdout.log"
        stderr_path = output / "yosys.stderr.log"
        script_path.write_text(
            _build_script(baseline_sources, candidate_sources, contract),
            encoding="utf-8",
        )
        result["evidence"]["script_path"] = script_path.name
        result["evidence"]["script_sha256"] = _sha256(script_path)

        tool = _BASE._resolve_tool(yosys)
        version = subprocess.run(
            [str(tool), "-V"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
            env={"PATH": os.environ.get("PATH", ""), "LANG": "C", "LC_ALL": "C"},
        )
        if version.returncode != 0:
            raise OSError("Yosys version probe failed")
        result["tool"] = {
            "name": "yosys",
            "path": str(tool),
            "sha256": _sha256(tool),
            "version": (version.stdout or version.stderr).strip(),
        }
        command = [str(tool), "-Q", "-s", str(script_path)]
        result["process"]["command"] = command
        started = time.monotonic()
        try:
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                env={"PATH": os.environ.get("PATH", ""), "LANG": "C", "LC_ALL": "C"},
            )
            stdout, stderr = completed.stdout, completed.stderr
            process_status = "completed"
            exit_code = completed.returncode
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout or ""
            stderr = exc.stderr or ""
            if isinstance(stdout, bytes):
                stdout = stdout.decode(errors="replace")
            if isinstance(stderr, bytes):
                stderr = stderr.decode(errors="replace")
            process_status = "timeout"
            exit_code = None
        duration = round(time.monotonic() - started, 6)
        stdout_path.write_text(stdout, encoding="utf-8")
        stderr_path.write_text(stderr, encoding="utf-8")
        combined = stdout + "\n" + stderr
        result["process"].update(
            {
                "status": process_status,
                "exit_code": exit_code,
                "wall_time_seconds": duration,
            }
        )
        result["evidence"].update(
            {
                "stdout_path": stdout_path.name,
                "stdout_sha256": _sha256(stdout_path),
                "stderr_path": stderr_path.name,
                "stderr_sha256": _sha256(stderr_path),
                "stdout_tail": stdout[-4000:],
                "stderr_tail": stderr[-4000:],
            }
        )
        if process_status == "timeout":
            result["verdict"] = "timeout"
            result["reason"] = "Yosys top-output BMC exceeded the configured timeout"
            return 2, result
        if exit_code == 0 and _SUCCESS_SENTINEL in combined:
            result["verdict"] = "pass"
            result["pass"] = True
            result["reason"] = "the configured reset-constrained top-output BMC obligation was discharged"
            result["proof"]["proof_obligation_discharged"] = True
            return 0, result
        if _FAIL_SENTINEL in combined:
            result["verdict"] = "equivalence_fail"
            result["reason"] = "Yosys produced a counterexample to the configured top-output BMC obligation"
            return 2, result
        if exit_code == 0:
            result["verdict"] = "infra_error"
            result["reason"] = "Yosys exited zero without the exact top-output BMC success sentinel"
            return 3, result
        result["verdict"] = "compile_error"
        result["reason"] = "Yosys could not construct or complete the top-output BMC model"
        return 2, result
    except InputError as exc:
        result["verdict"] = "invalid_input"
        result["reason"] = str(exc)
        return 2, result
    except (FileNotFoundError, OSError, subprocess.SubprocessError) as exc:
        result["verdict"] = "infra_error"
        result["reason"] = f"{type(exc).__name__}: {exc}"
        return 3, result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline-root", type=Path, required=True)
    parser.add_argument("--candidate-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--yosys", default="yosys")
    parser.add_argument("--timeout-seconds", type=int, default=300)
    return parser


def main() -> int:
    args = _parser().parse_args()
    exit_code, result = run(
        baseline_root=args.baseline_root,
        candidate_root=args.candidate_root,
        output_root=args.output_dir,
        contract_path=args.contract,
        yosys=args.yosys,
        timeout_seconds=args.timeout_seconds,
    )
    result_path: Path | None = None
    try:
        baseline = _BASE._source_root(args.baseline_root.expanduser())
        candidate = _BASE._source_root(args.candidate_root.expanduser())
        output = args.output_dir.expanduser().resolve()
        output_is_safe = (
            output.is_dir()
            and not output.is_symlink()
            and output not in {baseline, candidate}
            and not output.is_relative_to(baseline)
            and not output.is_relative_to(candidate)
        )
    except (_BASE.InputError, OSError):
        output_is_safe = False
    if output_is_safe:
        result_path = output / "result.json"
        result_path.write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    print(
        json.dumps(
            {
                "task_id": result["task_id"],
                "verdict": result["verdict"],
                "pass": result["pass"],
                "reason": result["reason"],
                "result_path": str(result_path) if result_path else None,
            },
            sort_keys=True,
        )
    )
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
