#!/usr/bin/env python3
"""Fail-closed public baseline/candidate equivalence preapproval runner.

The runner is task-neutral.  It consumes an explicit public contract, reads
only the allowlisted RTL files from separate baseline and candidate roots, and
uses Yosys ``equiv_make``/``equiv_simple``/``equiv_induct`` and the strict
``equiv_status -assert`` terminator.  A PASS
means that this exact configured proof obligation was discharged.  It is not
a frozen hidden oracle, ISA-compliance result, or complete equivalence claim.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
from typing import Any


CONTRACT_SCHEMA_VERSION = "rtlflowbench.yosys_equivalence_contract.v1"
RESULT_SCHEMA_VERSION = "rtlflowbench.yosys_equivalence_result.v1"
_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_$]*$")
_RTL_SUFFIXES = frozenset({".v", ".sv"})
_SUCCESS_SENTINEL = "Equivalence successfully proven!"
_UNPROVEN_RE = re.compile(r"Found (\d+) unproven \$equiv cells")
_PROVEN_RE = re.compile(r"Of those cells (\d+) are proven and (\d+) are unproven")


class InputError(ValueError):
    """The public contract or source projection is invalid."""


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _sha256_json(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _safe_relative(value: str) -> Path:
    candidate = Path(value)
    if (
        not value
        or candidate.is_absolute()
        or ".." in candidate.parts
        or candidate.as_posix() != value.replace("\\", "/")
        or candidate.suffix.lower() not in _RTL_SUFFIXES
    ):
        raise InputError(f"unsafe or non-RTL source path: {value!r}")
    return candidate


def _safe_source(root: Path, relative: Path) -> Path:
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise InputError(
                f"source path contains a symlink: {relative.as_posix()}"
            )
    try:
        path = (root / relative).resolve(strict=True)
    except FileNotFoundError as exc:
        raise InputError(
            f"source path is missing: {relative.as_posix()}"
        ) from exc
    if not path.is_file() or not path.is_relative_to(root):
        raise InputError(
            f"source path is not a regular file: {relative.as_posix()}"
        )
    return path


def _load_contract(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InputError(f"cannot parse equivalence contract: {exc}") from exc
    if not isinstance(payload, dict):
        raise InputError("equivalence contract must be a JSON object")
    required = {
        "schema_version",
        "task_id",
        "top_module",
        "language",
        "source_paths",
        "parameters",
        "sequential_depth",
        "max_source_bytes",
    }
    if set(payload) != required:
        raise InputError(
            "equivalence contract fields must exactly equal: "
            + ", ".join(sorted(required))
        )
    if payload.get("schema_version") != CONTRACT_SCHEMA_VERSION:
        raise InputError("unsupported equivalence contract schema_version")
    if not isinstance(payload.get("task_id"), str) or not payload["task_id"]:
        raise InputError("equivalence contract requires a non-empty task_id")
    top = payload.get("top_module")
    if not isinstance(top, str) or not _IDENTIFIER_RE.fullmatch(top):
        raise InputError("equivalence contract top_module is invalid")
    if top in {"gold", "gate", "equiv"}:
        raise InputError("equivalence contract top_module uses a reserved name")
    if payload.get("language") not in {"verilog_2005", "systemverilog"}:
        raise InputError("equivalence contract language is unsupported")
    sources = payload.get("source_paths")
    if (
        not isinstance(sources, list)
        or not 1 <= len(sources) <= 64
        or not all(isinstance(item, str) for item in sources)
        or len(sources) != len(set(sources))
    ):
        raise InputError(
            "equivalence contract source_paths must contain 1..64 unique paths"
        )
    for item in sources:
        _safe_relative(item)
    parameters = payload.get("parameters")
    if not isinstance(parameters, dict) or not parameters:
        raise InputError("equivalence contract parameters must be non-empty")
    for name, value in parameters.items():
        if not isinstance(name, str) or not _IDENTIFIER_RE.fullmatch(name):
            raise InputError(f"invalid parameter name: {name!r}")
        if isinstance(value, bool) or not isinstance(value, (int, str)):
            raise InputError(f"invalid parameter value for {name}")
        if isinstance(value, str) and (not value or any(ch in value for ch in "\n\r\"\\")):
            raise InputError(f"unsafe string parameter value for {name}")
    depth = payload.get("sequential_depth")
    if isinstance(depth, bool) or not isinstance(depth, int) or not 1 <= depth <= 32:
        raise InputError("sequential_depth must be an integer from 1 to 32")
    limit = payload.get("max_source_bytes")
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 16_777_216:
        raise InputError("max_source_bytes must be an integer from 1 to 16777216")
    return payload


def _source_manifest(
    root: Path,
    relative_paths: list[Path],
    *,
    max_source_bytes: int,
) -> tuple[dict[str, dict[str, int | str]], list[Path]]:
    if root.is_symlink() or not root.is_dir():
        raise InputError(f"source root is not a regular directory: {root}")
    resolved_root = root.resolve(strict=True)
    manifest: dict[str, dict[str, int | str]] = {}
    resolved: list[Path] = []
    total = 0
    for relative in relative_paths:
        path = _safe_source(resolved_root, relative)
        raw = path.read_bytes()
        total += len(raw)
        if total > max_source_bytes:
            raise InputError(
                f"allowlisted RTL exceeds {max_source_bytes} bytes"
            )
        manifest[relative.as_posix()] = {
            "sha256": hashlib.sha256(raw).hexdigest(),
            "bytes": len(raw),
        }
        resolved.append(path)
    return manifest, resolved


def _source_root(path: Path) -> Path:
    if path.is_symlink() or not path.is_dir():
        raise InputError(f"source root is not a regular directory: {path}")
    return path.resolve(strict=True)


def _safe_output_root(
    output_root: Path,
    *,
    baseline_root: Path,
    candidate_root: Path,
) -> Path:
    output = output_root.expanduser().resolve()
    if (
        output in {baseline_root, candidate_root}
        or output.is_relative_to(baseline_root)
        or output.is_relative_to(candidate_root)
    ):
        raise InputError("output root must be outside both source roots")
    if output.exists():
        if output.is_symlink() or not output.is_dir() or any(output.iterdir()):
            raise InputError("output root must be absent or an empty directory")
    else:
        output.mkdir(parents=True)
    return output


def _yosys_quote(value: str | Path) -> str:
    rendered = str(value)
    return '"' + rendered.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _parameter_command(parameters: dict[str, int | str], top: str) -> str:
    parts = ["chparam"]
    for name, value in parameters.items():
        rendered = str(value) if isinstance(value, int) else _yosys_quote(value)
        parts.extend(["-set", name, rendered])
    parts.append(top)
    return " ".join(parts)


def _design_commands(
    sources: list[Path],
    *,
    language: str,
    top: str,
    parameters: dict[str, int | str],
    renamed_top: str,
) -> list[str]:
    language_flag = " -sv" if language == "systemverilog" else ""
    return [
        *(f"read_verilog -defer{language_flag} {_yosys_quote(path)}" for path in sources),
        _parameter_command(parameters, top),
        f"hierarchy -check -top {top}",
        f"prep -top {top} -flatten",
        f"rename {top} {renamed_top}",
        f"design -stash {renamed_top}",
        "design -reset",
    ]


def _build_script(
    baseline_sources: list[Path],
    candidate_sources: list[Path],
    contract: dict[str, Any],
) -> str:
    top = contract["top_module"]
    parameters = contract["parameters"]
    return "\n".join(
        [
            *_design_commands(
                baseline_sources,
                language=contract["language"],
                top=top,
                parameters=parameters,
                renamed_top="gold",
            ),
            *_design_commands(
                candidate_sources,
                language=contract["language"],
                top=top,
                parameters=parameters,
                renamed_top="gate",
            ),
            "design -copy-from gold -as gold gold",
            "design -copy-from gate -as gate gate",
            "equiv_make gold gate equiv",
            "hierarchy -top equiv",
            f"equiv_simple -seq {contract['sequential_depth']}",
            f"equiv_induct -seq {contract['sequential_depth']}",
            "equiv_status -assert",
            "",
        ]
    )


def _empty_result(*, task_id: str = "") -> dict[str, Any]:
    return {
        "schema_version": RESULT_SCHEMA_VERSION,
        "task_id": task_id,
        "verdict": "invalid_input",
        "pass": False,
        "reason": "equivalence runner did not start",
        "contract_sha256": None,
        "baseline_manifest_sha256": None,
        "candidate_manifest_sha256": None,
        "compared_source_count": 0,
        "proof": {
            "method": "yosys_equiv_simple_induct_sequential",
            "sequential_depth": None,
            "proof_obligation_discharged": False,
            "proven_equiv_cells": None,
            "unproven_equiv_cells": None,
            "complete_formal_equivalence_claimed": False,
        },
        "tool": {
            "name": "yosys",
            "path": None,
            "sha256": None,
            "version": None,
        },
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
            "This public preapproval gate is not a hidden benchmark oracle or benchmark PASS.",
            "The configured Yosys proof obligation is not a complete ISA, P2P, or universal formal-equivalence claim.",
            "A successful proof does not establish QoR, PPA, score, adapter readiness, or benchmark readiness.",
        ],
    }


def _resolve_tool(value: str) -> Path:
    discovered = shutil.which(value) if os.sep not in value else value
    if not discovered:
        raise OSError(f"Yosys executable not found: {value}")
    path = Path(discovered).expanduser().resolve(strict=True)
    if not path.is_file() or not os.access(path, os.X_OK):
        raise OSError(f"Yosys executable is not runnable: {path}")
    return path


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
        result["proof"]["sequential_depth"] = contract["sequential_depth"]
        if timeout_seconds < 1 or timeout_seconds > 3600:
            raise InputError("timeout_seconds must be from 1 to 3600")
        baseline = _source_root(baseline_root.expanduser())
        candidate = _source_root(candidate_root.expanduser())
        output = _safe_output_root(
            output_root,
            baseline_root=baseline,
            candidate_root=candidate,
        )
        relative_paths = [_safe_relative(item) for item in contract["source_paths"]]
        baseline_manifest, baseline_sources = _source_manifest(
            baseline,
            relative_paths,
            max_source_bytes=contract["max_source_bytes"],
        )
        candidate_manifest, candidate_sources = _source_manifest(
            candidate,
            relative_paths,
            max_source_bytes=contract["max_source_bytes"],
        )
        result["baseline_manifest_sha256"] = _sha256_json(baseline_manifest)
        result["candidate_manifest_sha256"] = _sha256_json(candidate_manifest)
        result["compared_source_count"] = len(relative_paths)

        script_path = output / "equivalence.ys"
        stdout_path = output / "yosys.stdout.log"
        stderr_path = output / "yosys.stderr.log"
        script_path.write_text(
            _build_script(baseline_sources, candidate_sources, contract),
            encoding="utf-8",
        )
        result["evidence"]["script_path"] = script_path.name
        result["evidence"]["script_sha256"] = _sha256(script_path)

        tool = _resolve_tool(yosys)
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
        proven_matches = _PROVEN_RE.findall(combined)
        unproven_matches = [int(item) for item in _UNPROVEN_RE.findall(combined)]
        proven_cells = int(proven_matches[-1][0]) if proven_matches else None
        unproven_cells = (
            int(proven_matches[-1][1])
            if proven_matches
            else (unproven_matches[-1] if unproven_matches else None)
        )
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
        result["proof"]["proven_equiv_cells"] = proven_cells
        result["proof"]["unproven_equiv_cells"] = unproven_cells

        if process_status == "timeout":
            result["verdict"] = "timeout"
            result["reason"] = "Yosys equivalence command exceeded the configured timeout"
            return 2, result
        if exit_code == 0 and _SUCCESS_SENTINEL in combined and unproven_cells == 0:
            result["verdict"] = "pass"
            result["pass"] = True
            result["reason"] = "the configured Yosys equivalence proof obligation was discharged"
            result["proof"]["proof_obligation_discharged"] = True
            return 0, result
        if unproven_cells is not None and unproven_cells > 0:
            result["verdict"] = "equivalence_fail"
            result["reason"] = f"Yosys reported {unproven_cells} unproven equivalence cells"
            return 2, result
        if exit_code == 0:
            result["verdict"] = "infra_error"
            result["reason"] = "Yosys exited zero without the exact proof-success sentinel"
            return 3, result
        result["verdict"] = "compile_error"
        result["reason"] = "Yosys could not construct or complete the configured equivalence model"
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
        baseline = _source_root(args.baseline_root.expanduser())
        candidate = _source_root(args.candidate_root.expanduser())
        output = args.output_dir.expanduser().resolve()
        output_is_safe = (
            output.is_dir()
            and not output.is_symlink()
            and output not in {baseline, candidate}
            and not output.is_relative_to(baseline)
            and not output.is_relative_to(candidate)
        )
    except (InputError, OSError):
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
