#!/usr/bin/env python3
"""Run the public G02 development suite without exposing private assets."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
from typing import Any


TASK_ID = "G02-common-rr-arbiter-spec"
REQUIRED_RTL = Path("rtl/golden12_rr_arbiter.sv")
HERE = Path(__file__).resolve().parent


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_verdict():
    path = HERE / "verdict.py"
    spec = importlib.util.spec_from_file_location("g02_visible_verdict", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"could not load verdict parser: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _stage(stage_id: str, status: str, exit_code: int | None, log_path: str | None, detail: str | None = None) -> dict[str, Any]:
    return {
        "stage_id": stage_id,
        "status": status,
        "exit_code": exit_code,
        "log_path": log_path,
        "detail": detail,
    }


def _run(argv: list[str], *, timeout: int) -> tuple[str, int | None, str]:
    try:
        result = subprocess.run(
            argv,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        return "infra_error", None, f"{type(exc).__name__}: {exc}\n"
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout or ""
        if isinstance(output, bytes):
            output = output.decode(errors="replace")
        return "timeout", None, output + f"\nTIMEOUT after {timeout}s\n"
    return "complete", result.returncode, result.stdout


def _write_log(output_dir: Path, name: str, payload: str) -> str:
    path = output_dir / name
    path.write_text(payload, encoding="utf-8")
    return path.relative_to(output_dir).as_posix()


def _scope_stage(workspace: Path) -> tuple[dict[str, Any], Path | None]:
    rtl = workspace / REQUIRED_RTL
    if not rtl.is_file() or rtl.is_symlink():
        return _stage("scope", "fail", None, None, "required RTL is missing or is a symlink"), None
    rtl_files = sorted(
        path.relative_to(workspace).as_posix()
        for path in (workspace / "rtl").rglob("*")
        if path.is_file() or path.is_symlink()
    )
    if rtl_files != [REQUIRED_RTL.as_posix()]:
        return _stage("scope", "fail", None, None, f"unexpected RTL scope: {rtl_files}"), None
    if rtl.stat().st_size > 65536:
        return _stage("scope", "fail", None, None, "submission exceeds 65536 bytes"), None
    return _stage("scope", "pass", 0, None, "exact one-file scope"), rtl


def _compile(
    *,
    stage_id: str,
    iverilog: str,
    top: str,
    sources: list[Path],
    image: Path,
    output_dir: Path,
    timeout: int,
) -> tuple[dict[str, Any], bool]:
    state, code, output = _run(
        [iverilog, "-g2012", "-s", top, "-o", str(image), *(str(path) for path in sources)],
        timeout=timeout,
    )
    log_path = _write_log(output_dir, f"{stage_id}.log", output)
    if state != "complete":
        return _stage(stage_id, state, code, log_path, None), False
    status = "pass" if code == 0 else "fail"
    return _stage(stage_id, status, code, log_path, None), code == 0


def _simulate(
    *,
    stage_id: str,
    vvp: str,
    image: Path,
    sentinel_key: str,
    output_dir: Path,
    timeout: int,
    verdict_module: Any,
) -> tuple[dict[str, Any], int]:
    state, code, output = _run([vvp, str(image)], timeout=timeout)
    log_path = _write_log(output_dir, f"{stage_id}.log", output)
    if state != "complete":
        return _stage(stage_id, state, code, log_path, None), 0
    count = verdict_module.exact_sentinel_count(
        output, verdict_module.PASS_SENTINELS[sentinel_key]
    )
    passed = verdict_module.simulation_passes(output, sentinel_key, code or 0)
    return _stage(stage_id, "pass" if passed else "fail", code, log_path, None), count


def run_visible(
    *, workspace: Path, output_dir: Path, iverilog: str, vvp: str, timeout: int
) -> dict[str, Any]:
    if output_dir.exists() and any(output_dir.iterdir()):
        raise FileExistsError(f"refusing non-empty output directory: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)
    workspace = workspace.resolve()
    stages: list[dict[str, Any]] = []
    compile_calls = 0
    simulation_calls = 0
    sentinel_count = 0
    invalid_rejected = False
    verdict_module = _load_verdict()

    scope, rtl = _scope_stage(workspace)
    stages.append(scope)
    if rtl is not None:
        cases = (
            ("requesters_4", "g02_visible_tb", HERE / "g02_visible_tb.sv"),
            ("requesters_1", "g02_singleton_tb", HERE / "g02_singleton_tb.sv"),
        )
        for key, top, tb in cases:
            image = output_dir / f"{key}.vvp"
            compile_stage, compiled = _compile(
                stage_id=f"compile_{key}", iverilog=iverilog, top=top,
                sources=[rtl, tb], image=image, output_dir=output_dir, timeout=timeout,
            )
            compile_calls += 1
            stages.append(compile_stage)
            if not compiled:
                break
            simulation_stage, count = _simulate(
                stage_id=f"simulate_{key}", vvp=vvp, image=image,
                sentinel_key=key, output_dir=output_dir, timeout=timeout,
                verdict_module=verdict_module,
            )
            simulation_calls += 1
            sentinel_count += count
            stages.append(simulation_stage)
            if simulation_stage["status"] != "pass":
                break

        if all(stage["status"] == "pass" for stage in stages):
            probe_image = output_dir / "parameter_probe.vvp"
            probe_stage, _ = _compile(
                stage_id="compile_parameter_probe", iverilog=iverilog,
                top="g02_compile_probe", sources=[rtl, HERE / "g02_visible_tb.sv"],
                image=probe_image, output_dir=output_dir, timeout=timeout,
            )
            compile_calls += 1
            stages.append(probe_stage)

        if all(stage["status"] == "pass" for stage in stages):
            invalid_image = output_dir / "invalid_parameter.vvp"
            state, code, output = _run(
                [iverilog, "-g2012", "-s", "g02_invalid_parameter_probe", "-o", str(invalid_image), str(rtl), str(HERE / "g02_invalid_parameter_probe.sv")],
                timeout=timeout,
            )
            compile_calls += 1
            compile_log = _write_log(output_dir, "compile_invalid_parameter.log", output)
            if state != "complete":
                stages.append(_stage("invalid_parameter_rejection", state, code, compile_log, None))
            elif code != 0:
                invalid_rejected = True
                stages.append(_stage("invalid_parameter_rejection", "pass", code, compile_log, "rejected during compile/elaboration"))
            else:
                state, code, output = _run([vvp, str(invalid_image)], timeout=timeout)
                simulation_calls += 1
                run_log = _write_log(output_dir, "simulate_invalid_parameter.log", output)
                invalid_rejected = state == "complete" and code not in (None, 0)
                status = "pass" if invalid_rejected else (state if state != "complete" else "fail")
                stages.append(_stage("invalid_parameter_rejection", status, code, run_log, "rejected at time zero" if invalid_rejected else "illegal instance ran successfully"))

    verdict = verdict_module.canonical_verdict(stages)
    visible_pass = verdict == "pass"
    result = {
        "schema_version": "rtlflowbench.g02_visible_result.v1",
        "task_id": TASK_ID,
        "status": "complete" if visible_pass else "failed",
        "verdict": verdict,
        "visible_pass": visible_pass,
        "score_eligible": False,
        "submission_sha256": _sha256(rtl) if rtl is not None else None,
        "stages": stages,
        "raw_metrics": {
            "compile_calls": compile_calls,
            "simulation_calls": simulation_calls,
            "visible_sentinel_count": sentinel_count,
            "invalid_parameter_rejected": invalid_rejected,
        },
        "excluded_claims": [
            "Visible PASS is not hidden, formal, benchmark, adapter, PPA, or performance PASS.",
            "The development runner and environment are not frozen."
        ],
    }
    (output_dir / "result.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--iverilog", default="iverilog")
    parser.add_argument("--vvp", default="vvp")
    parser.add_argument("--timeout-seconds", type=int, default=30)
    args = parser.parse_args()
    try:
        result = run_visible(
            workspace=args.workspace, output_dir=args.output_dir,
            iverilog=args.iverilog, vvp=args.vvp, timeout=args.timeout_seconds,
        )
    except Exception as exc:
        print(json.dumps({"status": "infra_error", "error": f"{type(exc).__name__}: {exc}"}, sort_keys=True))
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["visible_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
