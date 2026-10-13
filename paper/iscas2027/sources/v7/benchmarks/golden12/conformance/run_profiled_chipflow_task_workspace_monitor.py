#!/usr/bin/env python3
"""Run a public visible runner in an offline, profile-bound task workspace."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import signal
import subprocess
import sys
import time
from types import ModuleType
from typing import Any

from jsonschema import Draft202012Validator


MONITOR_ID = "rtlflowbench.profiled_bwrap_strace_monitor.v1"
BASE_MONITOR = (
    Path(__file__).resolve().parent
    / "run_chipflow_task_workspace_monitor.py"
)
PROFILE_SCHEMA = (
    Path(__file__).resolve().parent
    / "task_workspace_monitor_profile.schema.json"
)


def _load_module(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load monitor support module: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _load_object(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"not a regular JSON file: {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain one JSON object")
    return value


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_new_json(path: Path, value: Any) -> None:
    if path.exists() or path.is_symlink():
        raise FileExistsError(f"refusing to overwrite output: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    if temporary.exists() or temporary.is_symlink():
        raise FileExistsError(f"temporary output already exists: {temporary}")
    temporary.write_text(
        json.dumps(
            value,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def _safe_relative(value: str) -> Path:
    pure = PurePosixPath(value)
    if pure.is_absolute() or not pure.parts or ".." in pure.parts:
        raise ValueError(f"unsafe profiled workspace path: {value}")
    return Path(*pure.parts)


def _safe_directory(
    run_root: Path,
    candidate: Path,
    *,
    label: str,
    must_exist: bool,
) -> Path:
    if candidate.is_symlink():
        raise ValueError(f"{label} must not be a symlink")
    resolved = candidate.expanduser().resolve()
    if not resolved.is_relative_to(run_root):
        raise ValueError(f"{label} escaped the ChipFlow run root")
    if must_exist and not resolved.is_dir():
        raise ValueError(f"{label} is not a directory")
    current = run_root
    for part in resolved.relative_to(run_root).parts:
        current = current / part
        if current.is_symlink():
            raise ValueError(f"{label} contains a symlink component")
    return resolved


def _copy_view(
    *,
    workspace: Path,
    destination: Path,
    relative_paths: list[str],
) -> list[dict[str, Any]]:
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(f"profiled view already exists: {destination}")
    destination.mkdir(parents=True)
    manifest: list[dict[str, Any]] = []
    for value in relative_paths:
        relative = _safe_relative(value)
        source = workspace / relative
        if source.is_symlink() or not source.is_file():
            raise ValueError(f"profiled workspace file is missing: {value}")
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        target.chmod(0o444)
        manifest.append(
            {
                "path": relative.as_posix(),
                "sha256": _sha256(target),
                "bytes": target.stat().st_size,
            }
        )
    for directory in sorted(
        (path for path in destination.rglob("*") if path.is_dir()),
        reverse=True,
    ):
        directory.chmod(0o555)
    destination.chmod(0o555)
    return manifest


def _terminate_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=2)


def _render_runner_argv(
    profile: dict[str, Any],
    *,
    command_timeout_seconds: int,
    tool_bindings: list[dict[str, Any]] | None = None,
) -> list[str]:
    substitutions = {
        "visible": "/visible",
        "repository": "/repository",
        "submission": "/submission",
        "output": "/output",
        "runner_output": "/output/runner",
        "iverilog": "/usr/bin/iverilog",
        "vvp": "/usr/bin/vvp",
        "python": "/usr/bin/python3",
        "command_timeout_seconds": str(command_timeout_seconds),
    }
    for binding in tool_bindings or []:
        name = str(binding["name"])
        if name in substitutions:
            raise ValueError(
                f"tool requirement uses reserved placeholder: {name}"
            )
        substitutions[name] = str(binding["sandbox_executable"])
    rendered = []
    for token in profile["runner_argv"]:
        try:
            value = token.format_map(substitutions)
        except KeyError as exc:
            raise ValueError(
                f"unknown runner_argv placeholder: {exc.args[0]}"
            ) from exc
        if not value:
            raise ValueError("runner_argv rendered an empty token")
        rendered.append(value)
    return rendered


def _resolve_tool_bindings(
    profile: dict[str, Any],
    tool_roots: dict[str, Path] | None,
) -> list[dict[str, Any]]:
    requirements = profile.get("tool_requirements") or []
    if not isinstance(requirements, list):
        raise ValueError("tool_requirements must be a list")
    provided = dict(tool_roots or {})
    names = [str(item.get("name") or "") for item in requirements]
    if len(names) != len(set(names)):
        raise ValueError("tool requirement names must be unique")
    if set(provided) != set(names):
        raise ValueError(
            "provided tool roots do not match profile requirements: "
            f"required={sorted(names)}, provided={sorted(provided)}"
        )
    bindings: list[dict[str, Any]] = []
    for requirement in requirements:
        name = str(requirement["name"])
        host_root = provided[name].expanduser().resolve(strict=True)
        if host_root.is_symlink() or not host_root.is_dir():
            raise ValueError(
                f"tool root must be a regular directory: {name}"
            )
        executable_relative = _safe_relative(
            str(requirement["executable"])
        )
        host_executable = host_root / executable_relative
        if (
            host_executable.is_symlink()
            or not host_executable.is_file()
            or not os.access(host_executable, os.X_OK)
        ):
            raise ValueError(
                f"tool executable is unavailable: {name}"
            )
        sandbox_root = Path(
            f"/opt/rtlflowbench-tools/{name}"
        )
        environment: dict[str, str] = {}
        for variable, relative_value in (
            requirement["environment_relative_paths"].items()
        ):
            relative = _safe_relative(str(relative_value))
            host_value = host_root / relative
            if (
                host_value.is_symlink()
                or not host_value.exists()
            ):
                raise ValueError(
                    f"tool environment path is unavailable: "
                    f"{name}:{variable}"
                )
            environment[str(variable)] = str(
                sandbox_root / relative
            )
        bindings.append(
            {
                "name": name,
                "host_root": host_root,
                "sandbox_root": sandbox_root,
                "host_executable": host_executable,
                "sandbox_executable": (
                    sandbox_root / executable_relative
                ),
                "executable_sha256": _sha256(host_executable),
                "environment": environment,
            }
        )
    return bindings


def _build_bwrap_argv(
    *,
    bwrap: Path,
    visible_root: Path,
    repository_view: Path,
    submission_view: Path,
    output_root: Path,
    runner_argv: list[str],
    tool_bindings: list[dict[str, Any]] | None = None,
) -> list[str]:
    tool_mounts: list[str] = []
    tool_environment: list[str] = []
    if tool_bindings:
        tool_mounts.extend(
            [
                "--dir",
                "/opt",
                "--dir",
                "/opt/rtlflowbench-tools",
            ]
        )
        for binding in tool_bindings:
            sandbox_root = str(binding["sandbox_root"])
            tool_mounts.extend(
                [
                    "--dir",
                    sandbox_root,
                    "--ro-bind",
                    str(binding["host_root"]),
                    sandbox_root,
                ]
            )
            for variable, value in sorted(
                binding["environment"].items()
            ):
                tool_environment.extend(
                    ["--setenv", variable, value]
                )
    return [
        str(bwrap),
        "--die-with-parent",
        "--new-session",
        "--unshare-all",
        "--ro-bind",
        "/usr",
        "/usr",
        "--symlink",
        "usr/bin",
        "/bin",
        "--symlink",
        "usr/lib",
        "/lib",
        "--symlink",
        "usr/lib64",
        "/lib64",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
        "--dir",
        "/visible",
        "--ro-bind",
        str(visible_root),
        "/visible",
        "--dir",
        "/repository",
        "--ro-bind",
        str(repository_view),
        "/repository",
        "--dir",
        "/submission",
        "--ro-bind",
        str(submission_view),
        "/submission",
        "--dir",
        "/output",
        "--bind",
        str(output_root),
        "/output",
        *tool_mounts,
        "--clearenv",
        "--setenv",
        "PATH",
        "/usr/bin:/bin",
        "--setenv",
        "LANG",
        "C.UTF-8",
        "--setenv",
        "LC_ALL",
        "C.UTF-8",
        "--setenv",
        "HOME",
        "/tmp",
        *tool_environment,
        "--chdir",
        "/submission",
        *runner_argv,
    ]


def run_profiled_visible_suite(
    *,
    chipflow_run_id: str,
    run_root: Path,
    workspace: Path,
    repository_baseline: Path | None = None,
    visible_root: Path,
    profile_path: Path,
    output_root: Path,
    monitor_root: Path,
    receipt_output: Path,
    timeout_seconds: int,
    command_timeout_seconds: int,
    tool_roots: dict[str, Path] | None = None,
) -> dict[str, Any]:
    if not chipflow_run_id.strip():
        raise ValueError("chipflow_run_id must be non-empty")
    if not 1 <= timeout_seconds <= 900:
        raise ValueError("timeout_seconds must be in [1, 900]")
    if not 1 <= command_timeout_seconds <= 300:
        raise ValueError("command_timeout_seconds must be in [1, 300]")
    base = _load_module(
        BASE_MONITOR,
        "rtlflowbench_base_task_workspace_monitor",
    )
    profile = _load_object(profile_path.expanduser().resolve(strict=True))
    schema = _load_object(PROFILE_SCHEMA)
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(profile)
    tool_bindings = _resolve_tool_bindings(
        profile,
        tool_roots,
    )
    run_root = run_root.expanduser().resolve(strict=True)
    if run_root.is_symlink() or not run_root.is_dir():
        raise ValueError("run_root must be a regular directory")
    workspace = _safe_directory(
        run_root,
        workspace,
        label="task workspace",
        must_exist=True,
    )
    repository_source = (
        workspace
        if repository_baseline is None
        else _safe_directory(
            run_root,
            repository_baseline,
            label="repository baseline",
            must_exist=True,
        )
    )
    repository_source_kind = (
        "workspace"
        if repository_baseline is None
        else "separate_baseline"
    )
    visible_root = _safe_directory(
        run_root,
        visible_root,
        label="public visible root",
        must_exist=True,
    )
    output_root = _safe_directory(
        run_root,
        output_root,
        label="visible output root",
        must_exist=False,
    )
    monitor_root = _safe_directory(
        run_root,
        monitor_root,
        label="monitor output root",
        must_exist=False,
    )
    receipt_output = receipt_output.expanduser().resolve()
    if not receipt_output.is_relative_to(run_root):
        raise ValueError("monitor receipt escaped the run root")
    for relative in profile["required_public_assets"]:
        source = visible_root / _safe_relative(relative)
        if source.is_symlink() or not source.is_file():
            raise ValueError(f"public visible asset is missing: {relative}")
    prior_attempt_archive = base._archive_previous_attempt_outputs(
        run_root=run_root,
        output_root=output_root,
        monitor_root=monitor_root,
        receipt_output=receipt_output,
    )
    if (
        output_root.exists()
        or monitor_root.exists()
        or receipt_output.exists()
        or receipt_output.is_symlink()
    ):
        raise FileExistsError("profiled monitor outputs must be new")
    bwrap = shutil.which("bwrap")
    strace = shutil.which("strace")
    if bwrap is None or strace is None:
        raise RuntimeError("bubblewrap and strace are both required")
    output_root.mkdir(parents=True)
    monitor_root.mkdir(parents=True)
    repository_view = monitor_root / "repository_view"
    submission_view = monitor_root / "submission_view"
    repository_manifest = _copy_view(
        workspace=repository_source,
        destination=repository_view,
        relative_paths=profile["repository_files"],
    )
    submission_manifest = _copy_view(
        workspace=workspace,
        destination=submission_view,
        relative_paths=profile["submission_files"],
    )
    runner_argv = _render_runner_argv(
        profile,
        command_timeout_seconds=command_timeout_seconds,
        tool_bindings=tool_bindings,
    )
    bwrap_argv = _build_bwrap_argv(
        bwrap=Path(bwrap).resolve(),
        visible_root=visible_root,
        repository_view=repository_view,
        submission_view=submission_view,
        output_root=output_root,
        runner_argv=runner_argv,
        tool_bindings=tool_bindings,
    )
    trace_prefix = monitor_root / "exec"
    invocation = [
        str(Path(strace).resolve()),
        "-ff",
        "-qq",
        "-ttt",
        "-s",
        "4096",
        "-e",
        "trace=process,network",
        "-o",
        str(trace_prefix),
        *bwrap_argv,
    ]
    _write_new_json(
        monitor_root / "invocation.json",
        {
            "monitor_id": MONITOR_ID,
            "argv": invocation,
            "timeout_seconds": timeout_seconds,
            "profile_sha256": _sha256(profile_path),
            "repository_source": {
                "kind": repository_source_kind,
                "path": str(repository_source.relative_to(run_root)),
            },
            "repository_manifest": repository_manifest,
            "submission_manifest": submission_manifest,
            "tool_bindings": [
                {
                    "name": binding["name"],
                    "host_root": str(binding["host_root"]),
                    "sandbox_root": str(binding["sandbox_root"]),
                    "host_executable": str(
                        binding["host_executable"]
                    ),
                    "sandbox_executable": str(
                        binding["sandbox_executable"]
                    ),
                    "executable_sha256": binding[
                        "executable_sha256"
                    ],
                    "environment": binding["environment"],
                }
                for binding in tool_bindings
            ],
        },
    )
    timed_out = False
    started = time.monotonic()
    with (
        (monitor_root / "stdout.log").open("wb") as stdout,
        (monitor_root / "stderr.log").open("wb") as stderr,
    ):
        process = subprocess.Popen(
            invocation,
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr,
            start_new_session=True,
            env={
                "PATH": os.environ.get("PATH", ""),
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
            },
        )
        try:
            returncode = process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
            _terminate_group(process)
            returncode = None
    trace_files = sorted(monitor_root.glob("exec.*"))
    if not trace_files:
        raise RuntimeError("strace did not produce monitor evidence")
    observed = base.parse_trace_files(trace_files)
    result_path = output_root / _safe_relative(profile["result_filename"])
    visible_result: dict[str, Any] | None = None
    if result_path.is_file() and not result_path.is_symlink():
        value = json.loads(result_path.read_text(encoding="utf-8"))
        if isinstance(value, dict):
            visible_result = value
    if visible_result is not None:
        _write_new_json(
            run_root / "raw_eda_results.json",
            base._raw_eda_results(visible_result),
        )
    suite_id = profile["suite_id"]
    visible_pass = bool(
        not timed_out
        and returncode == 0
        and visible_result is not None
        and visible_result.get("task_id") == profile["task_id"]
        and (
            suite_id is None
            or visible_result.get("suite_id") == suite_id
        )
        and visible_result.get("verdict") == "pass"
        and visible_result.get("pass") is True
    )
    monitor_pass = bool(
        observed["network_attempt_count"] == 0
        and observed["supervisor_exec_count"] == 1
        and observed["process_count"] > 0
    )
    receipt = {
        "schema_version": (
            "rtlflowbench.chipflow_task_workspace_monitor.v1"
        ),
        "chipflow_run_id": chipflow_run_id,
        "monitoring_complete": True,
        "network_isolation_enforced": True,
        "network_access_observed": (
            observed["network_attempt_count"] > 0
        ),
        "network_attempt_count": observed["network_attempt_count"],
        "monitor_backend": MONITOR_ID,
        "eda_calls": observed["eda_calls"],
        "observed_commands": observed["observed_commands"],
    }
    _write_new_json(receipt_output, receipt)
    _write_new_json(
        monitor_root / "monitor_summary.json",
        {
            **observed,
            "monitor_id": MONITOR_ID,
            "monitor_source_sha256": _sha256(Path(__file__).resolve()),
            "base_monitor_source_sha256": _sha256(BASE_MONITOR),
            "profile_sha256": _sha256(profile_path),
            "repository_source": {
                "kind": repository_source_kind,
                "path": str(repository_source.relative_to(run_root)),
                "manifest": repository_manifest,
            },
            "tool_bindings": [
                {
                    "name": binding["name"],
                    "host_root": str(binding["host_root"]),
                    "sandbox_root": str(binding["sandbox_root"]),
                    "executable_sha256": binding[
                        "executable_sha256"
                    ],
                    "environment": binding["environment"],
                }
                for binding in tool_bindings
            ],
            "bwrap_sha256": _sha256(Path(bwrap)),
            "strace_sha256": _sha256(Path(strace)),
            "timed_out": timed_out,
            "workflow_exit_code": returncode,
            "wall_time_seconds": round(
                time.monotonic() - started,
                6,
            ),
            "visible_result_path": str(
                result_path.relative_to(run_root)
            ),
            "visible_result_sha256": (
                _sha256(result_path)
                if visible_result is not None
                else None
            ),
            "visible_pass": visible_pass,
            "monitor_pass": monitor_pass,
            "prior_attempt_archive": prior_attempt_archive,
        },
    )
    if visible_result is not None:
        print(json.dumps(visible_result, indent=2, sort_keys=True))
    if visible_pass and monitor_pass:
        print(profile["pass_sentinel"])
    return {
        "status": "pass" if visible_pass and monitor_pass else "fail",
        "visible_pass": visible_pass,
        "monitor_pass": monitor_pass,
        "receipt": receipt,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--chipflow-run-id", required=True)
    parser.add_argument("--run-root", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument(
        "--repository-baseline",
        type=Path,
        help=(
            "Optional immutable repository source inside run-root. "
            "Repository files are copied from this baseline while submission "
            "files remain copied from --workspace."
        ),
    )
    parser.add_argument("--visible-root", type=Path, required=True)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--monitor-root", type=Path, required=True)
    parser.add_argument("--receipt-output", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=300)
    parser.add_argument(
        "--command-timeout-seconds",
        type=int,
        default=30,
    )
    parser.add_argument(
        "--tool-root",
        action="append",
        default=[],
        metavar="NAME=PATH",
    )
    args = parser.parse_args()
    tool_roots: dict[str, Path] = {}
    for item in args.tool_root:
        name, separator, value = item.partition("=")
        if (
            not separator
            or not name
            or not value
            or name in tool_roots
        ):
            raise ValueError(
                "--tool-root requires unique NAME=PATH values"
            )
        tool_roots[name] = Path(value)
    try:
        result = run_profiled_visible_suite(
            chipflow_run_id=args.chipflow_run_id,
            run_root=args.run_root,
            workspace=args.workspace,
            repository_baseline=args.repository_baseline,
            visible_root=args.visible_root,
            profile_path=args.profile,
            output_root=args.output_root,
            monitor_root=args.monitor_root,
            receipt_output=args.receipt_output,
            timeout_seconds=args.timeout_seconds,
            command_timeout_seconds=args.command_timeout_seconds,
            tool_roots=tool_roots,
        )
    except Exception as exc:
        print(
            json.dumps(
                {
                    "status": "infra_error",
                    "verdict": "infra_error",
                    "error": f"{type(exc).__name__}: {exc}",
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 2
    return 0 if result["status"] == "pass" else 2


if __name__ == "__main__":
    raise SystemExit(main())
