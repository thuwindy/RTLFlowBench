#!/usr/bin/env python3
"""Measure one neutral workflow launcher without producing an RTL verdict.

This envelope samples a launched process tree and an isolated scratch root. It
does not infer provider or EDA concurrency, enforce the benchmark network
policy, invoke a private evaluator, or classify RTL correctness. Those missing
signals stay null until independently bound telemetry is supplied.
"""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import resource
import signal
import stat
import subprocess
import threading
import time
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


HERE = Path(__file__).resolve().parent
REQUEST_SCHEMA = HERE / "workflow_resource_measurement_request.schema.json"
RECEIPT_SCHEMA = HERE / "workflow_resource_measurement_receipt.schema.json"
RUNNER_ID = "rtlflowbench.workflow_resource_measurement_envelope.v1"
PAGE_SIZE = os.sysconf("SC_PAGE_SIZE")
PODMAN_REQUIRED_PREFIX = {
    "run",
    "--rm",
    "--pull=never",
    "--network=none",
    "--read-only",
    "--cap-drop=all",
    "--security-opt=no-new-privileges",
    "--entrypoint=/bin/sh",
    "--workdir=/work",
    "--volume=.:/work:rw",
}


def _load(path: Path, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a regular non-symlink file")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{label} must contain one JSON object")
    return value


def _sha(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"expected regular non-symlink file: {path}")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_new(path: Path, value: Any) -> None:
    if path.exists() or path.is_symlink():
        raise FileExistsError(f"refusing to overwrite: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def _empty_root(path: Path, label: str) -> Path:
    if path.is_symlink():
        raise ValueError(f"{label} must not be a symlink")
    path = path.expanduser().resolve()
    if path.exists():
        if not path.is_dir() or any(path.iterdir()):
            raise ValueError(f"{label} must be an empty directory")
    else:
        path.mkdir(parents=True)
    return path


def _safe_relative(path: str) -> PurePosixPath:
    relative = PurePosixPath(path)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("working_directory must be a safe relative path")
    return relative


def _regular_executable(path: str, expected_sha256: str) -> Path:
    executable = Path(path)
    if not executable.is_absolute() or executable.is_symlink():
        raise ValueError("launcher executable must be an absolute regular file")
    executable = executable.resolve(strict=True)
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise ValueError("launcher executable is unavailable or not executable")
    if _sha(executable) != expected_sha256:
        raise ValueError("launcher executable differs from expected SHA256")
    return executable


def _validate_podman_argv(request: dict[str, Any], executable: Path) -> int:
    if executable.name != "podman":
        raise ValueError("v1 launcher executable must be named podman")
    image_index = request["runtime_image_argv_index"]
    argv = request["argv"]
    if image_index >= len(argv) - 1:
        raise ValueError("runtime image must be followed by a container command")
    if argv[image_index] != request["runtime_binding"]["image_id"]:
        raise ValueError("runtime image argument differs from the bound image ID")
    prefix = argv[1:image_index]
    pids_limits = [value for value in prefix if value.startswith("--pids-limit=")]
    if len(pids_limits) != 1:
        raise ValueError("exactly one pids limit is required")
    try:
        pids_limit = int(pids_limits[0].split("=", 1)[1])
    except ValueError as exc:
        raise ValueError("pids limit must be an integer") from exc
    if not 2 <= pids_limit <= 4096:
        raise ValueError("pids limit must be in the closed interval [2, 4096]")
    names = [value for value in prefix if value.startswith("--name=")]
    expected_name = f"--name={request['measurement_id']}"
    if names != [expected_name]:
        raise ValueError("podman container name must equal the measurement ID")
    if len(prefix) != len(PODMAN_REQUIRED_PREFIX) + 2:
        raise ValueError("podman prefix contains missing, duplicate, or extra options")
    if set(prefix) - {pids_limits[0], expected_name} != PODMAN_REQUIRED_PREFIX:
        raise ValueError("podman prefix does not match the safe offline profile")
    return image_index


def _proc_children(pid: int) -> list[int]:
    path = Path(f"/proc/{pid}/task/{pid}/children")
    try:
        return [int(value) for value in path.read_text().split()]
    except (FileNotFoundError, PermissionError, ProcessLookupError, ValueError):
        return []


def _process_tree(root_pid: int) -> set[int]:
    observed: set[int] = set()
    pending = [root_pid]
    while pending:
        pid = pending.pop()
        if pid in observed:
            continue
        observed.add(pid)
        pending.extend(_proc_children(pid))
    return observed


def _rss_bytes(pid: int) -> int:
    try:
        fields = Path(f"/proc/{pid}/statm").read_text().split()
        return int(fields[1]) * PAGE_SIZE
    except (FileNotFoundError, PermissionError, ProcessLookupError, ValueError, IndexError):
        return 0


def _scratch_usage(root: Path) -> tuple[int, bool]:
    total = 0
    valid = True
    for path in root.rglob("*"):
        try:
            metadata = path.lstat()
            mode = metadata.st_mode
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(mode) or not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
            valid = False
            continue
        if stat.S_ISREG(mode):
            total += metadata.st_size
    return total, valid


def _resolve_container_cgroup(
    *, podman: Path, container_name: str, environment: dict[str, str]
) -> Path | None:
    completed = subprocess.run(
        [str(podman), "inspect", "--format", "{{.State.Pid}}", container_name],
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        timeout=2,
        check=False,
    )
    if completed.returncode != 0:
        return None
    values = completed.stdout.split()
    if len(values) != 1 or not values[0].isdigit() or int(values[0]) <= 1:
        return None
    cgroup_file = Path(f"/proc/{values[0]}/cgroup")
    try:
        relative_rows = [
            line[3:]
            for line in cgroup_file.read_text(encoding="utf-8").splitlines()
            if line.startswith("0::/")
        ]
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        return None
    if len(relative_rows) != 1:
        return None
    cgroup_root = Path("/sys/fs/cgroup").resolve(strict=True)
    try:
        candidate = (cgroup_root / relative_rows[0].lstrip("/")).resolve(strict=True)
    except FileNotFoundError:
        return None
    if not candidate.is_relative_to(cgroup_root):
        return None
    return candidate


def _read_container_cgroup(cgroup: Path) -> tuple[int, float, int]:
    memory_peak = int((cgroup / "memory.peak").read_text(encoding="utf-8").strip())
    pids_peak = int((cgroup / "pids.peak").read_text(encoding="utf-8").strip())
    cpu_rows = {}
    for line in (cgroup / "cpu.stat").read_text(encoding="utf-8").splitlines():
        key, value = line.split()
        cpu_rows[key] = int(value)
    if "usage_usec" not in cpu_rows:
        raise ValueError("cpu.stat lacks usage_usec")
    if memory_peak < 0 or pids_peak < 0 or cpu_rows["usage_usec"] < 0:
        raise ValueError("container cgroup metrics must be non-negative")
    return memory_peak, cpu_rows["usage_usec"] / 1_000_000, pids_peak


class _Sampler:
    def __init__(
        self,
        *,
        root_pid: int,
        scratch_root: Path,
        interval_seconds: float,
        podman: Path,
        container_name: str,
        environment: dict[str, str],
    ):
        self.root_pid = root_pid
        self.scratch_root = scratch_root
        self.interval_seconds = interval_seconds
        self.stop = threading.Event()
        self.sample_count = 0
        self.peak_rss_bytes = 0
        self.peak_process_count = 0
        self.peak_scratch_bytes = 0
        self.scratch_integrity_valid = True
        self.podman = podman
        self.container_name = container_name
        self.environment = environment
        self.container_cgroup: Path | None = None
        self.container_cgroup_sample_count = 0
        self.container_cgroup_lookup_error_count = 0
        self.container_cgroup_read_error_count = 0
        self.peak_container_memory_bytes = 0
        self.container_cpu_time_seconds = 0.0
        self.peak_container_pids = 0
        self.last_cgroup_lookup = 0.0
        self.thread = threading.Thread(target=self._run, daemon=True)

    def _sample(self) -> None:
        pids = _process_tree(self.root_pid)
        self.peak_process_count = max(self.peak_process_count, len(pids))
        self.peak_rss_bytes = max(
            self.peak_rss_bytes,
            sum(_rss_bytes(pid) for pid in pids),
        )
        scratch_bytes, valid = _scratch_usage(self.scratch_root)
        self.peak_scratch_bytes = max(self.peak_scratch_bytes, scratch_bytes)
        self.scratch_integrity_valid = self.scratch_integrity_valid and valid
        if self.container_cgroup is None and time.monotonic() - self.last_cgroup_lookup >= 0.1:
            self.last_cgroup_lookup = time.monotonic()
            try:
                self.container_cgroup = _resolve_container_cgroup(
                    podman=self.podman,
                    container_name=self.container_name,
                    environment=self.environment,
                )
            except (OSError, subprocess.SubprocessError, ValueError):
                self.container_cgroup = None
            if self.container_cgroup is None:
                self.container_cgroup_lookup_error_count += 1
        if self.container_cgroup is not None:
            try:
                memory_peak, cpu_time, pids_peak = _read_container_cgroup(
                    self.container_cgroup
                )
            except (OSError, ValueError):
                self.container_cgroup_read_error_count += 1
            else:
                self.peak_container_memory_bytes = max(
                    self.peak_container_memory_bytes, memory_peak
                )
                self.container_cpu_time_seconds = max(
                    self.container_cpu_time_seconds, cpu_time
                )
                self.peak_container_pids = max(self.peak_container_pids, pids_peak)
                self.container_cgroup_sample_count += 1
        self.sample_count += 1

    def _run(self) -> None:
        while not self.stop.is_set():
            self._sample()
            self.stop.wait(self.interval_seconds)
        self._sample()

    def start(self) -> None:
        self.thread.start()

    def finish(self) -> None:
        self.stop.set()
        self.thread.join(timeout=max(3.0, self.interval_seconds * 4))
        if self.thread.is_alive():
            raise RuntimeError("resource sampler did not stop")


def _cpu_snapshot() -> tuple[float, float]:
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    return usage.ru_utime, usage.ru_stime


def run_measurement(
    *,
    request_path: Path,
    scratch_root: Path,
    output_root: Path,
    observed_at: str,
) -> dict[str, Any]:
    parsed = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("observed_at must include a timezone")
    request_path = request_path.expanduser()
    if request_path.is_symlink():
        raise ValueError("measurement request must not be a symlink")
    request_path = request_path.resolve(strict=True)
    request = _load(request_path, "measurement request")
    request_schema = _load(REQUEST_SCHEMA, "measurement request schema")
    receipt_schema = _load(RECEIPT_SCHEMA, "measurement receipt schema")
    Draft202012Validator.check_schema(request_schema)
    Draft202012Validator.check_schema(receipt_schema)
    Draft202012Validator(request_schema).validate(request)
    executable = _regular_executable(
        request["argv"][0], request["launcher_executable_sha256"]
    )
    image_index = _validate_podman_argv(request, executable)
    scratch_candidate = scratch_root.expanduser().resolve()
    output_candidate_input = output_root.expanduser()
    if output_candidate_input.is_symlink():
        raise ValueError("output root must not be a symlink")
    output_candidate = output_candidate_input.resolve()
    if output_candidate.is_relative_to(scratch_candidate) or scratch_candidate.is_relative_to(
        output_candidate
    ):
        raise ValueError("scratch root and output root must not overlap")
    scratch_root = _empty_root(scratch_root, "scratch root")
    output_root = output_candidate
    if output_root.exists() or output_root.is_symlink():
        raise FileExistsError(f"refusing to overwrite output root: {output_root}")
    output_root.mkdir(parents=True)
    relative_working = _safe_relative(request["working_directory"])
    working = scratch_root / relative_working
    working.mkdir(parents=True, exist_ok=True)
    if not working.resolve().is_relative_to(scratch_root):
        raise ValueError("working directory escapes scratch root")

    argv = [str(executable), *request["argv"][1:]]
    argv_binding = hashlib.sha256(
        json.dumps(argv, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    invocation = {
        "runner_id": RUNNER_ID,
        "argv_sha256": argv_binding,
        "argument_count": len(argv),
        "argv_values_recorded": False,
        "launcher_path_recorded": False,
        "working_directory": relative_working.as_posix(),
        "timeout_seconds": request["timeout_seconds"],
        "sampling_interval_ms": request["sampling_interval_ms"],
        "environment_keys": sorted(
            {"PATH", "LANG", "LC_ALL", *request["inherited_environment_keys"]}
        ),
        "environment_values_recorded": False,
    }
    _write_new(output_root / "invocation.json", invocation)
    environment = {
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }
    for key in request["inherited_environment_keys"]:
        value = os.environ.get(key)
        if not value:
            raise ValueError(f"required launcher environment key is missing: {key}")
        environment[key] = value
    cpu_before = _cpu_snapshot()
    started = time.monotonic()
    timed_out = False
    with (
        (output_root / "stdout.log").open("wb") as stdout,
        (output_root / "stderr.log").open("wb") as stderr,
    ):
        process = subprocess.Popen(
            argv,
            cwd=working,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr,
            start_new_session=True,
        )
        sampler = _Sampler(
            root_pid=process.pid,
            scratch_root=scratch_root,
            interval_seconds=request["sampling_interval_ms"] / 1000,
            podman=executable,
            container_name=request["measurement_id"],
            environment=environment,
        )
        sampler.start()
        try:
            returncode = process.wait(timeout=request["timeout_seconds"])
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=2)
            returncode = None
        finally:
            sampler.finish()
    wall_time = time.monotonic() - started
    cpu_after = _cpu_snapshot()
    user_cpu = max(0.0, cpu_after[0] - cpu_before[0])
    system_cpu = max(0.0, cpu_after[1] - cpu_before[1])
    scope = request["measurement_scope"]
    status = "measurement_timeout" if timed_out else "measurement_completed"
    receipt = {
        "schema_version": "rtlflowbench.workflow_resource_measurement_receipt.v1",
        "observed_at": observed_at,
        "status": status,
        "runner_id": RUNNER_ID,
        "measurement_id": request["measurement_id"],
        "measurement_scope": scope,
        "workflow_slot_id": request["workflow_slot_id"],
        "workflow_id": request["workflow_id"],
        "task_id": request["task_id"],
        "attempt_id": request["attempt_id"],
        "source_binding": request["source_binding"],
        "runtime_binding": request["runtime_binding"],
        "request_sha256": _sha(request_path),
        "runner_sha256": _sha(Path(__file__).resolve()),
        "request_schema_sha256": _sha(REQUEST_SCHEMA),
        "receipt_schema_sha256": _sha(RECEIPT_SCHEMA),
        "launcher": {
            "kind": "podman_oci",
            "executable_sha256": request["launcher_executable_sha256"],
            "exit_code": returncode,
            "timed_out": timed_out,
            "outcome": (
                "timed_out"
                if timed_out
                else "exited_zero"
                if returncode == 0
                else "exited_nonzero"
            ),
            "argv_sha256": argv_binding,
            "argument_count": len(argv),
            "argv_values_recorded": False,
            "launcher_path_recorded": False,
            "runtime_image_argv_index": image_index,
            "runtime_image_binding_enforced_by_measurement_envelope": True,
            "network_policy_declared": request["network_policy"],
            "network_policy_enforced_by_measurement_envelope": True,
        },
        "metrics": {
            "wall_time_seconds": round(wall_time, 6),
            "envelope_child_user_cpu_time_seconds": round(user_cpu, 6),
            "envelope_child_system_cpu_time_seconds": round(system_cpu, 6),
            "envelope_child_cpu_time_seconds": round(user_cpu + system_cpu, 6),
            "peak_launcher_process_tree_rss_bytes": sampler.peak_rss_bytes,
            "peak_launcher_process_tree_count": sampler.peak_process_count,
            "peak_container_cgroup_memory_bytes": sampler.peak_container_memory_bytes,
            "container_cgroup_cpu_time_seconds": round(
                sampler.container_cpu_time_seconds, 6
            ),
            "peak_container_cgroup_pids": sampler.peak_container_pids,
            "container_cgroup_sample_count": sampler.container_cgroup_sample_count,
            "container_cgroup_lookup_error_count": (
                sampler.container_cgroup_lookup_error_count
            ),
            "container_cgroup_read_error_count": (
                sampler.container_cgroup_read_error_count
            ),
            "peak_scratch_bytes": sampler.peak_scratch_bytes,
            "peak_eda_concurrency": None,
            "peak_llm_concurrency": None,
            "forced_eda_activity_closure_count": 0,
            "sample_count": sampler.sample_count,
            "sampling_interval_ms": request["sampling_interval_ms"],
            "scratch_integrity_valid": sampler.scratch_integrity_valid,
        },
        "missing_measurements": [
            "peak_eda_concurrency",
            "peak_llm_concurrency",
        ],
        "raw_evidence": {
            "invocation_sha256": _sha(output_root / "invocation.json"),
            "stdout_sha256": _sha(output_root / "stdout.log"),
            "stderr_sha256": _sha(output_root / "stderr.log"),
            "raw_content_embedded": False,
        },
        "attempt_accounting": {
            "official_attempt_started": False,
            "official_semantic_attempt_consumed": False,
            "resource_calibration_attempt_consumed": scope
            == "full_workflow_calibration",
            "benchmark_result_created": False,
            "private_evaluator_calls": 0,
        },
        "readiness": {
            "launcher_completed_successfully": (
                not timed_out and returncode == 0
            ),
            "process_tree_measurement_complete": (
                not timed_out
                and sampler.sample_count > 0
                and sampler.scratch_integrity_valid
            ),
            "container_cgroup_measurement_complete": (
                not timed_out
                and sampler.container_cgroup_sample_count > 0
                and sampler.peak_container_memory_bytes > 0
                and sampler.peak_container_pids > 0
            ),
            "full_workflow_resource_calibration_eligible": False,
            "host_capacity_policy_derivation_permitted": False,
            "official_attempts_permitted": False,
        },
        "excluded_claims": [
            "This process-tree measurement is not an RTL PASS, FAIL, BLOCK, INFRA verdict, score, or QoR result.",
            "The envelope binds a reviewed Podman executable, exact OCI image ID, and safe offline argument profile but does not observe provider and EDA concurrency.",
            "Missing provider and EDA concurrency remains null and blocks full-workflow resource calibration.",
            "No official Golden-12 attempt is started or consumed, and no private evaluator is invoked.",
        ],
    }
    Draft202012Validator(
        receipt_schema, format_checker=FormatChecker()
    ).validate(receipt)
    _write_new(output_root / "resource-measurement-receipt.json", receipt)
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--scratch-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--observed-at", required=True)
    args = parser.parse_args()
    try:
        receipt = run_measurement(
            request_path=args.request,
            scratch_root=args.scratch_root,
            output_root=args.output_root,
            observed_at=args.observed_at,
        )
    except Exception as exc:
        print(json.dumps({"status": "error", "error_class": type(exc).__name__}))
        return 2
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return (
        0
        if receipt["status"] == "measurement_completed"
        and receipt["launcher"]["outcome"] == "exited_zero"
        else 2
    )


if __name__ == "__main__":
    raise SystemExit(main())
