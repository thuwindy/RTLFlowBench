"""Normalize one protected, post-trace cgroup snapshot without rereading files."""

import hashlib
import json
import re
import os
from pathlib import Path
import tempfile


def digest(data):
    return hashlib.sha256(data).hexdigest()


def document(data):
    if not isinstance(data, bytes) or len(data) > 65536:
        raise ValueError("invalid_document_bytes")

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate_json_key")
            result[key] = value
        return result

    def invalid(_):
        raise ValueError("nonfinite_json")

    value = json.loads(data, object_pairs_hook=pairs, parse_constant=invalid)
    if not isinstance(value, dict):
        raise ValueError("document_object_required")
    return value


def kernel_integer(text, *, positive=False):
    if (
        not isinstance(text, str)
        or len(text) > 64
        or not re.fullmatch(r"[0-9]+\n?", text)
    ):
        raise ValueError("invalid_kernel_counter")
    value = int(text)
    if positive and value == 0:
        raise ValueError("empty_terminal_cgroup")
    return value


def normalize(raw):
    if not isinstance(raw, dict) or set(raw) != {
        "cpu.stat",
        "memory.peak",
        "pids.peak",
    }:
        raise ValueError("incomplete_terminal_cgroup")
    text = raw["cpu.stat"]
    if not isinstance(text, str) or len(text) > 8192:
        raise ValueError("invalid_cpu_stat")
    counters = {}
    for line in text.splitlines():
        found = re.fullmatch(r"([a-z][a-z_.]*) ([0-9]+)", line)
        if not found or found[1] in counters:
            raise ValueError("invalid_cpu_stat")
        counters[found[1]] = int(found[2])
    if "usage_usec" not in counters:
        raise ValueError("cpu_usage_missing")
    return {
        "terminal_container_cpu_usage_usec": counters["usage_usec"],
        "terminal_container_cpu_seconds": counters["usage_usec"] / 1_000_000,
        "terminal_container_memory_peak_bytes": kernel_integer(
            raw["memory.peak"], positive=True
        ),
        "terminal_container_pids_peak": kernel_integer(raw["pids.peak"], positive=True),
    }


def save_new_atomic(path, value):
    """Publish a complete receipt without replacing an existing receipt."""
    path = Path(path)
    parent = path.parent
    if (
        parent.is_symlink()
        or not parent.is_dir()
        or parent.stat().st_uid != os.geteuid()
        or parent.stat().st_mode & 0o077
    ):
        raise ValueError("private_owned_receipt_directory_required")
    data = (json.dumps(value, sort_keys=True, allow_nan=False) + "\n").encode()
    if len(data) > 65536:
        raise ValueError("receipt_too_large")
    fd, name = tempfile.mkstemp(prefix=".pending-", dir=parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def verify_chain(
    *,
    terminal_bytes,
    snapshot_bytes,
    release_bytes,
    released_bytes,
    expected_native_request_sha256,
    expected_supervisor_request_sha256,
):
    """Content/order consistency only; caller still proves mount/UID isolation."""
    terminal = document(terminal_bytes)
    snapshot = document(snapshot_bytes)
    release = document(release_bytes)
    released = document(released_bytes)
    for expected in [
        expected_native_request_sha256,
        expected_supervisor_request_sha256,
    ]:
        if (
            not isinstance(expected, str)
            or re.fullmatch(r"[0-9a-f]{64}", expected) is None
        ):
            raise ValueError("invalid_request_digest")
    if (
        terminal.get("schema_version") != "chipflow.protected_collector_terminal.v1"
        or type(terminal.get("exit_code")) is not int
    ):
        raise ValueError("invalid_terminal")
    if snapshot.get("schema_version") != "chipflow.protected_terminal_resources.v1":
        raise ValueError("invalid_snapshot")
    if (
        terminal.get("request_sha256") != expected_supervisor_request_sha256
        or snapshot.get("native_request_sha256") != expected_native_request_sha256
        or snapshot.get("supervisor_request_sha256")
        != expected_supervisor_request_sha256
        or released.get("request_sha256") != expected_supervisor_request_sha256
    ):
        raise ValueError("request_binding_drift")
    if (
        snapshot.get("terminal_sha256") != digest(terminal_bytes)
        or release.get("terminal_sha256") != digest(terminal_bytes)
        or release.get("terminal_resources_sha256") != digest(snapshot_bytes)
        or released.get("release_sha256") != digest(release_bytes)
    ):
        raise ValueError("terminal_chain_hash_drift")
    if (
        snapshot.get("snapshot_before_release") is not True
        or release.get("terminal_resources_recorded") is not True
    ):
        raise ValueError("terminal_snapshot_not_acknowledged")
    start, end = (
        snapshot.get("sample_start_monotonic_ns"),
        snapshot.get("sample_end_monotonic_ns"),
    )
    if type(start) is not int or type(end) is not int or start <= 0 or end < start:
        raise ValueError("invalid_snapshot_interval")
    metrics = normalize(snapshot.get("raw_cgroup"))
    if any(
        type(snapshot.get(key)) is not type(value) or snapshot[key] != value
        for key, value in metrics.items()
    ):
        raise ValueError("normalized_counter_drift")
    if snapshot.get("canonical_resource_chain") is not False:
        raise ValueError("unsupported_completeness_claim")
    return {
        "schema_version": "chipflow.protected_terminal_resource_chain.v1",
        "status": "bound_terminal_snapshot",
        "terminal_exit_code": terminal["exit_code"],
        "metrics": metrics,
        "terminal_sha256": digest(terminal_bytes),
        "snapshot_sha256": digest(snapshot_bytes),
        "release_sha256": digest(release_bytes),
        "released_sha256": digest(released_bytes),
        "canonical_resource_chain": False,
        "neutral_export_eligible": False,
        "benchmark_verdict": None,
        "scope": "container through terminal snapshot; includes collector overhead and excludes release/teardown; not workload-only CPU",
    }
