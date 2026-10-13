#!/usr/bin/env python3
"""Offline EDA broker for the networked MAGE provider control plane.

The provider process can reach an LLM endpoint but cannot execute native EDA.
Its ``iverilog`` and ``vvp`` shims send one strictly validated argv request over
a local Unix socket. This broker snapshots only the provider-owned output tree
and executes the tool in a separate no-network container.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import signal
import socket
import struct
import subprocess
import tempfile
from typing import Any, Callable


REQUEST_SCHEMA_VERSION = "rtlflowbench.mage_eda_request.v1"
RESPONSE_SCHEMA_VERSION = "rtlflowbench.mage_eda_response.v1"
RECEIPT_SCHEMA_VERSION = "rtlflowbench.mage_eda_call_receipt.v1"
PUBLIC_EDA_IMAGE = "localhost/rtlflowbench-protocol-cli"
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
SESSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
TOP_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_$]*$")
DEFINE_RE = re.compile(r"^-D[A-Za-z_][A-Za-z0-9_]*(?:=[A-Za-z0-9_+-]+)?$")
FORBIDDEN_PARTS = {
    "evaluator",
    "golden",
    "hidden",
    "oracle",
    "private",
    "reference",
}
SNAPSHOT_SUFFIXES = {".hex", ".mem", ".sv", ".v", ".vh", ".vvp"}
NO_VALUE_IVERILOG_FLAGS = {
    "-Wall",
    "-Winfloop",
    "-Wno-timescale",
    "-g2012",
}
MAX_REQUEST_BYTES = 1024 * 1024
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_SNAPSHOT_FILES = 64
MAX_SNAPSHOT_BYTES = 16 * 1024 * 1024
MAX_TOOL_OUTPUT_BYTES = 1024 * 1024
CONTROLLER_PROTOCOL_VERSION = "rtlflowbench.observed_controller_transport.v1"


@dataclass(frozen=True)
class ValidatedRequest:
    session_id: str
    tool: str
    cwd_relative: Path
    argv: tuple[str, ...]
    input_relatives: tuple[Path, ...]
    output_relative: Path | None


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical_sha256(value: Any) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _controller_rpc(
    socket_path: Path,
    *,
    session_id: str,
    operation: str,
    invocation_id: str,
    tool: str | None = None,
    outcome: str | None = None,
) -> None:
    request: dict[str, Any] = {
        "schema_version": CONTROLLER_PROTOCOL_VERSION,
        "session_id": session_id,
        "operation": operation,
        "invocation_id": invocation_id,
    }
    if operation == "eda_start":
        request["tool"] = tool
    elif operation == "eda_finish":
        request["outcome"] = outcome
    else:
        raise ValueError("unsupported observed-controller operation")
    payload = json.dumps(
        request, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.settimeout(30)
    try:
        connection.connect(str(socket_path))
        connection.sendall(struct.pack("!I", len(payload)) + payload)
        header = connection.recv(4)
        if len(header) != 4:
            raise RuntimeError("observed controller response header is incomplete")
        size = struct.unpack("!I", header)[0]
        if not 1 <= size <= MAX_RESPONSE_BYTES:
            raise RuntimeError("observed controller response size is invalid")
        chunks = bytearray()
        while len(chunks) < size:
            chunk = connection.recv(size - len(chunks))
            if not chunk:
                raise RuntimeError("observed controller response is incomplete")
            chunks.extend(chunk)
        response = json.loads(chunks.decode("utf-8"))
    finally:
        connection.close()
    if not isinstance(response, dict) or response.get("status") not in {
        "accepted",
        "ok",
    }:
        raise RuntimeError("observed controller rejected the EDA event")


def _safe_relative(value: str, *, label: str) -> Path:
    if not value or "\x00" in value or "\n" in value or "\r" in value:
        raise ValueError(f"{label} is empty or contains control characters")
    pure = PurePosixPath(value)
    if pure.is_absolute() or ".." in pure.parts:
        raise ValueError(f"{label} escapes the control root")
    if any(part.casefold() in FORBIDDEN_PARTS for part in pure.parts):
        raise ValueError(f"{label} uses a forbidden path")
    return Path(*pure.parts)


def _resolve_input(control_root: Path, cwd: Path, value: str) -> Path:
    relative = _safe_relative(value, label="input path")
    combined = Path(os.path.normpath((cwd / relative).as_posix()))
    if combined.is_absolute() or ".." in combined.parts:
        raise ValueError("input path escapes the control root")
    path = control_root / combined
    if path.is_symlink():
        raise ValueError("input path is a symlink")
    if not path.is_file():
        raise ValueError(f"input path is not a regular file: {value}")
    if path.suffix.casefold() not in SNAPSHOT_SUFFIXES:
        raise ValueError(f"unsupported input file type: {value}")
    return combined


def _resolve_output(control_root: Path, cwd: Path, value: str) -> Path | None:
    if value == "/dev/null":
        return None
    if value.startswith("/"):
        raise ValueError("output path must stay under the control root")
    relative = _safe_relative(value, label="output path")
    combined = Path(os.path.normpath((cwd / relative).as_posix()))
    if combined.is_absolute() or ".." in combined.parts:
        raise ValueError("output path escapes the control root")
    target = control_root / combined
    if target.is_symlink() or target.parent.is_symlink():
        raise ValueError("output path cannot use a symlink")
    if not target.parent.is_dir():
        raise ValueError("output parent must already exist")
    if target.suffix.casefold() != ".vvp":
        raise ValueError("output path must name one .vvp artifact")
    return combined


def _validate_iverilog(
    argv: list[str],
    *,
    control_root: Path,
    cwd: Path,
) -> tuple[tuple[Path, ...], Path | None]:
    inputs: list[Path] = []
    output: Path | None = None
    output_seen = False
    index = 0
    while index < len(argv):
        argument = argv[index]
        if argument in NO_VALUE_IVERILOG_FLAGS or DEFINE_RE.fullmatch(argument):
            index += 1
            continue
        if argument == "-t":
            if index + 1 >= len(argv) or argv[index + 1] != "null":
                raise ValueError("unsupported iverilog target")
            index += 2
            continue
        if argument == "-s":
            if index + 1 >= len(argv) or not TOP_RE.fullmatch(argv[index + 1]):
                raise ValueError("unsupported iverilog top identifier")
            index += 2
            continue
        if argument == "-o":
            if output_seen or index + 1 >= len(argv):
                raise ValueError("output option must appear exactly once")
            output = _resolve_output(control_root, cwd, argv[index + 1])
            output_seen = True
            index += 2
            continue
        if argument.startswith("-"):
            raise ValueError(f"unsupported iverilog option: {argument}")
        inputs.append(_resolve_input(control_root, cwd, argument))
        index += 1
    if not output_seen:
        raise ValueError("output option must appear exactly once")
    if not inputs:
        raise ValueError("iverilog requires at least one input")
    return tuple(inputs), output


def _validate_vvp(
    argv: list[str],
    *,
    control_root: Path,
    cwd: Path,
) -> tuple[Path, ...]:
    if len(argv) != 2 or argv[0] not in {"-n", "-N"}:
        raise ValueError("vvp requires exactly one input and -n/-N")
    return (_resolve_input(control_root, cwd, argv[1]),)


def validate_request(
    request: dict[str, Any],
    *,
    expected_session_id: str,
    control_root: Path,
) -> ValidatedRequest:
    if not isinstance(request, dict) or set(request) != {
        "schema_version",
        "session_id",
        "tool",
        "cwd",
        "argv",
    }:
        raise ValueError("request fields are invalid")
    if request["schema_version"] != REQUEST_SCHEMA_VERSION:
        raise ValueError("request schema version is invalid")
    if request["session_id"] != expected_session_id:
        raise ValueError("session id does not match broker")
    if not SESSION_RE.fullmatch(expected_session_id):
        raise ValueError("expected session id is invalid")
    tool = request["tool"]
    if tool not in {"iverilog", "vvp"}:
        raise ValueError(f"unsupported tool: {tool}")
    argv = request["argv"]
    if (
        not isinstance(argv, list)
        or not argv
        or len(argv) > 64
        or any(not isinstance(item, str) or len(item) > 4096 for item in argv)
    ):
        raise ValueError("argv is invalid")
    control_root = control_root.expanduser().resolve(strict=True)
    cwd_value = request["cwd"]
    if not isinstance(cwd_value, str):
        raise ValueError("cwd is invalid")
    cwd = _safe_relative(cwd_value, label="cwd")
    cwd_path = control_root / cwd
    if cwd_path.is_symlink() or not cwd_path.is_dir():
        raise ValueError("cwd is not a regular directory")
    if tool == "iverilog":
        inputs, output = _validate_iverilog(
            argv,
            control_root=control_root,
            cwd=cwd,
        )
    else:
        inputs = _validate_vvp(argv, control_root=control_root, cwd=cwd)
        output = None
    return ValidatedRequest(
        session_id=expected_session_id,
        tool=tool,
        cwd_relative=cwd,
        argv=tuple(argv),
        input_relatives=inputs,
        output_relative=output,
    )


def _tree_entries(root: Path) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    total_bytes = 0
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            raise ValueError(f"snapshot source contains a symlink: {relative}")
        if path.is_dir():
            continue
        if not path.is_file():
            raise ValueError(f"snapshot source contains a special file: {relative}")
        if any(part.casefold() in FORBIDDEN_PARTS for part in Path(relative).parts):
            raise ValueError(f"snapshot source uses a forbidden path: {relative}")
        if path.suffix.casefold() not in SNAPSHOT_SUFFIXES:
            raise ValueError(f"snapshot source contains an unsupported file: {relative}")
        size = path.stat().st_size
        total_bytes += size
        if len(entries) + 1 > MAX_SNAPSHOT_FILES:
            raise ValueError("snapshot file count exceeds limit")
        if total_bytes > MAX_SNAPSHOT_BYTES:
            raise ValueError("snapshot bytes exceed limit")
        entries.append(
            {
                "path": relative,
                "bytes": size,
                "sha256": _sha256(path),
            }
        )
    if not entries:
        raise ValueError("snapshot source is empty")
    return entries


def snapshot_control_tree(control_root: Path, snapshot_root: Path) -> dict[str, Any]:
    control_root = control_root.expanduser().resolve(strict=True)
    snapshot_root = snapshot_root.expanduser().absolute()
    if snapshot_root.exists() or snapshot_root.is_symlink():
        raise ValueError("snapshot destination already exists")
    entries = _tree_entries(control_root)
    snapshot_root.mkdir(parents=True)
    for entry in entries:
        source = control_root / entry["path"]
        target = snapshot_root / entry["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target, follow_symlinks=False)
        os.chmod(target, 0o444)
    copied_entries = _tree_entries(snapshot_root)
    source_after_entries = _tree_entries(control_root)
    manifest_sha256 = _canonical_sha256(entries)
    copied_manifest_sha256 = _canonical_sha256(copied_entries)
    source_after_manifest_sha256 = _canonical_sha256(source_after_entries)
    if manifest_sha256 != copied_manifest_sha256:
        raise ValueError("snapshot copy manifest differs")
    if manifest_sha256 != source_after_manifest_sha256:
        raise ValueError("snapshot source changed while it was being copied")
    return {
        "regular_file_count": len(entries),
        "total_regular_bytes": sum(item["bytes"] for item in entries),
        "manifest_sha256": manifest_sha256,
        "copied_manifest_sha256": copied_manifest_sha256,
        "source_after_manifest_sha256": source_after_manifest_sha256,
    }


def _mapped_argv(request: ValidatedRequest) -> list[str]:
    input_map = {
        relative.as_posix(): f"/workspace/{relative.as_posix()}"
        for relative in request.input_relatives
    }
    mapped: list[str] = []
    output_next = False
    for argument in request.argv:
        if output_next:
            if request.output_relative is None:
                mapped.append("/dev/null")
            else:
                mapped.append(f"/output/{request.output_relative.as_posix()}")
            output_next = False
        elif argument == "-o":
            mapped.append(argument)
            output_next = True
        elif argument in input_map:
            mapped.append(input_map[argument])
        else:
            normalized = Path(
                os.path.normpath((request.cwd_relative / Path(argument)).as_posix())
            ).as_posix()
            mapped.append(input_map.get(normalized, argument))
    return mapped


def build_offline_command(
    request: ValidatedRequest,
    *,
    snapshot_root: Path,
    output_root: Path,
    image_digest: str,
) -> list[str]:
    if not SHA256_RE.fullmatch(image_digest):
        raise ValueError("offline EDA image digest is invalid")
    workdir = "/workspace"
    if request.cwd_relative != Path("."):
        workdir += f"/{request.cwd_relative.as_posix()}"
    return [
        "podman",
        "run",
        "--rm",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "all",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        "256",
        "--memory",
        "2g",
        "--cpus",
        "2",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=64m",
        "--volume",
        f"{snapshot_root.resolve()}:/workspace:ro",
        "--volume",
        f"{output_root.resolve()}:/output:rw",
        "--workdir",
        workdir,
        "--entrypoint",
        f"/usr/bin/{request.tool}",
        f"{PUBLIC_EDA_IMAGE}@{image_digest}",
        *_mapped_argv(request),
    ]


def _write_new(path: Path, payload: bytes) -> None:
    if path.exists() or path.is_symlink():
        raise FileExistsError(f"refusing to overwrite evidence: {path.name}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)


def _external_root(path: Path, *, control_root: Path, label: str) -> Path:
    candidate = path.expanduser().absolute()
    if candidate == control_root or candidate.is_relative_to(control_root):
        raise ValueError(f"{label} must be outside the provider control root")
    if candidate.is_symlink():
        raise ValueError(f"{label} cannot be a symlink")
    candidate.mkdir(parents=True, exist_ok=True)
    resolved = candidate.resolve(strict=True)
    if resolved == control_root or resolved.is_relative_to(control_root):
        raise ValueError(f"{label} must be outside the provider control root")
    return resolved


def execute_request(
    request_payload: dict[str, Any],
    *,
    expected_session_id: str,
    control_root: Path,
    evidence_root: Path,
    scratch_root: Path,
    image_digest: str,
    call_index: int,
    controller_socket: Path | None = None,
    controller_session_id: str | None = None,
) -> dict[str, Any]:
    if not 1 <= call_index <= 1024:
        raise ValueError("call index must be between 1 and 1024")
    control_root = control_root.expanduser().resolve(strict=True)
    evidence_root = _external_root(
        evidence_root,
        control_root=control_root,
        label="evidence root",
    )
    scratch_root = _external_root(
        scratch_root,
        control_root=control_root,
        label="scratch root",
    )
    request = validate_request(
        request_payload,
        expected_session_id=expected_session_id,
        control_root=control_root,
    )
    scratch_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=f"mage-eda-{call_index:04d}-",
        dir=scratch_root,
    ) as temporary:
        temporary_root = Path(temporary)
        snapshot_root = temporary_root / "snapshot"
        output_root = temporary_root / "output"
        output_root.mkdir()
        if request.output_relative is not None:
            (output_root / request.output_relative).parent.mkdir(
                parents=True,
                exist_ok=True,
            )
        snapshot = snapshot_control_tree(control_root, snapshot_root)
        command = build_offline_command(
            request,
            snapshot_root=snapshot_root,
            output_root=output_root,
            image_digest=image_digest,
        )
        if (controller_socket is None) != (controller_session_id is None):
            raise ValueError("observed controller socket/session must be paired")
        invocation_id = f"mage.{request.tool}.{call_index}"
        if controller_socket is not None and controller_session_id is not None:
            _controller_rpc(
                controller_socket,
                session_id=controller_session_id,
                operation="eda_start",
                invocation_id=invocation_id,
                tool=request.tool,
            )
        controller_outcome = "failed"
        try:
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                timeout=90,
            )
            stdout = completed.stdout
            stderr = completed.stderr
            exit_code = completed.returncode
            process_status = "completed"
            controller_outcome = "completed" if exit_code == 0 else "failed"
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout or b""
            stderr = exc.stderr or b""
            exit_code = 124
            process_status = "timeout"
            controller_outcome = "timed_out"
        finally:
            if controller_socket is not None and controller_session_id is not None:
                _controller_rpc(
                    controller_socket,
                    session_id=controller_session_id,
                    operation="eda_finish",
                    invocation_id=invocation_id,
                    outcome=controller_outcome,
                )
        if len(stdout) > MAX_TOOL_OUTPUT_BYTES or len(stderr) > MAX_TOOL_OUTPUT_BYTES:
            stdout = stdout[:MAX_TOOL_OUTPUT_BYTES]
            stderr = stderr[:MAX_TOOL_OUTPUT_BYTES]
            exit_code = 125
            process_status = "output_limit"
        copied_output_sha256 = None
        if request.output_relative is not None and exit_code == 0:
            generated = output_root / request.output_relative
            if generated.is_symlink() or not generated.is_file():
                exit_code = 126
                process_status = "missing_output"
                stderr += b"offline broker: expected output is missing\n"
            else:
                copied_output_sha256 = _sha256(generated)
                destination = control_root / request.output_relative
                staged = destination.with_name(f".{destination.name}.broker-tmp")
                if staged.exists() or staged.is_symlink():
                    raise FileExistsError("staged broker output already exists")
                shutil.copyfile(generated, staged, follow_symlinks=False)
                os.replace(staged, destination)
        receipt = {
            "schema_version": RECEIPT_SCHEMA_VERSION,
            "session_id": request.session_id,
            "call_index": call_index,
            "tool": request.tool,
            "argv": list(request.argv),
            "cwd": request.cwd_relative.as_posix(),
            "input_paths": [path.as_posix() for path in request.input_relatives],
            "output_path": (
                request.output_relative.as_posix()
                if request.output_relative is not None
                else None
            ),
            "request_sha256": _canonical_sha256(request_payload),
            "snapshot": snapshot,
            "offline_image_digest": image_digest,
            "sandbox": {
                "network": "none",
                "root_filesystem_read_only": True,
                "capabilities": "all_dropped",
                "no_new_privileges": True,
                "pids_limit": 256,
                "memory_limit_bytes": 2 * 1024 * 1024 * 1024,
                "cpu_limit": 2,
            },
            "process_status": process_status,
            "exit_code": exit_code,
            "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
            "stdout_bytes": len(stdout),
            "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
            "stderr_bytes": len(stderr),
            "copied_output_sha256": copied_output_sha256,
            "provider_environment_forwarded": False,
            "private_evaluator_mounted": False,
            "rtl_verdict_produced": False,
        }
        receipt_key = _canonical_sha256(receipt)
        receipt_dir = evidence_root / f"{call_index:04d}-{receipt_key}"
        _write_new(
            receipt_dir / "receipt.json",
            (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode(),
        )
        _write_new(receipt_dir / "stdout.log", stdout)
        _write_new(receipt_dir / "stderr.log", stderr)
    return {
        "schema_version": RESPONSE_SCHEMA_VERSION,
        "exit_code": exit_code,
        "stdout": stdout.decode("utf-8", errors="replace"),
        "stderr": stderr.decode("utf-8", errors="replace"),
        "receipt_id": receipt_dir.name,
        "rtl_verdict_produced": False,
    }


def _receive_json(connection: socket.socket) -> dict[str, Any]:
    header = connection.recv(4)
    if len(header) != 4:
        raise ValueError("request framing header is incomplete")
    size = struct.unpack("!I", header)[0]
    if size < 2 or size > MAX_REQUEST_BYTES:
        raise ValueError("request size is invalid")
    chunks = bytearray()
    while len(chunks) < size:
        chunk = connection.recv(size - len(chunks))
        if not chunk:
            raise ValueError("request framing body is incomplete")
        chunks.extend(chunk)
    value = json.loads(chunks.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("request must be one JSON object")
    return value


def _send_json(connection: socket.socket, value: dict[str, Any]) -> None:
    payload = json.dumps(value, sort_keys=True).encode("utf-8")
    if len(payload) > MAX_RESPONSE_BYTES:
        raise ValueError("response exceeds size limit")
    connection.sendall(struct.pack("!I", len(payload)) + payload)


def serve(
    *,
    socket_path: Path,
    session_id: str,
    control_root: Path,
    evidence_root: Path,
    scratch_root: Path,
    image_digest: str,
    max_requests: int,
    controller_socket: Path | None = None,
    controller_session_id: str | None = None,
    stop_requested: Callable[[], bool] | None = None,
) -> int:
    control_root = control_root.expanduser().resolve(strict=True)
    socket_path = socket_path.expanduser().absolute()
    if socket_path.exists() or socket_path.is_symlink():
        raise FileExistsError("broker socket path already exists")
    if socket_path.is_relative_to(control_root):
        raise ValueError("broker socket cannot be inside the control root")
    socket_path.parent.mkdir(parents=True, exist_ok=True)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    request_count = 0
    try:
        server.bind(str(socket_path))
        os.chmod(socket_path, 0o600)
        server.listen(1)
        server.settimeout(0.5)
        while request_count < max_requests:
            if stop_requested is not None and stop_requested():
                break
            try:
                connection, _ = server.accept()
            except socket.timeout:
                continue
            request_count += 1
            call_index = request_count
            with connection:
                try:
                    request = _receive_json(connection)
                    response = execute_request(
                        request,
                        expected_session_id=session_id,
                        control_root=control_root,
                        evidence_root=evidence_root,
                        scratch_root=scratch_root,
                        image_digest=image_digest,
                        call_index=call_index,
                        controller_socket=controller_socket,
                        controller_session_id=controller_session_id,
                    )
                except Exception as exc:
                    response = {
                        "schema_version": RESPONSE_SCHEMA_VERSION,
                        "exit_code": 127,
                        "stdout": "",
                        "stderr": f"offline EDA broker rejected request: {type(exc).__name__}: {exc}\n",
                        "receipt_id": None,
                        "rtl_verdict_produced": False,
                    }
                _send_json(connection, response)
    finally:
        server.close()
        socket_path.unlink(missing_ok=True)
    return request_count


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", type=Path, required=True)
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--control-root", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--scratch-root", type=Path, required=True)
    parser.add_argument("--image-digest", required=True)
    parser.add_argument("--max-requests", type=int, required=True)
    parser.add_argument("--controller-socket", type=Path)
    parser.add_argument("--controller-session-id")
    args = parser.parse_args()
    if not 1 <= args.max_requests <= 1024:
        raise ValueError("max requests must be between 1 and 1024")
    if (args.controller_socket is None) != (args.controller_session_id is None):
        raise ValueError("controller socket and session ID must be supplied together")
    stopping = {"requested": False}

    def _request_stop(_signum: int, _frame: Any) -> None:
        stopping["requested"] = True

    previous_handler = signal.signal(signal.SIGTERM, _request_stop)
    try:
        request_count = serve(
            socket_path=args.socket,
            session_id=args.session_id,
            control_root=args.control_root,
            evidence_root=args.evidence_root,
            scratch_root=args.scratch_root,
            image_digest=args.image_digest,
            max_requests=args.max_requests,
            controller_socket=args.controller_socket,
            controller_session_id=args.controller_session_id,
            stop_requested=lambda: stopping["requested"],
        )
    finally:
        signal.signal(signal.SIGTERM, previous_handler)
    print(
        json.dumps(
            {
                "status": "stopped" if stopping["requested"] else "request_limit_reached",
                "request_count": request_count,
                "rtl_verdict_produced": False,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
