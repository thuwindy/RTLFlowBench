"""Bound public runner descendants, without counting interpreters as EDA.

Opt-in successor to the direct native observer. The same host exec auditor
must still detect bypasses; this module does not prove global coverage.
"""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import socket
import struct
import subprocess
import sys
import uuid


def _module(path):
    spec = importlib.util.spec_from_file_location("_runner_base_observer", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


base = _module(Path(__file__).with_name("native_eda_observer_v2.py"))
ObservationError = base.ObservationError


def _save(path, value):
    with Path(path).open("x", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True, allow_nan=False)
        stream.write("\n")
    Path(path).chmod(0o600)


def _bound_file(path, expected):
    path = Path(path)
    if (
        not path.is_absolute()
        or path.is_symlink()
        or not path.is_file()
        or str(path.resolve()) != str(path)
        or base.sha(path) != expected
    ):
        raise ObservationError("runner_binding_drift")


def _exact(connection, length):
    chunks = []
    while length:
        chunk = connection.recv(length)
        if not chunk:
            raise ObservationError("controller_response_incomplete")
        chunks.append(chunk)
        length -= len(chunk)
    return b"".join(chunks)


def _rpc(path, request):
    payload = json.dumps(request, sort_keys=True, separators=(",", ":")).encode()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(10)
        client.connect(path)
        client.sendall(struct.pack("!I", len(payload)) + payload)
        length = struct.unpack("!I", _exact(client, 4))[0]
        if not 0 < length < 65536:
            raise ObservationError("controller_response_size")
        result = json.loads(_exact(client, length))
    if (
        result.get("schema_version") != base.PROTOCOL
        or result.get("status") != "accepted"
    ):
        raise ObservationError("controller_acknowledgement_missing")
    return result


def run_shim(config_path, config_sha256, tool, arguments):
    """Only this child owns accounting for this one real executable."""
    _bound_file(config_path, config_sha256)
    config = json.loads(Path(config_path).read_text())
    _bound_file(__file__, config["shim_source_sha256"])
    _bound_file(base.__file__, config["base_source_sha256"])
    binding = config["tools"][tool]
    _bound_file(binding["path"], binding["sha256"])
    command = [binding["path"], *arguments]
    invocation = "runner-eda." + uuid.uuid4().hex
    row = {
        "invocation_id": invocation,
        "tool": tool,
        "tool_sha256": binding["sha256"],
        "argv_sha256": base.canonical(command),
        "start_acknowledged": False,
        "finish_acknowledged": False,
        "outcome": None,
        "errors": [],
    }
    events = Path(config["events"])
    _save(events / (invocation + ".intent.json"), row)

    def ack(operation, **fields):
        _rpc(
            config["socket"],
            {
                "schema_version": base.PROTOCOL,
                "session_id": config["session"],
                "operation": operation,
                "invocation_id": invocation,
                **fields,
            },
        )

    ack("eda_start", tool=tool)
    row["start_acknowledged"] = True
    outcome = "failed"
    try:
        process = subprocess.run(command, check=False)
        outcome = "completed" if process.returncode == 0 else "failed"
        return (
            process.returncode if process.returncode >= 0 else 128 - process.returncode
        )
    finally:
        row["outcome"] = outcome
        try:
            _bound_file(binding["path"], binding["sha256"])
            ack("eda_finish", outcome=outcome)
            row["finish_acknowledged"] = True
        except (ObservationError, OSError, ValueError):
            row["errors"].append("child_finish_or_binding_failed")
            raise
        finally:
            _save(events / (invocation + ".finished.json"), row)


class RunnerEDAObservation(base.NativeEDAObservation):
    """Fresh trusted process only; no provider credentials in child env."""

    def __init__(
        self,
        *,
        runner_bindings,
        controller_socket,
        shim_python,
        shim_python_sha256,
        **kwargs,
    ):
        self.root = Path(kwargs["evidence_root"])
        kwargs["evidence_root"] = self.root / "direct"
        super().__init__(**kwargs)
        self.runners = [dict(r) for r in runner_bindings]
        self.socket = str(controller_socket)
        self.python = str(shim_python)
        self.python_sha = shim_python_sha256
        self.runner_calls = []
        self.shim_pins = {}
        self.source_sha = base.sha(__file__)
        self.base_sha = base.sha(base.__file__)

    def __enter__(self):
        if self.root.exists() or self.root.is_symlink():
            raise FileExistsError("fresh_runner_observation_required")
        self._validate_runners()
        _bound_file(self.python, self.python_sha)
        if not Path(self.socket).is_socket():
            raise ObservationError("controller_socket_missing")
        if getattr(self.module._run_cancellable_process, "__self__", None) is not None:
            raise ObservationError("native_observer_already_installed")
        self.root.mkdir(mode=0o700)
        # Base installation verifies native/tool bindings and takes its global lock.
        super().__enter__()
        try:
            self.events = self.root / "events"
            self.events.mkdir(mode=0o700)
            self.shims = self.root / "shims"
            self.shims.mkdir(mode=0o700)
            tools = {r["tool"]: r for r in self.bindings}
            if len(tools) != len(self.bindings):
                raise ObservationError("ambiguous_tool_name")
            config = {
                "tools": tools,
                "events": str(self.events),
                "socket": self.socket,
                "session": self.session,
                "shim_source_sha256": self.source_sha,
                "base_source_sha256": self.base_sha,
            }
            config_path = self.root / "shim-config.json"
            _save(config_path, config)
            self.shim_pins[str(config_path)] = base.sha(config_path)
            for tool in tools:
                command = [
                    self.python,
                    "-B",
                    str(Path(__file__).resolve()),
                    "--shim",
                    str(config_path),
                    base.sha(config_path),
                    tool,
                ]
                path = self.shims / tool
                with path.open("x") as stream:
                    stream.write("#!/bin/sh\nexec " + shlex.join(command) + ' "$@"\n')
                path.chmod(0o700)
                self.shim_pins[str(path)] = base.sha(path)
            return self
        except BaseException as exc:
            self.errors.append("runner_install_failed")
            super().__exit__(type(exc), exc, exc.__traceback__)
            raise

    def _validate_runners(self):
        seen = set()
        if not self.runners:
            raise ObservationError("runner_bindings_empty")
        for item in self.runners:
            if set(item) != {
                "executable",
                "executable_sha256",
                "script",
                "script_sha256",
                "script_index",
                "argv_sha256",
            }:
                raise ObservationError("invalid_runner_binding")
            _bound_file(item["executable"], item["executable_sha256"])
            _bound_file(item["script"], item["script_sha256"])
            if (
                type(item["script_index"]) is not int
                or item["script_index"] < 1
                or not isinstance(item["argv_sha256"], str)
                or re.fullmatch(r"[0-9a-f]{64}", item["argv_sha256"]) is None
                or item["argv_sha256"] in seen
            ):
                raise ObservationError("invalid_runner_identity")
            seen.add(item["argv_sha256"])

    def _pins(self):
        _bound_file(__file__, self.source_sha)
        _bound_file(base.__file__, self.base_sha)
        _bound_file(self.source, self.expected_source)
        _bound_file(self.python, self.python_sha)
        self._validate_runners()
        for path, expected in self.shim_pins.items():
            _bound_file(path, expected)

    def _run(self, **kwargs):
        command = kwargs.get("command")
        if isinstance(command, (list, tuple)) and command and command[0] in self.tools:
            return super()._run(**kwargs)
        row = None
        try:
            self._pins()
            binding = next(
                (
                    r
                    for r in self.runners
                    if r["argv_sha256"] == base.canonical(list(command))
                ),
                None,
            )
            if binding is None or command[0] != binding["executable"]:
                raise ObservationError("undeclared_runner_command")
            script = (Path(kwargs["cwd"]) / command[binding["script_index"]]).resolve()
            if str(script) != binding["script"]:
                raise ObservationError("runner_script_path_mismatch")
            row = {"argv_sha256": binding["argv_sha256"], "completed": False}
            with self.lock:
                self.runner_calls.append(row)
            # Preserve native command, cwd, timeout, cancellation and return contract.
            # Only PATH gains bound tool shims. Socket/session stay out of child env.
            environment = dict(kwargs.get("env") or {})
            environment["PATH"] = (
                str(self.shims) + os.pathsep + environment.get("PATH", os.defpath)
            )
            return self.original(**{**kwargs, "env": environment})
        except (subprocess.TimeoutExpired, OSError):
            raise
        except BaseException:
            self.errors.append("runner_invocation_rejected")
            raise
        finally:
            if row is not None:
                row["completed"] = True
                try:
                    self._pins()
                except (ObservationError, OSError):
                    self.errors.append("runner_binding_drift")
                    raise

    def __exit__(self, exc_type, exc, tb):
        pending_error = None
        try:
            self._pins()
            intents = {
                p.name.removesuffix(".intent.json"): p
                for p in self.events.glob("*.intent.json")
            }
            finished = {
                p.name.removesuffix(".finished.json"): p
                for p in self.events.glob("*.finished.json")
            }
            expected_paths = set(intents.values()) | set(finished.values())
            if set(self.events.iterdir()) != expected_paths or any(
                p.is_symlink() or not p.is_file() or p.stat().st_nlink != 1
                for p in expected_paths
            ):
                raise ObservationError("runner_event_files_unsafe")
            if intents.keys() != finished.keys():
                self.errors.append("runner_child_observation_incomplete")
            for identity in sorted(intents.keys() & finished.keys()):
                start = json.loads(intents[identity].read_text())
                row = json.loads(finished[identity].read_text())
                keys = ["invocation_id", "tool", "tool_sha256", "argv_sha256"]
                if (
                    row.get("invocation_id") != identity
                    or any(row.get(k) != start.get(k) for k in keys)
                    or row.get("errors") != []
                    or row.get("start_acknowledged") is not True
                    or row.get("finish_acknowledged") is not True
                    or row.get("outcome") not in {"completed", "failed", "timed_out"}
                ):
                    self.errors.append("runner_child_observation_invalid")
                self.rows.append(row)
            if any(not r["completed"] for r in self.runner_calls):
                self.errors.append("runner_invocation_unclosed")
        except (OSError, ValueError, ObservationError) as error:
            self.errors.append("runner_evidence_unreadable_or_drifted")
            pending_error = error
        try:
            super().__exit__(exc_type, exc, tb)
        except BaseException as error:
            pending_error = error
        finally:
            path = self.output / "observation.json"
            if path.is_file():
                receipt = json.loads(path.read_text())
                receipt.update(
                    observer_source_sha256=self.source_sha,
                    base_observer_source_sha256=self.base_sha,
                    observation_mode="bound_runner_descendants_v3",
                    runner_bindings_sha256=base.canonical(self.runners),
                    runner_calls=self.runner_calls,
                    shim_bindings_sha256=base.canonical(self.shim_pins),
                )
                _save(self.root / "observation.json", receipt)
        if pending_error is not None and exc is None:
            raise pending_error
        return False


if __name__ == "__main__":
    try:
        if len(sys.argv) < 5 or sys.argv[1] != "--shim":
            raise ObservationError("invalid_shim_invocation")
        raise SystemExit(run_shim(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5:]))
    except (ObservationError, OSError, ValueError, KeyError):
        # No raw argv, controller payload, source text or credential output.
        print("bound EDA shim failed closed", file=sys.stderr)
        raise SystemExit(125)
