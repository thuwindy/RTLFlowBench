"""Opt-in launcher bridge for ChipFlow's native cancellable EDA boundary.

Routes structured native invocations to the existing host controller without
passing its socket/session into the scrubbed EDA environment. This is scoped
API observation, NOT proof that no other process-launch API was used.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import subprocess
import threading
import uuid

PROTOCOL = "rtlflowbench.observed_controller_transport.v1"
TOOLS = {"iverilog", "vvp", "yosys"}  # exactly the current controller wire vocabulary
_INSTALL_LOCK = threading.Lock()


class ObservationError(RuntimeError):
    pass


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def canonical(value):
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
    ).hexdigest()


class NativeEDAObservation:
    """Install only in a fresh, trusted, single-workflow launcher process.

    The launcher supplies byte-pinned native source, real resolved tools and
    the authenticated controller RPC. No task IDs, hints, RTL or oracle data
    are accepted. Unknown tools and missing acknowledgements stop execution.
    """

    def __init__(
        self,
        *,
        eda_module,
        rpc,
        session_id,
        expected_source_sha256,
        tool_bindings,
        evidence_root,
    ):
        self.module = eda_module
        self.rpc = rpc
        self.session = session_id
        self.expected_source = expected_source_sha256
        self.source = Path(eda_module.__file__)
        self.bindings = [dict(item) for item in tool_bindings]
        self.output = Path(evidence_root)
        self.rows = []
        self.errors = []
        self.active = 0
        self.lock = threading.Lock()
        self.tools = {}

    def __enter__(self):
        if not _INSTALL_LOCK.acquire(blocking=False):
            raise ObservationError("native_observer_already_installed")
        try:
            if self.source.is_symlink() or sha(self.source) != self.expected_source:
                raise ObservationError("native_source_binding_drift")
            if re.fullmatch(r"[a-z0-9][a-z0-9-]{15,127}", self.session) is None:
                raise ObservationError("invalid_controller_session")
            for item in self.bindings:
                if set(item) != {"path", "tool", "sha256"}:
                    raise ObservationError("invalid_tool_binding")
                p = Path(item["path"])
                if (
                    not p.is_absolute()
                    or p.is_symlink()
                    or str(p.resolve()) != str(p)
                    or item["tool"] not in TOOLS
                    or str(p) in self.tools
                    or sha(p) != item["sha256"]
                ):
                    raise ObservationError("tool_binding_missing_duplicated_or_drifted")
                self.tools[str(p)] = dict(item)
            if not self.tools:
                raise ObservationError("tool_bindings_empty")
            self.output.mkdir(mode=0o700, parents=True, exist_ok=False)
            self.original = self.module._run_cancellable_process
            self.wrapper = self._run
            self.module._run_cancellable_process = self.wrapper
            return self
        except BaseException:
            _INSTALL_LOCK.release()
            raise

    def _ack(self, operation, **fields):
        response = self.rpc(
            dict(
                schema_version=PROTOCOL,
                session_id=self.session,
                operation=operation,
                **fields,
            )
        )
        if (
            not isinstance(response, dict)
            or response.get("schema_version") != PROTOCOL
            or response.get("status") != "accepted"
        ):
            raise ObservationError("controller_acknowledgement_missing")

    def _run(self, **kwargs):
        # Leave native kwargs/env, return tuple, cancellation and exceptions intact.
        row = None
        try:
            command = kwargs.get("command")
            if (
                not isinstance(command, (list, tuple))
                or not command
                or not all(isinstance(a, str) for a in command)
            ):
                raise ObservationError("invalid_native_argv")
            tool = self.tools.get(command[0])
            if (
                tool is None
                or sha(tool["path"]) != tool["sha256"]
                or sha(self.source) != self.expected_source
            ):
                raise ObservationError("unbound_or_drifted_native_tool")
            row = {
                "invocation_id": "native-eda." + uuid.uuid4().hex,
                "tool": tool["tool"],
                "tool_sha256": tool["sha256"],
                "argv_sha256": canonical(list(command)),
                "start_acknowledged": False,
                "finish_acknowledged": False,
                "outcome": None,
            }
            with self.lock:
                self.rows.append(row)
                self.active += 1
            self._ack(
                "eda_start", invocation_id=row["invocation_id"], tool=tool["tool"]
            )
            row["start_acknowledged"] = True
            outcome = "failed"
            try:
                result = self.original(**kwargs)
                if not isinstance(result, tuple) or len(result) != 4:
                    raise ObservationError("native_process_return_contract_drift")
                outcome = (
                    "completed" if result[2] == 0 and result[3] is False else "failed"
                )
                return result
            except subprocess.TimeoutExpired:
                outcome = "timed_out"
                raise
            finally:
                row["outcome"] = outcome
                self._ack(
                    "eda_finish", invocation_id=row["invocation_id"], outcome=outcome
                )
                row["finish_acknowledged"] = True
                if sha(tool["path"]) != tool["sha256"]:
                    raise ObservationError("tool_drift_during_execution")
        except (ObservationError, ConnectionError, OSError) as exc:
            # An actual process-launch OSError is a measured failed invocation,
            # unlike a missing controller ACK or unreadable binding. Preserve it.
            if not (row and row["finish_acknowledged"] and isinstance(exc, OSError)):
                with self.lock:
                    self.errors.append(type(exc).__name__)
            raise
        except BaseException as exc:
            if not (
                row
                and row["finish_acknowledged"]
                and isinstance(exc, subprocess.TimeoutExpired)
            ):
                with self.lock:
                    self.errors.append(type(exc).__name__)
            raise
        finally:
            if row is not None:
                with self.lock:
                    self.active -= 1

    def __exit__(self, exc_type, exc, tb):
        try:
            if self.module._run_cancellable_process is self.wrapper:
                self.module._run_cancellable_process = self.original
            else:
                self.errors.append("native_hook_replaced")
            try:
                if sha(self.source) != self.expected_source:
                    self.errors.append("native_source_changed")
                if any(sha(p) != item["sha256"] for p, item in self.tools.items()):
                    self.errors.append("native_tool_changed")
            except OSError:
                self.errors.append("native_source_or_tool_unreadable")
            complete = (
                not self.errors
                and self.active == 0
                and all(r["finish_acknowledged"] for r in self.rows)
            )
            receipt = {
                "schema_version": "chipflow.native_eda_observation.v2",
                "native_source_sha256": self.expected_source,
                "observer_source_sha256": sha(Path(__file__)),
                "tool_bindings_sha256": canonical(self.bindings),
                "wrapper_calls_complete": complete,
                "active_count": self.active,
                "errors": self.errors,
                "invocations": self.rows,
                "all_eda_invocations_observed": None,
                "provider_observation_complete": None,
                "neutral_export_eligible": False,
                "benchmark_verdict": None,
                "limitations": [
                    "Native API observation does not prove process-wide coverage or observer authenticity.",
                    "Host exec trace and full provider/process/resource binding are separate gates.",
                    "Controller outcomes count invocation cost, not DUT functional correctness.",
                ],
            }
            with (self.output / "observation.json").open("x") as stream:
                json.dump(receipt, stream, indent=2, sort_keys=True)
                stream.write("\n")
            if not complete and exc is None:
                raise ObservationError("native_observation_incomplete")
        finally:
            _INSTALL_LOCK.release()
        return False
