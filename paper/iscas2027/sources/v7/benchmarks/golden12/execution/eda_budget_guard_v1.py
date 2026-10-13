"""Opt-in EDA admission limits around the existing observed controller.

Requires a fresh, host-owned evidence directory and exact public-task digest.
Counts every accepted start, including preapproval checks and failed commands.
Does not change the default controller, native workflow, tool argv or verdict.
This is host-trusted enforcement, not process isolation or campaign admission.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import threading

import observed_controller_transport as base

FAMILIES = {"compile_or_lint", "simulation", "formal", "synthesis"}


def digest(path):
    if any(p.is_symlink() for p in (path, *path.parents)) or not path.is_file():
        raise ValueError("unsafe_budget_file")
    return hashlib.sha256(path.read_bytes()).hexdigest()


class BudgetedControllerState(base.ControllerState):
    def __init__(
        self,
        *,
        public_task_path,
        expected_public_task_sha256,
        budget_evidence_root,
        **kwargs,
    ):
        self._eda_guard_lock = threading.RLock()
        self._budget_task = Path(public_task_path).absolute()
        self._budget_task_sha = expected_public_task_sha256
        if digest(self._budget_task) != self._budget_task_sha:
            raise ValueError("public_task_drift")
        task = json.loads(self._budget_task.read_text())
        limits = task["budget"]["eda_call_limits"]
        if (
            not isinstance(limits, dict)
            or set(limits) != FAMILIES
            or any(type(v) is not int or not 0 <= v <= 4096 for v in limits.values())
        ):
            raise ValueError("invalid_eda_limits")
        root = Path(budget_evidence_root).absolute()
        if root.exists() or any(p.is_symlink() for p in (root, *root.parents)):
            raise ValueError("fresh_nonsymlink_budget_evidence_required")
        if not root.parent.is_dir():
            raise ValueError("budget_evidence_parent_missing")
        super().__init__(**kwargs)
        self._budget_root = root
        self._limits = dict(limits)
        self._started_counts = dict.fromkeys(sorted(FAMILIES), 0)
        self._denied_counts = dict.fromkeys(sorted(FAMILIES), 0)
        self._budget_events = {}
        self._budget_stop = None
        self._source_hashes = {
            Path(__file__): digest(Path(__file__)),
            Path(base.__file__): digest(Path(base.__file__)),
        }
        root.mkdir(mode=0o700)
        self._event(
            "binding",
            {
                "public_task_sha256": self._budget_task_sha,
                "limits": self._limits,
                "session_id": self.session_id,
                "guard_source_sha256": digest(Path(__file__)),
                "base_source_sha256": digest(Path(base.__file__)),
            },
        )

    def _event(self, kind, payload):
        name = f"event-{len(self._budget_events):05d}.json"
        value = {
            "schema": "rtlflowbench.eda_budget_event.v1",
            "kind": kind,
            "sequence": len(self._budget_events),
            "previous_sha256": next(reversed(self._budget_events.values()), None),
            **payload,
        }
        encoded = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
        path = self._budget_root / name
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        self._budget_events[name] = hashlib.sha256(encoded).hexdigest()

    def _boundary(self):
        if self._budget_stop is not None:
            raise RuntimeError(self._budget_stop)
        try:
            if any(
                digest(path) != expected
                for path, expected in self._source_hashes.items()
            ):
                raise ValueError("controller_source_drift")
            if digest(self._budget_task) != self._budget_task_sha:
                raise ValueError("public_task_drift")
            if set(p.name for p in self._budget_root.iterdir()) != set(
                self._budget_events
            ):
                raise ValueError("budget_journal_drift")
            for name, expected in self._budget_events.items():
                if digest(self._budget_root / name) != expected:
                    raise ValueError("budget_journal_drift")
        except (OSError, ValueError) as exc:
            self._budget_stop = str(exc)
            with self._lock:
                self._terminal_guard_reason = self._budget_stop
            # Preserve a content-bound stop even if the original bytes return.
            # If storage itself failed, the existing fresh-root rule still
            # forbids restart/re-adoption of this incomplete journal.
            try:
                self._event("blocked", {"reason": self._budget_stop})
            except OSError:
                pass
            raise

    def eda_start(self, request):
        with self._eda_guard_lock:
            self._boundary()
            kind = base.EDA_TO_KIND.get(request.get("tool"))
            # Preserve the original protocol validator for malformed requests.
            required = {
                "schema_version",
                "session_id",
                "operation",
                "invocation_id",
                "tool",
            }
            if (
                set(request) != required
                or kind is None
                or base.ACTIVITY_RE.fullmatch(str(request.get("invocation_id"))) is None
            ):
                return super().eda_start(request)
            family = kind.removeprefix("eda_")
            if self._started_counts[family] >= self._limits[family]:
                self._denied_counts[family] += 1
                self._budget_stop = "eda_budget_exhausted:" + family
                self._event(
                    "denied",
                    {
                        "family": family,
                        "tool": request["tool"],
                        "invocation_id": request["invocation_id"],
                        "reason": self._budget_stop,
                    },
                )
                with self._lock:
                    self._terminal_guard_reason = self._budget_stop
                raise RuntimeError(self._budget_stop)
            result = super().eda_start(request)
            self._started_counts[family] += 1
            try:
                self._event(
                    "admitted",
                    {
                        "family": family,
                        "tool": request["tool"],
                        "invocation_id": request["invocation_id"],
                        "admitted_count": self._started_counts[family],
                    },
                )
            except Exception:
                self._budget_stop = "eda_budget_evidence_write_failed"
                with self._lock:
                    self._terminal_guard_reason = self._budget_stop
                raise
            return result

    def _settled_provider_http(self, request):
        # Parent provider_http owns the single-flight lock before this method.
        with self._eda_guard_lock:
            self._boundary()
        return super()._settled_provider_http(request)

    def eda_budget_receipt(self):
        with self._eda_guard_lock:
            return copy.deepcopy(
                {
                    "schema": "rtlflowbench.eda_budget_receipt.v1",
                    "public_task_sha256": self._budget_task_sha,
                    "limits": self._limits,
                    "started_counts": self._started_counts,
                    "denied_counts": self._denied_counts,
                    "stop_reason": self._budget_stop,
                    "event_sha256": self._budget_events,
                    "count_semantics": "admitted starts, never refunded on failure",
                    "process_isolation_attested": False,
                }
            )
