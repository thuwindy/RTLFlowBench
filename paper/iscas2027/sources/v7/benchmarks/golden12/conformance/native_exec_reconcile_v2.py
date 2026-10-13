"""Offline reconciliation of native invocation records and host exec evidence.

Pure data projection, no evaluator dependency or raw-argv output. Caller must
retain a trusted closed host trace and byte-pinned runtime inventory. Hashes
bind content; they do not authenticate a hostile collector or prove isolation.
"""

from __future__ import annotations

import ast
from collections import Counter
import hashlib
import json
from pathlib import PurePosixPath
import re
import signal

QUOTED = r'"(?:[^"\\]|\\.)*"'
MAX_BYTES = 32 * 1024 * 1024


def digest(value):
    return hashlib.sha256(value).hexdigest()


def canonical(value):
    return digest(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
    )


def document(data):
    if not isinstance(data, bytes) or len(data) > MAX_BYTES:
        raise ValueError("document_size_or_type")

    def pairs(items):
        result = {}
        for k, v in items:
            if k in result:
                raise ValueError("duplicate_json_key")
            result[k] = v
        return result

    def nonfinite(_):
        raise ValueError("nonfinite_json")

    result = json.loads(data, object_pairs_hook=pairs, parse_constant=nonfinite)
    if not isinstance(result, dict):
        raise ValueError("object_required")
    return result


def path(value):
    if (
        not isinstance(value, str)
        or not value.startswith("/")
        or PurePosixPath(value).as_posix() != value
        or ".." in value.split("/")
        or any(x in value for x in ["(deleted)", "memfd:", "/proc/", "/dev/fd/"])
    ):
        raise ValueError("noncanonical_executable")
    return value


def sha_value(value):
    if not isinstance(value, str) or re.fullmatch("[0-9a-f]{64}", value) is None:
        raise ValueError("invalid_digest")
    return value


def parse_trace(data):
    if not isinstance(data, bytes) or not data or len(data) > MAX_BYTES:
        raise ValueError("trace_size_or_type")
    text = data.decode("ascii")
    pending = {}
    events = []
    exits = {}
    issues = []
    for line in text.splitlines():
        found = re.fullmatch(r"(\d+)\s+(.*)", line)
        if not found:
            raise ValueError("unparsed_trace_line")
        pid = int(found[1])
        call = found[2]
        if call.startswith("execveat(") or call.startswith("<... execveat resumed>"):
            raise ValueError("execveat_not_supported_by_this_binding")
        if call.startswith("execve(") and "<unfinished ...>" in call:
            if pid in pending:
                raise ValueError("duplicate_unfinished_exec")
            pending[pid] = call.replace("<unfinished ...>", "")
            continue
        if call.startswith("<... execve resumed>"):
            if pid not in pending:
                raise ValueError("orphan_exec_completion")
            call = pending.pop(pid) + call.removeprefix("<... execve resumed>")
        if call.startswith("execve("):
            match = re.fullmatch(
                rf"execve\(({QUOTED}), (\[.*\]), .*\)\s*= (0|-1 [A-Z0-9_]+(?: \(.*\))?)",
                call,
            )
            if not match:
                raise ValueError("unparsed_exec")
            executable = path(ast.literal_eval(match[1]))
            argv = ast.literal_eval(match[2])
            if (
                not isinstance(argv, list)
                or not argv
                or not all(isinstance(v, str) for v in argv)
            ):
                raise ValueError("incomplete_argv")
            events.append(
                {
                    "pid": pid,
                    "executable": executable,
                    "argv_sha256": canonical(argv),
                    "exec_succeeded": match[3] == "0",
                }
            )
            continue
        exit_match = re.fullmatch(r"\+\+\+ exited with (\d+) \+\+\+", call)
        killed = re.fullmatch(
            r"\+\+\+ killed by (SIG[A-Z0-9]+)(?: \(core dumped\))? \+\+\+", call
        )
        if exit_match or killed:
            if pid in exits:
                raise ValueError("duplicate_process_exit")
            exits[pid] = (
                int(exit_match[1]) if exit_match else -int(signal.Signals[killed[1]])
            )
            continue
        if re.fullmatch(r"--- SIG[A-Z0-9]+ \{.*\} ---", call):
            continue
        raise ValueError("unsupported_trace_record")
    if pending:
        issues.append("unfinished_exec")
    if not events:
        issues.append("no_root_exec")
    if {e["pid"] for e in events} - set(exits):
        issues.append("missing_process_exit")
    if issues:
        raise ValueError(";".join(issues))
    return events, exits


def reconcile(trace_bytes, observation_bytes, inventory_bytes, process_bytes):
    result = {
        "schema_version": "chipflow.native_exec_reconciliation.v2",
        "status": "blocked",
        "issues": [],
        "matched_invocations": None,
        "unmatched_host_invocations": None,
        "unmatched_observer_invocations": None,
        "neutral_export_eligible": False,
        "benchmark_verdict": None,
        "limits": [
            "This verifies exec evidence against a reviewed inventory, not collector authenticity or full environment isolation.",
            "No claim about in-process EDA libraries, provider accounting, workload correctness, or full neutral submission.",
        ],
    }
    try:
        observation = document(observation_bytes)
        inventory = document(inventory_bytes)
        process = document(process_bytes)
        if (
            process.get("schema_version") != "chipflow.native_traced_process.v2"
            or process.get("trace_complete") is not True
            or process.get("trace_mode")
            != "strace-follow-execve-execveat-no-abbreviation-with-exits"
        ):
            raise ValueError("unqualified_trace_collection")
        for key, data in [
            ("trace_sha256", trace_bytes),
            ("observation_sha256", observation_bytes),
            ("inventory_sha256", inventory_bytes),
        ]:
            if process.get(key) != digest(data):
                raise ValueError("process_artifact_hash_drift")
        for key in ["exit_code", "tracer_exit_code"]:
            if type(process.get(key)) is not int:
                raise ValueError("missing_exit_measurement")
        if process["exit_code"] != process["tracer_exit_code"]:
            raise ValueError("tracer_process_outcome_mismatch")
        if (
            observation.get("schema_version") != "chipflow.native_eda_observation.v2"
            or observation.get("wrapper_calls_complete") is not True
            or type(observation.get("active_count")) is not int
            or observation["active_count"] != 0
            or observation.get("errors") != []
        ):
            raise ValueError("incomplete_native_wrapper")
        for key in ["native_source_sha256", "observer_source_sha256"]:
            if sha_value(process.get(key)) != observation.get(key):
                raise ValueError("native_runtime_binding_drift")
        bindings = inventory["native_tool_bindings"]
        if observation["tool_bindings_sha256"] != canonical(bindings):
            raise ValueError("tool_inventory_binding_drift")
        tools = {}
        for item in bindings:
            if set(item) != {"path", "tool", "sha256"} or item["tool"] not in {
                "iverilog",
                "vvp",
                "yosys",
            }:
                raise ValueError("unsupported_tool_binding")
            p = path(item["path"])
            sha_value(item["sha256"])
            if p in tools:
                raise ValueError("duplicate_tool_binding")
            tools[p] = item
        entries = {}
        for item in inventory["executables"]:
            p = path(item["path"])
            sha_value(item["sha256"])
            if p in entries or item["role"] not in {"runtime", "eda"}:
                raise ValueError("invalid_executable_inventory")
            if item["role"] == "eda":
                if p not in tools or any(
                    item.get(k) != tools[p][k] for k in ["tool", "sha256"]
                ):
                    raise ValueError("unbound_eda_inventory")
            elif p in tools or item["sha256"] in {b["sha256"] for b in tools.values()}:
                raise ValueError("eda_misclassified_as_runtime")
            entries[p] = item
        if set(tools) - set(entries):
            raise ValueError("missing_tool_inventory")
        events, exits = parse_trace(trace_bytes)
        root = events[0]
        if (
            not root["exec_succeeded"]
            or root["argv_sha256"] != process.get("command_argv_sha256")
            or exits[root["pid"]] != process["exit_code"]
        ):
            raise ValueError("root_process_binding_mismatch")
        host = []
        for event in events:
            item = entries.get(event["executable"])
            if item is None:
                raise ValueError("unclassified_executable")
            if item["role"] == "eda":
                host.append(
                    (
                        item["tool"],
                        item["sha256"],
                        event["argv_sha256"],
                        event["exec_succeeded"],
                        exits[event["pid"]],
                    )
                )
        observed = []
        ids = set()
        for row in observation["invocations"]:
            identity = row.get("invocation_id")
            if not isinstance(identity, str) or not identity or identity in ids:
                raise ValueError("duplicate_or_missing_invocation_id")
            ids.add(identity)
            if (
                row.get("start_acknowledged") is not True
                or row.get("finish_acknowledged") is not True
                or row.get("outcome") not in {"completed", "failed", "timed_out"}
            ):
                raise ValueError("incomplete_invocation")
            observed.append(
                (
                    row["tool"],
                    sha_value(row["tool_sha256"]),
                    sha_value(row["argv_sha256"]),
                    row["outcome"],
                )
            )
        host_keys = Counter(row[:3] for row in host)
        observed_keys = Counter(row[:3] for row in observed)
        result["unmatched_host_invocations"] = sum((host_keys - observed_keys).values())
        result["unmatched_observer_invocations"] = sum(
            (observed_keys - host_keys).values()
        )
        if host_keys != observed_keys:
            raise ValueError("invocation_multiset_mismatch")
        # Successful process claims need successful exec and exit. For identical
        # invocations compare multiplicities, not arbitrary list order.
        successful = Counter(row[:3] for row in host if row[3] and row[4] == 0)
        completed = Counter(row[:3] for row in observed if row[3] == "completed")
        if completed - successful:
            raise ValueError("completed_call_without_successful_process")
        result.update(
            status="reconciled",
            matched_invocations=len(host),
            trace_sha256=digest(trace_bytes),
            observation_sha256=digest(observation_bytes),
            inventory_sha256=digest(inventory_bytes),
            process_sha256=digest(process_bytes),
            count_semantics="bound_top_level_exec_attempts_not_DUT_correctness",
        )
    except (
        ValueError,
        TypeError,
        KeyError,
        AttributeError,
        SyntaxError,
        UnicodeError,
    ) as exc:
        # Never return argv, paths or untrusted exception text.
        safe = (
            str(exc)
            if isinstance(exc, ValueError)
            and re.fullmatch("[a-z_]+(?:;[a-z_]+)*", str(exc))
            else "malformed_evidence"
        )
        result["issues"] = [safe]
    return result
