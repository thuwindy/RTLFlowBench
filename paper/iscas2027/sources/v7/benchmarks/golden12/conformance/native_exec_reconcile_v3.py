"""Versioned reconciliation of explicitly absent Python metadata probes.

This does not grant a failed EDA invocation an exemption. The caller must bind
the pre-run absence observation to its immutable offline image/source mount.
The resulting trace remains diagnostic until collector trust and the complete
same-run resource chain have been established separately.
"""

import ast
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import re

BASE_SHA256 = "352369c21b683a2f772a1324bb462a48cf6f9b31e7df3b9b89b160441cd8bc29"
base_path = Path(__file__).with_name("native_exec_reconcile_v2.py")
if hashlib.sha256(base_path.read_bytes()).hexdigest() != BASE_SHA256:
    raise ValueError("base_auditor_source_drift")
spec = importlib.util.spec_from_file_location("_exec_auditor_v2", base_path)
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)

METADATA_ARGVS = (("uname", "-p"), ("uname", "-rs"), ("lsb_release", "-a"))


def encoded(value):
    return (json.dumps(value, sort_keys=True, allow_nan=False) + "\n").encode()


def reconcile(
    trace_bytes, observation_bytes, inventory_bytes, process_bytes, absence_bytes
):
    result = {
        "schema_version": "chipflow.native_exec_reconciliation.v3",
        "status": "blocked",
        "issues": [],
        "neutral_export_eligible": False,
        "benchmark_verdict": None,
        "optional_absent_probe_count": None,
        "collector_authenticity_proven": False,
    }
    try:
        inventory = base.document(inventory_bytes)
        process = base.document(process_bytes)
        absence = base.document(absence_bytes)
        for key, data in [
            ("trace_sha256", trace_bytes),
            ("observation_sha256", observation_bytes),
            ("inventory_sha256", inventory_bytes),
            ("absence_probe_sha256", absence_bytes),
        ]:
            if process.get(key) != base.digest(data):
                raise ValueError("process_artifact_hash_drift")
        if (
            absence.get("schema_version") != "chipflow.offline_runtime_absence.v1"
            or absence.get("before_session") is not True
        ):
            raise ValueError("invalid_absence_probe")
        for field in ["image_id", "source_closure_sha256"]:
            if base.sha_value(process.get(field)) != absence.get(field):
                raise ValueError("absence_environment_binding_drift")
        probes = inventory.get("optional_absent_runtime_probes")
        if not isinstance(probes, list) or not probes or len(probes) > 8:
            raise ValueError("invalid_optional_probe_inventory")
        known = {item["path"] for item in inventory["executables"]}
        optional = {}
        for item in probes:
            if set(item) != {"path", "argv", "maximum_attempts"}:
                raise ValueError("invalid_optional_probe")
            path = base.path(item["path"])
            argv = item["argv"]
            key = (path, base.canonical(argv))
            observed = absence["paths"].get(path)
            if (
                not isinstance(argv, list)
                or tuple(argv) not in METADATA_ARGVS
                or PurePosixPath(path).name != argv[0]
                or type(item["maximum_attempts"]) is not int
                or item["maximum_attempts"] != 1
                or key in optional
                or path in known
                or not isinstance(observed, dict)
                or set(observed) != {"lexists"}
                or observed["lexists"] is not False
            ):
                raise ValueError("invalid_or_unproven_optional_probe")
            optional[key] = argv
        optional_paths = {key[0] for key in optional}
        if set(absence["paths"]) != optional_paths:
            raise ValueError("absence_inventory_mismatch")
        # Parse the complete original trace first: no truncation, missing exit,
        # unfinished syscall or successful root exec may be hidden by filtering.
        events, exits = base.parse_trace(trace_bytes)
        root = events[0]
        if (
            not root["exec_succeeded"]
            or root["argv_sha256"] != process.get("command_argv_sha256")
            or exits[root["pid"]] != process.get("exit_code")
        ):
            raise ValueError("original_root_process_binding_mismatch")
        candidates = [e for e in events if e["executable"] in optional_paths]
        for event in candidates:
            if (
                event["exec_succeeded"]
                or (event["executable"], event["argv_sha256"]) not in optional
            ):
                raise ValueError("optional_probe_execution_or_argv_drift")
        counts = {key: 0 for key in optional}
        retained = []
        for line in trace_bytes.decode("ascii").splitlines(keepends=True):
            found = re.fullmatch(
                rf"\d+\s+execve\(({base.QUOTED}), (\[.*\]), .*\)\s*= -1 ENOENT \(No such file or directory\)\n?",
                line,
            )
            path = ast.literal_eval(found[1]) if found else None
            if path in optional_paths:
                argv = ast.literal_eval(found[2])
                key = (path, base.canonical(argv))
                if key not in optional or argv != optional[key]:
                    raise ValueError("optional_probe_argv_drift")
                counts[key] += 1
                if counts[key] > 1:
                    raise ValueError("optional_probe_attempt_limit")
            else:
                retained.append(line)
        if sum(counts.values()) != len(candidates):
            raise ValueError("optional_probe_errno_or_format_not_supported")
        projected_trace = "".join(retained).encode("ascii")
        projected_inventory = dict(inventory)
        del projected_inventory["optional_absent_runtime_probes"]
        projected_inventory_bytes = encoded(projected_inventory)
        projected_process = dict(process)
        projected_process.update(
            trace_sha256=base.digest(projected_trace),
            inventory_sha256=base.digest(projected_inventory_bytes),
        )
        projected_process_bytes = encoded(projected_process)
        checked = base.reconcile(
            projected_trace,
            observation_bytes,
            projected_inventory_bytes,
            projected_process_bytes,
        )
        result.update(
            status=checked["status"],
            issues=checked["issues"],
            optional_absent_probe_count=sum(counts.values()),
            matched_invocations=checked.get("matched_invocations"),
            unmatched_host_invocations=checked.get("unmatched_host_invocations"),
            unmatched_observer_invocations=checked.get(
                "unmatched_observer_invocations"
            ),
            trace_sha256=base.digest(trace_bytes),
            inventory_sha256=base.digest(inventory_bytes),
            observation_sha256=base.digest(observation_bytes),
            process_sha256=base.digest(process_bytes),
            absence_probe_sha256=base.digest(absence_bytes),
            base_auditor_sha256=BASE_SHA256,
            projection={
                "trace_sha256": base.digest(projected_trace),
                "inventory_sha256": base.digest(projected_inventory_bytes),
                "process_sha256": base.digest(projected_process_bytes),
            },
            limits=[
                "Only three explicitly declared Python metadata probe forms with ENOENT are classified.",
                "Absence preflight is caller evidence, not collector authentication or a full resource chain.",
                "No workload correctness, model success, in-process EDA coverage or neutral export claim.",
            ],
        )
    except (
        ValueError,
        TypeError,
        KeyError,
        AttributeError,
        SyntaxError,
        UnicodeError,
    ) as exc:
        safe = (
            str(exc)
            if isinstance(exc, ValueError)
            and re.fullmatch("[a-z_]+(?:;[a-z_]+)*", str(exc))
            else "malformed_evidence"
        )
        result["issues"] = [safe]
    return result
