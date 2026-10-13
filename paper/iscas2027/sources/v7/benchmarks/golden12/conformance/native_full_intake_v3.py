"""Opt-in full-review public intake; never a paid launcher or readiness claim.

Prepare real native context and a five-role graph using the existing core
factory. The diagnostic entry has no provider credentials or default model
dispatch. It deliberately stops at the model boundary. Instrumentation gaps
are reported separately from native API support and RTL correctness.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import shutil
import sys
from pathlib import Path


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def save(path, value):
    with Path(path).open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write("\n")


def load_controller(root):
    path = root / "benchmarks/golden12/chipflow/controller.py"
    spec = importlib.util.spec_from_file_location("_full_intake_controller", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def tree_binding(root):
    """Reject links and special files; retain every input byte in the binding."""
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("input_root_not_regular_directory")
    result = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError("input_symlink")
        if path.is_dir():
            continue
        if not path.is_file():
            raise ValueError("input_not_regular_file")
        result[path.relative_to(root).as_posix()] = digest(path)
    return result


def command_coverage(oracle, bindings, *, search_path):
    """Conservative compatibility with v2 direct native EDA observation.

    An interpreter/container/script is NOT counted as an EDA tool, and its
    descendants are not claimed covered. This is planning, not execution.
    """
    tools = {}
    for item in bindings:
        if set(item) != {"path", "tool", "sha256"}:
            raise ValueError("invalid_tool_binding")
        path = Path(item["path"])
        if not path.is_absolute() or path.is_symlink() or str(path.resolve()) != str(path) or item["tool"] not in {"iverilog", "vvp", "yosys"} or str(path) in tools or digest(path) != item["sha256"]:
            raise ValueError("invalid_or_drifted_tool_binding")
        tools[str(path)] = item
    commands = oracle.get("commands")
    if not isinstance(commands, list) or not commands:
        raise ValueError("missing_public_commands")
    rows = []
    seen = set()
    for command in commands:
        command_id = command.get("command_id")
        argv = command.get("argv")
        if not isinstance(command_id, str) or not command_id or command_id in seen or not isinstance(argv, list) or not argv or not all(isinstance(v, str) and v for v in argv):
            raise ValueError("invalid_public_command")
        seen.add(command_id)
        executable = shutil.which(argv[0], path=search_path)
        selected = tools.get(executable)
        reason = "executable_missing" if executable is None else "direct_tool_bound" if selected else "native_observer_v2_has_no_wrapper_descendant_route"
        rows.append(
            {
                "command_id": command_id,
                "status": "bound_direct_tool" if selected else "instrumentation_gap",
                "reason": reason,
                "tool": selected["tool"] if selected else None,
                "resolved_executable_sha256": digest(executable) if executable else None,
            }
        )
    return rows


def validate_topology(graph, reviewers):
    """Inspect the graph actually constructed, not a config boolean."""
    topology = graph.get_graph()
    nodes = set(topology.nodes)
    expected = {"REVIEW__" + r.replace("-", "_").upper() for r in reviewers}
    actual = {n for n in nodes if n.startswith("REVIEW__")}
    required = {
        "CONTRACT",
        "DESIGN",
        "ENGINEERING_ROUNDTABLE",
        "JUDGE",
        "PATCH_PLAN",
        "UNIT_APPROVAL",
        "EXECUTE",
        "SMOKE_VERIFY",
        "DEBUG",
        "BLOCKED",
    }
    if len(expected) != 5 or actual != expected or not required.issubset(nodes):
        raise ValueError("full_review_topology_missing")
    edges = {(e.source, e.target) for e in topology.edges}
    if any((r, "ENGINEERING_ROUNDTABLE") not in edges for r in expected):
        raise ValueError("review_join_missing")
    if ("ENGINEERING_ROUNDTABLE", "JUDGE") not in edges:
        raise ValueError("roundtable_judge_handoff_missing")
    return {
        "reviewer_ids": list(reviewers),
        "nodes": sorted(nodes),
        "edges": sorted([list(e) for e in edges]),
    }


def prepare(
    *,
    root,
    public_root,
    workspace_source,
    output,
    runnable_config,
    owner_id,
    thread_id,
    request_id,
    dispatch,
    checkpointer,
    python_public_verification=None,
    broker_session_id=None,
    compute_envelope=None,
):
    """Native preparation shared with a future separately authorized launcher.

    The caller owns environment/source/runtime isolation and accounting.
    Dispatch is required: there is no implicit paid-provider fallback.
    No graph invocation, approval, RTL edit, or neutral export occurs here.
    """
    if not callable(dispatch):
        raise ValueError("explicit_dispatch_required")
    if python_public_verification is None:
        if broker_session_id is not None or compute_envelope is not None:
            raise ValueError("broker_session_requires_explicit_python_profile")
    else:
        from langgraph.checkpoint.sqlite import SqliteSaver

        if type(broker_session_id) is not str or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", broker_session_id) is None or not isinstance(checkpointer, SqliteSaver):
            raise ValueError("explicit_host_session_and_durable_sqlite_required")
    compute_binding = None
    if compute_envelope is not None:
        from deerflow.chipflow.research.compute_envelope import require_compute_envelope

        require_compute_envelope(compute_envelope).check_active()
        compute_binding = compute_envelope.binding()
    output = Path(output)
    if output.exists() or output.is_symlink():
        raise FileExistsError("fresh_intake_output_required")
    before = tree_binding(public_root)
    workspace_before = tree_binding(workspace_source)
    controller = load_controller(root)
    task = controller._load_object(public_root / "external_task.json", "public task")
    controller._validate(root / "benchmarks/golden12/schemas/task.schema.json", task, "task")
    from deerflow.chipflow.native_subagents import freeze_native_chipflow_run_runtime
    from deerflow.chipflow.research.design_unit_full_review import REVIEWERS
    from deerflow.chipflow.research.design_unit_full_runtime import (
        build_full_engineering_design_unit_graph,
    )
    from deerflow.chipflow.research.design_unit_runtime import (
        materialize_design_unit_context,
    )
    from deerflow.chipflow.research.public_packet_runtime import (
        admit_public_packet_interface,
        compile_public_packet_runtime_spec,
    )

    if admit_public_packet_interface(public_root=public_root, external_task=task) is None:
        raise ValueError("full_design_unit_intake_does_not_select_cpu_route")
    wall = task["budget"]["wall_time_seconds"]
    if type(wall) is not int or wall <= 0:
        raise ValueError("invalid_public_wall_budget")
    oracle, _ = controller._public_visible_oracle(public_root=public_root, task_id=task["task_id"], wall_time_seconds=wall)
    output.mkdir(mode=0o700)
    save(output / "public-visible-oracle.json", oracle)
    spec = compile_public_packet_runtime_spec(
        public_root=public_root,
        external_task=task,
        workspace_source=workspace_source,
        oracle_source=output / "public-visible-oracle.json",
        python_public_verification=python_public_verification,
    )
    if spec is None:
        raise ValueError("non_cpu_projection_disappeared")
    context, state = materialize_design_unit_context(
        spec=spec,
        run_root=output / "native-run",
        owner_id=owner_id,
        thread_id=thread_id,
        request_id=request_id,
        runnable_config=runnable_config,
    )
    # The explicit Python branch uses the existing host-owned session; do not
    # send submitted Python through the legacy graph's host EDA callback.
    if python_public_verification is not None:
        from deerflow.chipflow.research.python_broker_session import PythonBrokerSession

        graph = PythonBrokerSession(
            context,
            checkpointer=checkpointer,
            config=runnable_config,
            session_id=broker_session_id,
            dispatch=dispatch,
            compute_envelope=compute_envelope,
        )
    else:
        graph = None
    frozen = freeze_native_chipflow_run_runtime(run_dir=context.run_dir, runnable_config=runnable_config)
    if frozen.status != "completed" or not frozen.manifest_hash:
        save(
            output / "runtime-freeze-failure.json",
            {
                "status": frozen.status,
                "blocked_reason": frozen.blocked_reason,
                "diagnostic_only": True,
            },
        )
        raise ValueError("native_runtime_freeze_failed")
    state["runtime_manifest_hash"] = frozen.manifest_hash
    if graph is None:
        graph = build_full_engineering_design_unit_graph(
            context,
            dispatch=dispatch,
            checkpointer=checkpointer,
            use_langgraph_interrupts=True,
        )
    if python_public_verification is not None:
        # Freeze can load substantial configuration/skills. Revalidate the
        # earlier input/profile binding rather than certifying stale intake.
        spec.validate()
        if compute_envelope is not None:
            compute_envelope.check_active()
            if compute_envelope.binding() != compute_binding:
                raise ValueError("compute_parent_drift_during_native_preparation")
    topology = validate_topology(graph, REVIEWERS)
    if tree_binding(public_root) != before or tree_binding(workspace_source) != workspace_before:
        raise ValueError("input_drift_during_native_preparation")
    receipt = {
        "schema_version": "chipflow.full_native_intake.v3",
        "task_id": task["task_id"],
        "public_files": before,
        "workspace_files": workspace_before,
        "runtime_manifest_hash": frozen.manifest_hash,
        "public_budget": task["budget"],
        "topology": topology,
        "native_context_prepared": True,
        "native_workflow_verified": False,
        "paid_launch_authorized": False,
        "adapter_ready": False,
        "benchmark_ready": False,
        "provider_usage": None,
        "benchmark_verdict": None,
        "entry_source_sha256": digest(__file__),
        "native_factory_source_sha256": digest(sys.modules[build_full_engineering_design_unit_graph.__module__].__file__),
        "controller_source_sha256": digest(controller.__file__),
    }
    if python_public_verification is not None:
        receipt.update(
            schema_version="chipflow.full_native_python_intake.v1",
            python_intake_sha256=spec.python_intake_sha256,
            host_session_source_sha256=digest(sys.modules[PythonBrokerSession.__module__].__file__),
            whole_workflow_usage=None,
            neutral_submission_exported=False,
            outer_container_integrated=False,
        )
        if compute_binding is not None:
            receipt.update(schema_version="chipflow.full_native_python_intake.v2", compute_envelope=compute_binding, worker_placement_verified=False)
    save(output / "intake.json", receipt)
    return context, state, graph, oracle, receipt
