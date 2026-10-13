"""A complete, content-bound experiment cohort; never authorizes model spend.

The old request is retained as baseline metadata, not misrepresented as the
new command. Public inputs and native API prerequisites are independent gates.
There is deliberately no supported-task-family table or 98/102 partition.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import shutil
import sys
from collections import Counter
from pathlib import Path, PurePosixPath

SCHEMA = "rtlflowbench.complete_public_cohort.v2"
BASE_RUNNER_SHA = "82b8b6407e14a05a057e86da1a927bad9b8b1f4dbbeec582939d845800ad282a"
WORKFLOW_SLOTS = {
    "chipflow": "chipflow",
    "same_model_vanilla_agent": "same_model_vanilla_agent",
    "mage": "external_airtl_1",
    "verilogcoder": "external_airtl_2",
    "hdlagent": "external_airtl_3",
}
REQUIRED_POLICY = {
    "launch_policy_sha256": "12ad99db7e514ac4876a6c0c78bda30b88e2bdc2c799d6c587ac4f3f2dd05989",
    "maximum_provider_calls": 4,
    "maximum_output_tokens_per_call": 8192,
    "maximum_input_tokens": 163840,
    "maximum_output_tokens": 16384,
    "maximum_consecutive_identical_requests": 2,
    "maximum_consecutive_identical_errors": 2,
    "memory_limit_bytes": 1073741824,
    "pids_limit": 128,
}
IDENTITY_FIELDS = (
    "measurement_id",
    "workflow_id",
    "workflow_slot_id",
    "task_id",
    "calibration_run_index",
)


def identity(value):
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode()
    ).hexdigest()


def sha(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError("unsafe regular file: " + path.name)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path, expected):
    if (
        not isinstance(expected, str)
        or not re.fullmatch("[a-f0-9]{64}", expected)
        or sha(path) != expected
    ):
        raise ValueError("content binding drift: " + path.name)
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ValueError("expected JSON object")
    return value


def child(root, relative):
    if root.is_symlink() or not root.is_dir():
        raise ValueError("unsafe artifact root")
    part = PurePosixPath(relative)
    if (
        not relative
        or str(part) != relative
        or part.is_absolute()
        or ".." in part.parts
        or any(p in {"private", "oracle", "evaluator"} for p in part.parts)
    ):
        raise ValueError("unsafe public artifact relative path")
    current = root
    for name in part.parts:
        current = current / name
        if current.is_symlink():
            raise ValueError("symlink in artifact path")
    if not current.exists() or not current.resolve().is_relative_to(root.resolve()):
        raise ValueError("artifact unavailable or outside root")
    return current


def route(workflow):
    if workflow not in WORKFLOW_SLOTS:
        raise ValueError("unknown workflow, not a native route")
    return (
        "existing_native"
        if workflow in {"chipflow", "same_model_vanilla_agent"}
        else "mage_complete_public"
        if workflow == "mage"
        else "external_complete_public"
    )


def validate_policy(policy):
    if any(
        type(policy.get(k)) is not type(v) or policy.get(k) != v
        for k, v in REQUIRED_POLICY.items()
    ):
        raise ValueError("frozen common resource policy drift")


def validate_schedule(baseline, rows):
    if len(baseline) != 200 or len(rows) != 200:
        raise ValueError("full 200-slot schedule required")
    seen = set()
    counts = Counter()
    tasks = set()
    for old, new in zip(baseline, rows, strict=True):
        if any(old.get(k) != new.get(k) for k in IDENTITY_FIELDS):
            raise ValueError("schedule order/identity drift")
        if WORKFLOW_SLOTS.get(new["workflow_id"]) != new["workflow_slot_id"]:
            raise ValueError("slot/workflow mismatch")
        key = (new["workflow_id"], new["task_id"], new["calibration_run_index"])
        if key in seen:
            raise ValueError("duplicate scheduled run")
        seen.add(key)
        counts[new["workflow_id"]] += 1
        tasks.add(new["task_id"])
    if (
        set(counts) != set(WORKFLOW_SLOTS)
        or set(counts.values()) != {40}
        or len(tasks) != 12
    ):
        raise ValueError("incomplete full-matrix coverage")
    for workflow in WORKFLOW_SLOTS:
        for task in tasks:
            if not all((workflow, task, index) in seen for index in (1, 2, 3)):
                raise ValueError("missing three-repeat task/workflow pair")


def summarize(rows):
    return {
        "bound_input_count": len(rows),
        "workflow_attempts": 0,
        "provider_calls": 0,
        "eda_calls": 0,
        "existing_native_prerequisites_deferred_count": sum(
            r["route"] == "existing_native" for r in rows
        ),
        "external_static_prerequisites_satisfied_count": sum(
            r["native_prerequisite_gaps"] == [] for r in rows
        ),
        "explicit_external_prerequisite_gap_count": sum(
            bool(r["native_prerequisite_gaps"]) for r in rows
        ),
        "benchmark_pass_count": None,
        "scientific_block_count": None,
        "adapter_ready": False,
        "benchmark_ready": False,
    }


def base_runner(repo):
    path = (
        repo
        / "benchmarks/golden12/execution/run_controller_aware_resource_measurement.py"
    )
    if sha(path) != BASE_RUNNER_SHA:
        raise ValueError("original controller implementation drift")
    spec = importlib.util.spec_from_file_location(
        "complete_public_pinned_original_controller", path
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    module._validate_runtime_source_closure()
    return module


def public_modules(repo):
    source = repo / "benchmarks/golden12/conformance"
    if str(source) not in sys.path:
        sys.path.insert(0, str(source))
    import complete_public_launch_plan_v2 as external_plan
    import external_complete_public_request_v2 as external_request
    import mage_complete_launch_plan_v2 as mage_plan
    import mage_complete_native_entry_v2 as mage_entry
    import mage_complete_public_request_v2 as mage_request
    import native_complete_public_launcher_v2 as external_entry
    import public_dependency_transport_v2 as dependency
    import public_input_bundle_v2 as public_bundle

    return {
        "external_plan": external_plan,
        "external_request": external_request,
        "mage_plan": mage_plan,
        "mage_entry": mage_entry,
        "mage_request": mage_request,
        "external_entry": external_entry,
        "dependency": dependency,
        "bundle": public_bundle,
    }


def source_binding(repo, base, mods):
    paths = {base.__file__: BASE_RUNNER_SHA}
    paths.update(
        {str(path): expected for path, expected in base.RUNTIME_SOURCE_CLOSURE}
    )
    balance_source = (
        repo / "benchmarks/golden12/execution/run_guarded_resource_batch.py"
    )
    expected_balance_source = (
        "1a70411878ab30a2cdf2f7ba2a40fa821f901f15a0ec7791d4f2a9f144c4b207"
    )
    if sha(balance_source) != expected_balance_source:
        raise ValueError("reviewed balance probe source drift")
    paths[str(balance_source)] = expected_balance_source
    for module in mods.values():
        paths[module.__file__] = sha(Path(module.__file__))
    # The versioned entry and cohort are a separately frozen host layer; upstream
    # source/image identity is preserved rather than overwritten by this layer.
    entry = Path(__file__).with_name("run_complete_public_measurement_v2.py")
    schema = Path(__file__).with_name(
        "complete_public_measurement_request_v2.schema.json"
    )
    return {
        "repository_files": {
            str(Path(path).relative_to(repo)): value
            for path, value in sorted(paths.items())
        },
        "host_files": {
            Path(__file__).name: sha(Path(__file__)),
            entry.name: sha(entry),
            schema.name: sha(schema),
        },
    }


def verify_sources(repo, binding):
    for relative, expected in binding["repository_files"].items():
        if sha(child(repo, relative)) != expected:
            raise ValueError("bound repository runtime drift")
    for name, expected in binding["host_files"].items():
        if name not in {
            "complete_public_cohort_v2.py",
            "run_complete_public_measurement_v2.py",
            "complete_public_measurement_request_v2.schema.json",
        }:
            raise ValueError("unknown host entry source")
        if sha(Path(__file__).with_name(name)) != expected:
            raise ValueError("bound host runtime drift")


def copy_tree(source, target, base):
    expected = base._tree_payload(source)
    if target.exists() or target.is_symlink():
        raise FileExistsError("public target must be fresh")
    shutil.copytree(source, target)
    if base._tree_payload(target) != expected:
        raise ValueError("public transport drift")
    return {"file_count": expected[0], "tree_sha256": expected[1]}


def native_binding(
    *, workflow, request_root, bundle_root, runtime_root, runtime_sha, mods
):
    if workflow == "mage":
        mods["mage_entry"].verify_runtime(runtime_root, runtime_sha)
        request_sha = sha(request_root / "public-request-binding.json")
        request = mods["mage_request"].validate_request(
            request_root=request_root,
            bundle_root=bundle_root,
            expected_binding_sha256=request_sha,
        )
        gaps = []
    else:
        mods["external_entry"].verify_runtime(runtime_root, runtime_sha)
        request_sha = sha(request_root / "native_input.json")
        request = mods["external_request"].validate_request(
            request_root=request_root,
            bundle_root=bundle_root,
            bridge_source=runtime_root / "public_spec_submission_bridge.py",
            expected_request_sha256=request_sha,
        )
        gaps = list(request["native_api_gaps"])
    loaded = mods["bundle"].load_bundle(
        bundle_root, expected_receipt_sha256=request["public_intake_receipt_sha256"]
    )
    try:
        mods["dependency"].declared_dependency_plan(loaded)
    except ValueError as error:
        gaps.append(
            {"gate": "explicit_public_dependency_contract", "reason": str(error)}
        )
    return {
        "request_binding_sha256": request_sha,
        "public_intake_sha256": request["public_intake_receipt_sha256"],
        "native_prerequisite_gaps": gaps,
        "output_shape": request["output_shape"],
    }


def build_campaign(
    *,
    repo,
    baseline_resource_set,
    baseline_resource_sha,
    baseline_bridge_set,
    baseline_bridge_sha,
    intake_audit,
    intake_sha,
    intake_root,
    mage_requests,
    external_requests,
    mage_runtime,
    mage_runtime_sha,
    external_runtime,
    external_runtime_sha,
    output,
):
    base = base_runner(repo)
    mods = public_modules(repo)
    resources = read(baseline_resource_set, baseline_resource_sha)
    bridges = read(baseline_bridge_set, baseline_bridge_sha)
    audit = read(intake_audit, intake_sha)
    base._validate(
        base.HERE / "full_workflow_resource_measurement_request_set.schema.json",
        resources,
        "baseline set",
    )
    base._validate(base.BRIDGE_SET_SCHEMA, bridges, "baseline bridge")
    if bridges["input_sha256"]["resource_request_set"] != baseline_resource_sha:
        raise ValueError("baseline chain drift")
    validate_schedule(resources["requests"], bridges["requests"])
    intake_anchors = {
        row["task_id"]: row["intake_receipt_sha256"] for row in audit["tasks"]
    }
    if (
        audit["workspace_set_sha256"] != bridges["input_sha256"]["public_workspace_set"]
        or len(intake_anchors) != 12
        or len(audit["tasks"]) != 12
    ):
        raise ValueError("complete intake/source workspace mismatch")
    sources = source_binding(repo, base, mods)
    if output.exists() or output.is_symlink():
        raise FileExistsError("cohort root must be new")
    output.mkdir(parents=True)
    # Raw baseline metadata remains present byte-for-byte, and separately named.
    shutil.copyfile(baseline_resource_set, output / "baseline-resource-set.json")
    shutil.copyfile(baseline_bridge_set, output / "baseline-bridge-set.json")
    shutil.copyfile(intake_audit, output / "public-intake-audit.json")
    mods["mage_entry"].verify_runtime(mage_runtime, mage_runtime_sha)
    mods["external_entry"].verify_runtime(external_runtime, external_runtime_sha)
    copy_tree(mage_runtime, output / "runtimes/mage", base)
    copy_tree(external_runtime, output / "runtimes/external", base)
    tasks = sorted({r["task_id"] for r in resources["requests"]})
    for task in tasks:
        mods["bundle"].load_bundle(
            child(intake_root, "bundles/" + task),
            expected_receipt_sha256=intake_anchors[task],
        )
        copy_tree(
            child(intake_root, "bundles/" + task), output / "bundles" / task, base
        )
    rows = []
    for old, bridge in zip(resources["requests"], bridges["requests"], strict=True):
        request_path = child(baseline_resource_set.parent, old["request_relative_path"])
        request = read(request_path, old["request_sha256"])
        base._validate(
            base.RESOURCE_REQUEST_SCHEMA, request, "baseline resource request"
        )
        validate_policy(request["resource_policy"])
        if bridge["resource_request_sha256"] != old["request_sha256"]:
            raise ValueError("baseline bridge request drift")
        workflow = old["workflow_id"]
        task = old["task_id"]
        run = old["calibration_run_index"]
        relative = f"requests/{workflow}/{task}/run-{run}"
        bundle_root = output / "bundles" / task
        payload = {
            "route": route(workflow),
            "request_relative_root": relative,
            "bundle_relative_root": "bundles/" + task,
            "runtime_relative_root": None,
            "runtime_manifest_sha256": None,
            "request_binding_sha256": None,
            "public_intake_sha256": None,
            "native_prerequisite_gaps": None,
            "output_shape": None,
        }
        if route(workflow) == "existing_native":
            _, _, bound_row, source = base._bound_inputs(
                resource_request_path=request_path,
                bridge_set_path=baseline_bridge_set,
                expected_bridge_set_sha256=baseline_bridge_sha,
            )
            if source is None:
                raise ValueError("existing native input is not materialized")
            tree = copy_tree(source, output / relative, base)
            mods["bundle"].load_bundle(
                bundle_root, expected_receipt_sha256=intake_anchors[task]
            )
            payload["public_intake_sha256"] = intake_anchors[task]
            # Prove availability parity without changing native prompt selection.
            for folder, origin in [("public", "public"), ("worktree", "repo")]:
                source_root = bundle_root / "inputs" / origin
                target_root = output / relative / folder
                if source_root.exists() and any(source_root.iterdir()):
                    if base._tree_payload(source_root) != base._tree_payload(
                        target_root
                    ):
                        raise ValueError("internal workflow input availability drift")
            if bound_row["request_payload_sha256"] != tree["tree_sha256"]:
                raise ValueError("internal native request changed")
        else:
            runtime_name = "mage" if workflow == "mage" else "external"
            source = (
                mage_requests / task
                if workflow == "mage"
                else external_requests / workflow / task
            )
            tree = copy_tree(source, output / relative, base)
            runtime_sha = (
                mage_runtime_sha if workflow == "mage" else external_runtime_sha
            )
            payload.update(
                native_binding(
                    workflow=workflow,
                    request_root=output / relative,
                    bundle_root=bundle_root,
                    runtime_root=output / "runtimes" / runtime_name,
                    runtime_sha=runtime_sha,
                    mods=mods,
                )
            )
            payload.update(
                runtime_relative_root="runtimes/" + runtime_name,
                runtime_manifest_sha256=runtime_sha,
            )
        if payload["public_intake_sha256"] != intake_anchors[task]:
            raise ValueError("native request bound to a different public packet")
        payload.update(tree)
        row = {key: old[key] for key in IDENTITY_FIELDS}
        row.update(payload)
        row["baseline_resource_request"] = request
        row["baseline_resource_request_sha256"] = old["request_sha256"]
        row["baseline_resource_relative_path"] = (
            "baseline-requests/" + old["request_relative_path"]
        )
        destination = output / row["baseline_resource_relative_path"]
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(request_path, destination)
        rows.append(row)
    validate_schedule(resources["requests"], rows)
    result = {
        "schema_version": SCHEMA,
        "status": "complete_public_inputs_bound_campaign_not_authorized",
        "baseline_resource_set_sha256": baseline_resource_sha,
        "baseline_bridge_set_sha256": baseline_bridge_sha,
        "public_intake_audit_sha256": intake_sha,
        "source_binding": sources,
        "rows": rows,
        "summary": summarize(rows),
        "requires_versioned_controller": True,
        "new_paid_campaign_authorized": False,
        "official_release": False,
        "private_evaluator_included": False,
        "baseline_results_imported": False,
    }
    (output / "campaign.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n"
    )
    validate_campaign(
        repo=repo,
        path=output / "campaign.json",
        expected_sha=sha(output / "campaign.json"),
    )
    return result


def validate_campaign(*, repo, path, expected_sha):
    value = read(path, expected_sha)
    root = path.parent
    expected_fields = {
        "schema_version",
        "status",
        "baseline_resource_set_sha256",
        "baseline_bridge_set_sha256",
        "public_intake_audit_sha256",
        "source_binding",
        "rows",
        "summary",
        "requires_versioned_controller",
        "new_paid_campaign_authorized",
        "official_release",
        "private_evaluator_included",
        "baseline_results_imported",
    }
    if (
        set(value) != expected_fields
        or value["schema_version"] != SCHEMA
        or value["status"] != "complete_public_inputs_bound_campaign_not_authorized"
        or value["requires_versioned_controller"] is not True
        or any(
            value[key] is not False
            for key in [
                "new_paid_campaign_authorized",
                "official_release",
                "private_evaluator_included",
                "baseline_results_imported",
            ]
        )
    ):
        raise ValueError("invalid complete cohort semantics")
    verify_sources(repo, value["source_binding"])
    base = base_runner(repo)
    mods = public_modules(repo)
    if value["source_binding"] != source_binding(repo, base, mods):
        raise ValueError("incomplete source closure")
    original = read(
        child(root, "baseline-resource-set.json"), value["baseline_resource_set_sha256"]
    )
    bridges = read(
        child(root, "baseline-bridge-set.json"), value["baseline_bridge_set_sha256"]
    )
    intake = read(
        child(root, "public-intake-audit.json"), value["public_intake_audit_sha256"]
    )
    anchors = {row["task_id"]: row["intake_receipt_sha256"] for row in intake["tasks"]}
    if (
        len(anchors) != 12
        or len(intake["tasks"]) != 12
        or bridges["input_sha256"]["resource_request_set"]
        != value["baseline_resource_set_sha256"]
        or bridges["input_sha256"]["public_workspace_set"]
        != intake["workspace_set_sha256"]
    ):
        raise ValueError("baseline intake authority mismatch")
    validate_schedule(original["requests"], value["rows"])
    validate_schedule(original["requests"], bridges["requests"])
    for old, bridge, row in zip(
        original["requests"], bridges["requests"], value["rows"], strict=True
    ):
        base._validate(
            Path(__file__).with_name(
                "complete_public_measurement_request_v2.schema.json"
            ),
            row,
            "complete public row",
        )
        request = read(
            child(root, row["baseline_resource_relative_path"]), old["request_sha256"]
        )
        base._validate(
            base.RESOURCE_REQUEST_SCHEMA, request, "immutable baseline resource request"
        )
        if (
            request != row["baseline_resource_request"]
            or old["request_sha256"] != row["baseline_resource_request_sha256"]
        ):
            raise ValueError("embedded baseline resource request drift")
        validate_policy(request["resource_policy"])
        if row["route"] != route(row["workflow_id"]):
            raise ValueError("workflow route drift")
        request_root = child(root, row["request_relative_root"])
        bundle_root = child(root, row["bundle_relative_root"])
        if base._tree_payload(request_root) != (row["file_count"], row["tree_sha256"]):
            raise ValueError("native request tree drift")
        if row["public_intake_sha256"] != anchors[row["task_id"]]:
            raise ValueError("public input anchor drift")
        mods["bundle"].load_bundle(
            bundle_root, expected_receipt_sha256=anchors[row["task_id"]]
        )
        if row["route"] != "existing_native":
            binding = native_binding(
                workflow=row["workflow_id"],
                request_root=request_root,
                bundle_root=bundle_root,
                runtime_root=child(root, row["runtime_relative_root"]),
                runtime_sha=row["runtime_manifest_sha256"],
                mods=mods,
            )
            if any(binding[k] != row[k] for k in binding):
                raise ValueError("native API/dependency gate drift")
        elif any(
            row[k] is not None
            for k in [
                "runtime_relative_root",
                "runtime_manifest_sha256",
                "request_binding_sha256",
                "native_prerequisite_gaps",
                "output_shape",
            ]
        ):
            raise ValueError(
                "existing native route must not assert external prerequisite readiness"
            )
        elif (
            row["tree_sha256"] != bridge["request_payload_sha256"]
            or row["file_count"] != bridge["request_file_count"]
        ):
            raise ValueError("existing native input byte identity drift")
    if value["summary"] != summarize(value["rows"]):
        raise ValueError("cohort summary differs from all200 rows")
    return value
