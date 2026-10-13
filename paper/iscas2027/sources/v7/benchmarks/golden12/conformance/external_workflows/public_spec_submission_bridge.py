#!/usr/bin/env python3
"""Fail-closed public-only bridge for external Spec-to-RTL workflows.

This module does not invoke a model, an EDA tool, or a private evaluator.  It
projects one Golden-12 public packet into the native public input accepted by
VerilogCoder or HDLAgent and maps an already-produced RTL file byte-for-byte
into the neutral submission contract.  Capability mismatches remain explicit
controller BLOCKs in the all-task schedule; they are never silently omitted.
"""

from __future__ import annotations

import argparse
import ast
from dataclasses import dataclass
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
from typing import Any


HERE = Path(__file__).resolve().parent
CONFORMANCE_ROOT = HERE.parent
PUBLIC_SPEC_PATHS = (
    "spec/design_spec.md",
    "spec/acceptance_spec.json",
    "spec/interface_spec.json",
)
BRIDGE_NAME = "rtlflowbench-public-spec-submission-bridge"
BRIDGE_VERSION = "2"
SUPPORTED_FAMILY = "spec_to_rtl"
FORBIDDEN_PATH_PARTS = frozenset({"private", "evaluator", "reference"})


@dataclass(frozen=True)
class WorkflowSpec:
    workflow_id: str
    display_name: str
    commit: str
    source_archive_sha256: str
    tracked_manifest_sha256: str
    launcher: str


WORKFLOWS = {
    "verilogcoder": WorkflowSpec(
        workflow_id="verilogcoder",
        display_name="VerilogCoder",
        commit="8b13108869f276c7b644dd88beabcb401a5cfa92",
        source_archive_sha256=(
            "68e51d9b7a4d1232560d68b9157112191579b34b860dd1ce722e59f8abf615e1"
        ),
        tracked_manifest_sha256=(
            "01ac57a9e5bdb79d12055554fc5646d2b6451602f982377f48f35505d2328d69"
        ),
        launcher="run_verilogcoder_public.py",
    ),
    "hdlagent": WorkflowSpec(
        workflow_id="hdlagent",
        display_name="HDLAgent",
        commit="bd2321e03d1d60b0656d7ff0992f35f5906a824d",
        source_archive_sha256=(
            "078b19c50456b4bccb59527a3f9d7a23e984ebd982c0f572256f1014d3212d8a"
        ),
        tracked_manifest_sha256=(
            "843ccf62106d6ae2e953f5d5b5a8fd7ea4160c969084d010acc59d4e7ba6d91f"
        ),
        launcher="run_hdlagent_public.py",
    ),
}


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ValueError(f"could not load module: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _load_object(path: Path, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a regular non-symlink file")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{label} must contain one JSON object")
    return value


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _canonical_sha256(value: dict[str, Any]) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return _sha256_bytes(encoded)


def _write_new_json(path: Path, value: dict[str, Any]) -> None:
    if path.exists() or path.is_symlink():
        raise FileExistsError(f"refusing to overwrite output: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _resolve_public_root(path: Path) -> Path:
    unresolved = path.expanduser().absolute()
    if unresolved.is_symlink():
        raise ValueError("task public root must be a regular non-symlink directory")
    root = unresolved.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("task public root must be a regular non-symlink directory")
    if (
        root.name != "public"
        or root.parent.parent.name != "tasks"
        or root.parent.parent.parent.name != "golden12"
        or root.parent.parent.parent.parent.name != "benchmarks"
    ):
        raise ValueError(
            "task public root must be benchmarks/golden12/tasks/<task>/public"
        )
    if (root / "private").exists() or (root / "evaluator").exists():
        raise ValueError("task public root contains a private evaluator directory")
    return root


def _read_public_file(root: Path, relative: str) -> tuple[bytes, Path]:
    relative_path = Path(relative)
    if (
        relative_path.is_absolute()
        or ".." in relative_path.parts
        or any(part in FORBIDDEN_PATH_PARTS for part in relative_path.parts)
    ):
        raise ValueError(f"unsafe public input path: {relative}")
    path = root / relative_path
    resolved = path.resolve(strict=True)
    if root not in resolved.parents or path.is_symlink() or not path.is_file():
        raise ValueError(f"public input is not a regular in-root file: {relative}")
    return path.read_bytes(), path


def _task(root: Path) -> tuple[dict[str, Any], Any]:
    packager = _load_module(
        "rtlflowbench_public_spec_packager",
        CONFORMANCE_ROOT / "package_submission.py",
    )
    task = _load_object(root / "external_task.json", "task descriptor")
    packager._validate("task", task)
    return task, packager


def classify_public_task_shape(task: dict[str, Any]) -> dict[str, Any]:
    """Classify support from public shape fields, never from a task id."""
    if task.get("family") != SUPPORTED_FAMILY:
        return {
            "supported": False,
            "reason_code": "unsupported_capability",
            "reason": (
                "The upstream workflow exposes a Spec-to-RTL generation path, "
                "not this Golden-12 capability family."
            ),
        }
    public = task.get("public_packet")
    if not isinstance(public, dict):
        return {
            "supported": False,
            "reason_code": "missing_required_public_contract",
            "reason": "The public packet declaration is missing.",
        }
    if public.get("contains_evaluator_assets") is not False:
        return {
            "supported": False,
            "reason_code": "security_policy_block",
            "reason": "The public packet does not prove evaluator-asset exclusion.",
        }
    if public.get("network_access") is not False:
        return {
            "supported": False,
            "reason_code": "missing_required_public_contract",
            "reason": "The adapter requires an offline workflow workspace.",
        }
    contract = task.get("submission_contract")
    if not isinstance(contract, dict):
        return {
            "supported": False,
            "reason_code": "missing_required_public_contract",
            "reason": "The submission contract is missing.",
        }
    required = contract.get("required_files")
    editable = contract.get("editable_paths")
    if (
        not isinstance(required, list)
        or len(required) != 1
        or editable != required
    ):
        return {
            "supported": False,
            "reason_code": "unsupported_submission_shape",
            "reason": (
                "The upstream generation path emits one new RTL module and "
                "cannot neutrally represent this output contract."
            ),
        }
    target = required[0]
    if not isinstance(target, str) or not target.endswith((".sv", ".v")):
        return {
            "supported": False,
            "reason_code": "unsupported_submission_shape",
            "reason": "The single required output is not a Verilog source file.",
        }
    return {
        "supported": True,
        "reason_code": None,
        "reason": None,
        "target_output_path": target,
    }


def _check_supported(task: dict[str, Any]) -> str:
    result = classify_public_task_shape(task)
    if not result["supported"]:
        raise ValueError(
            f"public spec bridge {result['reason_code']}: {result['reason']}"
        )
    return result["target_output_path"]


def _source_binding(
    workflow_id: str,
    *,
    upstream_commit: str,
    source_manifest_sha256: str,
) -> WorkflowSpec:
    try:
        workflow = WORKFLOWS[workflow_id]
    except KeyError as exc:
        raise ValueError(f"unsupported workflow id: {workflow_id}") from exc
    if upstream_commit != workflow.commit:
        raise ValueError("upstream commit disagrees with the reviewed source")
    if source_manifest_sha256 != workflow.tracked_manifest_sha256:
        raise ValueError("source manifest disagrees with the reviewed source")
    return workflow


def _check_release_task(
    task: dict[str, Any], isolation_receipt_path: Path | None
) -> dict[str, Any]:
    if (
        task["packet_status"] != "frozen"
        or task["public_packet"]["digest_status"] != "frozen"
        or task["public_packet"]["sha256"] is None
        or task["budget"]["status"] != "frozen"
    ):
        raise ValueError("release mode requires a frozen packet, digest and budget")
    if (
        task["rights"]["status"] != "approved"
        or not task["rights"]["redistribution_review_complete"]
    ):
        raise ValueError("release mode requires completed independent rights review")
    if isolation_receipt_path is None:
        raise ValueError("release mode requires an isolation receipt")
    receipt = _load_object(isolation_receipt_path, "isolation receipt")
    required = {
        "status": "pass",
        "provider_egress_separated": True,
        "workspace_network_disabled": True,
        "eda_subprocess_network_disabled": True,
    }
    if any(receipt.get(key) != value for key, value in required.items()):
        raise ValueError("isolation receipt does not prove separated offline EDA")
    evidence_sha256 = receipt.get("evidence_sha256")
    if not isinstance(evidence_sha256, str) or not re.fullmatch(
        r"[0-9a-f]{64}", evidence_sha256
    ):
        raise ValueError("isolation receipt evidence_sha256 is invalid")
    return {
        "status": "pass",
        "receipt_sha256": _sha256(isolation_receipt_path),
        "evidence_sha256": evidence_sha256,
    }


def _build_prompt(root: Path) -> tuple[str, list[dict[str, Any]]]:
    sections: list[str] = []
    sources: list[dict[str, Any]] = []
    for relative in PUBLIC_SPEC_PATHS:
        content, path = _read_public_file(root, relative)
        if len(content) > 1_048_576:
            raise ValueError(f"public specification is unexpectedly large: {relative}")
        text = content.decode("utf-8")
        sections.append(f"## {relative}\n\n{text.rstrip()}\n")
        sources.append(
            {"path": relative, "sha256": _sha256(path), "bytes": len(content)}
        )
    return "\n".join(sections), sources


def _visible_testbench(root: Path) -> tuple[bytes, str, dict[str, Any]]:
    plan = _load_object(root / "visible/plan.json", "visible test plan")
    if plan.get("contains_testbench") is not True:
        raise ValueError("VerilogCoder requires a public visible testbench")
    candidates = sorted((root / "visible").glob("*_visible_tb.sv"))
    if len(candidates) != 1:
        raise ValueError("expected exactly one public visible SystemVerilog testbench")
    source = candidates[0]
    relative = source.relative_to(root).as_posix()
    original, _ = _read_public_file(root, relative)
    text = original.decode("utf-8")
    module_match = re.search(r"(?m)^module\s+([A-Za-z_][A-Za-z0-9_]*)\b", text)
    if module_match is None:
        raise ValueError("public visible testbench has no top module declaration")
    module_name = module_match.group(1)
    declaration = f"module {module_name}"
    if text.count(declaration) != 1:
        raise ValueError("public visible top module declaration is ambiguous")
    text = text.replace(declaration, "module tb", 1)
    pass_marker = "GOLDEN12_VISIBLE_PASS"
    marker_position = text.find(pass_marker)
    if marker_position < 0:
        raise ValueError("public visible testbench has no PASS sentinel")
    finish_position = text.find("$finish;", marker_position)
    if finish_position < 0:
        raise ValueError("public visible testbench has no post-PASS finish")
    sentinel = '$display("Mismatches: 0 in 1 samples");\n    '
    text = text[:finish_position] + sentinel + text[finish_position:]
    transformed = text.encode("utf-8")
    binding = {
        "source_path": relative,
        "source_sha256": _sha256_bytes(original),
        "source_bytes": len(original),
        "projected_path": "input/public_visible_tb.sv",
        "projected_sha256": _sha256_bytes(transformed),
        "projected_bytes": len(transformed),
        "transformations": [
            "rename_public_visible_top_module_to_tb",
            "emit_VerilogCoder_zero_mismatch_protocol_only_after_public_PASS",
        ],
        "private_or_reference_testbench_included": False,
    }
    return transformed, relative, binding


def _rewrite_public_ternary(expression: str) -> str:
    match = re.fullmatch(
        r"\s*\((?P<condition>[^?]+)\)\s*\?\s*"
        r"(?P<true_value>[^:]+)\s*:\s*(?P<false_value>.+)\s*",
        expression,
    )
    if match is None:
        return expression
    return (
        f"({match.group('true_value')} if {match.group('condition')} "
        f"else {match.group('false_value')})"
    )


def _evaluate_public_width(expression: str, defaults: dict[str, int]) -> int:
    rewritten = _rewrite_public_ternary(expression).replace("$clog2", "clog2")
    try:
        tree = ast.parse(rewritten, mode="eval")
    except SyntaxError as exc:
        raise ValueError("interface width contains unsupported syntax") from exc

    def evaluate(node: ast.AST) -> int | bool:
        if isinstance(node, ast.Expression):
            return evaluate(node.body)
        if isinstance(node, ast.Constant) and type(node.value) is int:
            return node.value
        if isinstance(node, ast.Name) and node.id in defaults:
            return defaults[node.id]
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
            value = evaluate(node.operand)
            if type(value) is not int:
                raise ValueError("width unary operand is not an integer")
            return value if isinstance(node.op, ast.UAdd) else -value
        if isinstance(node, ast.BinOp) and isinstance(
            node.op, (ast.Add, ast.Sub, ast.Mult, ast.FloorDiv)
        ):
            left = evaluate(node.left)
            right = evaluate(node.right)
            if type(left) is not int or type(right) is not int:
                raise ValueError("width arithmetic operand is not an integer")
            if isinstance(node.op, ast.Add):
                return left + right
            if isinstance(node.op, ast.Sub):
                return left - right
            if isinstance(node.op, ast.Mult):
                return left * right
            if right == 0:
                raise ValueError("width division by zero")
            return left // right
        if isinstance(node, ast.Compare) and len(node.ops) == len(node.comparators) == 1:
            left = evaluate(node.left)
            right = evaluate(node.comparators[0])
            if type(left) is not int or type(right) is not int:
                raise ValueError("width comparison operand is not an integer")
            operator = node.ops[0]
            if isinstance(operator, ast.Lt):
                return left < right
            if isinstance(operator, ast.LtE):
                return left <= right
            if isinstance(operator, ast.Gt):
                return left > right
            if isinstance(operator, ast.GtE):
                return left >= right
            if isinstance(operator, ast.Eq):
                return left == right
            raise ValueError("width comparison operator is unsupported")
        if isinstance(node, ast.IfExp):
            condition = evaluate(node.test)
            if type(condition) is not bool:
                raise ValueError("width conditional is not boolean")
            return evaluate(node.body if condition else node.orelse)
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "clog2"
            and len(node.args) == 1
            and not node.keywords
        ):
            value = evaluate(node.args[0])
            if type(value) is not int or value < 1:
                raise ValueError("$clog2 width argument must be positive")
            return (value - 1).bit_length()
        raise ValueError("interface width expression is outside the public subset")

    result = evaluate(tree)
    if type(result) is not int or not 1 <= result <= 1024 * 1024:
        raise ValueError("interface width does not resolve to a supported positive value")
    return result


def _hdlagent_interface(interface: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    top = interface.get("top_module")
    if not isinstance(top, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", top):
        raise ValueError("interface top_module is invalid")
    parameters = interface.get("parameters", [])
    ports = interface.get("ports")
    if not isinstance(parameters, list) or not isinstance(ports, list) or not ports:
        raise ValueError("interface parameters or ports are invalid")
    defaults: dict[str, int] = {}
    for item in parameters:
        name = item.get("name")
        default = item.get("default")
        declared_type = item.get("type", "integer")
        if not isinstance(name, str) or not re.fullmatch(
            r"[A-Za-z_][A-Za-z0-9_]*", name
        ):
            raise ValueError("interface parameter name is invalid")
        if type(default) is not int or default < 1:
            raise ValueError("interface parameter default is not a positive integer")
        if declared_type not in {"int unsigned", "integer", "positive_integer"}:
            raise ValueError("interface parameter type is unsupported")
        defaults[name] = default
    derived = interface.get("derived_widths", {})
    if derived is None:
        derived = {}
    if not isinstance(derived, dict) or any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in derived.items()
    ):
        raise ValueError("interface derived widths are invalid")
    rendered_ports = []
    for item in ports:
        name = item.get("name")
        direction = item.get("direction")
        width = item.get("width")
        if (
            not isinstance(name, str)
            or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name)
            or direction not in {"input", "output", "inout"}
            or not isinstance(width, str)
        ):
            raise ValueError("interface port is invalid")
        width_expression = derived.get(width, width)
        resolved_width = _evaluate_public_width(width_expression, defaults)
        rendered_ports.append(
            f"  {direction} [{resolved_width - 1}:0] {name}"
        )
    declaration = f"module {top}(\n" + ",\n".join(rendered_ports) + "\n);"
    projection = {
        "version": "hdlagent-default-parameter-interface-v3",
        "parameter_defaults": defaults,
        "authoritative_parameter_contract": "public_description_and_interface_spec",
        "native_design_name": top,
        "native_design_name_source": "public_interface_spec.top_module",
        "native_filename_binding_required_by_upstream": True,
        "purpose": "upstream_parser_compatibility_only",
    }
    return declaration, projection


def _yaml_block(value: str, *, indent: int = 2) -> str:
    prefix = " " * indent
    return "\n".join(prefix + line for line in value.rstrip().splitlines())


def _hdlagent_spec(
    prompt: str, interface: dict[str, Any]
) -> tuple[bytes, dict[str, Any]]:
    declaration, projection = _hdlagent_interface(interface)
    value = (
        "description: |\n"
        f"{_yaml_block(prompt)}\n"
        "interface: |\n"
        f"{_yaml_block(declaration)}\n"
    )
    return value.encode("utf-8"), projection


def _configuration(
    *,
    workflow: WorkflowSpec,
    task: dict[str, Any],
    mode: str,
    target: str,
    input_files: list[dict[str, Any]],
    isolation: dict[str, Any],
) -> dict[str, Any]:
    return {
        "adapter_name": BRIDGE_NAME,
        "adapter_version": BRIDGE_VERSION,
        "workflow_id": workflow.workflow_id,
        "upstream_commit": workflow.commit,
        "source_manifest_sha256": workflow.tracked_manifest_sha256,
        "task_descriptor_sha256": _canonical_sha256(task),
        "mode": mode,
        "target_output_path": target,
        "input_files": input_files,
        "isolation": isolation,
    }


def prepare_request(
    *,
    workflow_id: str,
    task_public_root: Path,
    output_dir: Path,
    observed_at: str,
    mode: str,
    upstream_commit: str,
    source_manifest_sha256: str,
    isolation_receipt_path: Path | None = None,
) -> dict[str, Any]:
    if mode not in {"development", "release"}:
        raise ValueError("mode must be development or release")
    output_dir = output_dir.expanduser().absolute()
    if output_dir.exists() or output_dir.is_symlink():
        raise FileExistsError(f"refusing to overwrite output: {output_dir}")
    workflow = _source_binding(
        workflow_id,
        upstream_commit=upstream_commit,
        source_manifest_sha256=source_manifest_sha256,
    )
    root = _resolve_public_root(task_public_root)
    task, _ = _task(root)
    target = _check_supported(task)
    isolation = (
        _check_release_task(task, isolation_receipt_path)
        if mode == "release"
        else {"status": "unproven_development_only"}
    )
    prompt, public_sources = _build_prompt(root)
    prompt_bytes = prompt.encode("utf-8")
    input_payloads: dict[str, bytes] = {"input/public_prompt.txt": prompt_bytes}
    input_files = [
        {
            "path": "input/public_prompt.txt",
            "sha256": _sha256_bytes(prompt_bytes),
            "bytes": len(prompt_bytes),
        }
    ]
    visible_testbench = None
    if workflow_id == "verilogcoder":
        testbench, _, visible_testbench = _visible_testbench(root)
        input_payloads["input/public_visible_tb.sv"] = testbench
        input_files.append(
            {
                "path": "input/public_visible_tb.sv",
                "sha256": _sha256_bytes(testbench),
                "bytes": len(testbench),
            }
        )
        expected_output = f"generated_verilog/{task['task_id']}_0.v"
        native_input = {
            "kind": "VerilogCoder.write_Verilog_module arguments",
            "spec_path": "input/public_prompt.txt",
            "visible_testbench_path": "input/public_visible_tb.sv",
            "visible_testbench_binding": visible_testbench,
            "golden_reference_rtl_path": None,
        }
    else:
        interface = _load_object(root / "spec/interface_spec.json", "interface spec")
        yaml_bytes, interface_projection = _hdlagent_spec(prompt, interface)
        native_design_name = interface_projection["native_design_name"]
        native_spec_path = f"input/{native_design_name}.yaml"
        input_payloads[native_spec_path] = yaml_bytes
        input_files.append(
            {
                "path": native_spec_path,
                "sha256": _sha256_bytes(yaml_bytes),
                "bytes": len(yaml_bytes),
            }
        )
        expected_output = f"{native_design_name}/{native_design_name}.v"
        native_input = {
            "kind": "HDLAgent spec YAML build input",
            "spec_path": native_spec_path,
            "bench_response": None,
            "golden_reference_rtl_path": None,
            "external_hdeval_alias": None,
            "interface_projection": interface_projection,
        }
    configuration = _configuration(
        workflow=workflow,
        task=task,
        mode=mode,
        target=target,
        input_files=input_files,
        isolation=isolation,
    )
    request = {
        "schema_version": "rtlflowbench.public_spec_bridge_request.v1",
        "observed_at": observed_at,
        "status": (
            "release_request_prepared_not_run"
            if mode == "release"
            else "development_only_not_run"
        ),
        "mode": mode,
        "workflow": {
            "workflow_id": workflow.workflow_id,
            "display_name": workflow.display_name,
            "commit": workflow.commit,
            "source_archive_sha256": workflow.source_archive_sha256,
            "tracked_manifest_sha256": workflow.tracked_manifest_sha256,
        },
        "task_id": task["task_id"],
        "task_binding": {
            "benchmark_id": task["benchmark_id"],
            "benchmark_version": task["benchmark_version"],
            "task_descriptor_sha256": _canonical_sha256(task),
            "public_packet_sha256": task["public_packet"]["sha256"],
        },
        "support_classification": classify_public_task_shape(task),
        "public_sources": public_sources,
        "input_files": input_files,
        "native_input": native_input,
        "execution": {
            "launcher": workflow.launcher,
            "expected_output_path_relative_to_work_dir": expected_output,
            "provider_configuration_embedded": False,
            "private_evaluator_available": False,
        },
        "submitted_output_path": target,
        "isolation": isolation,
        "configuration_sha256": _canonical_sha256(configuration),
        "airtl_run_observed": False,
        "hidden_evaluator_run": False,
        "rtl_verdict_produced": False,
        "adapter_ready": False,
        "benchmark_ready": False,
        "excluded_claims": [
            "A public input projection is not an AIRTL workflow run.",
            "No private evaluator, hidden test, reference RTL or human solution is supplied.",
            "No PASS, FAIL, score, QoR, PPA, readiness or publication claim is made.",
        ],
    }
    output_dir.mkdir(parents=True)
    for relative, content in input_payloads.items():
        path = output_dir / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    _write_new_json(output_dir / "bridge_request.json", request)
    return request


def _validate_prepared_request(
    *,
    root: Path,
    task: dict[str, Any],
    request_path: Path,
) -> tuple[dict[str, Any], WorkflowSpec, str]:
    request = _load_object(request_path, "bridge request")
    if request.get("schema_version") != "rtlflowbench.public_spec_bridge_request.v1":
        raise ValueError("unsupported public spec bridge request")
    workflow_value = request.get("workflow")
    if not isinstance(workflow_value, dict):
        raise ValueError("bridge request workflow binding is missing")
    workflow_id = workflow_value.get("workflow_id")
    if workflow_id not in WORKFLOWS:
        raise ValueError("bridge request workflow identity is unsupported")
    workflow = WORKFLOWS[workflow_id]
    if workflow_value != {
        "workflow_id": workflow.workflow_id,
        "display_name": workflow.display_name,
        "commit": workflow.commit,
        "source_archive_sha256": workflow.source_archive_sha256,
        "tracked_manifest_sha256": workflow.tracked_manifest_sha256,
    }:
        raise ValueError("bridge request workflow source binding drift")
    target = _check_supported(task)
    if request.get("task_id") != task["task_id"]:
        raise ValueError("bridge request task identity drift")
    binding = request.get("task_binding")
    if not isinstance(binding, dict) or binding != {
        "benchmark_id": task["benchmark_id"],
        "benchmark_version": task["benchmark_version"],
        "task_descriptor_sha256": _canonical_sha256(task),
        "public_packet_sha256": task["public_packet"]["sha256"],
    }:
        raise ValueError("bridge request task binding drift")
    if request.get("support_classification") != classify_public_task_shape(task):
        raise ValueError("bridge request support classification drift")
    if request.get("submitted_output_path") != target:
        raise ValueError("bridge request target output drift")
    request_root = request_path.expanduser().resolve(strict=True).parent
    files = request.get("input_files")
    if not isinstance(files, list) or not files:
        raise ValueError("bridge request input file manifest is missing")
    for item in files:
        relative = item.get("path")
        if not isinstance(relative, str):
            raise ValueError("bridge request input path is invalid")
        path = request_root / relative
        resolved = path.resolve(strict=True)
        if (
            request_root not in resolved.parents
            or path.is_symlink()
            or not path.is_file()
            or _sha256(path) != item.get("sha256")
            or path.stat().st_size != item.get("bytes")
        ):
            raise ValueError("bridge request input file digest drift")
    if any(
        request.get(key) is not False
        for key in (
            "airtl_run_observed",
            "hidden_evaluator_run",
            "rtl_verdict_produced",
            "adapter_ready",
            "benchmark_ready",
        )
    ):
        raise ValueError("bridge request contains an unsupported success claim")
    return request, workflow, target


def collect_output(
    *,
    task_public_root: Path,
    request_path: Path,
    metadata_path: Path,
    workflow_output_path: Path,
    bundle_root: Path,
    submission_path: Path,
    receipt_path: Path,
    observed_at: str,
) -> dict[str, Any]:
    root = _resolve_public_root(task_public_root)
    task, packager = _task(root)
    request, workflow, target = _validate_prepared_request(
        root=root,
        task=task,
        request_path=request_path,
    )
    metadata = _load_object(metadata_path, "submission metadata")
    workflow_metadata = metadata.get("workflow")
    if not isinstance(workflow_metadata, dict):
        raise ValueError("submission workflow metadata is missing")
    if (
        workflow_metadata.get("name") != workflow.display_name
        or workflow_metadata.get("adapter_name") != BRIDGE_NAME
        or workflow_metadata.get("adapter_version") != BRIDGE_VERSION
        or workflow_metadata.get("config_sha256")
        != request["configuration_sha256"]
    ):
        raise ValueError("submission workflow metadata disagrees with request")
    output = workflow_output_path.expanduser().resolve(strict=True)
    if output.is_symlink() or not output.is_file():
        raise ValueError("workflow RTL output must be a regular non-symlink file")
    rtl = output.read_bytes()
    if len(rtl) > task["submission_contract"]["max_submission_bytes"]:
        raise ValueError("workflow RTL output exceeds the submission byte budget")
    bundle_root = bundle_root.expanduser().absolute()
    submission_path = submission_path.expanduser().absolute()
    receipt_path = receipt_path.expanduser().absolute()
    for path in (bundle_root, submission_path, receipt_path):
        if path.exists() or path.is_symlink():
            raise FileExistsError(f"refusing to overwrite output: {path}")
    bundle_root.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=".public-spec-bridge-", dir=bundle_root.parent))
    try:
        staged_target = stage / target
        staged_target.parent.mkdir(parents=True, exist_ok=True)
        staged_target.write_bytes(rtl)
        submission = packager.package_submission(
            task=task,
            metadata=metadata,
            bundle_root=stage,
        )
        os.replace(stage, bundle_root)
    finally:
        if stage.exists():
            shutil.rmtree(stage)
    _write_new_json(submission_path, submission)
    receipt = {
        "schema_version": "rtlflowbench.public_spec_bridge_receipt.v1",
        "observed_at": observed_at,
        "status": "conformant_submission_mapping_only",
        "workflow_id": workflow.workflow_id,
        "task_id": task["task_id"],
        "request_sha256": _sha256(request_path),
        "metadata_sha256": _sha256(metadata_path),
        "submission_sha256": _sha256(submission_path),
        "mapping": {
            "source_sha256": _sha256_bytes(rtl),
            "target_file": target,
            "target_sha256": _sha256(bundle_root / target),
            "bytes_preserved_exactly": True,
        },
        "airtl_run_observed": False,
        "hidden_evaluator_run": False,
        "rtl_verdict_produced": False,
        "adapter_ready": False,
        "benchmark_ready": False,
        "excluded_claims": [
            "Output mapping does not prove the external workflow produced the RTL.",
            "Submission conformance is not private evaluation or RTL PASS.",
            "No score, QoR, PPA, success rate or readiness is claimed.",
        ],
    }
    _write_new_json(receipt_path, receipt)
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("prepare")
    prepare.add_argument("--workflow-id", choices=tuple(WORKFLOWS), required=True)
    prepare.add_argument("--task-public-root", type=Path, required=True)
    prepare.add_argument("--output-dir", type=Path, required=True)
    prepare.add_argument("--observed-at", required=True)
    prepare.add_argument("--mode", choices=("development", "release"), required=True)
    prepare.add_argument("--upstream-commit", required=True)
    prepare.add_argument("--source-manifest-sha256", required=True)
    prepare.add_argument("--isolation-receipt", type=Path)
    collect = commands.add_parser("collect")
    collect.add_argument("--task-public-root", type=Path, required=True)
    collect.add_argument("--request", type=Path, required=True)
    collect.add_argument("--metadata", type=Path, required=True)
    collect.add_argument("--workflow-output", type=Path, required=True)
    collect.add_argument("--bundle-root", type=Path, required=True)
    collect.add_argument("--submission", type=Path, required=True)
    collect.add_argument("--receipt", type=Path, required=True)
    collect.add_argument("--observed-at", required=True)
    args = parser.parse_args()
    try:
        if args.command == "prepare":
            result = prepare_request(
                workflow_id=args.workflow_id,
                task_public_root=args.task_public_root,
                output_dir=args.output_dir,
                observed_at=args.observed_at,
                mode=args.mode,
                upstream_commit=args.upstream_commit,
                source_manifest_sha256=args.source_manifest_sha256,
                isolation_receipt_path=args.isolation_receipt,
            )
        else:
            result = collect_output(
                task_public_root=args.task_public_root,
                request_path=args.request,
                metadata_path=args.metadata,
                workflow_output_path=args.workflow_output,
                bundle_root=args.bundle_root,
                submission_path=args.submission,
                receipt_path=args.receipt,
                observed_at=args.observed_at,
            )
    except Exception as exc:
        print(
            json.dumps(
                {"status": "fail", "error": f"{type(exc).__name__}: {exc}"},
                indent=2,
                sort_keys=True,
            )
        )
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
