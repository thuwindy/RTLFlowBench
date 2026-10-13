#!/usr/bin/env python3
"""Provider-free, source-bound preflight for external AIRTL workflows."""

from __future__ import annotations

import argparse
import ast
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tomllib
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


HERE = Path(__file__).resolve().parent
SCHEMA_PATH = HERE / "source_runtime_preflight.schema.json"


@dataclass(frozen=True)
class WorkflowSpec:
    workflow_id: str
    display_name: str
    repository: str
    commit: str
    archive_sha256: str
    tracked_manifest_sha256: str
    entrypoint: str
    metadata_path: str
    metadata_kind: str
    source_locator: str
    source_archive_locator: str


WORKFLOWS = {
    "verilogcoder": WorkflowSpec(
        workflow_id="verilogcoder",
        display_name="VerilogCoder",
        repository="https://github.com/NVlabs/VerilogCoder",
        commit="8b13108869f276c7b644dd88beabcb401a5cfa92",
        archive_sha256=(
            "68e51d9b7a4d1232560d68b9157112191579b34b860dd1ce722e59f8abf615e1"
        ),
        tracked_manifest_sha256=(
            "01ac57a9e5bdb79d12055554fc5646d2b6451602f982377f48f35505d2328d69"
        ),
        entrypoint="hardware_agent/examples/VerilogCoder/run_verilog_coder.py",
        metadata_path="setup.py",
        metadata_kind="setuptools_ast",
        source_locator=(
            "SERVER26:rtlflowbench/dev-intake/"
            "external-workflows-primary-20260812a/verilogcoder/source"
        ),
        source_archive_locator=(
            "SERVER26:rtlflowbench/evidence/"
            "golden12-external-workflow-source-intake-20260812a/"
            "verilogcoder.source.tar"
        ),
    ),
    "hdlagent": WorkflowSpec(
        workflow_id="hdlagent",
        display_name="HDLAgent",
        repository="https://github.com/masc-ucsc/hdlagent",
        commit="bd2321e03d1d60b0656d7ff0992f35f5906a824d",
        archive_sha256=(
            "078b19c50456b4bccb59527a3f9d7a23e984ebd982c0f572256f1014d3212d8a"
        ),
        tracked_manifest_sha256=(
            "843ccf62106d6ae2e953f5d5b5a8fd7ea4160c969084d010acc59d4e7ba6d91f"
        ),
        entrypoint="hdlagent/cli_agent.py",
        metadata_path="pyproject.toml",
        metadata_kind="poetry_toml",
        source_locator=(
            "SERVER26:rtlflowbench/dev-intake/"
            "external-workflows-alternates-20260812a/hdlagent/source"
        ),
        source_archive_locator=(
            "SERVER26:rtlflowbench/evidence/"
            "golden12-external-workflow-alternate-source-intake-20260812a/"
            "hdlagent.source.tar"
        ),
    ),
}


def _sha256(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"expected regular non-symlink file: {path.name}")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _tracked_manifest_sha256(source_root: Path) -> str:
    """Recreate the source-intake manifest without writing source data."""
    raw_paths = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=source_root,
        check=True,
        capture_output=True,
    ).stdout
    digest = hashlib.sha256()
    for raw_path in raw_paths.split(b"\0"):
        if not raw_path:
            continue
        relative = raw_path.decode("utf-8")
        if "\n" in relative or "\r" in relative:
            raise ValueError("tracked path contains an unsupported line separator")
        path = source_root / relative
        content_digest = hashlib.sha256()
        if path.is_symlink():
            kind = "symlink"
            content_digest.update(os.readlink(path).encode("utf-8"))
        elif path.is_file():
            kind = "file"
            with path.open("rb") as handle:
                while chunk := handle.read(1024 * 1024):
                    content_digest.update(chunk)
        else:
            raise ValueError(f"tracked path is not a regular file: {path.name}")
        digest.update(
            f"{content_digest.hexdigest()}  {kind}  {relative}\n".encode("utf-8")
        )
    return digest.hexdigest()


def _run(
    command: list[str],
    *,
    cwd: Path,
    timeout: int = 30,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _git_output(source_root: Path, *args: str) -> str:
    result = _run(["git", *args], cwd=source_root)
    if result.returncode != 0:
        raise ValueError(f"git {' '.join(args)} failed")
    return result.stdout


def _git_archive_sha256(source_root: Path) -> str:
    process = subprocess.Popen(
        ["git", "archive", "--format=tar", "HEAD"],
        cwd=source_root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.stdout is not None
    digest = hashlib.sha256()
    while chunk := process.stdout.read(1024 * 1024):
        digest.update(chunk)
    _, stderr = process.communicate(timeout=30)
    if process.returncode != 0:
        raise ValueError(
            f"git archive failed: {stderr.decode('utf-8', errors='replace')[:160]}"
        )
    return digest.hexdigest()


def _literal_assignments(tree: ast.AST) -> dict[str, Any]:
    values: dict[str, Any] = {}
    for node in getattr(tree, "body", []):
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
        ):
            try:
                values[node.targets[0].id] = ast.literal_eval(node.value)
            except (ValueError, TypeError):
                continue
    return values


def _setuptools_dependencies(path: Path) -> tuple[str, list[dict[str, Any]]]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=path.name)
    assignments = _literal_assignments(tree)
    setup_call = None
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "setup"
        ):
            setup_call = node
            break
    if setup_call is None:
        raise ValueError("setuptools setup() call not found")
    keywords = {item.arg: item.value for item in setup_call.keywords if item.arg}
    python_requires = ast.literal_eval(keywords["python_requires"])
    install_node = keywords["install_requires"]
    if isinstance(install_node, ast.Name):
        dependencies = assignments.get(install_node.id)
    else:
        dependencies = ast.literal_eval(install_node)
    if not isinstance(python_requires, str) or not isinstance(dependencies, list):
        raise ValueError("setuptools dependency metadata is not static")
    return python_requires, [
        _dependency_record(item) for item in dependencies if isinstance(item, str)
    ]


def _poetry_dependencies(path: Path) -> tuple[str, list[dict[str, Any]]]:
    value = tomllib.loads(path.read_text(encoding="utf-8"))
    dependencies = value["tool"]["poetry"]["dependencies"]
    python_requires = dependencies["python"]
    if not isinstance(python_requires, str):
        raise ValueError("Poetry Python constraint is not a string")
    result = []
    for name, constraint in sorted(dependencies.items()):
        if name == "python":
            continue
        if isinstance(constraint, str):
            result.append(_dependency_record(f"{name}{constraint}"))
        elif isinstance(constraint, dict):
            vcs = constraint.get("git")
            branch = constraint.get("branch")
            rev = constraint.get("rev")
            rendered = json.dumps(constraint, sort_keys=True)
            result.append(
                {
                    "name": name,
                    "constraint": rendered,
                    "exact_pin": bool(rev) and not branch,
                    "mutable_vcs_reference": bool(vcs and branch and not rev),
                }
            )
        else:
            raise ValueError(f"unsupported Poetry constraint for {name}")
    return python_requires, result


def _dependency_record(rendered: str) -> dict[str, Any]:
    separators = ("==", ">=", "<=", "!=", "~=", ">", "<", "^", "~")
    name = rendered
    for separator in separators:
        if separator in rendered:
            name = rendered.split(separator, 1)[0]
            break
    exact = "==" in rendered and not any(
        marker in rendered for marker in (",", "*", ">", "<", "!=", "~=")
    )
    return {
        "name": name.strip(),
        "constraint": rendered,
        "exact_pin": exact,
        "mutable_vcs_reference": False,
    }


def _tool_probe(command: str) -> dict[str, Any]:
    path = shutil.which(command)
    if path is None:
        return {"available": False, "version_line": None}
    arguments = [path, "--version"]
    if command == "iverilog":
        arguments = [path, "-V"]
    result = subprocess.run(
        arguments,
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    lines = [
        line.strip()
        for line in (result.stdout + "\n" + result.stderr).splitlines()
        if line.strip()
    ]
    return {
        "available": result.returncode == 0,
        "version_line": lines[0] if lines else None,
    }


def _boundary_analysis(
    workflow_id: str,
    *,
    entrypoint_text: str,
    source_root: Path,
) -> dict[str, Any]:
    if workflow_id == "verilogcoder":
        implementation = (
            source_root
            / "hardware_agent/examples/VerilogCoder/verilogcoder.py"
        ).read_text(encoding="utf-8")
        return {
            "requires_testbench_input": "golden_test_bench" in implementation,
            "hardcoded_task_selection": "user_task_ids = {'zero'}"
            in entrypoint_text,
            "external_benchmark_alias_present": False,
            "public_visible_only_adapter_required": True,
            "external_benchmark_alias_must_be_forbidden": False,
            "golden_reference_input_permitted": False,
            "private_evaluator_mount_permitted": False,
        }
    return {
        "requires_testbench_input": False,
        "hardcoded_task_selection": False,
        "external_benchmark_alias_present": "hdeval:" in entrypoint_text,
        "public_visible_only_adapter_required": True,
        "external_benchmark_alias_must_be_forbidden": True,
        "golden_reference_input_permitted": False,
        "private_evaluator_mount_permitted": False,
    }


def build_preflight(
    *,
    workflow_id: str,
    source_root: Path,
    source_archive: Path,
    observed_at: str,
) -> dict[str, Any]:
    if workflow_id not in WORKFLOWS:
        raise ValueError("unsupported workflow id")
    spec = WORKFLOWS[workflow_id]
    source_root = source_root.expanduser().resolve(strict=True)
    source_archive = source_archive.expanduser().resolve(strict=True)
    if source_root.is_symlink() or not source_root.is_dir():
        raise ValueError("source root must be a regular directory")
    head = _git_output(source_root, "rev-parse", "HEAD").strip()
    status = _git_output(
        source_root, "status", "--porcelain=v1", "--untracked-files=all"
    )
    submodules = _git_output(source_root, "submodule", "status")
    archive_sha256 = _sha256(source_archive)
    recreated_archive_sha256 = _git_archive_sha256(source_root)
    tracked_manifest_sha256 = _tracked_manifest_sha256(source_root)

    entrypoint = source_root / spec.entrypoint
    metadata_path = source_root / spec.metadata_path
    for path in (entrypoint, metadata_path):
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"required source file is missing: {path.name}")
        tracked = _run(
            ["git", "ls-files", "--error-unmatch", path.relative_to(source_root).as_posix()],
            cwd=source_root,
        )
        if tracked.returncode != 0:
            raise ValueError(f"required source file is untracked: {path.name}")

    entrypoint_text = entrypoint.read_text(encoding="utf-8")
    ast.parse(entrypoint_text, filename=spec.entrypoint)
    if spec.metadata_kind == "setuptools_ast":
        python_requires, dependencies = _setuptools_dependencies(metadata_path)
    elif spec.metadata_kind == "poetry_toml":
        python_requires, dependencies = _poetry_dependencies(metadata_path)
    else:
        raise ValueError("unsupported dependency metadata kind")

    checks = {
        "source_commit_matches": head == spec.commit,
        "worktree_clean": status == "",
        "submodule_status_empty": submodules == "",
        "source_archive_matches": archive_sha256 == spec.archive_sha256,
        "recreated_archive_matches": recreated_archive_sha256
        == spec.archive_sha256,
        "tracked_manifest_matches": tracked_manifest_sha256
        == spec.tracked_manifest_sha256,
        "entrypoint_ast_parses": True,
        "dependency_metadata_parsed": bool(dependencies),
    }
    if not all(checks.values()):
        raise ValueError("source binding or static preflight check failed")

    pinned_count = sum(item["exact_pin"] for item in dependencies)
    mutable_vcs = [
        item["name"]
        for item in dependencies
        if item["mutable_vcs_reference"]
    ]
    boundary = _boundary_analysis(
        workflow_id,
        entrypoint_text=entrypoint_text,
        source_root=source_root,
    )
    blockers = [
        "The dependency graph is not fully exact-pinned or resolved into a content-addressed wheelhouse.",
        "A deterministic OCI image has not been built and reproduced twice.",
        "The neutral all-twelve-task adapter has not passed conformance.",
        "Independent rights and environment review remain pending.",
    ]
    if workflow_id == "verilogcoder":
        blockers.append(
            "The upstream entrypoint hardcodes a task id and passes a golden-named testbench input; the adapter must replace task selection generically and expose public visible tests only."
        )
    else:
        blockers.append(
            "The Poetry graph contains a mutable hdeval branch dependency and the hdeval: external benchmark path must be disabled by the adapter."
        )

    return {
        "schema_version": "rtlflowbench.external_workflow_source_preflight.v1",
        "observed_at": observed_at,
        "status": "source_preflight_pass_environment_blocked",
        "workflow": {
            "workflow_id": workflow_id,
            "display_name": spec.display_name,
            "repository": spec.repository,
            "commit": spec.commit,
            "source_locator": spec.source_locator,
            "source_archive_locator": spec.source_archive_locator,
        },
        "source_binding": {
            "archive_sha256": archive_sha256,
            "recreated_archive_sha256": recreated_archive_sha256,
            "tracked_manifest_sha256": tracked_manifest_sha256,
            "worktree_clean": True,
            "submodules_present": False,
        },
        "entrypoint": {
            "path": spec.entrypoint,
            "metadata_path": spec.metadata_path,
            "metadata_kind": spec.metadata_kind,
            "ast_parse_passed": True,
            "executed": False,
        },
        "dependencies": {
            "python_constraint": python_requires,
            "items": dependencies,
            "dependency_count": len(dependencies),
            "exact_pin_count": pinned_count,
            "fully_exact_pinned": pinned_count == len(dependencies),
            "mutable_vcs_dependencies": mutable_vcs,
            "resolved_lock_complete": False,
            "wheelhouse_complete": False,
        },
        "boundary": boundary,
        "host_observation": {
            "python": _tool_probe("python3"),
            "podman": _tool_probe("podman"),
            "iverilog": _tool_probe("iverilog"),
            "yosys": _tool_probe("yosys"),
            "verilator": _tool_probe("verilator"),
            "symbiyosys": _tool_probe("sby"),
            "host_tools_are_frozen_environment": False,
        },
        "checks": checks,
        "readiness": {
            "source_preflight_passed": True,
            "dependency_lock_frozen": False,
            "environment_reproduced": False,
            "adapter_conformance_passed": False,
            "airtl_run_observed": False,
            "private_evaluator_run": False,
            "rtl_verdict_produced": False,
            "official_attempts_permitted": False,
            "publication_permitted": False,
        },
        "blockers": blockers,
        "excluded_claims": [
            "Static source preflight is not environment reproduction or an AIRTL workflow run.",
            "Host tool availability is not a frozen workflow environment.",
            "No private evaluator, RTL PASS, score, QoR, PPA, adapter readiness, or publication readiness is claimed.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--workflow-id",
        required=True,
        choices=sorted(WORKFLOWS),
    )
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--source-archive", type=Path, required=True)
    parser.add_argument("--observed-at", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.expanduser().resolve()
    if output.exists() or output.is_symlink():
        raise FileExistsError(f"refusing to overwrite output: {output}")
    try:
        result = build_preflight(
            workflow_id=args.workflow_id,
            source_root=args.source_root,
            source_archive=args.source_archive,
            observed_at=args.observed_at,
        )
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(
            schema,
            format_checker=FormatChecker(),
        ).validate(result)
    except Exception as exc:
        print(
            json.dumps(
                {"status": "invalid", "error": f"{type(exc).__name__}: {exc}"},
                indent=2,
                sort_keys=True,
            )
        )
        return 2
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
