#!/usr/bin/env python3
"""Task-neutral public launcher for the same-model vanilla baseline.

The controller prepares one public-only trial workspace.  This launcher binds
that workspace, the frozen/development model binding, and the runtime source
snapshot before delegating to the existing vanilla controller.  It never
loads or invokes a private evaluator and never projects a visible result as a
benchmark verdict.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import re
import sys
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


WORKFLOW_ID = "same_model_vanilla_agent"
WORKFLOW_NAME = "same-model-vanilla-agent"
SOURCE_ROOT_DEFAULT = Path("/opt/workflow")
SOURCE_DESCRIPTOR_DEFAULT = Path("/opt/source_snapshot.json")
REQUEST_SCHEMA_DEFAULT = Path(__file__).with_name(
    "vanilla_launch_request.schema.json"
)
CORE_RELATIVE = Path(
    "benchmarks/golden12/baselines/vanilla_agent/core.py"
)
PROVIDER_RELATIVE = Path(
    "benchmarks/golden12/baselines/vanilla_agent/openrouter_provider.py"
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
FORBIDDEN_PATH_PARTS = frozenset(
    {"evaluator", "hidden", "oracle", "private"}
)
RUNTIME_COMPONENT_PATHS = frozenset(
    {
        "benchmarks/golden12/baselines/vanilla_agent/run_public.py",
        "benchmarks/golden12/baselines/vanilla_agent/vanilla_launch_request.schema.json",
        "benchmarks/golden12/baselines/vanilla_agent/core.py",
        "benchmarks/golden12/baselines/vanilla_agent/openrouter_provider.py",
        "benchmarks/golden12/baselines/vanilla_agent/provider_response.schema.json",
        "benchmarks/golden12/baselines/vanilla_agent/workflow_binding.schema.json",
        "benchmarks/golden12/baselines/vanilla_agent/run_receipt.schema.json",
        "benchmarks/golden12/conformance/adapters/scan_submission_adapter.py",
        "benchmarks/golden12/schemas/task.schema.json",
        "benchmarks/golden12/schemas/submission.schema.json",
        "benchmarks/golden12/schemas/visible_runner_contract.schema.json",
        "benchmarks/golden12/admission/public_trial_workspace_receipt.schema.json",
    }
)


def _sha256(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"expected a regular non-symlink file: {path}")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_object(path: Path, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a regular non-symlink file")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{label} must contain one JSON object")
    return value


def _canonical_sha256(value: Any) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _regular_root(path: Path, label: str) -> Path:
    unresolved = path.expanduser().absolute()
    if unresolved.is_symlink():
        raise ValueError(f"{label} cannot be a symlink")
    resolved = unresolved.resolve(strict=True)
    if not resolved.is_dir():
        raise ValueError(f"{label} must be a directory")
    return resolved


def _safe_relative(value: Any, label: str) -> Path:
    if not isinstance(value, str) or not value or "\\" in value:
        raise ValueError(f"{label} is not a safe POSIX relative path")
    pure = PurePosixPath(value)
    if pure.is_absolute() or ".." in pure.parts:
        raise ValueError(f"{label} escapes the request root")
    if any(part.casefold() in FORBIDDEN_PATH_PARTS for part in pure.parts):
        raise ValueError(f"{label} contains a private-control path component")
    return Path(*pure.parts)


def _regular_in_root(root: Path, relative: Path, label: str) -> Path:
    path = root / relative
    resolved = path.resolve(strict=True)
    if root not in resolved.parents or path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a regular in-root file")
    return path


def _directory_in_root(root: Path, relative: Path, label: str) -> Path:
    path = root / relative
    resolved = path.resolve(strict=True)
    if root not in resolved.parents or path.is_symlink() or not path.is_dir():
        raise ValueError(f"{label} must be a regular in-root directory")
    return resolved


def _assert_public_only_tree(root: Path) -> None:
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if any(
            part.casefold() in FORBIDDEN_PATH_PARTS
            for part in relative.parts
        ):
            raise ValueError("request tree contains a private-control path")
        if path.is_symlink():
            raise ValueError("request tree contains a symlink")
        if not path.is_dir() and not path.is_file():
            raise ValueError("request tree contains a non-regular entry")


def _validate(schema_path: Path, value: dict[str, Any]) -> None:
    schema = _load_object(schema_path, "vanilla launch request schema")
    Draft202012Validator.check_schema(schema)
    errors = sorted(
        Draft202012Validator(
            schema, format_checker=FormatChecker()
        ).iter_errors(value),
        key=lambda error: list(error.absolute_path),
    )
    if errors:
        first = errors[0]
        location = "/".join(str(part) for part in first.absolute_path)
        raise ValueError(
            "vanilla launch request schema error at "
            f"{location or '<root>'}: {first.message}"
        )


def _load_module(path: Path):
    spec = importlib.util.spec_from_file_location(
        "rtlflowbench_vanilla_runtime_core", path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load the bound vanilla controller")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def bind_runtime(
    *,
    source_root: Path,
    source_descriptor_path: Path,
    request_schema_path: Path,
) -> tuple[Path, Path]:
    source = _regular_root(source_root, "runtime source root")
    descriptor_input = source_descriptor_path.expanduser()
    request_schema_input = request_schema_path.expanduser()
    descriptor = _load_object(descriptor_input, "runtime source descriptor")
    _load_object(request_schema_input, "vanilla launch request schema")
    if descriptor.get("schema_version") != "rtlflowbench.runtime_source_descriptor.v1":
        raise ValueError("runtime source descriptor schema version is invalid")
    if descriptor.get("workflow_id") != WORKFLOW_ID:
        raise ValueError("runtime source descriptor has the wrong workflow id")
    if descriptor.get("private_evaluator_included") is not False:
        raise ValueError("runtime source descriptor does not exclude private assets")
    if COMMIT_RE.fullmatch(str(descriptor.get("source_commit"))) is None:
        raise ValueError("runtime source descriptor has no source commit")
    if SHA256_RE.fullmatch(
        str(descriptor.get("source_content_manifest_sha256"))
    ) is None:
        raise ValueError("runtime source descriptor has no source manifest")
    core = source / CORE_RELATIVE
    provider = source / PROVIDER_RELATIVE
    bindings = {
        "entrypoint_source_sha256": _sha256(Path(__file__).resolve(strict=True)),
        "request_schema_sha256": _sha256(request_schema_input),
        "controller_source_sha256": _sha256(core),
        "provider_runner_source_sha256": _sha256(provider),
    }
    if any(descriptor.get(key) != digest for key, digest in bindings.items()):
        raise ValueError("runtime source descriptor content binding drifted")
    components = descriptor.get("runtime_components")
    if not isinstance(components, list):
        raise ValueError("runtime source descriptor has no component manifest")
    observed = []
    observed_paths = set()
    for item in components:
        if not isinstance(item, dict) or set(item) != {"path", "bytes", "sha256"}:
            raise ValueError("runtime component entry is invalid")
        relative = item["path"]
        if relative not in RUNTIME_COMPONENT_PATHS or relative in observed_paths:
            raise ValueError("runtime component path is unexpected or duplicated")
        observed_paths.add(relative)
        if relative.endswith("/run_public.py"):
            path = Path(__file__).resolve(strict=True)
        elif relative.endswith("/vanilla_launch_request.schema.json"):
            path = request_schema_input
        else:
            path = source / Path(relative)
        digest = _sha256(path)
        entry = {"path": relative, "bytes": path.stat().st_size, "sha256": digest}
        if item != entry:
            raise ValueError("runtime component content binding drifted")
        observed.append(entry)
    if observed_paths != RUNTIME_COMPONENT_PATHS:
        raise ValueError("runtime component manifest is incomplete")
    observed.sort(key=lambda item: item["path"])
    manifest_sha256 = _canonical_sha256(observed)
    if (
        descriptor.get("runtime_component_manifest_sha256") != manifest_sha256
        or SHA256_RE.fullmatch(manifest_sha256) is None
    ):
        raise ValueError("runtime component manifest digest drifted")
    return core, provider


def load_request(
    *, request_root: Path, request_schema_path: Path, model: str
) -> dict[str, Any]:
    root = _regular_root(request_root, "public request root")
    _assert_public_only_tree(root)
    request_path = _regular_in_root(
        root, Path("vanilla_request.json"), "vanilla launch request"
    )
    request = _load_object(request_path, "vanilla launch request")
    _validate(request_schema_path.expanduser(), request)
    expected_status = {
        "development": "development_request_prepared_not_run",
        "release": "release_request_prepared_not_run",
    }[request["mode"]]
    if request["status"] != expected_status:
        raise ValueError("request mode and status disagree")
    if request["model"] != model:
        raise ValueError("CLI model differs from the request model binding")

    paths = request["paths"]
    public_root = _directory_in_root(
        root, _safe_relative(paths["public_root"], "public root"), "public root"
    )
    task_path = _regular_in_root(
        root, _safe_relative(paths["task"], "task path"), "task descriptor"
    )
    receipt_path = _regular_in_root(
        root,
        _safe_relative(paths["workspace_receipt"], "workspace receipt path"),
        "workspace receipt",
    )
    binding_path = _regular_in_root(
        root,
        _safe_relative(paths["workflow_binding"], "workflow binding path"),
        "workflow binding",
    )
    repository_relative = paths["repository_root"]
    repository_root = (
        None
        if repository_relative is None
        else _directory_in_root(
            root,
            _safe_relative(repository_relative, "repository root"),
            "repository root",
        )
    )
    if task_path != public_root / "external_task.json":
        raise ValueError("task descriptor is not bound to the public root")
    if receipt_path.parent != root or binding_path.parent != root:
        raise ValueError("control files are not rooted in the trial workspace")
    observed = {
        "task": _sha256(task_path),
        "workspace_receipt": _sha256(receipt_path),
        "workflow_binding": _sha256(binding_path),
    }
    if request["sha256"] != observed:
        raise ValueError("public launch input digest drifted")

    task = _load_object(task_path, "task descriptor")
    binding = _load_object(binding_path, "workflow binding")
    if request["task_id"] != task.get("task_id"):
        raise ValueError("request task id differs from the public task")
    workflow = binding.get("workflow")
    if not isinstance(workflow, dict) or workflow.get("name") != WORKFLOW_NAME:
        raise ValueError("workflow binding is not the same-model vanilla agent")
    bound_model = workflow.get("model")
    if not isinstance(bound_model, dict) or bound_model.get("name") != model:
        raise ValueError("workflow binding model differs from the frozen model")
    expected_binding_status = {
        "development": "development_not_frozen",
        "release": "frozen",
    }[request["mode"]]
    if binding.get("status") != expected_binding_status:
        raise ValueError("workflow binding status disagrees with request mode")
    return {
        "request": request,
        "task_path": task_path,
        "public_root": public_root,
        "repository_root": repository_root,
        "workspace_receipt_path": receipt_path,
        "workflow_binding_path": binding_path,
    }


def run_public(
    *,
    request_root: Path,
    work_dir: Path,
    model: str,
    source_root: Path = SOURCE_ROOT_DEFAULT,
    source_descriptor_path: Path = SOURCE_DESCRIPTOR_DEFAULT,
    request_schema_path: Path = REQUEST_SCHEMA_DEFAULT,
) -> dict[str, Any]:
    core_path, provider_path = bind_runtime(
        source_root=source_root,
        source_descriptor_path=source_descriptor_path,
        request_schema_path=request_schema_path,
    )
    inputs = load_request(
        request_root=request_root,
        request_schema_path=request_schema_path,
        model=model,
    )
    work = work_dir.expanduser().absolute()
    if work.exists() or work.is_symlink():
        raise FileExistsError("refusing to reuse vanilla work directory")
    request = inputs["request"]
    core = _load_module(core_path)
    receipt = core.run_baseline(
        task_path=inputs["task_path"],
        public_root=inputs["public_root"],
        repository_root=inputs["repository_root"],
        workspace_receipt_path=inputs["workspace_receipt_path"],
        expected_workspace_receipt_sha256=request["sha256"]["workspace_receipt"],
        workflow_binding_path=inputs["workflow_binding_path"],
        provider_runner=provider_path,
        run_root=work,
        attempt=request["attempt"],
        submission_id=request["submission_id"],
        allow_development=request["mode"] == "development",
        maximum_public_text_bytes=request["limits"][
            "maximum_public_text_bytes"
        ],
        maximum_repository_text_bytes=request["limits"][
            "maximum_repository_text_bytes"
        ],
    )
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--request-root", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument(
        "--source-root", type=Path, default=SOURCE_ROOT_DEFAULT
    )
    parser.add_argument(
        "--source-descriptor", type=Path, default=SOURCE_DESCRIPTOR_DEFAULT
    )
    parser.add_argument(
        "--request-schema", type=Path, default=REQUEST_SCHEMA_DEFAULT
    )
    args = parser.parse_args()
    try:
        receipt = run_public(
            request_root=args.request_root,
            work_dir=args.work_dir,
            model=args.model,
            source_root=args.source_root,
            source_descriptor_path=args.source_descriptor,
            request_schema_path=args.request_schema,
        )
    except Exception as exc:
        status = "control_plane_error"
        exit_code = 2
        if type(exc).__name__ == "ProviderInfraError":
            status, exit_code = "provider_infra_block", 3
        elif type(exc).__name__ == "InvalidProviderResponse":
            status, exit_code = "invalid_provider_response", 4
        print(
            json.dumps(
                {
                    "status": status,
                    "exception_class": type(exc).__name__,
                    "raw_exception_text_recorded": False,
                    "private_evaluator_run": False,
                    "benchmark_verdict_produced": False,
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return exit_code
    visible = receipt.get("visible_result")
    expected = isinstance(visible, dict) and visible.get("expected_outcome") is True
    print(
        json.dumps(
            {
                "status": receipt["status"],
                "task_id": receipt["task_id"],
                "submission_observed": receipt.get("final_submission") is not None,
                "visible_expected_outcome": expected,
                "private_evaluator_run": False,
                "benchmark_verdict_produced": False,
            },
            sort_keys=True,
        )
    )
    return 0 if expected else 1


if __name__ == "__main__":
    raise SystemExit(main())
