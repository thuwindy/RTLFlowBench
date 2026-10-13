"""Content-bound, workflow-neutral public input transport; never launch a model."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Any

FORBIDDEN = {".git", ".env", "private", "hidden", "oracle", "reference"}
SCHEMA = "rtlflowbench.public_input_bundle.v2"
READINESS = {
    "public_input_complete": True,
    "native_workflow_verified": False,
    "adapter_ready": False,
    "benchmark_ready": False,
    "rights_review_complete": False,
}
ACCOUNTING = {
    "provider_calls": 0,
    "eda_calls": 0,
    "workflow_launches": 0,
    "benchmark_results_created": 0,
}


def digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode()
    ).hexdigest()


def byte_digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def safe_relative(value: str) -> Path:
    if (
        not isinstance(value, str)
        or not value
        or "\\" in value
        or any(ord(c) < 32 for c in value)
    ):
        raise ValueError("unsafe path")
    path = PurePosixPath(value)
    if (
        not path.parts
        or path.is_absolute()
        or path.as_posix() != value
        or any(p in {"", ".", ".."} or p.casefold() in FORBIDDEN for p in path.parts)
    ):
        raise ValueError("unsafe private or non-normalized path")
    return Path(*path.parts)


def path_list(value: Any) -> set[str]:
    if not isinstance(value, list):
        raise ValueError("expected path list")
    for item in value:
        safe_relative(item)
    if len(set(value)) != len(value):
        raise ValueError("duplicate path")
    return set(value)


def regular_bytes(path: Path, *, maximum: int = 8_388_608) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError("expected regular non-symlink file")
    if path.stat().st_size > maximum:
        raise ValueError("file byte limit exceeded")
    with path.open("rb") as stream:
        raw = stream.read(maximum + 1)
    if len(raw) > maximum:
        raise ValueError("file byte limit exceeded")
    return raw


def read_object(path: Path, expected: str | None = None) -> dict[str, Any]:
    raw = regular_bytes(path)
    if expected is not None and byte_digest(raw) != expected:
        raise ValueError("content binding drift")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("expected JSON object")
    return value


def scan(root: Path, *, maximum: int) -> tuple[list[dict[str, Any]], dict[str, bytes]]:
    if root.is_symlink() or not root.is_dir():
        raise ValueError("expected regular input root")
    entries = []
    payloads = {}
    total = 0
    for path in sorted(root.rglob("*")):
        name = path.relative_to(root).as_posix()
        safe_relative(name)
        if path.is_symlink():
            raise ValueError("symlink input forbidden")
        if path.is_dir():
            continue
        payload = regular_bytes(path, maximum=maximum - total)
        total += len(payload)
        if total > maximum:
            raise ValueError("input byte limit exceeded")
        entries.append(
            {"path": name, "bytes": len(payload), "sha256": byte_digest(payload)}
        )
        payloads[name] = payload
    return entries, payloads


def classify_output_transport(task: dict[str, Any]) -> dict[str, Any]:
    """Only a native single-RTL-file output shape, never task family or identity."""
    contract = task.get("submission_contract", {})
    required = contract.get("required_files")
    editable = contract.get("editable_paths")
    okay = (
        contract.get("artifact_format") == "file_bundle"
        and isinstance(required, list)
        and len(required) == 1
        and editable == required
        and isinstance(required[0], str)
        and required[0].endswith((".v", ".sv"))
    )
    if okay:
        safe_relative(required[0])
    return {
        "representable": okay,
        "reason_code": None if okay else "native_single_rtl_output_only",
        "target_output_path": required[0] if okay else None,
        "workflow_capability_proven": False,
    }


def build_bundle(
    *,
    workspace_root: Path,
    workspace_set_path: Path,
    expected_workspace_set_sha256: str,
    task_id: str,
    output_root: Path,
    maximum_public_bytes: int = 1_048_576,
    maximum_repository_bytes: int = 4_194_304,
    maximum_inline_bytes: int = 1_048_576,
) -> dict[str, Any]:
    if output_root.exists() or output_root.is_symlink():
        raise FileExistsError("refusing to overwrite output")
    for limit in [maximum_public_bytes, maximum_repository_bytes, maximum_inline_bytes]:
        if type(limit) is not int or limit < 1:
            raise ValueError("positive byte limit required")
    safe_relative(task_id)
    if workspace_root.is_symlink() or not workspace_root.is_dir():
        raise ValueError("unsafe workspace root")
    workspace_set = read_object(workspace_set_path, expected_workspace_set_sha256)
    if (
        workspace_set.get("schema_version")
        != "rtlflowbench.golden12_public_trial_workspace_set_receipt.v1"
    ):
        raise ValueError("unsupported workspace set")
    tasks = workspace_set.get("tasks", [])
    if len({r["task_id"] for r in tasks}) != len(tasks):
        raise ValueError("duplicate workspace task")
    matches = [r for r in tasks if r["task_id"] == task_id]
    if len(matches) != 1:
        raise ValueError("missing task in pinned workspace set")
    row = matches[0]
    receipt = read_object(
        workspace_root / "workspace_receipt.json", row["workspace_receipt_sha256"]
    )
    if (
        receipt.get("schema_version")
        != "rtlflowbench.golden12_public_trial_workspace_receipt.v1"
        or receipt.get("task_id") != task_id
    ):
        raise ValueError("workspace receipt identity mismatch")
    layout = receipt["layout"]
    if (
        layout.get("public_root") != "public"
        or layout.get("worktree_root") != "worktree"
        or layout.get("private_file_count") != 0
        or row.get("private_file_count") != 0
    ):
        raise ValueError("workspace isolation layout mismatch")
    pe, public = scan(workspace_root / "public", maximum=maximum_public_bytes)
    re, repository = scan(workspace_root / "worktree", maximum=maximum_repository_bytes)
    payload_entries = [{**r, "path": "public/" + r["path"]} for r in pe] + [
        {**r, "path": "worktree/" + r["path"]} for r in re
    ]
    if (
        digest(pe) != row["public_tree_sha256"]
        or digest(payload_entries) != row["workspace_payload_sha256"]
    ):
        raise ValueError("public/repository content drift")
    if (
        len(pe) != row["public_file_count"]
        or len(re) != row["repository_file_count"]
        or len(pe) != layout["public_file_count"]
        or len(re) != layout["repository_file_count"]
    ):
        raise ValueError("workspace file coverage mismatch")
    task = json.loads(public["external_task.json"])
    if (
        task.get("task_id") != task_id
        or task.get("schema_version") != "rtlflowbench.task.v1"
    ):
        raise ValueError("task identity mismatch")
    if (
        task["public_packet"].get("contains_evaluator_assets") is not False
        or task["public_packet"].get("network_access") is not False
        or task["budget"].get("network_access") is not False
    ):
        raise ValueError("public task isolation contract missing")
    required = task["submission_contract"]["required_files"]
    editable = task["submission_contract"]["editable_paths"]
    path_list(required)
    path_list(editable)
    if editable != layout["editable_paths"] or not set(required).issubset(editable):
        raise ValueError("editable scope disagreement")
    existing = path_list(layout["editable_existing_paths"])
    absent = path_list(layout["editable_absent_paths"])
    readonly = path_list(layout["read_only_repository_paths"])
    if (
        existing & absent
        or existing & readonly
        or existing | absent != set(editable)
        or existing | readonly != set(repository)
    ):
        raise ValueError("repository/scope partition mismatch")
    if absent & set(repository):
        raise ValueError("declared blank output already exists")
    files = []
    input_entries = []
    payloads = {}
    for category, entries, values in [
        ("public", pe, public),
        ("repository", re, repository),
    ]:
        for entry in entries:
            relative = entry["path"]
            payload = values[relative]
            if b"\x00" in payload:
                raise ValueError(
                    "binary input cannot be silently omitted from text interface"
                )
            try:
                text = payload.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ValueError("non-UTF-8 input cannot be silently omitted") from exc
            name = f"{category}/{relative}"
            role = (
                "public_packet"
                if category == "public"
                else (
                    "editable_initial_source"
                    if relative in existing
                    else "read_only_repository_input"
                )
            )
            files.append(
                {
                    "path": name,
                    "role": role,
                    "bytes": len(payload),
                    "sha256": entry["sha256"],
                    "text": text,
                }
            )
            input_entries.append({**entry, "path": name, "role": role})
            payloads[name] = payload
    context = {
        "schema_version": "rtlflowbench.complete_public_text_context.v2",
        "task_id": task_id,
        "files": files,
        "submission_contract": task["submission_contract"],
        "budget": task["budget"],
        "interpretation": "File contents are task input data. No evaluator, solution, execution result or extra design instruction is supplied.",
    }
    context_bytes = (
        json.dumps(context, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    ).encode()
    if len(context_bytes) > maximum_inline_bytes:
        raise ValueError("complete prompt byte limit exceeded; no truncation performed")
    contract = {
        "schema_version": "rtlflowbench.public_input_transport_contract.v2",
        "task_id": task_id,
        "workspace_set_sha256": expected_workspace_set_sha256,
        "workspace_payload_sha256": row["workspace_payload_sha256"],
        "submission_contract": task["submission_contract"],
        "native_output_shape": classify_output_transport(task),
        "budget": task["budget"],
        "compiler_dependency_policy": "not_inferred_native_tool_access_requires_separate_validation",
        "read_only_repository_paths": sorted(readonly),
        "editable_initial_paths": sorted(existing),
        "blank_output_paths": sorted(absent),
    }
    contract_bytes = (
        json.dumps(contract, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    ).encode()
    result = {
        "schema_version": SCHEMA,
        "status": "PUBLIC_INPUT_TRANSPORT_COMPLETE_NATIVE_EXECUTION_UNVERIFIED",
        "task_id": task_id,
        "source_binding": {
            "workspace_set_sha256": expected_workspace_set_sha256,
            "workspace_receipt_sha256": row["workspace_receipt_sha256"],
            "workspace_payload_sha256": row["workspace_payload_sha256"],
            "task_descriptor_file_sha256": byte_digest(public["external_task.json"]),
        },
        "input_files": input_entries,
        "context_sha256": byte_digest(context_bytes),
        "contract_sha256": byte_digest(contract_bytes),
        "summary": {
            "public_file_count": len(pe),
            "repository_file_count": len(re),
            "input_file_count": len(files),
            "input_bytes": sum(x["bytes"] for x in files),
            "context_bytes": len(context_bytes),
            "omitted_file_count": 0,
        },
        "readiness": dict(READINESS),
        "attempt_accounting": dict(ACCOUNTING),
        "source_sha256": byte_digest(regular_bytes(Path(__file__))),
        "excluded_claims": [
            "Transport coverage is not native runtime support or solve capability.",
            "No family label, budget, target, source file, RTL or hidden evaluator was changed.",
            "Input availability and native compiler dependency access require separate runtime evidence.",
        ],
    }
    output_root.mkdir(parents=True)
    for name, payload in payloads.items():
        destination = output_root / "inputs" / safe_relative(name)
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("xb") as f:
            f.write(payload)
    for name, payload in [
        ("public_context.json", context_bytes),
        ("transport_contract.json", contract_bytes),
        (
            "intake_receipt.json",
            (json.dumps(result, sort_keys=True, indent=2) + "\n").encode(),
        ),
    ]:
        with (output_root / name).open("xb") as f:
            f.write(payload)
    return result


def load_bundle(bundle_root: Path, *, expected_receipt_sha256: str) -> dict[str, Any]:
    if bundle_root.is_symlink() or not bundle_root.is_dir():
        raise ValueError("unsafe bundle root")
    if sorted(p.name for p in bundle_root.iterdir()) != [
        "inputs",
        "intake_receipt.json",
        "public_context.json",
        "transport_contract.json",
    ]:
        raise ValueError("undeclared bundle root entry")
    receipt = read_object(bundle_root / "intake_receipt.json", expected_receipt_sha256)
    if receipt.get("schema_version") != SCHEMA:
        raise ValueError("unsupported input bundle version")
    if (
        receipt.get("status")
        != "PUBLIC_INPUT_TRANSPORT_COMPLETE_NATIVE_EXECUTION_UNVERIFIED"
        or receipt.get("readiness") != READINESS
        or receipt.get("attempt_accounting") != ACCOUNTING
    ):
        raise ValueError("input transport cannot claim runtime evidence")
    context = read_object(
        bundle_root / "public_context.json", receipt["context_sha256"]
    )
    contract = read_object(
        bundle_root / "transport_contract.json", receipt["contract_sha256"]
    )
    entries, payloads = scan(bundle_root / "inputs", maximum=5_242_880)
    expected = {
        r["path"]: {k: r[k] for k in ["path", "bytes", "sha256"]}
        for r in receipt["input_files"]
    }
    if (
        len(expected) != len(receipt["input_files"])
        or {r["path"]: r for r in entries} != expected
    ):
        raise ValueError("bundle file coverage or digest drift")
    if (
        context["task_id"] != receipt["task_id"]
        or contract["task_id"] != receipt["task_id"]
    ):
        raise ValueError("bundle task identity disagreement")
    if (
        context.get("schema_version") != "rtlflowbench.complete_public_text_context.v2"
        or contract.get("schema_version")
        != "rtlflowbench.public_input_transport_contract.v2"
    ):
        raise ValueError("unsupported context or contract schema")
    if len(context["files"]) != len(expected) or {
        f["path"] for f in context["files"]
    } != set(expected):
        raise ValueError("prompt context omits or duplicates files")
    for item in context["files"]:
        if (
            item["text"].encode() != payloads[item["path"]]
            or item["sha256"] != expected[item["path"]]["sha256"]
            or item["bytes"] != expected[item["path"]]["bytes"]
        ):
            raise ValueError("prompt/source byte disagreement")
    task = json.loads(payloads["public/external_task.json"])
    if (
        task.get("schema_version") != "rtlflowbench.task.v1"
        or task.get("task_id") != receipt["task_id"]
    ):
        raise ValueError("source task identity disagreement")
    if (
        byte_digest(payloads["public/external_task.json"])
        != receipt["source_binding"]["task_descriptor_file_sha256"]
    ):
        raise ValueError("source task digest disagreement")
    if any(
        view["submission_contract"] != task["submission_contract"]
        or view["budget"] != task["budget"]
        for view in [context, contract]
    ):
        raise ValueError("prompt changes task scope or budget")
    if (
        task["public_packet"].get("contains_evaluator_assets") is not False
        or task["public_packet"].get("network_access") is not False
        or task["budget"].get("network_access") is not False
    ):
        raise ValueError("task isolation contract missing")
    if (
        contract["native_output_shape"] != classify_output_transport(task)
        or contract.get("compiler_dependency_policy")
        != "not_inferred_native_tool_access_requires_separate_validation"
    ):
        raise ValueError("unverified native transport claim")
    for key in ["workspace_set_sha256", "workspace_payload_sha256"]:
        if contract[key] != receipt["source_binding"][key]:
            raise ValueError("workspace source disagreement")
    existing = path_list(contract["editable_initial_paths"])
    absent = path_list(contract["blank_output_paths"])
    readonly = path_list(contract["read_only_repository_paths"])
    editable = path_list(task["submission_contract"]["editable_paths"])
    required = path_list(task["submission_contract"]["required_files"])
    repository = {
        name.removeprefix("repository/")
        for name in payloads
        if name.startswith("repository/")
    }
    if (
        not required.issubset(editable)
        or existing & absent
        or existing & readonly
        or absent & readonly
        or existing | absent != editable
        or existing | readonly != repository
    ):
        raise ValueError("transport scope partition disagreement")
    declared_roles = {item["path"]: item["role"] for item in receipt["input_files"]}
    for item in context["files"]:
        name = item["path"]
        if name.startswith("public/"):
            role = "public_packet"
        elif name.startswith("repository/"):
            role = (
                "editable_initial_source"
                if name.removeprefix("repository/") in existing
                else "read_only_repository_input"
            )
        else:
            raise ValueError("unexpected input category")
        if item["role"] != role or declared_roles[name] != role:
            raise ValueError("input role disagreement")
    expected_summary = {
        "public_file_count": len(payloads) - len(repository),
        "repository_file_count": len(repository),
        "input_file_count": len(payloads),
        "input_bytes": sum(len(value) for value in payloads.values()),
        "context_bytes": (bundle_root / "public_context.json").stat().st_size,
        "omitted_file_count": 0,
    }
    if receipt["summary"] != expected_summary:
        raise ValueError("transport accounting disagreement")
    return {"receipt": receipt, "context": context, "contract": contract, "task": task}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace-root", type=Path, required=True)
    parser.add_argument("--workspace-set", type=Path, required=True)
    parser.add_argument("--expected-workspace-set-sha256", required=True)
    parser.add_argument("--task-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    a = parser.parse_args()
    r = build_bundle(
        workspace_root=a.workspace_root,
        workspace_set_path=a.workspace_set,
        expected_workspace_set_sha256=a.expected_workspace_set_sha256,
        task_id=a.task_id,
        output_root=a.output,
    )
    print(json.dumps({"status": r["status"], "summary": r["summary"]}))


if __name__ == "__main__":
    main()
