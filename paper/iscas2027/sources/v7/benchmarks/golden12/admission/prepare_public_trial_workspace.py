#!/usr/bin/env python3
"""Materialize one authenticated, public-only Golden-12 trial workspace.

This is a transport boundary, not an evaluator.  It authenticates the outer
public-suite candidate, revalidates one nested public packet, optionally binds
an operator-provided repository projection, and exposes only ``public/`` plus
the scoped ``worktree/`` to an external workflow.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import sys
import tarfile
import tempfile
from typing import Any

from jsonschema import Draft202012Validator


TASK_IDS = (
    "G01-common-fifo-spec",
    "G02-common-rr-arbiter-spec",
    "G03-axis-fifo-backpressure",
    "G04-wb2axip-split-bridge",
    "G05-picorv32-missing-irq",
    "G06-ibex-debug-csr-exception",
    "G07-ibex-ifetch-error-timing",
    "G08-common-fifo-dv",
    "G09-axis-fifo-dv",
    "G10-serv-area-qor",
    "G11-picorv32-qor",
    "G12-common-cdc-missing-contract",
)
SUITE_ROOT = "rtlflowbench-golden12-development-candidate"
ROOT = Path(__file__).resolve().parent
SUITE_VERIFIER = ROOT / "verify_public_suite_candidate.py"
RECEIPT_SCHEMA = ROOT / "public_trial_workspace_receipt.schema.json"
MAX_PROJECTION_MEMBERS = 256
MAX_PROJECTION_MEMBER_BYTES = 32 * 1024 * 1024
MAX_PROJECTION_BYTES = 128 * 1024 * 1024


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _sha256(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _canonical_digest(entries: list[dict[str, Any]]) -> str:
    return _sha256_bytes(
        json.dumps(entries, separators=(",", ":"), sort_keys=True).encode()
    )


def _load(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"required JSON is not a regular file: {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain one JSON object")
    return value


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load required module: {path.name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _safe_relative(value: str) -> Path:
    pure = PurePosixPath(value)
    if (
        pure.is_absolute()
        or not pure.parts
        or any(part in {"", ".", ".."} for part in pure.parts)
        or "\\" in value
        or value != pure.as_posix()
        or "private" in {part.lower() for part in pure.parts}
    ):
        raise ValueError(f"unsafe workspace path: {value}")
    return Path(*pure.parts)


def _require_paths(value: object, label: str, *, allow_empty: bool) -> list[str]:
    if (
        not isinstance(value, list)
        or (not allow_empty and not value)
        or not all(isinstance(item, str) for item in value)
        or len(value) != len(set(value))
    ):
        raise ValueError(f"{label} must be a unique path array")
    for item in value:
        _safe_relative(item)
    return value


def _projection_contract(
    lock: dict[str, Any], scope: dict[str, Any]
) -> tuple[list[dict[str, Any]], list[str]]:
    if lock.get("task_id") != scope.get("task_id"):
        raise ValueError("repository lock and allowed scope task IDs disagree")
    editable = _require_paths(scope.get("editable_paths"), "editable_paths", allow_empty=False)
    read_only = _require_paths(
        scope.get("read_only_repository_paths", []),
        "read_only_repository_paths",
        allow_empty=True,
    )
    if set(editable).intersection(read_only):
        raise ValueError("editable and read-only repository paths overlap")
    notices = _require_paths(
        lock.get("required_notice_paths"), "required_notice_paths", allow_empty=False
    )

    raw_entries = lock.get("repository_projection_files")
    entries: list[dict[str, Any]] = []
    if raw_entries is not None:
        if not isinstance(raw_entries, list) or not raw_entries:
            raise ValueError("repository_projection_files must be non-empty")
        for raw in raw_entries:
            if not isinstance(raw, dict):
                raise ValueError("repository projection file entry must be an object")
            path = raw.get("path")
            mode = raw.get("mode")
            digest = raw.get("sha256")
            byte_count = raw.get("bytes")
            if not isinstance(path, str):
                raise ValueError("repository projection path must be a string")
            _safe_relative(path)
            if mode not in {"editable", "read_only"}:
                raise ValueError(f"invalid repository projection mode: {path}")
            if (
                not isinstance(digest, str)
                or len(digest) != 64
                or any(char not in "0123456789abcdef" for char in digest)
                or not isinstance(byte_count, int)
                or isinstance(byte_count, bool)
                or byte_count < 0
            ):
                raise ValueError(f"invalid locked repository projection content: {path}")
            entries.append(
                {
                    "path": path,
                    "mode": mode,
                    "sha256": digest,
                    "bytes": byte_count,
                    "archive_mode": 0o644 if mode == "editable" else 0o444,
                }
            )
        paths = [entry["path"] for entry in entries]
        if len(paths) != len(set(paths)):
            raise ValueError("repository projection paths are not unique")
        if [entry["path"] for entry in entries if entry["mode"] == "editable"] != editable:
            raise ValueError("locked editable projection differs from allowed scope")
        if set(entry["path"] for entry in entries if entry["mode"] == "read_only") != set(read_only):
            raise ValueError("locked read-only projection differs from allowed scope")
    else:
        allowlist = _require_paths(
            lock.get("repository_projection_allowlist"),
            "repository_projection_allowlist",
            allow_empty=False,
        )
        classified = set(editable) | set(read_only)
        if not set(allowlist).issubset(classified) or not set(read_only).issubset(allowlist):
            raise ValueError("projection allowlist differs from allowed scope")
        locked_digests = lock.get("repository_projection_sha256")
        if locked_digests is not None and (
            not isinstance(locked_digests, dict) or set(locked_digests) != set(allowlist)
        ):
            raise ValueError("repository projection digest map differs from allowlist")
        for path in allowlist:
            digest = locked_digests.get(path) if locked_digests else None
            if digest is not None and (
                not isinstance(digest, str)
                or len(digest) != 64
                or any(char not in "0123456789abcdef" for char in digest)
            ):
                raise ValueError(f"invalid locked repository projection digest: {path}")
            entries.append(
                {
                    "path": path,
                    "mode": "editable" if path in editable else "read_only",
                    "sha256": digest,
                    "bytes": None,
                    "archive_mode": 0o444,
                }
            )
    paths = [entry["path"] for entry in entries]
    if not set(notices).issubset(paths):
        raise ValueError("required notice is absent from repository projection")
    return entries, notices


def _projection_digest_entries(
    *,
    contract: list[dict[str, Any]],
    notices: list[str],
    payloads: dict[str, bytes],
    receipt: dict[str, Any],
) -> list[dict[str, Any]]:
    schema_version = str(receipt.get("schema_version", ""))
    mode_aware = ".g06_" in schema_version or ".g07_" in schema_version
    transform = receipt.get("transform")
    transformed_path: str | None = None
    if transform is not None:
        if not isinstance(transform, dict) or not isinstance(transform.get("path"), str):
            raise ValueError("repository projection transform is invalid")
        transformed_path = transform["path"]
        declaration = receipt.get("task_id") == "G12-common-cdc-missing-contract"
        if not declaration or transformed_path not in payloads:
            raise ValueError("repository projection transform path is invalid")
        if (
            transform.get("projected_sha256") != _sha256_bytes(payloads[transformed_path])
            or transform.get("projected_bytes") != len(payloads[transformed_path])
            or transform.get("non_comment_tokens_preserved") is not True
            or transform.get("copyright_license_header_preserved") is not True
        ):
            raise ValueError("withheld-contract transform receipt is invalid")
    entries: list[dict[str, Any]] = []
    by_path = {entry["path"]: entry for entry in contract}
    for path, payload in sorted(payloads.items()):
        locked = by_path[path]
        if mode_aware:
            role = (
                "license_notice"
                if path in notices
                else (
                    "editable_repository_source"
                    if locked["mode"] == "editable"
                    else "read_only_repository_dependency"
                )
            )
            entries.append(
                {
                    "path": path,
                    "mode": locked["mode"],
                    "archive_mode": format(locked["archive_mode"], "04o"),
                    "bytes": len(payload),
                    "sha256": _sha256_bytes(payload),
                    "role": role,
                }
            )
        else:
            role = "license_notice" if path in notices else "read_only_repository_dependency"
            if path == transformed_path:
                role = "read_only_withheld_contract_projection"
            entries.append(
                {
                    "path": path,
                    "bytes": len(payload),
                    "sha256": _sha256_bytes(payload),
                    "role": role,
                }
            )
    return entries


def _read_projection(
    *, archive_path: Path, receipt_path: Path, repo_lock_path: Path, allowed_scope_path: Path
) -> tuple[dict[str, bytes], dict[str, Any]]:
    archive_input = archive_path.expanduser()
    receipt_input = receipt_path.expanduser()
    if archive_input.is_symlink() or not archive_input.is_file():
        raise ValueError("repository projection archive must be a regular non-symlink file")
    if receipt_input.is_symlink() or not receipt_input.is_file():
        raise ValueError("repository projection receipt must be a regular non-symlink file")
    archive_path = archive_input.resolve(strict=True)
    receipt_path = receipt_input.resolve(strict=True)
    lock = _load(repo_lock_path)
    scope = _load(allowed_scope_path)
    receipt = _load(receipt_path)
    contract, notices = _projection_contract(lock, scope)
    expected_paths = [entry["path"] for entry in contract]
    archive_digest = _sha256(archive_path)
    status = receipt.get("status")
    if (
        receipt.get("task_id") != lock.get("task_id")
        or receipt.get("source_id") != lock.get("source_id")
        or receipt.get("source_archive_sha256") != lock.get("source_archive_sha256")
        or receipt.get("repo_lock_sha256") != _sha256(repo_lock_path)
        or receipt.get("archive_sha256") != archive_digest
        or receipt.get("archive_bytes") != archive_path.stat().st_size
        or receipt.get("projected_file_count") != len(expected_paths)
        or receipt.get("contains_evaluator_assets") is not False
        or receipt.get("redistribution_review_complete") is not False
        or not isinstance(status, str)
        or "development" not in status
        or "not_frozen" not in status
    ):
        raise ValueError("repository projection receipt disagrees with public lock/archive")
    if receipt.get("allowed_scope_sha256") not in {None, _sha256(allowed_scope_path)}:
        raise ValueError("repository projection receipt disagrees with allowed scope")
    if receipt.get("workflow_files_writable") not in {None, False}:
        raise ValueError("repository projection claims writable workflow files")
    if receipt.get("source_archive_exposed_to_workflow") not in {None, False}:
        raise ValueError("repository projection exposes the source archive")
    if receipt.get("projection_frozen") not in {None, False}:
        raise ValueError("development repository projection claims frozen status")
    projected_paths = receipt.get("projected_paths")
    if projected_paths is None:
        projected_paths = list(receipt.get("editable_paths", [])) + list(
            receipt.get("read_only_paths", [])
        )
    if sorted(projected_paths) != sorted(expected_paths):
        raise ValueError("repository projection receipt path set is invalid")

    payloads: dict[str, bytes] = {}
    total = 0
    contract_by_path = {entry["path"]: entry for entry in contract}
    try:
        with tarfile.open(archive_path, mode="r:gz") as archive:
            members = archive.getmembers()
            if not members or len(members) > MAX_PROJECTION_MEMBERS:
                raise ValueError("repository projection member count is unsafe")
            for member in members:
                relative = _safe_relative(member.name).as_posix()
                if relative in payloads or relative not in contract_by_path:
                    raise ValueError(f"unexpected/duplicate projection path: {relative}")
                locked = contract_by_path[relative]
                if (
                    not member.isfile()
                    or member.size < 0
                    or member.size > MAX_PROJECTION_MEMBER_BYTES
                    or member.uid != 0
                    or member.gid != 0
                    or member.uname != ""
                    or member.gname != ""
                    or member.mtime != 0
                    or member.mode != locked["archive_mode"]
                ):
                    raise ValueError(f"non-canonical projection member: {relative}")
                total += member.size
                if total > MAX_PROJECTION_BYTES:
                    raise ValueError("repository projection exceeds size limit")
                stream = archive.extractfile(member)
                if stream is None:
                    raise ValueError(f"cannot read repository projection path: {relative}")
                payload = stream.read(MAX_PROJECTION_MEMBER_BYTES + 1)
                if len(payload) != member.size:
                    raise ValueError(f"repository projection size mismatch: {relative}")
                digest = _sha256_bytes(payload)
                if locked["sha256"] is not None and locked["sha256"] != digest:
                    raise ValueError(f"locked repository projection digest drift: {relative}")
                if locked["bytes"] is not None and locked["bytes"] != len(payload):
                    raise ValueError(f"locked repository projection size drift: {relative}")
                payloads[relative] = payload
    except (tarfile.TarError, OSError) as exc:
        raise ValueError(f"repository projection cannot be decoded: {exc}") from exc
    if set(payloads) != set(expected_paths):
        raise ValueError("repository projection archive path closure is invalid")
    digest_entries = _projection_digest_entries(
        contract=contract, notices=notices, payloads=payloads, receipt=receipt
    )
    if receipt.get("projection_digest") != _canonical_digest(digest_entries):
        raise ValueError("repository projection tree digest is invalid")
    return payloads, receipt


def _public_tree_digest(payloads: dict[str, bytes]) -> str:
    entries = [
        {"path": path, "bytes": len(payload), "sha256": _sha256_bytes(payload)}
        for path, payload in sorted(payloads.items())
    ]
    return _canonical_digest(entries)


def _copy_public_packet(payloads: dict[str, bytes], destination: Path) -> int:
    destination.mkdir(parents=True)
    for relative, payload in sorted(payloads.items()):
        target = destination / _safe_relative(relative)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
    for path in sorted(destination.rglob("*"), reverse=True):
        os.chmod(path, 0o555 if path.is_dir() else 0o444)
    os.chmod(destination, 0o555)
    return len(payloads)


def _prepare_worktree(
    *, root: Path, payloads: dict[str, bytes], editable_paths: list[str]
) -> tuple[list[str], list[str]]:
    root.mkdir(parents=True)
    for relative, payload in sorted(payloads.items()):
        target = root / _safe_relative(relative)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
    editable = set(editable_paths)
    existing_editable = sorted(editable.intersection(payloads))
    absent_editable = sorted(editable - set(payloads))
    for relative in sorted(editable):
        (root / _safe_relative(relative)).parent.mkdir(parents=True, exist_ok=True)
    for path in root.rglob("*"):
        os.chmod(path, 0o555 if path.is_dir() else 0o444)
    os.chmod(root, 0o555)
    for relative in sorted(editable):
        target = root / _safe_relative(relative)
        parent = target.parent
        while True:
            os.chmod(parent, 0o755)
            if parent == root:
                break
            parent = parent.parent
        if target.exists():
            os.chmod(target, 0o644)
    return existing_editable, absent_editable


def _remove_tree(root: Path) -> None:
    if not root.exists():
        return
    for path in sorted((item for item in root.rglob("*") if item.is_dir()), reverse=True):
        os.chmod(path, 0o755)
    os.chmod(root, 0o755)
    shutil.rmtree(root)


def prepare_public_trial_workspace(
    *,
    suite_archive: Path,
    expected_suite_archive_sha256: str,
    task_id: str,
    output_dir: Path,
    observed_at: str,
    projection_archive: Path | None = None,
    projection_receipt: Path | None = None,
) -> dict[str, Any]:
    if task_id not in TASK_IDS:
        raise ValueError(f"task is not in Golden-12: {task_id}")
    output_dir = output_dir.expanduser().resolve()
    if output_dir.exists() or output_dir.is_symlink():
        raise FileExistsError(f"refusing to overwrite output: {output_dir}")
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{output_dir.name}-", dir=output_dir.parent))
    try:
        verifier = _load_module(
            SUITE_VERIFIER, "rtlflowbench_golden12_public_suite_trial_verifier"
        )
        verified_root = temporary / "verified-suite"
        verification = verifier.verify_public_suite_candidate(
            archive_path=suite_archive,
            expected_archive_sha256=expected_suite_archive_sha256,
            output_dir=verified_root,
            observed_at=observed_at,
        )
        suite_root = verified_root / SUITE_ROOT
        suite = _load(suite_root / "suite.json")
        task_summary = next(item for item in suite["tasks"] if item["task_id"] == task_id)
        nested_path = suite_root / task_summary["public_archive_path"]
        nested_payload = nested_path.read_bytes()
        if _sha256_bytes(nested_payload) != task_summary["public_archive_sha256"]:
            raise ValueError("task public archive digest drifted after suite verification")
        nested = verifier._read_tar_members(
            payload=nested_payload,
            label=f"{task_id} task archive",
            name_validator=verifier._validate_task_name,
            max_members=verifier.MAX_TASK_MEMBERS,
            max_member_bytes=verifier.MAX_TASK_MEMBER_BYTES,
            max_unpacked_bytes=verifier.MAX_TASK_UNPACKED_BYTES,
        )
        public_payloads = {
            PurePosixPath(name).relative_to("public").as_posix(): payload
            for name, payload in nested.items()
        }
        if not public_payloads or any(not path for path in public_payloads):
            raise ValueError("task public archive did not yield a public packet")

        staging = temporary / "workspace"
        staging.mkdir()
        public_root = staging / "public"
        public_count = _copy_public_packet(public_payloads, public_root)
        task = _load(public_root / "external_task.json")
        lock_path = public_root / "repo.lock"
        scope_path = public_root / "allowed_scope.json"
        lock = _load(lock_path)
        scope = _load(scope_path)
        if task.get("task_id") != task_id or lock.get("task_id") != task_id:
            raise ValueError("task/public lock IDs disagree")
        editable_paths = task["submission_contract"]["editable_paths"]
        if editable_paths != scope.get("editable_paths"):
            raise ValueError("external task and allowed scope editable paths disagree")
        projection_required = lock.get("source_snapshot_exposed_to_workflow") is True
        if projection_required and lock.get("agent_source_mode") not in {
            "repository_base",
            "repository_base_with_withheld_contract",
        }:
            raise ValueError("task source mode is unsupported for trial materialization")
        if projection_required != (projection_archive is not None):
            raise ValueError("projection archive presence disagrees with task source mode")
        if projection_required != (projection_receipt is not None):
            raise ValueError("projection receipt presence disagrees with task source mode")

        payloads: dict[str, bytes] = {}
        projection_value: dict[str, Any] | None = None
        if projection_required:
            assert projection_archive is not None and projection_receipt is not None
            payloads, projection_value = _read_projection(
                archive_path=projection_archive,
                receipt_path=projection_receipt,
                repo_lock_path=lock_path,
                allowed_scope_path=scope_path,
            )
        existing_editable, absent_editable = _prepare_worktree(
            root=staging / "worktree",
            payloads=payloads,
            editable_paths=editable_paths,
        )
        read_only_paths = sorted(set(payloads) - set(existing_editable))
        receipt_schema_payload = RECEIPT_SCHEMA.read_bytes()
        receipt_schema = json.loads(receipt_schema_payload)
        Draft202012Validator.check_schema(receipt_schema)
        projection_summary = None
        if projection_value is not None:
            assert projection_receipt is not None
            projection_summary = {
                "required": True,
                "receipt_schema_version": projection_value["schema_version"],
                "receipt_sha256": _sha256(projection_receipt.expanduser().resolve(strict=True)),
                "archive_sha256": projection_value["archive_sha256"],
                "projection_digest": projection_value["projection_digest"],
                "projected_paths": sorted(payloads),
                "redistribution_review_complete": False,
            }
        receipt = {
            "schema_version": "rtlflowbench.golden12_public_trial_workspace_receipt.v1",
            "observed_at": observed_at,
            "status": "development_trial_workspace_materialized_not_admitted",
            "task_id": task_id,
            "public_suite": {
                "archive_sha256": verification["archive_sha256"],
                "verification_receipt_sha256": _sha256(
                    verified_root / "verification_receipt.json"
                ),
                "suite_descriptor_sha256": verification["suite_descriptor_sha256"],
                "candidate_lock_sha256": task_summary["candidate_lock_sha256"],
                "task_public_archive_sha256": task_summary["public_archive_sha256"],
                "task_public_tree_sha256": _public_tree_digest(public_payloads),
            },
            "repository_projection": projection_summary,
            "layout": {
                "public_root": "public",
                "worktree_root": "worktree",
                "public_file_count": public_count,
                "repository_file_count": len(payloads),
                "private_file_count": 0,
                "editable_paths": editable_paths,
                "editable_existing_paths": existing_editable,
                "editable_absent_paths": absent_editable,
                "read_only_repository_paths": read_only_paths,
                "filesystem_permissions_not_security_boundary": True,
                "scope_monitor_required": True,
            },
            "readiness": {
                "rights_review_complete": False,
                "benchmark_ready": False,
                "chipflow_adapter_ready": False,
                "publishable_score_permitted": False,
            },
            "materializer_sha256": _sha256(Path(__file__)),
            "public_suite_verifier_sha256": _sha256(SUITE_VERIFIER),
            "receipt_schema_sha256": _sha256_bytes(receipt_schema_payload),
            "excluded_claims": [
                "This workspace is a development transport, not an admitted or frozen benchmark release.",
                "Filesystem modes do not replace an independent sandbox and scope monitor.",
                "No private evaluator, workflow PASS, score, QoR, PPA, or performance result is included.",
            ],
        }
        Draft202012Validator(receipt_schema).validate(receipt)
        (staging / "workspace_receipt.json").write_text(
            json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        staging.replace(output_dir)
        return receipt
    finally:
        _remove_tree(temporary)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--suite-archive", type=Path, required=True)
    parser.add_argument("--expected-suite-archive-sha256", required=True)
    parser.add_argument("--task-id", choices=TASK_IDS, required=True)
    parser.add_argument("--projection-archive", type=Path)
    parser.add_argument("--projection-receipt", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--observed-at", required=True)
    args = parser.parse_args()
    try:
        receipt = prepare_public_trial_workspace(
            suite_archive=args.suite_archive,
            expected_suite_archive_sha256=args.expected_suite_archive_sha256,
            task_id=args.task_id,
            projection_archive=args.projection_archive,
            projection_receipt=args.projection_receipt,
            output_dir=args.output_dir,
            observed_at=args.observed_at,
        )
    except Exception as exc:
        print(json.dumps({"status": "fail", "error": f"{type(exc).__name__}: {exc}"}, indent=2, sort_keys=True))
        return 2
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
