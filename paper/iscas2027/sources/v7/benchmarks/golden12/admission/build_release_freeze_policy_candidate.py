#!/usr/bin/env python3
"""Refresh release-freeze guard bindings without changing policy semantics."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator


REPO_ROOT = Path(__file__).resolve().parents[3]
POLICY_RELATIVE = Path(
    "benchmarks/golden12/admission/release_freeze_policy_candidate.json"
)
SCHEMA_RELATIVE = Path(
    "benchmarks/golden12/admission/release_freeze_policy_candidate.schema.json"
)


def _load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected one JSON object: {path}")
    return value


def _sha256(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"guard source must be a regular non-symlink file: {path}")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_policy(*, repo_root: Path, template: Path | None = None) -> dict[str, Any]:
    repo_root = repo_root.expanduser().resolve(strict=True)
    template_path = (template or (repo_root / POLICY_RELATIVE)).expanduser().resolve(
        strict=True
    )
    if not template_path.is_relative_to(repo_root) or template_path.is_symlink():
        raise ValueError("policy template must be a regular file inside repo_root")
    policy = _load_object(template_path)
    bindings = policy.get("guard_source_bindings")
    if not isinstance(bindings, dict) or not bindings:
        raise ValueError("policy has no guard source bindings")
    for name, binding in bindings.items():
        if not isinstance(binding, dict) or not isinstance(binding.get("path"), str):
            raise ValueError(f"invalid guard source binding: {name}")
        source = (repo_root / binding["path"]).resolve(strict=True)
        if not source.is_relative_to(repo_root):
            raise ValueError(f"guard source escapes repo_root: {binding['path']}")
        binding["sha256"] = _sha256(source)
    schema = _load_object(repo_root / SCHEMA_RELATIVE)
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(policy)
    return policy


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    parser.add_argument("--template", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.expanduser().absolute()
    if output.exists() or output.is_symlink():
        raise FileExistsError(f"refusing to overwrite output: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(
            build_policy(repo_root=args.repo_root, template=args.template),
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
