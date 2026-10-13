#!/usr/bin/env python3
"""Validate task-neutral OCI runtime replacements without starting an attempt."""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


HERE = Path(__file__).resolve().parent
SCHEMA = HERE / "workflow_runtime_supersession_set.schema.json"
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
IMAGE_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
POLICIES = {
    "mage": {
        "workflow_slot_id": "external_airtl_1",
        "entrypoint_source": HERE.parent
        / "conformance/external_workflows/mage_provider_runner.py",
        "entrypoint": "/opt/rtlflowbench/run_mage_public.py",
        "aux_sources": [
            (
                "mage_openai_compat",
                HERE.parent
                / "conformance/external_workflows/mage_openai_compat.py",
                "/usr/local/libexec/rtlflowbench/mage_openai_compat.py",
            )
        ],
        "source_descriptor": "/opt/source_snapshot.json",
        "commit_label": "org.rtlflowbench.mage.commit",
        "manifest_label": "org.rtlflowbench.mage.source-tracked-manifest-sha256",
        "help_tokens": ["--max-tokens", "--thinking-mode"],
    },
    "hdlagent": {
        "workflow_slot_id": "external_airtl_3",
        "entrypoint_source": HERE.parent
        / "conformance/external_workflows/run_hdlagent_public.py",
        "entrypoint": "/opt/rtlflowbench/run_hdlagent_public.py",
        "aux_sources": [],
        "source_descriptor": "/opt/source_snapshot.json",
        "commit_label": "org.rtlflowbench.workflow.commit",
        "manifest_label": "org.rtlflowbench.workflow.source-manifest-sha256",
        "help_tokens": ["--provider-mode"],
    },
}


def _load(path: Path, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a regular non-symlink file")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{label} must contain one JSON object")
    return value


def _sha(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"expected regular non-symlink file: {path}")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _require(path: Path, expected: str, label: str) -> str:
    if SHA_RE.fullmatch(expected) is None or _sha(path) != expected:
        raise ValueError(f"{label} differs from its out-of-band SHA256")
    return expected


def _normal_id(value: Any) -> str | None:
    text = str(value or "")
    if text.startswith("sha256:"):
        text = text[7:]
    return f"sha256:{text}" if SHA_RE.fullmatch(text) else None


def _catalog(podman: Path) -> list[dict[str, Any]]:
    completed = subprocess.run(
        [str(podman), "images", "--format", "json"],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    value = json.loads(completed.stdout)
    if not isinstance(value, list):
        raise ValueError("Podman image catalog is not an array")
    return value


def _resolve(
    catalog: list[dict[str, Any]], digest: str, expected_id: str
) -> tuple[str, int]:
    matches = [row for row in catalog if row.get("Digest") == digest]
    ids = {value for row in matches if (value := _normal_id(row.get("Id")))}
    sizes = {
        row.get("Size")
        for row in matches
        if isinstance(row.get("Size"), int) and row["Size"] > 0
    }
    if ids != {expected_id} or len(sizes) != 1:
        raise ValueError("replacement runtime image is unavailable or ambiguous")
    return next(iter(ids)), next(iter(sizes))


def _inspect(podman: Path, image_id: str) -> dict[str, Any]:
    completed = subprocess.run(
        [str(podman), "inspect", image_id],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    value = json.loads(completed.stdout)
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        raise ValueError("replacement runtime inspect result is invalid")
    return value[0]


def _container_run(
    podman: Path, image_id: str, argv: list[str]
) -> subprocess.CompletedProcess[str]:
    environment = {
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "HOME": os.environ["HOME"],
        "XDG_RUNTIME_DIR": os.environ["XDG_RUNTIME_DIR"],
    }
    return subprocess.run(
        [
            str(podman),
            "run",
            "--rm",
            "--pull=never",
            "--network=none",
            "--read-only",
            "--cap-drop=all",
            "--security-opt=no-new-privileges",
            "--pids-limit=32",
            "--entrypoint=/usr/bin/python3",
            image_id,
            *argv,
        ],
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=60,
        check=False,
    )


def _probe_content(
    podman: Path, image_id: str, paths: dict[str, str]
) -> dict[str, str]:
    code = (
        "import hashlib,json,os,sys; p=json.loads(sys.argv[1]); "
        "h=lambda x: hashlib.sha256(open(x,'rb').read()).hexdigest() "
        "if os.path.isfile(x) else None; print(json.dumps({k:h(v) for k,v in p.items()},sort_keys=True))"
    )
    completed = _container_run(podman, image_id, ["-c", code, json.dumps(paths)])
    if completed.returncode != 0:
        raise ValueError("replacement runtime content probe failed")
    try:
        value = json.loads(completed.stdout.strip())
    except json.JSONDecodeError as exc:
        raise ValueError("replacement runtime content probe is invalid") from exc
    if not isinstance(value, dict) or set(value) != set(paths):
        raise ValueError("replacement runtime content probe shape drifted")
    if any(SHA_RE.fullmatch(str(item)) is None for item in value.values()):
        raise ValueError("replacement runtime content is missing")
    return value


def _probe_help(
    podman: Path, image_id: str, entrypoint: str, tokens: list[str]
) -> bool:
    completed = _container_run(podman, image_id, [entrypoint, "--help"])
    return completed.returncode == 0 and all(token in completed.stdout for token in tokens)


def _prior_rows(value: dict[str, Any]) -> dict[str, dict[str, Any]]:
    if value.get("schema_version") != "rtlflowbench.workflow_launch_runtime_set.v1":
        raise ValueError("prior runtime set schema drifted")
    rows = value.get("workflows")
    if not isinstance(rows, list) or len(rows) != 5:
        raise ValueError("prior runtime set must contain five workflows")
    result = {row.get("workflow_id"): row for row in rows if isinstance(row, dict)}
    if len(result) != 5:
        raise ValueError("prior runtime set workflow identities drifted")
    return result


def _candidate_rows(value: dict[str, Any]) -> list[dict[str, Any]]:
    if value.get("schema_version") != "rtlflowbench.workflow_runtime_supersession_candidate.v1":
        raise ValueError("runtime supersession candidate schema drifted")
    rows = value.get("replacements")
    if not isinstance(rows, list) or not 1 <= len(rows) <= len(POLICIES):
        raise ValueError("runtime supersession candidate replacement count is invalid")
    allowed = {
        "workflow_slot_id",
        "workflow_id",
        "prior_image_digest",
        "prior_image_id",
        "replacement_image_digest",
        "replacement_image_id",
        "supersession_reason_code",
    }
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != allowed:
            raise ValueError("runtime supersession candidate row shape drifted")
        workflow_id = row.get("workflow_id")
        if workflow_id not in POLICIES or workflow_id in seen:
            raise ValueError("runtime supersession workflow identity is invalid")
        seen.add(workflow_id)
        policy = POLICIES[workflow_id]
        if row.get("workflow_slot_id") != policy["workflow_slot_id"]:
            raise ValueError("runtime supersession workflow slot drifted")
        if row.get("supersession_reason_code") != "runtime_control_source_binding_repair":
            raise ValueError("runtime supersession reason is not allowed")
        for key in (
            "prior_image_digest",
            "prior_image_id",
            "replacement_image_digest",
            "replacement_image_id",
        ):
            if IMAGE_RE.fullmatch(str(row.get(key))) is None:
                raise ValueError("runtime supersession image identity is invalid")
        if (
            row["prior_image_digest"] == row["replacement_image_digest"]
            or row["prior_image_id"] == row["replacement_image_id"]
        ):
            raise ValueError("runtime supersession does not replace the prior image")
    return rows


def build_set(
    *,
    prior_runtime_set_path: Path,
    expected_prior_runtime_set_sha256: str,
    candidate_path: Path,
    expected_candidate_sha256: str,
    podman_path: Path,
    observed_at: str,
) -> dict[str, Any]:
    parsed = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("observed_at must include timezone")
    digests = {
        "prior_runtime_set": _require(
            prior_runtime_set_path,
            expected_prior_runtime_set_sha256,
            "prior runtime set",
        ),
        "candidate": _require(candidate_path, expected_candidate_sha256, "candidate"),
    }
    podman = podman_path.expanduser().resolve(strict=True)
    if podman.name != "podman" or not podman.is_file():
        raise ValueError("Podman path is invalid")
    prior_rows = _prior_rows(_load(prior_runtime_set_path, "prior runtime set"))
    candidates = _candidate_rows(_load(candidate_path, "candidate"))
    catalog = _catalog(podman)
    replacements = []
    for candidate in candidates:
        workflow_id = candidate["workflow_id"]
        policy = POLICIES[workflow_id]
        prior = prior_rows[workflow_id]
        if (
            prior.get("workflow_slot_id") != candidate["workflow_slot_id"]
            or prior.get("runtime_image_digest") != candidate["prior_image_digest"]
            or prior.get("runtime_image_id") != candidate["prior_image_id"]
        ):
            raise ValueError("runtime supersession prior binding drifted")
        image_id, image_size = _resolve(
            catalog,
            candidate["replacement_image_digest"],
            candidate["replacement_image_id"],
        )
        inspect = _inspect(podman, image_id)
        labels = inspect.get("Labels") or (inspect.get("Config") or {}).get("Labels") or {}
        if not isinstance(labels, dict):
            raise ValueError("replacement runtime labels are invalid")
        if (
            labels.get(policy["commit_label"]) != prior.get("source_commit")
            or labels.get(policy["manifest_label"])
            != prior.get("source_manifest_sha256")
        ):
            raise ValueError("replacement runtime source identity drifted")
        expected_content = {
            "entrypoint": _sha(policy["entrypoint_source"]),
            **{
                role: _sha(host_path)
                for role, host_path, _ in policy["aux_sources"]
            },
        }
        container_paths = {
            "entrypoint": policy["entrypoint"],
            **{
                role: container_path
                for role, _, container_path in policy["aux_sources"]
            },
        }
        observed_content = _probe_content(podman, image_id, container_paths)
        if observed_content != expected_content:
            raise ValueError("replacement runtime control source binding mismatch")
        if not _probe_help(
            podman, image_id, policy["entrypoint"], policy["help_tokens"]
        ):
            raise ValueError("replacement runtime task-neutral help probe failed")
        descriptor_probe = _probe_content(
            podman,
            image_id,
            {"source_descriptor": policy["source_descriptor"]},
        )
        replacements.append(
            {
                **candidate,
                "source_commit": prior["source_commit"],
                "source_manifest_sha256": prior["source_manifest_sha256"],
                "stored_image_size_bytes": image_size,
                "runtime_control_sha256": expected_content,
                "source_descriptor_sha256": descriptor_probe["source_descriptor"],
                "network_policy": "none",
                "task_neutral_help_probe_passed": True,
                "runtime_control_source_binding_passed": True,
                "validation_status": "task_neutral_runtime_supersession_validated",
            }
        )
    result = {
        "schema_version": "rtlflowbench.workflow_runtime_supersession_set.v1",
        "observed_at": observed_at,
        "status": "task_neutral_runtime_supersession_set_validated",
        "scope": "runtime_control_repairs_without_task_or_provider_execution",
        "input_sha256": digests,
        "source_sha256": {
            "builder": _sha(Path(__file__).resolve()),
            "schema": _sha(SCHEMA),
            "podman": _sha(podman),
        },
        "replacements": replacements,
        "summary": {
            "replacement_count": len(replacements),
            "container_probe_count": len(replacements) * 3,
            "task_packet_load_count": 0,
            "provider_call_count": 0,
            "eda_call_count": 0,
            "private_evaluator_call_count": 0,
            "benchmark_verdict_count": 0,
        },
        "attempt_accounting": {
            "official_attempts_started": 0,
            "semantic_attempts_consumed": 0,
            "benchmark_results_created": 0,
        },
        "readiness": {
            "runtime_supersession_validated": True,
            "runtime_release_frozen": False,
            "official_attempts_permitted": False,
        },
        "blockers": [
            "downstream_release_inventory_launch_and_authorization_relock_required"
        ],
        "excluded_claims": [
            "This receipt validates task-neutral runtime control content and does not run a benchmark task.",
            "A help probe is not a functional benchmark verdict or a provider preflight.",
            "Runtime supersession does not freeze a release or erase prior INFRA evidence.",
        ],
    }
    schema = _load(SCHEMA, "runtime supersession-set schema")
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(result)
    rendered = json.dumps(result)
    if any(token in rendered for token in ("/home/", "/Users/", "API_KEY")):
        raise ValueError("runtime supersession receipt exposes a private path or credential")
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--prior-runtime-set", type=Path, required=True)
    parser.add_argument("--expected-prior-runtime-set-sha256", required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--expected-candidate-sha256", required=True)
    parser.add_argument("--podman", type=Path, default=Path("/usr/bin/podman"))
    parser.add_argument("--observed-at", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.expanduser().absolute()
    if output.exists() or output.is_symlink():
        raise FileExistsError("refusing to overwrite runtime supersession set")
    result = build_set(
        prior_runtime_set_path=args.prior_runtime_set,
        expected_prior_runtime_set_sha256=args.expected_prior_runtime_set_sha256,
        candidate_path=args.candidate,
        expected_candidate_sha256=args.expected_candidate_sha256,
        podman_path=args.podman,
        observed_at=args.observed_at,
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(
        json.dumps(
            {"status": result["status"], **result["summary"]}, sort_keys=True
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
