#!/usr/bin/env python3
"""Join five task-neutral runtime candidates without freezing a release."""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
import subprocess
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


HERE = Path(__file__).resolve().parent
SCHEMA = HERE / "workflow_launch_runtime_set.schema.json"
SLOTS = (
    ("chipflow", "chipflow"),
    ("same_model_vanilla_agent", "same_model_vanilla_agent"),
    ("external_airtl_1", "mage"),
    ("external_airtl_2", "verilogcoder"),
    ("external_airtl_3", "hdlagent"),
)
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
IMAGE_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


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


def _rows(value: dict[str, Any], label: str) -> dict[str, dict[str, Any]]:
    rows = value.get("workflows")
    if not isinstance(rows, list) or len(rows) != 5:
        raise ValueError(f"{label} must contain five workflows")
    if any(not isinstance(row, dict) for row in rows):
        raise ValueError(f"{label} workflow rows must be objects")
    result = {row.get("workflow_slot_id"): row for row in rows}
    if list(result) != [slot for slot, _ in SLOTS]:
        raise ValueError(f"{label} workflow order or identity drifted")
    for slot, workflow_id in SLOTS:
        if result[slot].get("workflow_id") != workflow_id:
            raise ValueError(f"{label} workflow slot mapping drifted: {slot}")
    return result


def _catalog(podman: Path) -> list[dict[str, Any]]:
    completed = subprocess.run(
        [str(podman), "images", "--format", "json"],
        check=True, capture_output=True, text=True, timeout=30,
    )
    value = json.loads(completed.stdout)
    if not isinstance(value, list):
        raise ValueError("Podman image catalog is not an array")
    return value


def _normal_id(value: Any) -> str | None:
    text = str(value or "")
    if text.startswith("sha256:"):
        text = text[7:]
    return f"sha256:{text}" if SHA_RE.fullmatch(text) else None


def _resolve(catalog: list[dict[str, Any]], digest: str) -> tuple[str, int]:
    matches = [row for row in catalog if row.get("Digest") == digest]
    ids = {value for row in matches if (value := _normal_id(row.get("Id")))}
    sizes = {row.get("Size") for row in matches if isinstance(row.get("Size"), int) and row["Size"] > 0}
    if len(ids) != 1 or len(sizes) != 1:
        raise ValueError(f"runtime digest is unavailable or ambiguous: {digest}")
    return next(iter(ids)), next(iter(sizes))


def build_set(
    *, base_release_path: Path, expected_base_release_sha256: str,
    prior_intake_path: Path, expected_prior_intake_sha256: str,
    chipflow_probe_path: Path | None, expected_chipflow_probe_sha256: str | None,
    mage_probe_path: Path, expected_mage_probe_sha256: str,
    vanilla_probe_path: Path, expected_vanilla_probe_sha256: str,
    vanilla_descriptor_path: Path, expected_vanilla_descriptor_sha256: str,
    podman_path: Path, observed_at: str,
    verilogcoder_runtime_path: Path | None = None,
    expected_verilogcoder_runtime_sha256: str | None = None,
    runtime_supersession_path: Path | None = None,
    expected_runtime_supersession_sha256: str | None = None,
) -> dict[str, Any]:
    parsed = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("observed_at must include timezone")
    if (chipflow_probe_path is None) != (expected_chipflow_probe_sha256 is None):
        raise ValueError("ChipFlow probe path and out-of-band SHA256 must be supplied together")
    if (verilogcoder_runtime_path is None) != (expected_verilogcoder_runtime_sha256 is None):
        raise ValueError(
            "VerilogCoder runtime path and out-of-band SHA256 must be supplied together"
        )
    if (runtime_supersession_path is None) != (
        expected_runtime_supersession_sha256 is None
    ):
        raise ValueError(
            "runtime supersession path and out-of-band SHA256 must be supplied together"
        )
    paths = {
        "base_release_candidate": (base_release_path, expected_base_release_sha256),
        "prior_launch_intake": (prior_intake_path, expected_prior_intake_sha256),
        "mage_probe": (mage_probe_path, expected_mage_probe_sha256),
        "vanilla_probe": (vanilla_probe_path, expected_vanilla_probe_sha256),
        "vanilla_descriptor": (vanilla_descriptor_path, expected_vanilla_descriptor_sha256),
    }
    digests = {name: _require(path, expected, name) for name, (path, expected) in paths.items()}
    digests["chipflow_probe"] = (
        None
        if chipflow_probe_path is None
        else _require(chipflow_probe_path, expected_chipflow_probe_sha256, "chipflow_probe")
    )
    digests["verilogcoder_runtime"] = (
        None
        if verilogcoder_runtime_path is None
        else _require(
            verilogcoder_runtime_path,
            expected_verilogcoder_runtime_sha256,
            "verilogcoder_runtime",
        )
    )
    digests["runtime_supersession"] = (
        None
        if runtime_supersession_path is None
        else _require(
            runtime_supersession_path,
            expected_runtime_supersession_sha256,
            "runtime_supersession",
        )
    )
    podman = podman_path.expanduser().resolve(strict=True)
    if podman.name != "podman" or not podman.is_file():
        raise ValueError("Podman path is invalid")
    release = _load(base_release_path, "base release candidate")
    intake = _load(prior_intake_path, "prior launch intake")
    chipflow = None if chipflow_probe_path is None else _load(chipflow_probe_path, "ChipFlow runtime probe")
    verilogcoder = (
        None
        if verilogcoder_runtime_path is None
        else _load(verilogcoder_runtime_path, "VerilogCoder runtime receipt")
    )
    mage = _load(mage_probe_path, "MAGE runtime probe")
    vanilla = _load(vanilla_probe_path, "vanilla runtime probe")
    descriptor = _load(vanilla_descriptor_path, "vanilla runtime descriptor")
    supersession = (
        None
        if runtime_supersession_path is None
        else _load(runtime_supersession_path, "runtime supersession set")
    )
    release_rows = _rows(release, "base release candidate")
    intake_rows = _rows(intake, "prior launch intake")
    if release.get("schema_version") != "rtlflowbench.workflow_release_set_candidate.v1":
        raise ValueError("base release candidate schema drifted")
    if intake.get("schema_version") != "rtlflowbench.workflow_launch_contract_intake.v1":
        raise ValueError("prior launch intake schema drifted")
    if not (
        mage.get("schema_version") == "rtlflowbench.single_workflow_launch_contract_probe.v1"
        and mage.get("workflow_id") == "mage" and mage.get("decision") == "PASS"
        and mage.get("official_attempts_permitted") is False
        and all(mage.get(key) == 0 for key in ("task_packet_load_count", "provider_call_count", "eda_call_count", "private_evaluator_call_count"))
    ):
        raise ValueError("MAGE runtime probe is not an offline launch PASS")
    if not (
        vanilla.get("schema_version") == "rtlflowbench.vanilla_runtime_probe.v1"
        and vanilla.get("status") == "pass"
        and vanilla.get("binding_probe_passed") is True
        and vanilla.get("fail_closed_probe_passed") is True
        and all(vanilla.get(key) == 0 for key in ("task_packet_load_count", "provider_call_count", "eda_call_count", "private_evaluator_call_count", "benchmark_verdict_count"))
    ):
        raise ValueError("vanilla runtime probe is not a fail-closed offline PASS")
    if chipflow is not None and not (
        chipflow.get("schema_version") == "rtlflowbench.chipflow_runtime_probe.v1"
        and chipflow.get("workflow_id") == "chipflow"
        and chipflow.get("decision") == "PASS"
        and chipflow.get("status") == "task_neutral_runtime_probe_passed"
        and (chipflow.get("readiness") or {}).get("task_neutral_launch_candidate_bound") is True
        and (chipflow.get("readiness") or {}).get("runtime_release_frozen") is False
        and (chipflow.get("readiness") or {}).get("official_attempts_permitted") is False
        and (chipflow.get("activity") or {}).get("task_packet_load_count") == 1
        and all(
            (chipflow.get("activity") or {}).get(key) == 0
            for key in (
                "provider_call_count", "eda_call_count", "private_evaluator_call_count",
                "task_mutation_count", "benchmark_verdict_count", "official_attempt_count",
            )
        )
    ):
        raise ValueError("ChipFlow runtime probe is not an offline structural launch PASS")
    if verilogcoder is not None:
        workflow = verilogcoder.get("workflow") or {}
        container = verilogcoder.get("container") or {}
        preflight = verilogcoder.get("preflight") or {}
        claims = verilogcoder.get("claims") or {}
        if not (
            verilogcoder.get("schema_version")
            == "rtlflowbench.external_runtime_environment_receipt.v1"
            and verilogcoder.get("status")
            == "same_server_deterministic_runtime_reproduced_not_release_frozen"
            and workflow.get("workflow_id") == "verilogcoder"
            and re.fullmatch(r"[0-9a-f]{40}", str(workflow.get("commit")))
            and SHA_RE.fullmatch(str(workflow.get("tracked_manifest_sha256")))
            and IMAGE_RE.fullmatch(str(container.get("image_digest")))
            and _normal_id(container.get("image_id")) is not None
            and isinstance(container.get("size_bytes"), int)
            and container.get("size_bytes") > 0
            and container.get("two_build_identity_equal") is True
            and preflight.get("status") == "pass"
            and preflight.get("source_binding") is True
            and preflight.get("network") == "none"
            and claims.get("environment_reproducible_same_server") is True
            and claims.get("release_frozen") is False
            and claims.get("provider_call_observed") is False
            and claims.get("airtl_run_observed") is False
            and claims.get("hidden_evaluator_run") is False
            and claims.get("rtl_verdict_produced") is False
            and claims.get("adapter_ready") is False
            and claims.get("benchmark_ready") is False
        ):
            raise ValueError(
                "VerilogCoder runtime receipt is not a fail-closed offline PASS"
            )
    if not (
        descriptor.get("workflow_id") == "same_model_vanilla_agent"
        and descriptor.get("private_evaluator_included") is False
        and SHA_RE.fullmatch(str(descriptor.get("runtime_component_manifest_sha256")))
    ):
        raise ValueError("vanilla runtime descriptor is incomplete")
    supersession_rows: list[dict[str, Any]] = []
    if supersession is not None:
        summary = supersession.get("summary") or {}
        accounting = supersession.get("attempt_accounting") or {}
        readiness = supersession.get("readiness") or {}
        supersession_rows = supersession.get("replacements") or []
        if not (
            supersession.get("schema_version")
            == "rtlflowbench.workflow_runtime_supersession_set.v1"
            and supersession.get("status")
            == "task_neutral_runtime_supersession_set_validated"
            and isinstance(supersession_rows, list)
            and supersession_rows
            and summary.get("replacement_count") == len(supersession_rows)
            and all(
                summary.get(key) == 0
                for key in (
                    "task_packet_load_count",
                    "provider_call_count",
                    "eda_call_count",
                    "private_evaluator_call_count",
                    "benchmark_verdict_count",
                )
            )
            and set(accounting)
            == {
                "official_attempts_started",
                "semantic_attempts_consumed",
                "benchmark_results_created",
            }
            and all(value == 0 for value in accounting.values())
            and readiness.get("runtime_supersession_validated") is True
            and readiness.get("runtime_release_frozen") is False
            and readiness.get("official_attempts_permitted") is False
        ):
            raise ValueError("runtime supersession set is not a task-neutral PASS")
    catalog = _catalog(podman)
    overrides = {
        "same_model_vanilla_agent": (
            vanilla["image_digest"], vanilla["image_id"], digests["vanilla_probe"],
            descriptor["source_commit"], descriptor["runtime_component_manifest_sha256"],
            "task_neutral_runtime_probe_passed", True,
        ),
        "external_airtl_1": (
            mage["runtime_image_digest"], mage["runtime_image_id"], digests["mage_probe"],
            release_rows["external_airtl_1"]["source_commit"], release_rows["external_airtl_1"]["source_manifest_sha256"],
            "task_neutral_runtime_probe_passed", True,
        ),
    }
    if verilogcoder is not None:
        workflow = verilogcoder["workflow"]
        container = verilogcoder["container"]
        overrides["external_airtl_2"] = (
            container["image_digest"], _normal_id(container["image_id"]),
            digests["verilogcoder_runtime"], workflow["commit"],
            workflow["tracked_manifest_sha256"],
            "deterministic_runtime_environment_reproduced", True,
        )
    if chipflow is not None:
        runtime_image = chipflow.get("runtime_image") or {}
        overrides["chipflow"] = (
            runtime_image.get("image_digest"), runtime_image.get("image_id"),
            digests["chipflow_probe"], chipflow.get("source_commit"),
            chipflow.get("source_manifest_sha256"),
            "task_neutral_runtime_probe_passed", True,
        )
    seen_supersession_slots: set[str] = set()
    for replacement in supersession_rows:
        if not isinstance(replacement, dict):
            raise ValueError("runtime supersession replacement is invalid")
        slot = replacement.get("workflow_slot_id")
        workflow_id = replacement.get("workflow_id")
        if slot in seen_supersession_slots or (slot, workflow_id) not in SLOTS:
            raise ValueError("runtime supersession workflow identity drifted")
        seen_supersession_slots.add(slot)
        base = release_rows[slot]
        effective_prior = overrides.get(slot)
        if effective_prior is None:
            prior_digest = base.get("runtime_image_digest")
            prior_id = intake_rows[slot].get("runtime_image_id")
            prior_commit = base.get("source_commit")
            prior_manifest = base.get("source_manifest_sha256")
        else:
            prior_digest = effective_prior[0]
            prior_id = effective_prior[1]
            prior_commit = effective_prior[3]
            prior_manifest = effective_prior[4]
        if not (
            replacement.get("prior_image_digest") == prior_digest
            and replacement.get("prior_image_id") == prior_id
            and replacement.get("source_commit") == prior_commit
            and replacement.get("source_manifest_sha256") == prior_manifest
            and replacement.get("validation_status")
            == "task_neutral_runtime_supersession_validated"
            and replacement.get("task_neutral_help_probe_passed") is True
            and replacement.get("runtime_control_source_binding_passed") is True
            and replacement.get("network_policy") == "none"
        ):
            raise ValueError("runtime supersession differs from the base release binding")
        overrides[slot] = (
            replacement.get("replacement_image_digest"),
            replacement.get("replacement_image_id"),
            digests["runtime_supersession"],
            replacement.get("source_commit"),
            replacement.get("source_manifest_sha256"),
            "task_neutral_runtime_supersession_validated",
            True,
        )
    workflows = []
    for slot, workflow_id in SLOTS:
        base = release_rows[slot]
        if slot in overrides:
            image_digest, expected_id, evidence_sha, source_commit, source_manifest, status, launch_bound = overrides[slot]
        else:
            image_digest = base["runtime_image_digest"]
            source_commit = base["source_commit"]
            source_manifest = base["source_manifest_sha256"]
            prior_contract = intake_rows[slot].get("launch_contract")
            launch_bound = prior_contract is not None
            status = "prior_task_neutral_launch_contract_bound" if launch_bound else "preflight_only_launch_missing"
            evidence_sha = digests["prior_launch_intake"] if launch_bound else digests["base_release_candidate"]
            expected_id = intake_rows[slot].get("runtime_image_id") if launch_bound else None
        image_id, size = _resolve(catalog, image_digest)
        if expected_id is not None and image_id != expected_id:
            raise ValueError(f"runtime image id drifted: {slot}")
        row_blockers = ["runtime_release_not_frozen", "official_attempts_not_permitted"]
        if not launch_bound:
            row_blockers.append("task_neutral_launch_candidate_missing")
        workflows.append({
            "workflow_slot_id": slot, "workflow_id": workflow_id,
            "source_commit": source_commit, "source_manifest_sha256": source_manifest,
            "runtime_image_digest": image_digest, "runtime_image_id": image_id,
            "stored_image_size_bytes": size,
            "runtime_evidence_receipt_sha256": evidence_sha,
            "runtime_candidate_status": status,
            "task_neutral_launch_candidate_bound": launch_bound,
            "runtime_release_frozen": False, "official_attempts_permitted": False,
            "blockers": row_blockers,
        })
    count = sum(row["task_neutral_launch_candidate_bound"] for row in workflows)
    result = {
        "schema_version": "rtlflowbench.workflow_launch_runtime_set.v1",
        "observed_at": observed_at,
        "status": "launch_runtime_set_complete" if count == 5 else "launch_runtime_set_partial",
        "scope": "five_workflow_task_neutral_launch_runtime_candidates",
        "input_sha256": digests,
        "source_sha256": {"builder": _sha(Path(__file__).resolve()), "schema": _sha(SCHEMA), "podman": _sha(podman)},
        "workflows": workflows,
        "summary": {"workflow_count": 5, "runtime_image_bound_count": 5, "task_neutral_launch_candidate_count": count, "missing_launch_candidate_count": 5 - count, "task_packet_load_count": 1 if chipflow is not None else 0, "provider_call_count": 0, "eda_call_count": 0, "private_evaluator_call_count": 0},
        "attempt_accounting": {"official_attempts_started": 0, "semantic_attempts_consumed": 0, "benchmark_results_created": 0},
        "readiness": {"all_runtime_images_bound": True, "all_task_neutral_launch_candidates_bound": count == 5, "runtime_release_frozen": False, "official_attempts_permitted": False},
        "blockers": (["chipflow_task_neutral_launch_candidate_missing"] if count == 4 else ["task_neutral_launch_candidate_set_incomplete"] if count < 5 else ["runtime_release_and_independent_review_pending"]),
        "excluded_claims": ["This set binds launch candidates and does not freeze workflow releases.", "The optional ChipFlow development probe loads one public packet only to prove the native approval BLOCK; no provider, EDA tool, private evaluator, or hidden oracle is invoked.", "A task-neutral entrypoint or structural-probe PASS is not a benchmark PASS, score, or official attempt."],
    }
    schema = _load(SCHEMA, "workflow launch runtime-set schema")
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(result)
    if any(token in json.dumps(result) for token in ("/home/", "/Users/", "API_KEY")):
        raise ValueError("runtime set exposes a private path or credential name")
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    for name in ("base-release", "prior-intake", "mage-probe", "vanilla-probe", "vanilla-descriptor"):
        parser.add_argument(f"--{name}", type=Path, required=True)
        parser.add_argument(f"--expected-{name}-sha256", required=True)
    parser.add_argument("--chipflow-probe", type=Path)
    parser.add_argument("--expected-chipflow-probe-sha256")
    parser.add_argument("--verilogcoder-runtime", type=Path)
    parser.add_argument("--expected-verilogcoder-runtime-sha256")
    parser.add_argument("--runtime-supersession", type=Path)
    parser.add_argument("--expected-runtime-supersession-sha256")
    parser.add_argument("--podman", type=Path, default=Path("/usr/bin/podman"))
    parser.add_argument("--observed-at", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.expanduser().absolute()
    if output.exists() or output.is_symlink():
        raise FileExistsError("refusing to overwrite runtime set")
    value = build_set(
        base_release_path=args.base_release, expected_base_release_sha256=args.expected_base_release_sha256,
        prior_intake_path=args.prior_intake, expected_prior_intake_sha256=args.expected_prior_intake_sha256,
        chipflow_probe_path=args.chipflow_probe, expected_chipflow_probe_sha256=args.expected_chipflow_probe_sha256,
        verilogcoder_runtime_path=args.verilogcoder_runtime,
        expected_verilogcoder_runtime_sha256=args.expected_verilogcoder_runtime_sha256,
        runtime_supersession_path=args.runtime_supersession,
        expected_runtime_supersession_sha256=args.expected_runtime_supersession_sha256,
        mage_probe_path=args.mage_probe, expected_mage_probe_sha256=args.expected_mage_probe_sha256,
        vanilla_probe_path=args.vanilla_probe, expected_vanilla_probe_sha256=args.expected_vanilla_probe_sha256,
        vanilla_descriptor_path=args.vanilla_descriptor, expected_vanilla_descriptor_sha256=args.expected_vanilla_descriptor_sha256,
        podman_path=args.podman, observed_at=args.observed_at,
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"status": value["status"], **value["summary"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
