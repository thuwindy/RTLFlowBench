#!/usr/bin/env python3
"""Probe five frozen OCI candidates and bind only executable neutral launchers."""

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
SCHEMA = HERE / "workflow_launch_contract_intake.schema.json"
SLOTS = (
    ("chipflow", "chipflow"),
    ("same_model_vanilla_agent", "same_model_vanilla_agent"),
    ("external_airtl_1", "mage"),
    ("external_airtl_2", "verilogcoder"),
    ("external_airtl_3", "hdlagent"),
)
SPECS = {
    "chipflow": {
        "python": "/opt/native-preflight-env/bin/python",
        "entrypoint": "/opt/rtlflowbench/run_chipflow_public.py",
        "source_descriptor": "/opt/source_snapshot.json",
        "entrypoint_source": HERE.parent / "chipflow/run_public.py",
        "runtime_aux_sources": [],
        "argv": [
            "/opt/native-preflight-env/bin/python", "/opt/rtlflowbench/run_chipflow_public.py",
            "--request-root", "{PUBLIC_BRIDGE_REQUEST_ROOT}", "--work-dir", "{WORK_ROOT}",
            "--model", "{FROZEN_MODEL}"
        ],
        "placeholders": ["PUBLIC_BRIDGE_REQUEST_ROOT", "WORK_ROOT", "FROZEN_MODEL"],
    },
    "same_model_vanilla_agent": {
        "python": "/opt/native-preflight-env/bin/python",
        "entrypoint": "/opt/rtlflowbench/run_vanilla_public.py",
        "source_descriptor": "/opt/source_snapshot.json",
        "entrypoint_source": HERE.parent / "baselines/vanilla_agent/run_public.py",
        "runtime_aux_sources": [],
        "argv": [
            "/opt/native-preflight-env/bin/python", "/opt/rtlflowbench/run_vanilla_public.py",
            "--request-root", "{PUBLIC_BRIDGE_REQUEST_ROOT}", "--work-dir", "{WORK_ROOT}",
            "--model", "{FROZEN_MODEL}"
        ],
        "placeholders": ["PUBLIC_BRIDGE_REQUEST_ROOT", "WORK_ROOT", "FROZEN_MODEL"],
    },
    "mage": {
        "python": "/usr/bin/python3",
        "entrypoint": "/opt/rtlflowbench/run_mage_public.py",
        "source_descriptor": "/opt/source_snapshot.json",
        "entrypoint_source": HERE.parent / "conformance/external_workflows/mage_provider_runner.py",
        "runtime_aux_sources": [
            (
                "/usr/local/libexec/rtlflowbench/mage_openai_compat.py",
                HERE.parent / "conformance/external_workflows/mage_openai_compat.py",
            )
        ],
        "argv": [
            "/usr/bin/python3", "/opt/rtlflowbench/run_mage_public.py",
            "--request-root", "{PUBLIC_BRIDGE_REQUEST_ROOT}",
            "--workspace-root", "{WORK_ROOT}",
            "--result", "{WORK_ROOT}/provider_result.json",
            "--observed-at", "{OBSERVED_AT}",
            "--model", "{FROZEN_MODEL}",
            "--context-window", "{MODEL_CONTEXT_WINDOW}",
            "--max-tokens", "{MAX_TOKENS_PER_CALL}",
            "--max-retries", "{PROVIDER_MAX_RETRIES}",
            "--timeout-seconds", "{PROVIDER_TIMEOUT_SECONDS}",
            "--thinking-mode", "{THINKING_MODE}",
            "--sim-max-retry", "{MAGE_SIM_MAX_RETRY}",
            "--rtl-max-candidates", "{MAGE_RTL_MAX_CANDIDATES}",
            "--rtl-selected-candidates", "{MAGE_RTL_SELECTED_CANDIDATES}"
        ],
        "placeholders": [
            "PUBLIC_BRIDGE_REQUEST_ROOT", "WORK_ROOT", "OBSERVED_AT",
            "FROZEN_MODEL", "MODEL_CONTEXT_WINDOW", "MAX_TOKENS_PER_CALL",
            "PROVIDER_MAX_RETRIES", "PROVIDER_TIMEOUT_SECONDS", "THINKING_MODE",
            "MAGE_SIM_MAX_RETRY", "MAGE_RTL_MAX_CANDIDATES",
            "MAGE_RTL_SELECTED_CANDIDATES"
        ],
    },
    "verilogcoder": {
        "python": "/usr/bin/python3",
        "entrypoint": "/opt/rtlflowbench/run_verilogcoder_public.py",
        "source_descriptor": "/opt/source_snapshot.json",
        "entrypoint_source": HERE.parent / "conformance/external_workflows/run_verilogcoder_public.py",
        "runtime_aux_sources": [],
        "argv": [
            "/usr/bin/python3", "/opt/rtlflowbench/run_verilogcoder_public.py",
            "--source-root", "/opt/workflow", "--source-manifest", "/opt/source_snapshot.json",
            "--request-root", "{PUBLIC_BRIDGE_REQUEST_ROOT}", "--work-dir", "{WORK_ROOT}"
        ],
        "placeholders": ["PUBLIC_BRIDGE_REQUEST_ROOT", "WORK_ROOT"],
    },
    "hdlagent": {
        "python": "/usr/bin/python3",
        "entrypoint": "/opt/rtlflowbench/run_hdlagent_public.py",
        "source_descriptor": "/opt/source_snapshot.json",
        "entrypoint_source": HERE.parent / "conformance/external_workflows/run_hdlagent_public.py",
        "runtime_aux_sources": [],
        "argv": [
            "/usr/bin/python3", "/opt/rtlflowbench/run_hdlagent_public.py",
            "--source-root", "/opt/workflow", "--source-manifest", "/opt/source_snapshot.json",
            "--request-root", "{PUBLIC_BRIDGE_REQUEST_ROOT}", "--work-dir", "{WORK_ROOT}",
            "--model", "{FROZEN_MODEL}", "--compile-limit", "{TASK_COMPILE_LIMIT}",
            "--provider-mode", "networkless-deepseek-v4-pro"
        ],
        "placeholders": ["PUBLIC_BRIDGE_REQUEST_ROOT", "WORK_ROOT", "FROZEN_MODEL", "TASK_COMPILE_LIMIT"],
    },
}
SHA_RE = re.compile(r"^[0-9a-f]{64}$")


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


def _require_sha(path: Path, expected: str, label: str) -> str:
    if SHA_RE.fullmatch(expected) is None or _sha(path) != expected:
        raise ValueError(f"{label} differs from out-of-band trust anchor")
    return expected


def _rows(value: dict[str, Any], label: str) -> dict[str, dict[str, Any]]:
    rows = value.get("workflows")
    if not isinstance(rows, list) or len(rows) != 5:
        raise ValueError(f"{label} must contain five workflows")
    result = {}
    for row in rows:
        slot = row.get("workflow_slot_id")
        if slot in result:
            raise ValueError(f"{label} contains duplicate workflow slot")
        result[slot] = row
    if set(result) != {slot for slot, _ in SLOTS}:
        raise ValueError(f"{label} workflow slots differ from frozen cohort")
    return result


def _probe(
    *, podman: Path, image_id: str, interpreter: str,
    entrypoint: str, source_descriptor: str, expected_entrypoint_sha256: str,
    expected_runtime_aux_sha256: dict[str, str],
) -> dict[str, Any]:
    probe = (
        "import hashlib,json,os,sys; "
        "i=sys.argv[1]; e=sys.argv[2]; s=sys.argv[3]; expected_e=sys.argv[4]; aux=json.loads(sys.argv[5]); "
        "h=lambda p: hashlib.sha256(open(p,'rb').read()).hexdigest() if os.path.isfile(p) else None; "
        "binding=os.path.isfile(s) and h(e)==expected_e and all(h(p)==v for p,v in aux.items()); "
        "print(json.dumps({'python_available':os.path.isfile(i) and os.access(i,os.X_OK),"
        "'entrypoint_available':os.path.isfile(e),"
        "'source_binding_available':binding,'entrypoint_sha256':h(e),"
        "'source_descriptor_sha256':h(s)},sort_keys=True))"
    )
    argv = [
        str(podman), "run", "--rm", "--pull=never", "--network=none",
        "--read-only", "--cap-drop=all", "--security-opt=no-new-privileges",
        "--pids-limit=32", "--entrypoint=/bin/sh", image_id, "-c",
        "test -x \"$1\" && exec \"$1\" -c \"$2\" \"$3\" \"$4\" \"$5\" \"$6\" \"$7\"",
        "rtlflowbench-probe", interpreter, probe, interpreter,
        entrypoint, source_descriptor, expected_entrypoint_sha256,
        json.dumps(expected_runtime_aux_sha256, sort_keys=True),
    ]
    environment = {
        "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
        "HOME": os.environ["HOME"], "XDG_RUNTIME_DIR": os.environ["XDG_RUNTIME_DIR"],
    }
    completed = subprocess.run(
        argv, env=environment, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, timeout=60, check=False,
    )
    value = None
    if completed.returncode == 0:
        try:
            value = json.loads(completed.stdout.strip())
        except json.JSONDecodeError:
            value = None
    if not isinstance(value, dict):
        value = {
            "python_available": False, "entrypoint_available": False,
            "source_binding_available": False, "entrypoint_sha256": None,
            "source_descriptor_sha256": None,
        }
    return {
        "container_started": True,
        "network_policy": "none",
        "exit_code": completed.returncode,
        **value,
        "raw_output_embedded": False,
    }


def _contract(workflow_id: str, probe: dict[str, Any]) -> dict[str, Any] | None:
    if not (
        probe["exit_code"] == 0
        and probe["python_available"]
        and probe["entrypoint_available"]
        and probe["source_binding_available"]
        and SHA_RE.fullmatch(str(probe["entrypoint_sha256"]))
        and SHA_RE.fullmatch(str(probe["source_descriptor_sha256"]))
    ):
        return None
    spec = SPECS[workflow_id]
    return {
        "contract_version": "rtlflowbench.task_neutral_launch_contract.v1",
        "entrypoint": spec["entrypoint"],
        "entrypoint_sha256": probe["entrypoint_sha256"],
        "argv_template": spec["argv"],
        "placeholders": spec["placeholders"],
        "provider_transport": "host_observed_openai_compatible_unix_socket",
        "eda_observation": "path_interposed_iverilog_vvp_yosys_unix_socket_events",
        "task_solution_knowledge_included": False,
        "hidden_evaluator_reachable": False,
    }


def inspect_contracts(
    *, release_path: Path, expected_release_sha256: str,
    inventory_path: Path, expected_inventory_sha256: str,
    podman_path: Path, observed_at: str,
) -> dict[str, Any]:
    parsed = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("observed_at must include timezone")
    release_path = release_path.expanduser().resolve(strict=True)
    inventory_path = inventory_path.expanduser().resolve(strict=True)
    podman_path = podman_path.expanduser().resolve(strict=True)
    if podman_path.name != "podman" or not os.access(podman_path, os.X_OK):
        raise ValueError("podman executable is unavailable")
    _require_sha(release_path, expected_release_sha256, "release candidate")
    _require_sha(inventory_path, expected_inventory_sha256, "OCI inventory")
    release_rows = _rows(_load(release_path, "release candidate"), "release candidate")
    inventory_rows = _rows(_load(inventory_path, "OCI inventory"), "OCI inventory")
    workflows = []
    blockers = []
    contract_count = 0
    for slot, workflow_id in SLOTS:
        release = release_rows[slot]
        inventory = inventory_rows[slot]
        if release.get("workflow_id") != workflow_id or inventory.get("workflow_id") != workflow_id:
            raise ValueError("workflow identity drift")
        if (
            inventory.get("expected_image_digest") != release.get("runtime_image_digest")
            or inventory.get("inventory_status") != "available_unique_digest_match"
            or not isinstance(inventory.get("resolved_image_id"), str)
        ):
            raise ValueError("release and OCI inventory binding drift")
        spec = SPECS[workflow_id]
        entrypoint_source = spec["entrypoint_source"]
        expected_auxiliary = {
            container_path: _sha(source_path)
            for container_path, source_path in spec["runtime_aux_sources"]
        }
        probe = _probe(
            podman=podman_path, image_id=inventory["resolved_image_id"],
            interpreter=spec["python"],
            entrypoint=spec["entrypoint"], source_descriptor=spec["source_descriptor"],
            expected_entrypoint_sha256=_sha(entrypoint_source),
            expected_runtime_aux_sha256=expected_auxiliary,
        )
        contract = _contract(workflow_id, probe)
        row_blockers = []
        if contract is None:
            if not probe["python_available"]:
                row_blockers.append("runtime_python_unavailable")
            if not probe["entrypoint_available"]:
                row_blockers.append("task_neutral_entrypoint_missing")
            if not probe["source_binding_available"]:
                row_blockers.append(
                    "runtime_control_source_binding_mismatch"
                    if SHA_RE.fullmatch(str(probe["source_descriptor_sha256"]))
                    else "runtime_source_descriptor_missing"
                )
            blocker = f"{slot}_launch_contract_unavailable"
            blockers.append(blocker)
            contract_count += 0
        else:
            contract_count += 1
        workflows.append(
            {
                "workflow_slot_id": slot,
                "workflow_id": workflow_id,
                "source_commit": release["source_commit"],
                "source_manifest_sha256": release["source_manifest_sha256"],
                "runtime_image_digest": release["runtime_image_digest"],
                "runtime_image_id": inventory["resolved_image_id"],
                "probe": probe,
                "launch_contract": contract,
                "blockers": row_blockers,
            }
        )
    complete = contract_count == 5
    result = {
        "schema_version": "rtlflowbench.workflow_launch_contract_intake.v1",
        "observed_at": observed_at,
        "status": "launch_contract_intake_complete" if complete else "launch_contract_intake_partial",
        "decision": "PASS" if complete else "BLOCK",
        "scope": "five_workflow_task_neutral_resource_launch_contract_intake",
        "input_sha256": {
            "workflow_release_candidate": expected_release_sha256,
            "oci_inventory": expected_inventory_sha256,
            "podman": _sha(podman_path),
            "builder": _sha(Path(__file__).resolve()),
            "schema": _sha(SCHEMA),
        },
        "workflows": workflows,
        "summary": {
            "workflow_count": 5,
            "offline_probe_container_count": 5,
            "launch_contract_count": contract_count,
            "missing_launch_contract_count": 5 - contract_count,
            "task_packet_load_count": 0,
            "provider_call_count": 0,
            "eda_call_count": 0,
            "private_evaluator_call_count": 0,
        },
        "attempt_accounting": {
            "official_attempts_started": 0,
            "official_semantic_attempts_consumed": 0,
            "resource_calibration_attempts_consumed": 0,
            "benchmark_results_created": 0,
        },
        "readiness": {
            "all_runtime_images_probed": True,
            "all_launch_contracts_bound": complete,
            "measurement_requests_permitted": complete,
            "resource_campaign_permitted": False,
            "official_attempts_permitted": False,
        },
        "blockers": blockers,
        "excluded_claims": [
            "Offline entrypoint probes are runtime-intake evidence and are not AIRTL executions or benchmark verdicts.",
            "A structurally bound launch contract does not prove provider compatibility, EDA correctness, or adapter conformance.",
            "No public task packet, provider credential, private evaluator, hidden oracle, or workflow submission is loaded by this intake.",
            "Resource measurement requests and official attempts remain prohibited unless all five task-neutral launch contracts are bound.",
        ],
    }
    schema = _load(SCHEMA, "launch contract intake schema")
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(result)
    rendered = json.dumps(result, sort_keys=True)
    if "/home/" in rendered or "/Users/" in rendered:
        raise ValueError("receipt exposes private host path")
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workflow-release-candidate", type=Path, required=True)
    parser.add_argument("--expected-workflow-release-candidate-sha256", required=True)
    parser.add_argument("--oci-inventory", type=Path, required=True)
    parser.add_argument("--expected-oci-inventory-sha256", required=True)
    parser.add_argument("--podman", type=Path, required=True)
    parser.add_argument("--observed-at", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists() or args.output.is_symlink():
        raise FileExistsError("refusing to overwrite launch contract intake receipt")
    try:
        result = inspect_contracts(
            release_path=args.workflow_release_candidate,
            expected_release_sha256=args.expected_workflow_release_candidate_sha256,
            inventory_path=args.oci_inventory,
            expected_inventory_sha256=args.expected_oci_inventory_sha256,
            podman_path=args.podman,
            observed_at=args.observed_at,
        )
    except Exception as exc:
        print(json.dumps({"status": "error", "error_class": type(exc).__name__}))
        return 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result["summary"], indent=2, sort_keys=True))
    return 0 if result["decision"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
