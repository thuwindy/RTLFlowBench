"""Bind full public MAGE input, its native entry and host-owned EDA broker."""

import sys
from pathlib import Path
import re

from mage_complete_native_entry_v2 import verify_runtime
from mage_complete_public_request_v2 import validate_request
from public_input_bundle_v2 import byte_digest, digest, regular_bytes

POLICY_SHA256 = "12ad99db7e514ac4876a6c0c78bda30b88e2bdc2c799d6c587ac4f3f2dd05989"
IMAGE_ID = "sha256:b2603ff50ac135f4c3926f103877cdef24a174c1f1846a07a0ae38267cbdf0bb"
IMAGE_DIGEST = "sha256:bcc34e79889c20d2d8f668a8341ecba291f9dc43036edc664e1347f3fd8d2a25"
EDA_DIGEST = "sha256:d6ed5a579d8ad959963079292b0d895107e0ba44ac2c91e636417a47f7a4b207"


def build_commands(
    *,
    request_root,
    bundle_root,
    runtime_root,
    expected_request_binding_sha256,
    expected_runtime_sha256,
    work_root,
    controller_root,
    client_root,
    broker_root,
    broker_evidence,
    broker_scratch,
    session,
    observed_at,
    preflight_only,
    policy_path,
):
    if type(preflight_only) is not bool:
        raise ValueError("explicit launch mode required")
    if not isinstance(session, str) or not re.fullmatch(
        r"[A-Za-z0-9_-]{1,64}", session
    ):
        raise ValueError("unsafe controller session")
    if byte_digest(regular_bytes(policy_path)) != POLICY_SHA256:
        raise ValueError("common policy drift")
    roots = [
        request_root,
        bundle_root,
        runtime_root,
        work_root,
        controller_root,
        client_root,
        broker_root,
    ]
    for root in roots:
        if (
            not root.is_absolute()
            or root.is_symlink()
            or not root.is_dir()
            or ":" in str(root)
        ):
            raise ValueError("unsafe MAGE mount root")
    resolved = [root.resolve() for root in roots]
    for i, root in enumerate(resolved):
        if any(
            root == other or root.is_relative_to(other) or other.is_relative_to(root)
            for other in resolved[i + 1 :]
        ):
            raise ValueError("overlapping mounts")
    if any(work_root.iterdir()) or any(client_root.iterdir()):
        raise FileExistsError("native scratch must be fresh")
    for path in [broker_evidence, broker_scratch]:
        if path.exists() or path.is_symlink() or not path.is_absolute():
            raise FileExistsError("broker scratch/evidence must be fresh")
        if any(
            path == root or path.is_relative_to(root) or root.is_relative_to(path)
            for root in resolved
        ):
            raise ValueError("broker evidence overlaps a mounted tree")
    verify_runtime(runtime_root, expected_runtime_sha256)
    binding = validate_request(
        request_root=request_root,
        bundle_root=bundle_root,
        expected_binding_sha256=expected_request_binding_sha256,
    )
    intake = binding["public_intake_receipt_sha256"]
    command = [
        "/usr/bin/python3",
        "/public-runtime/mage_complete_native_entry_v2.py",
        "--request-root",
        "/input",
        "--request-binding-sha256",
        expected_request_binding_sha256,
        "--public-bundle",
        "/public-bundle",
        "--runtime-sha256",
        expected_runtime_sha256,
        "--work-root",
        "/work",
        "--observed-at",
        observed_at,
    ]
    if preflight_only:
        command.append("--preflight-only")
    argv = [
        "podman",
        "run",
        "--rm",
        "--pull=never",
        "--network=none",
        "--read-only",
        "--cap-drop=all",
        "--security-opt=no-new-privileges",
        "--memory=1073741824",
        "--pids-limit=128",
        "--workdir=/work",
        "--entrypoint=/usr/bin/python3",
        "--volume",
        str(request_root) + ":/input:ro",
        "--volume",
        str(bundle_root) + ":/public-bundle:ro",
        "--volume",
        str(runtime_root) + ":/public-runtime:ro",
        "--volume",
        str(work_root) + ":/work:rw",
        "--volume",
        str(controller_root) + ":/run/rtlflowbench:ro",
        "--volume",
        str(client_root) + ":/run/rtlflowbench-client:rw",
        "--volume",
        str(broker_root) + ":/run/mage-eda:ro",
        "--env=PYTHONDONTWRITEBYTECODE=1",
        "--env=RTLFLOWBENCH_PUBLIC_INPUT_BUNDLE=/public-bundle",
        "--env=RTLFLOWBENCH_PUBLIC_INTAKE_SHA256=" + intake,
        "--env=RTLFLOWBENCH_MAGE_EDA_ACCOUNTING=host-broker-v2",
        "--env=RTLFLOWBENCH_MAGE_EDA_SOCKET=/run/mage-eda/broker.sock",
        "--env=RTLFLOWBENCH_MAGE_EDA_SESSION_ID=" + session,
        "--env=RTLFLOWBENCH_MAGE_EDA_CONTROL_ROOT=/work",
        IMAGE_ID,
        "/public-runtime/mage_controller_client_v2.py",
        "--socket",
        "/run/rtlflowbench/controller.sock",
        "--session",
        session,
        "--shim-root",
        "/run/rtlflowbench-client/shims",
        "--",
        *command,
    ]
    broker = [
        sys.executable,
        str(runtime_root / "mage_public_dependency_broker_v2.py"),
        "--base-broker",
        str(runtime_root / "mage_eda_broker.py"),
        "--public-input-bundle",
        str(bundle_root),
        "--public-intake-receipt-sha256",
        intake,
        "--socket",
        str(broker_root / "broker.sock"),
        "--session-id",
        session,
        "--control-root",
        str(work_root),
        "--evidence-root",
        str(broker_evidence),
        "--scratch-root",
        str(broker_scratch),
        "--image-digest",
        EDA_DIGEST,
        "--max-requests",
        "2",
        "--controller-socket",
        str(controller_root / "controller.sock"),
        "--controller-session-id",
        session,
    ]
    return (
        argv,
        broker,
        {
            "schema_version": "rtlflowbench.mage_complete_public_launch_plan.v2",
            "task_id": binding["task_id"],
            "request_binding_sha256": expected_request_binding_sha256,
            "runtime_manifest_sha256": expected_runtime_sha256,
            "image_id": IMAGE_ID,
            "image_digest": IMAGE_DIGEST,
            "eda_image_digest": EDA_DIGEST,
            "argv_sha256": digest(argv),
            "broker_argv_sha256": digest(broker),
            "preflight_only": preflight_only,
            "common_policy_sha256": POLICY_SHA256,
            "eda_accounting_owner": "host_broker_only_for_iverilog_vvp",
            "native_image_pythonpath_preserved": True,
            "private_evaluator_mounted": False,
            "host_authorization_created": False,
            "new_campaign_identity_required": True,
            "benchmark_verdict": None,
            "source_sha256": byte_digest(Path(__file__).read_bytes()),
        },
    )
