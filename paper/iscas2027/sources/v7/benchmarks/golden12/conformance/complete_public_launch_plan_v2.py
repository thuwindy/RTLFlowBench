"""Build a bound native OCI command; never authorizes or starts a campaign."""

from pathlib import Path
import re

from external_complete_public_request_v2 import validate_request
from native_complete_public_launcher_v2 import verify_runtime
from public_input_bundle_v2 import byte_digest, digest, regular_bytes

POLICY_SHA256 = "12ad99db7e514ac4876a6c0c78bda30b88e2bdc2c799d6c587ac4f3f2dd05989"
IMAGES = {
    "verilogcoder": {
        "image_id": "sha256:c94231c94fee83b5ee6ace21846cde18e841abc38d9deac581e021c9b9ceda53",
        "image_digest": "sha256:702a5aebe52854489199657e076eb974425688119dc65bd163616601a6b25a81",
    },
    "hdlagent": {
        "image_id": "sha256:1203f76b5b92633cd83a3587f264721bcc43db5b1910eae1f64b6a9280b94854",
        "image_digest": "sha256:20d317045a6ed61a7eca1ef206bf66aa03f6988ea062e455b50f15e29deb5afc",
    },
}


def build_command(
    *,
    request_root,
    bundle_root,
    runtime_root,
    expected_request_sha256,
    expected_runtime_sha256,
    work_root,
    controller_root,
    client_root,
    session,
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
        raise ValueError("common resource policy drift")
    roots = [
        request_root,
        bundle_root,
        runtime_root,
        work_root,
        controller_root,
        client_root,
    ]
    for root in roots:
        if (
            not root.is_absolute()
            or root.is_symlink()
            or not root.is_dir()
            or ":" in str(root)
        ):
            raise ValueError("unsafe mount root")
    resolved = [root.resolve() for root in roots]
    for index, first in enumerate(resolved):
        if any(
            first == other or first.is_relative_to(other) or other.is_relative_to(first)
            for other in resolved[index + 1 :]
        ):
            raise ValueError("overlapping input/control/work mounts")
    if any(work_root.iterdir()) or any(client_root.iterdir()):
        raise FileExistsError("work and client roots must be fresh")
    runtime = verify_runtime(runtime_root, expected_runtime_sha256)
    request = validate_request(
        request_root=request_root,
        bundle_root=bundle_root,
        bridge_source=runtime_root / "public_spec_submission_bridge.py",
        expected_request_sha256=expected_request_sha256,
    )
    image = IMAGES[request["workflow_id"]]
    command = [
        "/usr/bin/python3",
        "/public-runtime/native_complete_public_launcher_v2.py",
        "--request-root",
        "/input",
        "--request-sha256",
        expected_request_sha256,
        "--public-bundle",
        "/public-bundle",
        "--runtime-sha256",
        expected_runtime_sha256,
        "--source-root",
        "/opt/workflow",
        "--source-manifest",
        "/opt/source_snapshot.json",
        "--work-dir",
        "/work/native",
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
        "--env=PYTHONDONTWRITEBYTECODE=1",
        "--env=RTLFLOWBENCH_BASE_CONTROLLER_CLIENT=/public-runtime/controller_client.py",
        "--env=RTLFLOWBENCH_PUBLIC_INPUT_BUNDLE=/public-bundle",
        "--env=RTLFLOWBENCH_PUBLIC_INTAKE_SHA256="
        + request["public_intake_receipt_sha256"],
        "--env=RTLFLOWBENCH_PUBLIC_EDA_BINDING_ROOT=/run/rtlflowbench-client/bindings",
        image["image_id"],
        "/public-runtime/controller_client_public_inputs_v2.py",
        "--socket",
        "/run/rtlflowbench/controller.sock",
        "--session",
        session,
        "--shim-root",
        "/run/rtlflowbench-client/shims",
        "--",
        *command,
    ]
    # Preserve native image PYTHONPATH (including /opt/rtlflowbench's startup
    # controls). Python supplies the new script directory itself; don't replace
    # the upstream runtime path with just the adapter source directory.
    plan = {
        "schema_version": "rtlflowbench.complete_public_oci_launch_plan.v2",
        "workflow_id": request["workflow_id"],
        "task_id": request["task_id"],
        "runtime_profile": runtime["profile"],
        "native_image_binding": image,
        "host_runtime_manifest_sha256": expected_runtime_sha256,
        "request_sha256": expected_request_sha256,
        "public_intake_sha256": request["public_intake_receipt_sha256"],
        "common_resource_policy_sha256": POLICY_SHA256,
        "argv_sha256": digest(argv),
        "preflight_only": preflight_only,
        "native_image_pythonpath_preserved": True,
        "private_evaluator_mounted": False,
        "new_campaign_identity_required": True,
        "host_authorization_created": False,
        "benchmark_verdict": None,
        "source_sha256": byte_digest(Path(__file__).read_bytes()),
    }
    return argv, plan
