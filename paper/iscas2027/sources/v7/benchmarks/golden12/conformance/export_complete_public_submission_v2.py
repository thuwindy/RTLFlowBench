"""Post-process bound native outputs; never design, repair, evaluate or launch.

Completion flags are provenance, not correctness. A caller must pin both the
authorized observation and merged resource receipt. Old and diagnostic runs
cannot be relabelled as complete-public experiments.
"""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent
PACKAGER_FILES = {
    "conformance/package_submission.py": "817134cf39a8d2de00b7b9e6f25a05e655cb19a5e0ef0e6f9457207028065c44",
    "schemas/task.schema.json": "eb551050fdbc15cb4542e83776d332a8dbe229b04ed8053fe79611e789e69370",
    "schemas/submission.schema.json": "6b95d49b57391785658c35f0bd8d86973a0a1e4205c4660ff74c1196bf8b84a7",
}
EXTERNAL_COMPLETION = "rtlflowbench.external_native_completion.v2"


def safe_path(root, relative):
    if not isinstance(relative, str) or not relative or "\\" in relative:
        raise ValueError("unsafe relative artifact path")
    if any(x in {"", ".", ".."} for x in relative.split("/")):
        raise ValueError("unsafe relative artifact path")
    root = Path(root).absolute()
    for component in (root, *root.parents):
        if component.is_symlink():
            raise ValueError("symlink artifact ancestor")
    target = root
    for part in relative.split("/"):
        target = target / part
        if target.is_symlink():
            raise ValueError("symlink artifact component")
    if not target.resolve().is_relative_to(root.resolve()):
        raise ValueError("artifact escaped root")
    return target


def sha(path):
    path = safe_path(path.parent, path.name)
    if not path.is_file():
        raise ValueError("missing regular evidence file")
    value = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            value.update(chunk)
    return value.hexdigest()


def pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def load(path, expected=None):
    digest = sha(path)
    if expected is not None and digest != expected:
        raise ValueError("evidence hash drift")
    if path.stat().st_size > 16 * 1024 * 1024:
        raise ValueError("oversized evidence JSON")
    value = json.loads(path.read_bytes(), object_pairs_hook=pairs)
    if not isinstance(value, dict):
        raise ValueError("evidence must contain an object")
    return value


def completions(path, *, mage=False):
    """Stream server-only logs, retaining only an exact typed completion object."""
    sha(path)  # Validate the regular file before opening it.
    if path.stat().st_size > 512 * 1024 * 1024:
        raise ValueError("oversized completion log")
    marker = b'"NATIVE_RUNNER_RETURNED"' if mage else EXTERNAL_COMPLETION.encode()
    found = []
    with path.open("rb") as stream:
        while line := stream.readline(1024 * 1024 + 1):
            if len(line) > 1024 * 1024:
                raise ValueError("oversized log line; no truncation permitted")
            if marker not in line:
                continue
            try:
                value = json.loads(line, object_pairs_hook=pairs)
            except (ValueError, UnicodeDecodeError):
                raise ValueError("invalid native completion record") from None
            if not isinstance(value, dict):
                raise ValueError("invalid native completion record")
            expected = value.get("status") if mage else value.get("schema_version")
            if expected != ("NATIVE_RUNNER_RETURNED" if mage else EXTERNAL_COMPLETION):
                raise ValueError("ambiguous native completion marker")
            found.append(value)
            if len(found) > 1:
                raise ValueError("duplicate native completion records")
    return found[0] if found else None


def select_native(*, row, request_root, scratch, stdout, mods):
    workflow = row["workflow_id"]
    task_id = row["task_id"]
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", task_id):
        raise ValueError("unsafe task identity")
    if workflow not in {"mage", "verilogcoder", "hdlagent"}:
        raise ValueError("existing native workflows retain their existing exporters")
    complete = completions(stdout, mage=workflow == "mage")
    if complete is None:
        return None, "native_completion_missing", {}
    if (
        complete.get("task_id") != task_id
        or complete.get("benchmark_verdict") is not None
    ):
        raise ValueError("native completion task/verdict drift")
    provenance = {"completion_log_sha256": sha(stdout)}
    if workflow == "mage":
        if complete.get("runtime_manifest_sha256") != row["runtime_manifest_sha256"]:
            raise ValueError("native runtime drift")
        result_path = safe_path(scratch, "work/provider_result.json")
        result = load(result_path)
        request_path = safe_path(request_root, "mage_request.json")
        request = load(request_path)
        expected_fields = {
            "schema_version": "rtlflowbench.mage_provider_run.v1",
            "task_id": task_id,
            "request_sha256": sha(request_path),
            "configuration_sha256": request["configuration_sha256"],
            "status": complete["native_status"],
            "airtl_run_observed": True,
            "private_evaluator_mounted": False,
            "private_evaluator_executed": False,
            "rtl_verdict_produced": False,
            "mage_internal_self_test_is_benchmark_verdict": False,
        }
        if any(result.get(k) != v for k, v in expected_fields.items()):
            raise ValueError("MAGE result/request binding drift")
        # Original runner does not bind provider_result.json in stdout. Record
        # this read-time hash honestly; it is not a runner-signed attestation.
        provenance["native_result_read_time_sha256"] = sha(result_path)
        provenance["native_result_hash_attested_by_runner"] = False
        output = result.get("output")
        if output is None:
            if result["status"] != "completed_without_output":
                raise ValueError("MAGE output/status contradiction")
            return None, "native_completed_without_output", provenance
        expected = f"output/GOLDEN12_PUBLIC_SPEC_{task_id}/rtl.sv"
        if (
            result["status"] != "completed_output_observed"
            or output.get("relative_path") != expected
        ):
            raise ValueError("MAGE declared output drift")
        target = safe_path(scratch, "work/" + expected)
        expected_sha = output.get("sha256")
        expected_bytes = output.get("bytes")
    else:
        request = load(
            safe_path(request_root, "native_input.json"), row["request_binding_sha256"]
        )
        contract = mods["external_entry"].entry_contract(
            request, dependency_plan=None, dependency_error=None
        )
        expected = contract["expected_native_output"]
        if contract["gaps"] or expected is None:
            raise ValueError("native output API unavailable")
        checks = {
            "workflow_id": workflow,
            "native_method_returned": True,
            "output_path": expected,
            "request_sha256": row["request_binding_sha256"],
            "runtime_sha256": row["runtime_manifest_sha256"],
        }
        if any(complete.get(k) != v for k, v in checks.items()):
            raise ValueError("native completion request/output binding drift")
        target = safe_path(scratch, "work/native/" + expected)
        expected_sha = complete.get("output_sha256")
        expected_bytes = None
    if sha(target) != expected_sha:
        raise ValueError("declared native output hash drift")
    if expected_bytes is not None and target.stat().st_size != expected_bytes:
        raise ValueError("declared native output size drift")
    return (
        target,
        None,
        {
            **provenance,
            "declared_native_output_path": expected,
            "validated_output_sha256": expected_sha,
        },
    )


def verify_telemetry(
    *, root, observation_sha, merged_sha, campaign, campaign_sha, row, cohort, base
):
    def path(name):
        return safe_path(root, name)

    observation = load(path("observation.json"), observation_sha)
    if (
        observation.get("mode") != "authorized"
        or observation.get("status") != "WORKFLOW_RESOURCE_OBSERVED_NOT_EVALUATED"
    ):
        raise ValueError("diagnostic or legacy observation is not authorized evidence")
    runner_sha = campaign["source_binding"]["host_files"][
        "run_complete_public_measurement_v2.py"
    ]
    expected = {
        "schema_version": "rtlflowbench.complete_public_controller_observation.v2",
        "measurement_id": row["measurement_id"],
        "campaign_sha256": campaign_sha,
        "row_canonical_sha256": cohort.identity(row),
        "runner_sha256": runner_sha,
        "benchmark_verdict": None,
        "private_evaluator_mounted": False,
    }
    if any(observation.get(k) != v for k, v in expected.items()):
        raise ValueError("observation identity drift")
    invocation = load(path("invocation.json"), observation["invocation_sha256"])
    for key in (
        "mode",
        "measurement_id",
        "campaign_sha256",
        "row_canonical_sha256",
        "private_evaluator_mounted",
    ):
        if invocation.get(key) != observation[key]:
            raise ValueError("invocation/observation drift")
    if (
        invocation.get("host_source_binding") != campaign["source_binding"]
        or invocation.get("raw_provider_content_embedded") is not False
    ):
        raise ValueError("invocation source/isolation drift")
    for key in ("authorization_sha256", "common_provider_gate_sha256"):
        if not re.fullmatch(r"[a-f0-9]{64}", invocation.get(key, "") or ""):
            raise ValueError("unbound run authorization")
    for name in ("stdout", "stderr"):
        if sha(path(name + ".log")) != observation[name + "_sha256"]:
            raise ValueError("process log drift")
    process = load(path("resource-measurement-receipt.json"))
    ledger = load(path("activity-ledger.json"))
    activity = load(path("activity-concurrency-receipt.json"))
    merged = load(path("full-workflow-resource-receipt.json"), merged_sha)
    for value in (process, ledger, activity, merged):
        for key in (
            "measurement_id",
            "workflow_slot_id",
            "workflow_id",
            "task_id",
            "attempt_id",
            "source_binding",
            "runtime_binding",
        ):
            if value.get(key) != row["baseline_resource_request"][key]:
                raise ValueError("resource identity drift")
    if (
        process.get("request_sha256") != cohort.identity(row)
        or process.get("runner_sha256") != runner_sha
    ):
        raise ValueError("process request/runner drift")
    if ledger.get("process_measurement_receipt_sha256") != sha(
        path("resource-measurement-receipt.json")
    ):
        raise ValueError("ledger/process binding drift")
    for key in ("invocation_sha256", "stdout_sha256", "stderr_sha256"):
        if process["raw_evidence"].get(key) != observation[key]:
            raise ValueError("process raw evidence drift")
    for key, observed_key in (
        ("exit_code", "process_exit_code"),
        ("timed_out", "process_timed_out"),
        ("controller_guard_terminated", "controller_guard_stopped"),
    ):
        if process["launcher"].get(key) != observation[observed_key]:
            raise ValueError("process outcome drift")
    if process["launcher"].get("argv_sha256") != invocation["argv_sha256"]:
        raise ValueError("process invocation command drift")
    if (
        process["launcher"].get("network_policy_declared") != "offline"
        or process["launcher"].get("network_policy_enforced_by_measurement_envelope")
        is not True
    ):
        raise ValueError("workflow network isolation not verified")
    rebuilt = base._module(base.ACTIVITY_BUILDER, "export_v2_activity").build_receipt(
        ledger_path=path("activity-ledger.json"), observed_at=activity["observed_at"]
    )
    if rebuilt != activity:
        raise ValueError("activity projection drift")
    rebuilt = base._module(base.MERGER, "export_v2_merger").merge_receipts(
        process_receipt_path=path("resource-measurement-receipt.json"),
        activity_receipt_path=path("activity-concurrency-receipt.json"),
        observed_at=merged["observed_at"],
    )
    if observation["broker_returncode"] not in (None, 0):
        rebuilt["readiness"]["sample_complete"] = False
        rebuilt["readiness"]["sample_eligible_for_resource_cohort"] = False
        rebuilt["status"] = "full_workflow_resource_sample_ineligible"
    if rebuilt != merged:
        raise ValueError("merged resource projection drift")
    return observation, merged, ledger


def resource_usage(merged, ledger, human_interventions):
    if type(human_interventions) is not int or human_interventions < 0:
        raise ValueError("explicit nonnegative intervention count required")
    metrics = merged["metrics"]
    tokens = metrics["token_usage"]
    if tokens.get("measurement_complete") is not True:
        raise ValueError("incomplete token accounting")
    for value in (
        tokens.get("input_tokens"),
        tokens.get("output_tokens"),
        metrics.get("provider_call_count"),
    ):
        if type(value) is not int or value < 0:
            raise ValueError("missing or invalid measured token/call count")
    counts = Counter(item["kind"] for item in ledger["activities"])
    return {
        "wall_time_seconds": metrics["wall_time_seconds"],
        "input_tokens": tokens["input_tokens"],
        "output_tokens": tokens["output_tokens"],
        "llm_calls": metrics["provider_call_count"],
        "eda_calls": {
            k: counts["eda_" + k]
            for k in ("compile_or_lint", "simulation", "formal", "synthesis")
        },
        "human_interventions": human_interventions,
        "missing_measurements": [],
    }


def copy_artifact(native, target, *, maximum_bytes, expected_sha):
    native = safe_path(native.parent, native.name)
    if native.stat().st_size > maximum_bytes:
        raise ValueError("native artifact exceeds public submission budget")
    with native.open("rb") as stream:
        payload = stream.read(maximum_bytes + 1)
    if len(payload) > maximum_bytes:
        raise ValueError("native artifact exceeds public submission budget")
    if hashlib.sha256(payload).hexdigest() != expected_sha:
        raise ValueError("native output changed while reading")
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("xb") as stream:
        stream.write(payload)
    if sha(target) != expected_sha:
        raise ValueError("exported artifact hash drift")


def build(
    *,
    repo,
    campaign_path,
    campaign_sha,
    measurement_id,
    measurement_root,
    observation_sha,
    merged_sha,
    scratch,
    output,
    human_interventions,
):
    if output.exists() or output.is_symlink():
        raise FileExistsError("export output must be fresh")
    roots = [
        safe_path(x.parent, x.name).resolve()
        for x in (campaign_path.parent, measurement_root, scratch, output)
    ]
    if any(
        a == b or a.is_relative_to(b) or b.is_relative_to(a)
        for i, a in enumerate(roots)
        for b in roots[i + 1 :]
    ):
        raise ValueError("export/input roots overlap")
    execution = repo / "benchmarks/golden12/execution"
    sys.path.insert(0, str(execution))
    import complete_public_cohort_v2 as cohort

    campaign = cohort.validate_campaign(
        repo=repo, path=campaign_path, expected_sha=campaign_sha
    )
    rows = [row for row in campaign["rows"] if row["measurement_id"] == measurement_id]
    if len(rows) != 1:
        raise ValueError("one bound schedule row required")
    row = rows[0]
    if row["route"] not in {"mage_complete_public", "external_complete_public"}:
        raise ValueError("existing native workflows retain their existing exporters")
    base, mods = cohort.base_runner(repo), cohort.public_modules(repo)
    _, merged, ledger = verify_telemetry(
        root=measurement_root,
        observation_sha=observation_sha,
        merged_sha=merged_sha,
        campaign=campaign,
        campaign_sha=campaign_sha,
        row=row,
        cohort=cohort,
        base=base,
    )
    if merged["status"] != "full_workflow_resource_sample_complete":
        raise ValueError("incomplete resource sample; do not invent missing usage")
    bundle = safe_path(campaign_path.parent, row["bundle_relative_root"])
    task = mods["bundle"].load_bundle(
        bundle, expected_receipt_sha256=row["public_intake_sha256"]
    )["task"]
    shape = mods["bundle"].classify_output_transport(task)
    if shape != row["output_shape"] or not shape["representable"]:
        raise ValueError(
            "single-output adapter cannot satisfy declared submission shape"
        )
    native, reason, provenance = select_native(
        row=row,
        request_root=safe_path(campaign_path.parent, row["request_relative_root"]),
        scratch=scratch,
        stdout=safe_path(measurement_root, "stdout.log"),
        mods=mods,
    )
    golden = repo / "benchmarks/golden12"
    for relative, expected in PACKAGER_FILES.items():
        if sha(safe_path(golden, relative)) != expected:
            raise ValueError("neutral packager/schema source drift")
    usage = resource_usage(merged, ledger, human_interventions)
    common = {
        "schema_version": "rtlflowbench.complete_public_submission_export.v2",
        "measurement_id": measurement_id,
        "task_id": row["task_id"],
        "workflow_id": row["workflow_id"],
        "campaign_sha256": campaign_sha,
        "row_canonical_sha256": cohort.identity(row),
        "observation_sha256": observation_sha,
        "merged_resource_sha256": merged_sha,
        "public_intake_sha256": row["public_intake_sha256"],
        "exporter_sha256": sha(Path(__file__)),
        "packager_source_binding": PACKAGER_FILES,
        "native_provenance": provenance,
        "human_interventions": human_interventions,
        "human_interventions_source": "explicit_operator_metadata",
        "benchmark_verdict": None,
        "private_evaluator_calls": 0,
        "official_release": False,
    }
    output.mkdir(parents=True)
    result = {
        **common,
        "status": "NO_SUBMISSION",
        "reason_code": reason,
        "submission_sha256": None,
    }
    if native is not None:
        target = safe_path(output / "bundle", shape["target_output_path"])
        native_sha = provenance["validated_output_sha256"]
        copy_artifact(
            native,
            target,
            maximum_bytes=task["submission_contract"]["max_submission_bytes"],
            expected_sha=native_sha,
        )
        request = row["baseline_resource_request"]
        metadata = {
            "schema_version": "rtlflowbench.submission_metadata.v1",
            "submission_id": "submission-" + request["attempt_id"],
            "workflow": {
                "name": row["workflow_id"],
                "version": request["runtime_binding"]["image_digest"],
                "adapter_name": "rtlflowbench-complete-declared-output",
                "adapter_version": "v2",
                "config_sha256": row["request_binding_sha256"],
                "model": {"provider": "deepseek", "name": "deepseek-v4-pro"},
            },
            "attempt": {
                "attempt_id": request["attempt_id"],
                "attempt_index": 1,
                "repeat_group_id": f"complete-public-v2-{row['workflow_id']}-{row['task_id']}",
                "seed": request["official_attempt_binding"]["seed"],
            },
            "resource_usage": usage,
            "network_access_observed": False,
            "claims": [],
        }
        spec = importlib.util.spec_from_file_location(
            "export_v2_packager", golden / "conformance/package_submission.py"
        )
        packager = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(packager)
        submission = packager.package_submission(
            task=task, metadata=metadata, bundle_root=output / "bundle"
        )
        base._write_new(output / "submission.json", submission)
        result.update(
            status="SUBMISSION_EXPORTED",
            reason_code=None,
            submission_sha256=sha(output / "submission.json"),
            artifact_sha256=native_sha,
        )
    base._write_new(output / "export-receipt.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("repo", "campaign-path", "measurement-root", "scratch", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("campaign-sha", "measurement-id", "observation-sha", "merged-sha"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--human-interventions", type=int, required=True)
    try:
        result = build(**vars(parser.parse_args()))
    except Exception as error:
        # Paths, native log contents and provider responses stay server-only.
        print(
            json.dumps(
                {
                    "status": "EXPORT_REJECTED",
                    "error_class": type(error).__name__,
                    "benchmark_verdict": None,
                }
            )
        )
        return 2
    print(
        json.dumps(
            {k: result[k] for k in ("status", "reason_code", "benchmark_verdict")}
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
