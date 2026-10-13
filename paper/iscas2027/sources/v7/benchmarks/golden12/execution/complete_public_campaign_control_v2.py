"""Exact full200 author-alpha authorization, append-only microbatches and resume.

No task selection, native design logic, private evaluation or scientific verdict.
The public controller's existing limits and one-slot balance probes are retained.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import fcntl
import hashlib
import json
from pathlib import Path
import re

import complete_public_cohort_v2 as cohort
import run_complete_public_measurement_v2 as runner

GATE_MAX_AGE_SECONDS = 6 * 3600
LOCK_SCHEMA = "rtlflowbench.complete_public_launch_lock.v2"


def write(path, value):
    with path.open("x") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def age_check(observed_at, now):
    observed = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
    if observed.tzinfo is None or now.tzinfo is None:
        raise ValueError("provider preflight timestamp needs timezone")
    age = (now - observed).total_seconds()
    if not -60 <= age <= GATE_MAX_AGE_SECONDS:
        raise ValueError("provider preflight expired or future-dated")


def execution_window(path, preflight_sha, now):
    value = cohort.read(path, cohort.sha(path))
    if (
        value.get("schema_version")
        != "rtlflowbench.provider_preflight_execution_window.v2"
        or value.get("preflight_sha256") != preflight_sha
        or value.get("launcher_exit_code") != 0
    ):
        raise ValueError("native preflight execution window binding drift")
    for field in ("started_at", "finished_at"):
        age_check(value[field], now)
    start = datetime.fromisoformat(value["started_at"])
    end = datetime.fromisoformat(value["finished_at"])
    if not 0 <= (end - start).total_seconds() <= 600:
        raise ValueError("invalid provider execution window")
    return cohort.sha(path)


def checked_gate(*, base, gate_path, gate_sha, campaign, evidence_root, now):
    gate, _ = base._provider_gate(gate_path, gate_sha)
    age_check(gate["observed_at"], now)
    if (
        gate["provider_binding"]["common_model_candidate_sha256"]
        != runner.MODEL_CANDIDATE
    ):
        raise ValueError("common model candidate drift")
    expected = {}
    for row in campaign["rows"]:
        workflow = row["workflow_id"]
        image = row["baseline_resource_request"]["runtime_binding"]["image_digest"]
        if workflow in expected and expected[workflow] != image:
            raise ValueError("mixed workflow image identity")
        expected[workflow] = image
    routes = gate["native_routes"]
    if len(routes) != 5 or {r["workflow_slot_id"] for r in routes} != set(expected):
        raise ValueError("five distinct native provider routes required")
    windows = {}
    for route in routes:
        if (
            route["status"] != "pass"
            or route["runtime_image_digest"] != expected[route["workflow_slot_id"]]
        ):
            raise ValueError("provider route/image mismatch")
        prefix = "SERVER26:rtlflowbench/evidence/"
        if not route["evidence_uri"].startswith(prefix):
            raise ValueError("unknown provider evidence authority")
        path = cohort.child(evidence_root, route["evidence_uri"][len(prefix) :])
        preflight = cohort.read(path, route["preflight_sha256"])
        if "observed_at" in preflight:
            age_check(preflight["observed_at"], now)
        else:
            window = path.with_suffix(".execution-window.json")
            windows[route["workflow_slot_id"]] = execution_window(
                window, route["preflight_sha256"], now
            )
    return gate, windows


def source_bindings(repo):
    paths = [
        Path(__file__),
        Path(runner.__file__),
        repo
        / "benchmarks/golden12/conformance/export_complete_public_submission_v2.py",
    ]
    # Postprocessing uses the same immutable neutral packager and schemas.
    mods = cohort.public_modules(repo)
    del mods
    import export_complete_public_submission_v2 as exporter

    paths += [repo / "benchmarks/golden12" / p for p in exporter.PACKAGER_FILES]
    return {
        str(p.relative_to(repo)) if p.is_relative_to(repo) else p.name: cohort.sha(p)
        for p in paths
    }


def authorization(campaign_sha, gate_sha):
    value = {
        "schema_version": "rtlflowbench.complete_public_authorization.v2",
        "campaign_sha256": campaign_sha,
        "common_provider_gate_sha256": gate_sha,
        "runner_sha256": cohort.sha(Path(runner.__file__)),
        "decision": "ALLOW_AUTHOR_ALPHA_RESOURCE_MEASUREMENTS_ONLY",
        "planned_slots": 200,
        "official_release": False,
        "private_evaluator_reachable": False,
        "maximum_provider_calls_per_slot": 4,
        "maximum_input_tokens_per_slot": 163840,
        "maximum_output_tokens_per_slot": 16384,
    }
    runner.validate_authorization(
        value,
        campaign_sha=campaign_sha,
        provider_gate_sha=gate_sha,
        runner_sha=value["runner_sha256"],
    )
    return value


def authorize(
    *, repo, campaign_path, campaign_sha, gate_path, gate_sha, evidence_root, output
):
    campaign = cohort.validate_campaign(
        repo=repo, path=campaign_path, expected_sha=campaign_sha
    )
    base = cohort.base_runner(repo)
    _, windows = checked_gate(
        base=base,
        gate_path=gate_path,
        gate_sha=gate_sha,
        campaign=campaign,
        evidence_root=evidence_root,
        now=datetime.now(timezone.utc),
    )
    if output.exists() or output.is_symlink():
        raise FileExistsError("fresh authorization root required")
    output.mkdir(parents=True)
    write(output / "authorization.json", authorization(campaign_sha, gate_sha))
    lock = {
        "schema_version": LOCK_SCHEMA,
        "campaign_sha256": campaign_sha,
        "common_provider_gate_sha256": gate_sha,
        "authorization_sha256": cohort.sha(output / "authorization.json"),
        "source_bindings": source_bindings(repo),
        "provider_execution_windows_sha256": windows,
        "maximum_batch_slots": 3,
        "planned_slots": 200,
        "model": "deepseek-v4-pro",
        "official_release": False,
        "private_evaluator_permitted": False,
        "scientific_verdict_produced": False,
    }
    write(output / "launch-lock.json", lock)
    return lock


def digest_file(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError("nonregular batch artifact")
    value = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            value.update(chunk)
    return value.hexdigest()


def artifact_inventory(batch):
    result = {}
    slots = batch / "slots"
    if not slots.exists():
        return result
    for slot in slots.iterdir():
        if slot.is_symlink() or not slot.is_dir():
            raise ValueError("unsafe slot output")
        # Workspaces can contain large native logs/waves and are not copied.
        # Exact exported bytes and host-owned measurements are bound instead.
        for name in ("measurement", "export"):
            root = slot / name
            if root.is_symlink():
                raise ValueError("symlink evidence root")
            if not root.exists():
                continue
            for path in sorted(root.rglob("*")):
                if path.is_symlink():
                    raise ValueError("symlink evidence artifact")
                if path.is_file():
                    result[str(path.relative_to(batch))] = digest_file(path)
    return result


def inspect_history(*, campaign, campaign_sha, lock_sha, root):
    schedule = [r["measurement_id"] for r in campaign["rows"]]
    if len(schedule) != 200 or len(set(schedule)) != 200:
        raise ValueError("complete unique 200-slot schedule required")
    completed, batches, previous, previous_stop = [], [], None, None
    if not root.exists():
        return {"completed": [], "pending": schedule, "batches": [], "last_stop": None}
    if root.is_symlink():
        raise ValueError("symlink campaign output")
    directories = sorted(p for p in root.iterdir() if p.name.startswith("batch-"))
    for index, batch in enumerate(directories, 1):
        if (
            batch.name != f"batch-{index:04d}"
            or batch.is_symlink()
            or not batch.is_dir()
        ):
            raise ValueError("batch history gap or invalid directory")
        receipt_path = batch / "receipt.json"
        if not receipt_path.is_file():
            raise ValueError("incomplete/in-flight batch; investigate before resume")
        receipt_path = cohort.child(batch, "receipt.json")
        receipt_sha = digest_file(receipt_path)
        receipt = cohort.read(receipt_path, receipt_sha)
        plan = cohort.read(cohort.child(batch, "plan.json"), receipt["plan_sha256"])
        if plan.get("schema_version") != "rtlflowbench.complete_public_batch_plan.v2":
            raise ValueError("unknown batch plan schema")
        if (
            receipt.get("schema_version")
            != "rtlflowbench.complete_public_batch_receipt.v2"
        ):
            raise ValueError("unknown batch receipt schema")
        for value in (plan, receipt):
            if (
                value["campaign_sha256"] != campaign_sha
                or value["launch_lock_sha256"] != lock_sha
            ):
                raise ValueError("batch lock drift")
        if plan["previous_receipt_sha256"] != previous:
            raise ValueError("batch history chain drift")
        if plan["acknowledged_stop_sha256"] != previous_stop:
            raise ValueError("historical stop acknowledgement drift")
        if (
            receipt.get("private_evaluator_calls") != 0
            or receipt.get("scientific_verdict_produced") is not False
        ):
            raise ValueError("batch attempted private/scientific promotion")
        pending = [x for x in schedule if x not in completed]
        planned = plan["measurement_ids"]
        if not 1 <= len(planned) <= 3 or planned != pending[: len(planned)]:
            raise ValueError("batch selected or reordered schedule")
        rows = receipt["slots"]
        observed = [r["measurement_id"] for r in rows]
        if (
            observed != planned[: len(observed)]
            or not observed
            or len(observed) > len(planned)
        ):
            raise ValueError("batch completion is not a unique planned prefix")
        if len(observed) < len(planned) and not receipt["stop_reasons"]:
            raise ValueError("short batch without explicit stop")
        if any(
            r["state"]
            not in {
                "resource_observed",
                "native_prerequisite_observed",
                "requires_review",
            }
            or r["benchmark_verdict"] is not None
            for r in rows
        ):
            raise ValueError("unknown or fabricated scientific slot state")
        if receipt["artifact_sha256"] != artifact_inventory(batch):
            raise ValueError("immutable batch artifact drift")
        completed.extend(observed)
        previous = receipt_sha
        previous_stop = previous if receipt["stop_reasons"] else None
        batches.append(
            {"receipt_sha256": receipt_sha, "stop_reasons": receipt["stop_reasons"]}
        )
    return {
        "completed": completed,
        "pending": [x for x in schedule if x not in completed],
        "batches": batches,
        "last_stop": previous if batches and batches[-1]["stop_reasons"] else None,
    }


def observe_slot(
    *,
    repo,
    row,
    campaign_path,
    campaign_sha,
    gate_path,
    gate_sha,
    auth_path,
    auth_sha,
    slot,
    podman,
    podman_sha,
    human_interventions,
):
    slot.mkdir()
    gap = bool(row["native_prerequisite_gaps"])
    result = runner.run_slot(
        repo=repo,
        campaign_path=campaign_path,
        campaign_sha=campaign_sha,
        measurement_id=row["measurement_id"],
        mode="native-preflight" if gap else "authorized",
        scratch=slot / "scratch",
        output=slot / "measurement",
        podman=podman,
        podman_sha=podman_sha,
        provider_gate_path=gate_path,
        provider_gate_sha=gate_sha,
        authorization_path=auth_path,
        authorization_sha=auth_sha,
    )
    summary = {
        "measurement_id": row["measurement_id"],
        "workflow_id": row["workflow_id"],
        "task_id": row["task_id"],
        "state": "requires_review",
        "benchmark_verdict": None,
        "usage": None,
        "submission_status": "not_available",
        "stop_reasons": [],
    }
    if gap:
        if (
            result["status"] == "DIAGNOSTIC_OBSERVED_NOT_BENCHMARK_RESULT"
            and result["process_exit_code"] == 78
        ):
            summary.update(
                state="native_prerequisite_observed",
                native_prerequisite_gaps=row["native_prerequisite_gaps"],
            )
        else:
            summary["stop_reasons"].append("unexpected_native_prerequisite_observation")
        return summary
    out = slot / "measurement"
    if (
        result["status"] == "OPERATIONAL_FAILURE_REQUIRES_REVIEW"
        or (out / "telemetry-incomplete.json").exists()
    ):
        summary["stop_reasons"].append("operational_or_telemetry_failure")
        return summary
    merged_path = out / "full-workflow-resource-receipt.json"
    merged = cohort.read(merged_path, cohort.sha(merged_path))
    summary["usage"] = merged["metrics"]
    summary["state"] = "resource_observed"
    if merged["status"] != "full_workflow_resource_sample_complete":
        summary["stop_reasons"].append("incomplete_resource_sample")
    if merged["metrics"]["provider_budget_exhausted"]:
        summary["stop_reasons"].append("provider_budget_exhausted")
    if not runner.positive_balance(
        cohort.read(out / "balance-after.json", cohort.sha(out / "balance-after.json"))
    ):
        summary["stop_reasons"].append("balance_after_not_positive")
    if row["route"] == "existing_native":
        summary["submission_status"] = "existing_native_postprocessing_pending"
    elif merged["status"] == "full_workflow_resource_sample_complete":
        import export_complete_public_submission_v2 as exporter

        export = exporter.build(
            repo=repo,
            campaign_path=campaign_path,
            campaign_sha=campaign_sha,
            measurement_id=row["measurement_id"],
            measurement_root=out,
            observation_sha=cohort.sha(out / "observation.json"),
            merged_sha=cohort.sha(merged_path),
            scratch=slot / "scratch",
            output=slot / "export",
            human_interventions=human_interventions,
        )
        summary["submission_status"] = export["status"]
    return summary


def run_batch(
    *,
    repo,
    campaign_path,
    campaign_sha,
    gate_path,
    gate_sha,
    evidence_root,
    lock_path,
    lock_sha,
    root,
    count,
    acknowledge_stop,
    podman,
    podman_sha,
    human_interventions,
):
    if type(count) is not int or not 1 <= count <= 3:
        raise ValueError("one to three sequential slots per batch")
    if type(human_interventions) is not int or human_interventions < 0:
        raise ValueError("explicit nonnegative intervention count required")
    for path in (root, *root.parents):
        if path.is_symlink():
            raise ValueError("symlink campaign path component")
    if (
        not root.resolve().is_relative_to(evidence_root.resolve())
        or root.resolve() == evidence_root.resolve()
    ):
        raise ValueError("dedicated server evidence subdirectory required")
    if root.resolve().is_relative_to(
        campaign_path.parent.resolve()
    ) or campaign_path.parent.resolve().is_relative_to(root.resolve()):
        raise ValueError("runtime output must not overlap frozen public inputs")
    campaign = cohort.validate_campaign(
        repo=repo, path=campaign_path, expected_sha=campaign_sha
    )
    lock = cohort.read(lock_path, lock_sha)
    auth_path = lock_path.with_name("authorization.json")
    _, windows = checked_gate(
        base=cohort.base_runner(repo),
        gate_path=gate_path,
        gate_sha=gate_sha,
        campaign=campaign,
        evidence_root=evidence_root,
        now=datetime.now(timezone.utc),
    )
    if lock != {
        "schema_version": LOCK_SCHEMA,
        "campaign_sha256": campaign_sha,
        "common_provider_gate_sha256": gate_sha,
        "authorization_sha256": cohort.sha(auth_path),
        "source_bindings": source_bindings(repo),
        "provider_execution_windows_sha256": windows,
        "maximum_batch_slots": 3,
        "planned_slots": 200,
        "model": "deepseek-v4-pro",
        "official_release": False,
        "private_evaluator_permitted": False,
        "scientific_verdict_produced": False,
    }:
        raise ValueError("launch lock identity/source/scope drift")
    runner.validate_authorization(
        cohort.read(auth_path, lock["authorization_sha256"]),
        campaign_sha=campaign_sha,
        provider_gate_sha=gate_sha,
        runner_sha=cohort.sha(Path(runner.__file__)),
    )
    checked_gate(
        base=cohort.base_runner(repo),
        gate_path=gate_path,
        gate_sha=gate_sha,
        campaign=campaign,
        evidence_root=evidence_root,
        now=datetime.now(timezone.utc),
    )
    if root.is_symlink():
        raise ValueError("symlink campaign root")
    root.mkdir(parents=True, exist_ok=True)
    with (root / ".controller.lock").open("a") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        history = inspect_history(
            campaign=campaign, campaign_sha=campaign_sha, lock_sha=lock_sha, root=root
        )
        if history["last_stop"] != acknowledge_stop:
            raise ValueError(
                "exact prior stop acknowledgement required; never retry the prior slot"
            )
        if not history["pending"]:
            raise ValueError("no unstarted slot remains")
        ids = history["pending"][:count]
        batch = root / f"batch-{len(history['batches']) + 1:04d}"
        batch.mkdir()
        (batch / "slots").mkdir()
        plan = {
            "schema_version": "rtlflowbench.complete_public_batch_plan.v2",
            "campaign_sha256": campaign_sha,
            "launch_lock_sha256": lock_sha,
            "previous_receipt_sha256": history["batches"][-1]["receipt_sha256"]
            if history["batches"]
            else None,
            "acknowledged_stop_sha256": acknowledge_stop,
            "measurement_ids": ids,
            "human_interventions": human_interventions,
        }
        write(batch / "plan.json", plan)
        rows, reasons = [], []
        by_id = {r["measurement_id"]: r for r in campaign["rows"]}
        for measurement_id in ids:
            if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", measurement_id):
                raise ValueError("unsafe measurement identity")
            try:
                row = observe_slot(
                    repo=repo,
                    row=by_id[measurement_id],
                    campaign_path=campaign_path,
                    campaign_sha=campaign_sha,
                    gate_path=gate_path,
                    gate_sha=gate_sha,
                    auth_path=auth_path,
                    auth_sha=lock["authorization_sha256"],
                    slot=batch / "slots" / measurement_id,
                    podman=podman,
                    podman_sha=podman_sha,
                    human_interventions=human_interventions,
                )
            except Exception as error:
                row = {
                    "measurement_id": measurement_id,
                    "state": "requires_review",
                    "benchmark_verdict": None,
                    "usage": None,
                    "submission_status": "not_available",
                    "error_class": type(error).__name__,
                    "stop_reasons": ["slot_or_export_operational_error"],
                }
            rows.append(row)
            reasons += row["stop_reasons"]
            if reasons:
                break
        receipt = {
            "schema_version": "rtlflowbench.complete_public_batch_receipt.v2",
            "campaign_sha256": campaign_sha,
            "launch_lock_sha256": lock_sha,
            "plan_sha256": cohort.sha(batch / "plan.json"),
            "slots": rows,
            "stop_reasons": reasons,
            "artifact_sha256": artifact_inventory(batch),
            "private_evaluator_calls": 0,
            "scientific_verdict_produced": False,
        }
        write(batch / "receipt.json", receipt)
        return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("authorize", "run-batch"):
        part = sub.add_parser(name)
        for flag in ("repo", "campaign-path", "gate-path", "evidence-root"):
            part.add_argument("--" + flag, type=Path, required=True)
        for flag in ("campaign-sha", "gate-sha"):
            part.add_argument("--" + flag, required=True)
        if name == "authorize":
            part.add_argument("--output", type=Path, required=True)
        else:
            for flag in ("lock-path", "root", "podman"):
                part.add_argument("--" + flag, type=Path, required=True)
            for flag in ("lock-sha", "podman-sha"):
                part.add_argument("--" + flag, required=True)
            part.add_argument("--count", type=int, required=True)
            part.add_argument("--human-interventions", type=int, required=True)
            part.add_argument("--acknowledge-stop")
    args = vars(parser.parse_args())
    command = args.pop("command")
    result = authorize(**args) if command == "authorize" else run_batch(**args)
    print(
        json.dumps(
            {
                "schema_version": result["schema_version"],
                "scientific_verdict_produced": False,
                "stop_reasons": result.get("stop_reasons", []),
            }
        )
    )


if __name__ == "__main__":
    main()
