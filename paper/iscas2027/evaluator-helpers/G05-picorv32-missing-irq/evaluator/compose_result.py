#!/usr/bin/env python3
"""Compose isolated G05 layer results into one fail-closed development result."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
from typing import Any

sys.dont_write_bytecode = True

TASK_ID = "G05-picorv32-missing-irq"
EVALUATOR_ROOT = Path(__file__).resolve().parent
PRIVATE_ROOT = EVALUATOR_ROOT.parent
SCORE_PATH = PRIVATE_ROOT / "scoring/score.py"
P2P_SUITES = {
    "mask_latch_reset",
    "reset_event_priority",
    "runtime_mask_service",
}
EXPECTED_SCHEMAS = {
    "f2p": "chipflow.golden12.g05_hidden_result.v1",
    "p2p": "chipflow.golden12.g05_p2p_result.v1",
    "formal": "rtlflowbench.g05_formal_result.v1",
    "firmware": "rtlflowbench.g05_firmware_result.v1",
    "build": "rtlflowbench.g05_build_result.v1",
    "coverage": "rtlflowbench.g05_coverage_result.v1",
}
VERDICT_PRIORITY = (
    "invalid_instance",
    "infra_error",
    "invalid_submission",
    "scope_violation",
    "blocked",
    "incomplete",
    "timeout",
    "compile_error",
    "invalid_evidence",
    "fail_f2p",
    "fail_p2p",
    "fail_formal",
    "fail_ppa",
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_score():
    spec = importlib.util.spec_from_file_location(
        "rtlflowbench_g05_actual_score",
        SCORE_PATH,
    )
    if spec is None or spec.loader is None:
        raise ImportError(f"could not load score source: {SCORE_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module.score_g05


def _load_result(path: Path, *, kind: str) -> tuple[dict[str, Any], dict[str, Any]]:
    resolved = path.expanduser().resolve()
    if not resolved.is_file() or resolved.is_symlink():
        raise ValueError(f"{kind} result must be one regular file: {resolved}")
    result = json.loads(resolved.read_text(encoding="utf-8"))
    if not isinstance(result, dict):
        raise ValueError(f"{kind} result must contain one JSON object")
    if result.get("task_id") != TASK_ID:
        raise ValueError(f"{kind} result task_id mismatch")
    if result.get("schema_version") != EXPECTED_SCHEMAS[kind]:
        raise ValueError(f"{kind} result schema_version mismatch")
    verdict = result.get("verdict")
    if not isinstance(verdict, str) or not verdict:
        raise ValueError(f"{kind} result verdict missing")
    return result, {
        "kind": kind,
        "path": str(resolved),
        "sha256": _sha256(resolved),
        "schema_version": result["schema_version"],
        "verdict": verdict,
    }


def _subject_sha(result: dict[str, Any], *, kind: str) -> str | None:
    if kind in {"f2p", "p2p"}:
        value = result.get("scope_receipt", {}).get("submission_sha256")
    elif kind == "formal":
        value = result.get("source_sha256")
    elif kind in {"firmware", "build"}:
        value = result.get("submission_sha256")
    elif kind == "coverage":
        value = result.get("scope_receipt", {}).get("submission_sha256")
    else:
        value = None
    return value if isinstance(value, str) else None


def _normalize_layer_verdict(kind: str, verdict: str) -> str:
    if verdict == "pass":
        return verdict
    if kind == "f2p" and verdict not in VERDICT_PRIORITY:
        return "fail_f2p"
    if kind in {"p2p", "firmware"} and verdict not in VERDICT_PRIORITY:
        return "fail_p2p"
    if kind == "formal" and verdict not in VERDICT_PRIORITY:
        return "fail_formal"
    return verdict


def _overall_verdict(verdicts: list[str]) -> str:
    for candidate in VERDICT_PRIORITY:
        if candidate in verdicts:
            return candidate
    return "pass" if verdicts and set(verdicts) == {"pass"} else "incomplete"


def compose(
    *,
    submission_root: Path,
    f2p_result: Path,
    p2p_results: list[Path],
    formal_result: Path,
    firmware_result: Path,
    build_result: Path,
    coverage_result: Path,
    output_dir: Path,
    observed_at: str,
) -> dict[str, Any]:
    output_dir = output_dir.expanduser().resolve()
    if output_dir.exists():
        raise FileExistsError(f"refusing to overwrite output: {output_dir}")
    submission_root = submission_root.expanduser().resolve()
    if not submission_root.is_dir() or submission_root.is_symlink():
        raise ValueError("neutral submission root must be one regular directory")
    submission_files = sorted(
        path.relative_to(submission_root).as_posix()
        for path in submission_root.rglob("*")
        if path.is_file()
    )
    if submission_files != ["picorv32.v"]:
        raise ValueError("neutral submission must contain exactly picorv32.v")
    if any(path.is_symlink() for path in submission_root.rglob("*")):
        raise ValueError("neutral submission must not contain symlinks")
    if output_dir == submission_root or output_dir.is_relative_to(
        submission_root
    ):
        raise ValueError("composite output must be outside neutral submission")
    submitted = submission_root / "picorv32.v"
    submission_sha256 = _sha256(submitted)

    evidence: list[dict[str, Any]] = []
    layer_results: dict[str, Any] = {}
    f2p, item = _load_result(f2p_result, kind="f2p")
    layer_results["f2p"] = f2p
    evidence.append(item)

    p2p_by_suite: dict[str, dict[str, Any]] = {}
    for path in p2p_results:
        result, p2p_item = _load_result(path, kind="p2p")
        suite_id = result.get("suite_id")
        if suite_id not in P2P_SUITES or suite_id in p2p_by_suite:
            raise ValueError("P2P result set has unknown or duplicate suite")
        p2p_by_suite[suite_id] = result
        p2p_item["suite_id"] = suite_id
        evidence.append(p2p_item)
    if set(p2p_by_suite) != P2P_SUITES:
        raise ValueError("P2P result set must contain all three fixed suites")
    layer_results["p2p"] = p2p_by_suite

    for kind, path in (
        ("formal", formal_result),
        ("firmware", firmware_result),
        ("build", build_result),
        ("coverage", coverage_result),
    ):
        result, result_item = _load_result(path, kind=kind)
        layer_results[kind] = result
        evidence.append(result_item)

    observed_subject_hashes = {
        value
        for kind, result in layer_results.items()
        for value in (
            (
                _subject_sha(item, kind=kind)
                for item in result.values()
            )
            if kind == "p2p"
            else (_subject_sha(result, kind=kind),)
        )
        if value is not None
    }
    if observed_subject_hashes != {submission_sha256}:
        raise ValueError(
            "layer results do not bind exactly to the neutral submission"
        )

    f2p_verdict = _normalize_layer_verdict("f2p", f2p["verdict"])
    p2p_suite_verdicts = {
        suite: _normalize_layer_verdict("p2p", result["verdict"])
        for suite, result in sorted(p2p_by_suite.items())
    }
    p2p_verdict = _overall_verdict(list(p2p_suite_verdicts.values()))
    formal_verdict = _normalize_layer_verdict(
        "formal",
        layer_results["formal"]["verdict"],
    )
    firmware_verdict = _normalize_layer_verdict(
        "firmware",
        layer_results["firmware"]["verdict"],
    )
    build_verdict = _normalize_layer_verdict(
        "build",
        layer_results["build"]["verdict"],
    )
    coverage_verdict = _normalize_layer_verdict(
        "coverage",
        layer_results["coverage"]["verdict"],
    )
    scope_inputs = [
        f2p.get("scope_receipt", {}),
        *(
            result.get("scope_receipt", {})
            for result in p2p_by_suite.values()
        ),
        layer_results["build"].get("scope_receipt", {}),
        layer_results["coverage"].get("scope_receipt", {}),
    ]
    scope_pass = all(
        receipt.get("status", "pass") == "pass"
        and receipt.get("submission_sha256") == submission_sha256
        for receipt in scope_inputs
    )
    scope_verdict = "pass" if scope_pass else "scope_violation"

    checks = [
        {
            "layer": "scope",
            "verdict": scope_verdict,
            "evidence_count": len(scope_inputs),
        },
        {
            "layer": "build",
            "verdict": build_verdict,
            "wrapper_tops": layer_results["build"].get("tops", []),
        },
        {
            "layer": "f2p",
            "verdict": f2p_verdict,
            "suite_count": 1,
        },
        {
            "layer": "p2p",
            "verdict": p2p_verdict,
            "suite_verdicts": p2p_suite_verdicts,
        },
        {
            "layer": "formal",
            "verdict": formal_verdict,
            "depth": layer_results["formal"].get("depth"),
            "property_count": len(
                layer_results["formal"].get("checks", [])
            ),
        },
        {
            "layer": "firmware",
            "verdict": firmware_verdict,
            "pass_sentinel_count": layer_results["firmware"].get(
                "pass_sentinel_count"
            ),
        },
        {
            "layer": "coverage",
            "verdict": coverage_verdict,
            "measurement_only": True,
        },
    ]
    overall = _overall_verdict(
        [str(check["verdict"]) for check in checks]
    )
    scope_receipt = {
        "status": scope_verdict,
        "submission_sha256": submission_sha256,
        "submission_files": submission_files,
        "layer_scope_receipts": len(scope_inputs),
    }
    scoring_input = {
        "verdict": overall,
        "scope_receipt": scope_receipt,
        "checks": checks,
    }
    score = _load_score()(scoring_input)
    coverage = layer_results["coverage"].get("coverage", {})
    result = {
        "schema_version": "rtlflowbench.g05_composite_result.v1",
        "task_id": TASK_ID,
        "observed_at": observed_at,
        "status": (
            "development_evaluated_not_frozen"
            if overall == "pass"
            else "fail"
        ),
        "classification": "evaluator_private",
        "workflow_workspace_exposed": False,
        "verdict": overall,
        "pass": overall == "pass",
        "submission_sha256": submission_sha256,
        "scope_receipt": scope_receipt,
        "checks": checks,
        "evidence": sorted(
            evidence,
            key=lambda item: (
                item["kind"],
                str(item.get("suite_id", "")),
            ),
        ),
        "raw_metrics": {
            "wrapper_tops_elaborated": len(
                [
                    check
                    for check in layer_results["build"].get("checks", [])
                    if check.get("layer") == "build"
                    and check.get("verdict") == "pass"
                ]
            ),
            "hidden_f2p_suites_passed": int(f2p_verdict == "pass"),
            "hidden_p2p_suites_passed": sum(
                verdict == "pass"
                for verdict in p2p_suite_verdicts.values()
            ),
            "formal_depth": layer_results["formal"].get("depth"),
            "formal_properties_passed": sum(
                check.get("verdict") == "pass"
                for check in layer_results["formal"].get("checks", [])
            ),
            "firmware_irq_counts": layer_results["firmware"].get(
                "irq_counts", {}
            ),
            "firmware_trap_cycle_count": layer_results["firmware"].get(
                "trap_cycle_count"
            ),
            "dut_line_coverage": coverage.get("totals", {}).get(
                "line_coverage"
            ),
            "dut_branch_or_toggle_coverage": coverage.get(
                "totals", {}
            ).get("lcov_branch_or_toggle_coverage"),
            "area": None,
            "timing": None,
            "performance": None,
        },
        "score": score,
        "readiness": {
            "benchmark_ready": False,
            "chipflow_adapter_ready": False,
            "independent_review_complete": False,
            "environment_frozen": False,
            "scoring_frozen": False,
        },
        "source_sha256": {
            "composer": _sha256(Path(__file__)),
            "score": _sha256(SCORE_PATH),
        },
        "excluded_claims": [
            "A development composite PASS is not G05-ready-v1 admission.",
            "The 40-point development score is not a frozen benchmark score.",
            "Coverage is a raw observation, not proof of semantic completeness.",
            "No QoR, PPA, area, timing, performance, multi-run, or human-level claim is made.",
            "The benchmark and ChipFlow adapter remain not_ready.",
        ],
    }
    output_dir.mkdir(parents=True)
    (output_dir / "result.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--submission-root", type=Path, required=True)
    parser.add_argument("--f2p-result", type=Path, required=True)
    parser.add_argument(
        "--p2p-result",
        type=Path,
        action="append",
        required=True,
    )
    parser.add_argument("--formal-result", type=Path, required=True)
    parser.add_argument("--firmware-result", type=Path, required=True)
    parser.add_argument("--build-result", type=Path, required=True)
    parser.add_argument("--coverage-result", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--observed-at", required=True)
    args = parser.parse_args()
    try:
        result = compose(
            submission_root=args.submission_root,
            f2p_result=args.f2p_result,
            p2p_results=args.p2p_result,
            formal_result=args.formal_result,
            firmware_result=args.firmware_result,
            build_result=args.build_result,
            coverage_result=args.coverage_result,
            output_dir=args.output_dir,
            observed_at=args.observed_at,
        )
    except Exception as exc:
        print(
            json.dumps(
                {
                    "verdict": "infra_error",
                    "error": f"{type(exc).__name__}: {exc}",
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["verdict"] == "pass" else 2


if __name__ == "__main__":
    raise SystemExit(main())
