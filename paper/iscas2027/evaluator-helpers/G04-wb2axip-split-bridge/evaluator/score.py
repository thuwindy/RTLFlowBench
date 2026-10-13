#!/usr/bin/env python3
"""Project a G04 result into a non-official development score."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

TASK_ID = "G04-wb2axip-split-bridge"


def score_result(result: dict[str, Any], profile: dict[str, Any]) -> dict[str, Any]:
    if result.get("task_id") != TASK_ID or profile.get("task_id") != TASK_ID:
        raise ValueError("result and profile must both target G04")
    completion = result.get("oracle_completion", {})
    metrics = result.get("metrics", {})
    checks = {item.get("check_id"): item for item in result.get("checks", [])}

    def dimension_status(
        check_id: str, functional_failures: set[str]
    ) -> bool | None:
        check = checks.get(check_id)
        if check is None:
            return None
        verdict = check.get("verdict")
        if verdict == "pass":
            return True
        if verdict in functional_failures:
            return False
        return None

    visible = dimension_status("public_visible", {"fail_f2p", "compile_error"})
    f2p = dimension_status("hidden_f2p_ownership", {"fail_f2p", "compile_error"})
    p2p = dimension_status("hidden_p2p_parameter_sweep", {"fail_p2p", "compile_error"})
    formal = dimension_status("formal_safety", {"fail_formal"})
    synthesis = dimension_status("synthesis_smoke", {"compile_error"})
    observed = {
        "visible_function_and_protocol": visible,
        "hidden_ownership_and_fairness_f2p": (
            None if f2p is None else f2p and metrics.get("f2p") is True
        ),
        "legal_parameter_robustness_p2p": (
            None if p2p is None else p2p and metrics.get("p2p") is True
        ),
        "bounded_formal_safety": (
            None if formal is None else formal and metrics.get("formal_depth") == 16
        ),
        "synthesis_smoke": synthesis,
    }
    dimensions = []
    for definition in profile["dimensions"]:
        dimension_id = definition["dimension_id"]
        achieved = observed[dimension_id]
        points = definition["points"] if achieved is True else (0 if achieved is False else None)
        dimensions.append({
            "dimension_id": dimension_id,
            "achieved": achieved,
            "development_points": points,
            "maximum_points": definition["points"],
        })

    verdict = result.get("verdict")
    policy = profile["failure_policy"]
    if verdict == "pass" and completion.get("complete") is True and all(
        item["achieved"] is True for item in dimensions
    ):
        classification = "development_full_pass"
        development_score: int | None = profile["maximum_points"]
    elif verdict in policy["candidate_failure_verdicts"]:
        classification = "observed_candidate_failure"
        development_score = policy["candidate_failure_development_score"]
    else:
        classification = "not_comparable_or_incomplete"
        development_score = None

    return {
        "schema_version": "rtlflowbench.g04_score_projection.v1",
        "task_id": TASK_ID,
        "source_verdict": verdict,
        "classification": classification,
        "dimensions": dimensions,
        "development_score": development_score,
        "maximum_points": profile["maximum_points"],
        "official_score": None,
        "score_eligible": False,
        "profile_status": profile["status"],
        "issues": [] if classification == "development_full_pass" else [
            "full comparable functional evidence is absent or the candidate failed a gate"
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--result", type=Path, required=True)
    parser.add_argument("--profile", type=Path, default=Path(__file__).with_name("scoring_profile.json"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    projection = score_result(
        json.loads(args.result.read_text(encoding="utf-8")),
        json.loads(args.profile.read_text(encoding="utf-8")),
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(projection, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(projection, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
