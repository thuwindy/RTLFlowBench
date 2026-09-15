#!/usr/bin/env python3
"""Strict G02 visible-suite sentinel and failure classifier."""

from __future__ import annotations

from typing import Any


TASK_ID = "G02-common-rr-arbiter-spec"
PASS_SENTINELS = {
    "requesters_4": f"GOLDEN12_VISIBLE_PASS task={TASK_ID} requesters=4",
    "requesters_1": f"GOLDEN12_VISIBLE_PASS task={TASK_ID} requesters=1",
}
FAIL_MARKERS = ("G02_VISIBLE_FAIL", "G02_INVALID_PARAMETER_NOT_REJECTED")


def exact_sentinel_count(output: str, sentinel: str) -> int:
    return sum(line.strip() == sentinel for line in output.splitlines())


def simulation_passes(output: str, sentinel_key: str, exit_code: int) -> bool:
    sentinel = PASS_SENTINELS[sentinel_key]
    return bool(
        exit_code == 0
        and exact_sentinel_count(output, sentinel) == 1
        and not any(marker in output for marker in FAIL_MARKERS)
    )


def canonical_verdict(stages: list[dict[str, Any]]) -> str:
    for stage in stages:
        status = stage["status"]
        stage_id = stage["stage_id"]
        if status == "infra_error":
            return "infra_error"
        if status == "timeout":
            return "timeout"
        if status == "fail" and stage_id == "scope":
            return "scope_violation"
        if status == "fail" and "compile" in stage_id:
            return "compile_error"
        if status == "fail":
            return "fail_f2p"
    return "pass" if stages and all(s["status"] == "pass" for s in stages) else "infra_error"
