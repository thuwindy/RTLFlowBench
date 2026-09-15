"""Strict verdict classification for the public G05 visible suite."""

from __future__ import annotations

from enum import StrEnum
import sys

sys.dont_write_bytecode = True

PASS_SENTINEL = (
    "GOLDEN12_VISIBLE_PASS task=G05-picorv32-missing-irq "
    "external_irq=1 timer_irq=1 service_edge_merge=1 reset=1"
)
FAIL_PREFIX = "GOLDEN12_VISIBLE_FAIL"


class VisibleVerdict(StrEnum):
    INVALID_SUBMISSION = "invalid_submission"
    SCOPE_VIOLATION = "scope_violation"
    INFRA_ERROR = "infra_error"
    TIMEOUT = "timeout"
    COMPILE_ERROR = "compile_error"
    FUNCTIONAL_FAIL = "functional_fail"
    PASS = "pass"


def classify_process(
    *,
    stage: str,
    process_status: str,
    exit_code: int | None,
    stdout: str,
) -> tuple[VisibleVerdict, str]:
    if process_status == "timeout":
        return VisibleVerdict.TIMEOUT, f"{stage} timed out"
    if process_status == "infra_error" or exit_code is None:
        return VisibleVerdict.INFRA_ERROR, f"{stage} could not execute"
    if exit_code != 0:
        verdict = (
            VisibleVerdict.COMPILE_ERROR
            if stage == "compile"
            else VisibleVerdict.FUNCTIONAL_FAIL
        )
        return verdict, f"{stage} exited with status {exit_code}"
    if stage == "compile":
        return VisibleVerdict.PASS, "compile exited successfully"
    if any(
        line.strip().lower() in {"time out", "timeout"}
        for line in stdout.splitlines()
    ):
        return VisibleVerdict.FUNCTIONAL_FAIL, (
            "simulation emitted timeout text without a valid runner timeout"
        )
    if any(
        line.strip().startswith(FAIL_PREFIX)
        for line in stdout.splitlines()
    ):
        return VisibleVerdict.FUNCTIONAL_FAIL, (
            "simulation emitted the failure sentinel"
        )
    count = sum(
        line.strip() == PASS_SENTINEL for line in stdout.splitlines()
    )
    if count != 1:
        return VisibleVerdict.FUNCTIONAL_FAIL, (
            f"simulation required one exact pass sentinel, observed {count}"
        )
    return VisibleVerdict.PASS, "simulation emitted one exact pass sentinel"
