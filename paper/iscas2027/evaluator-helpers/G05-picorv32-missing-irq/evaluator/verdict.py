"""Strict verdict classification for the private G05 F2P evaluator."""

from __future__ import annotations

from enum import StrEnum

PASS_SENTINEL = (
    "GOLDEN12_G05_F2P_PASS simultaneous=00000009 "
    "retained_merge=00000028"
)
FAIL_PREFIX = "GOLDEN12_G05_F2P_FAIL"


class HiddenVerdict(StrEnum):
    INVALID_SUBMISSION = "invalid_submission"
    SCOPE_VIOLATION = "scope_violation"
    INFRA_ERROR = "infra_error"
    TIMEOUT = "timeout"
    COMPILE_ERROR = "compile_error"
    FAIL_F2P = "fail_f2p"
    PASS = "pass"


def classify_process(
    *,
    stage: str,
    process_status: str,
    exit_code: int | None,
    stdout: str,
) -> tuple[HiddenVerdict, str]:
    if process_status == "timeout":
        return HiddenVerdict.TIMEOUT, f"{stage} timed out"
    if process_status == "infra_error" or exit_code is None:
        return HiddenVerdict.INFRA_ERROR, f"{stage} could not execute"
    if exit_code != 0:
        verdict = (
            HiddenVerdict.COMPILE_ERROR
            if stage == "compile"
            else HiddenVerdict.FAIL_F2P
        )
        return verdict, f"{stage} exited with status {exit_code}"
    if stage == "compile":
        return HiddenVerdict.PASS, "compile exited successfully"
    if any(
        line.strip().lower() in {"time out", "timeout"}
        for line in stdout.splitlines()
    ):
        return HiddenVerdict.FAIL_F2P, (
            "simulation emitted timeout text without runner timeout"
        )
    if any(
        line.strip().startswith(FAIL_PREFIX)
        for line in stdout.splitlines()
    ):
        return HiddenVerdict.FAIL_F2P, (
            "simulation emitted the F2P failure sentinel"
        )
    count = sum(
        line.strip() == PASS_SENTINEL for line in stdout.splitlines()
    )
    if count != 1:
        return HiddenVerdict.FAIL_F2P, (
            f"simulation required one exact pass sentinel, observed {count}"
        )
    return HiddenVerdict.PASS, "simulation emitted one exact pass sentinel"
