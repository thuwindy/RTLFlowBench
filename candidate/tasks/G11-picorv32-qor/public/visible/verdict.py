"""Fail-closed verdict helpers for the G11 public visible runner."""

from __future__ import annotations

from enum import StrEnum


class VisibleVerdict(StrEnum):
    INVALID_SUBMISSION = "invalid_submission"
    SCOPE_VIOLATION = "scope_violation"
    INFRA_ERROR = "infra_error"
    TIMEOUT = "timeout"
    COMPILE_ERROR = "compile_error"
    STRUCTURAL_FAIL = "structural_fail"
    FUNCTIONAL_FAIL = "functional_fail"
    PASS = "pass"


def classify_build(
    *, process_status: str, exit_code: int | None, stage: str
) -> tuple[VisibleVerdict, str]:
    """Classify an elaboration, synthesis, or compilation process."""

    if process_status == "timeout":
        return VisibleVerdict.TIMEOUT, f"{stage} timed out"
    if process_status == "infra_error" or exit_code is None:
        return VisibleVerdict.INFRA_ERROR, f"{stage} could not execute"
    if exit_code != 0:
        return VisibleVerdict.COMPILE_ERROR, f"{stage} exited with status {exit_code}"
    return VisibleVerdict.PASS, f"{stage} exited successfully"


def classify_simulation(
    *,
    process_status: str,
    exit_code: int | None,
    stdout: str,
    sentinel: str,
) -> tuple[VisibleVerdict, str]:
    """Require one exact sentinel; exit code zero alone never means PASS."""

    if process_status == "timeout":
        return VisibleVerdict.TIMEOUT, "visible firmware smoke timed out"
    if process_status == "infra_error" or exit_code is None:
        return VisibleVerdict.INFRA_ERROR, "visible simulator could not execute"
    if exit_code != 0:
        return (
            VisibleVerdict.FUNCTIONAL_FAIL,
            f"visible firmware smoke exited with status {exit_code}",
        )
    lines = [line.strip() for line in stdout.splitlines() if line.strip()]
    if lines.count(sentinel) != 1:
        return (
            VisibleVerdict.FUNCTIONAL_FAIL,
            "visible firmware smoke did not emit exactly one exact pass sentinel",
        )
    if any(line.startswith("GOLDEN12_G11_VISIBLE_SMOKE_FAIL") for line in lines):
        return (
            VisibleVerdict.FUNCTIONAL_FAIL,
            "visible firmware smoke emitted a failure marker",
        )
    return VisibleVerdict.PASS, "visible firmware smoke emitted its exact pass sentinel"
