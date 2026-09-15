"""Fail-closed visible-preflight verdicts for G10."""

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


def classify_process(
    *,
    process_status: str,
    exit_code: int | None,
) -> tuple[VisibleVerdict, str]:
    if process_status == "timeout":
        return VisibleVerdict.TIMEOUT, "Yosys structural preflight timed out"
    if process_status == "infra_error" or exit_code is None:
        return (
            VisibleVerdict.INFRA_ERROR,
            "Yosys structural preflight could not execute",
        )
    if exit_code != 0:
        return (
            VisibleVerdict.COMPILE_ERROR,
            f"Yosys structural preflight exited with status {exit_code}",
        )
    return VisibleVerdict.PASS, "Yosys structural preflight exited successfully"


def classify_compile(
    *,
    process_status: str,
    exit_code: int | None,
) -> tuple[VisibleVerdict, str]:
    if process_status == "timeout":
        return VisibleVerdict.TIMEOUT, "visible smoke compilation timed out"
    if process_status == "infra_error" or exit_code is None:
        return VisibleVerdict.INFRA_ERROR, "visible smoke compiler could not execute"
    if exit_code != 0:
        return (
            VisibleVerdict.COMPILE_ERROR,
            f"visible smoke compiler exited with status {exit_code}",
        )
    return VisibleVerdict.PASS, "visible smoke compilation exited successfully"


def classify_simulation(
    *,
    process_status: str,
    exit_code: int | None,
    stdout: str,
    sentinel: str,
) -> tuple[VisibleVerdict, str]:
    if process_status == "timeout":
        return VisibleVerdict.TIMEOUT, "visible software smoke timed out"
    if process_status == "infra_error" or exit_code is None:
        return VisibleVerdict.INFRA_ERROR, "visible simulator could not execute"
    if exit_code != 0:
        return (
            VisibleVerdict.FUNCTIONAL_FAIL,
            f"visible software smoke exited with status {exit_code}",
        )
    lines = [line.strip() for line in stdout.splitlines() if line.strip()]
    if lines.count(sentinel) != 1:
        return (
            VisibleVerdict.FUNCTIONAL_FAIL,
            "visible software smoke did not emit exactly one exact pass sentinel",
        )
    if any(line.startswith("GOLDEN12_G10_VISIBLE_SMOKE_FAIL") for line in lines):
        return (
            VisibleVerdict.FUNCTIONAL_FAIL,
            "visible software smoke emitted a failure marker",
        )
    return VisibleVerdict.PASS, "visible software smoke emitted its exact pass sentinel"
