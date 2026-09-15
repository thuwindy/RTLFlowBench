"""Strict verdict helpers for the public G01 visible suite.

The visible runner never treats a zero exit status as sufficient evidence for a
simulation PASS.  A successful simulation must also emit the exact per-case
sentinel once and must not emit the failure sentinel.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any


FAIL_SENTINEL = "GOLDEN12_VISIBLE_FAIL"


class VisibleVerdict(StrEnum):
    INVALID_SUBMISSION = "invalid_submission"
    SCOPE_VIOLATION = "scope_violation"
    INFRA_ERROR = "infra_error"
    TIMEOUT = "timeout"
    COMPILE_ERROR = "compile_error"
    FUNCTIONAL_FAIL = "functional_fail"
    PASS = "pass"


_VERDICT_PRIORITY = (
    VisibleVerdict.INVALID_SUBMISSION,
    VisibleVerdict.SCOPE_VIOLATION,
    VisibleVerdict.INFRA_ERROR,
    VisibleVerdict.TIMEOUT,
    VisibleVerdict.COMPILE_ERROR,
    VisibleVerdict.FUNCTIONAL_FAIL,
    VisibleVerdict.PASS,
)


def exact_line_count(text: str, expected: str) -> int:
    """Count exact stripped output lines, not substring matches."""

    return sum(line.strip() == expected for line in text.splitlines())


def classify_required_success(
    *,
    stage: str,
    exit_code: int,
    stdout: str,
    expected_sentinel: str | None,
) -> tuple[VisibleVerdict, str]:
    """Classify a command that is required to succeed."""

    if exit_code != 0:
        verdict = (
            VisibleVerdict.COMPILE_ERROR
            if stage == "compile"
            else VisibleVerdict.FUNCTIONAL_FAIL
        )
        return verdict, f"{stage} exited with status {exit_code}"
    if expected_sentinel is None:
        return VisibleVerdict.PASS, f"{stage} exited successfully"
    if any(
        line.strip().startswith(FAIL_SENTINEL)
        for line in stdout.splitlines()
    ):
        return VisibleVerdict.FUNCTIONAL_FAIL, (
            f"{stage} emitted the failure sentinel"
        )
    count = exact_line_count(stdout, expected_sentinel)
    if count != 1:
        return VisibleVerdict.FUNCTIONAL_FAIL, (
            f"{stage} required exactly one pass sentinel, observed {count}"
        )
    return VisibleVerdict.PASS, f"{stage} emitted the exact pass sentinel"


def classify_expected_rejection(
    *,
    compile_exit_code: int,
    simulation_exit_code: int | None,
    simulation_stdout: str,
    accepted_sentinel: str,
) -> tuple[VisibleVerdict, str]:
    """Classify an invalid-parameter probe that must be rejected.

    Compile/elaboration rejection and a non-zero simulation termination are
    both acceptable static-failure evidence.  A zero-exit simulation that
    reaches the explicit acceptance sentinel proves that the invalid
    parameterization was incorrectly accepted.
    """

    if compile_exit_code != 0:
        return VisibleVerdict.PASS, "invalid parameters rejected during compile"
    if simulation_exit_code is None:
        return VisibleVerdict.INFRA_ERROR, (
            "invalid-parameter simulation did not produce an exit status"
        )
    if simulation_exit_code != 0:
        return VisibleVerdict.PASS, (
            "invalid parameters rejected during elaboration or simulation startup"
        )
    count = exact_line_count(simulation_stdout, accepted_sentinel)
    if count == 1:
        return VisibleVerdict.FUNCTIONAL_FAIL, (
            "invalid parameterization reached the acceptance sentinel"
        )
    return VisibleVerdict.FUNCTIONAL_FAIL, (
        "invalid parameterization returned zero without rejection evidence"
    )


def aggregate_visible_verdict(checks: list[dict[str, Any]]) -> VisibleVerdict:
    """Return the highest-priority observed check verdict."""

    if not checks:
        return VisibleVerdict.INFRA_ERROR
    observed = {
        VisibleVerdict(str(check["verdict"]))
        for check in checks
    }
    for verdict in _VERDICT_PRIORITY:
        if verdict in observed:
            return verdict
    return VisibleVerdict.INFRA_ERROR
