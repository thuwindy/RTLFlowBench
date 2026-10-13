"""Strict verdict classification for the G03 hidden evaluator."""

from __future__ import annotations

from enum import StrEnum
from typing import Any


FAIL_SENTINEL = "GOLDEN12_G03_HIDDEN_FAIL"


class HiddenVerdict(StrEnum):
    INVALID_SUBMISSION = "invalid_submission"
    SCOPE_VIOLATION = "scope_violation"
    INFRA_ERROR = "infra_error"
    TIMEOUT = "timeout"
    COMPILE_ERROR = "compile_error"
    FAIL_F2P = "fail_f2p"
    FAIL_P2P = "fail_p2p"
    INCOMPLETE = "incomplete"
    PASS = "pass"


_PRIORITY = (
    HiddenVerdict.INVALID_SUBMISSION,
    HiddenVerdict.SCOPE_VIOLATION,
    HiddenVerdict.INFRA_ERROR,
    HiddenVerdict.TIMEOUT,
    HiddenVerdict.COMPILE_ERROR,
    HiddenVerdict.FAIL_F2P,
    HiddenVerdict.FAIL_P2P,
    HiddenVerdict.INCOMPLETE,
    HiddenVerdict.PASS,
)


def exact_line_count(text: str, expected: str) -> int:
    return sum(line.strip() == expected for line in text.splitlines())


def classify_simulation(
    *,
    layer: str,
    process_status: str,
    exit_code: int | None,
    stdout: str,
    expected_sentinel: str,
) -> tuple[HiddenVerdict, str]:
    failure = {
        "f2p": HiddenVerdict.FAIL_F2P,
        "p2p": HiddenVerdict.FAIL_P2P,
    }[layer]
    if process_status == "timeout":
        return HiddenVerdict.TIMEOUT, "simulation timed out"
    if process_status == "infra_error":
        return HiddenVerdict.INFRA_ERROR, "simulation could not be executed"
    if any(
        line.strip().startswith(FAIL_SENTINEL)
        for line in stdout.splitlines()
    ):
        return failure, f"{layer} emitted the hidden failure sentinel"
    if exit_code != 0:
        return failure, f"{layer} simulation exited with status {exit_code}"
    count = exact_line_count(stdout, expected_sentinel)
    if count != 1:
        return (
            failure,
            f"{layer} required exactly one pass sentinel, observed {count}",
        )
    return HiddenVerdict.PASS, f"{layer} emitted the exact pass sentinel"


def aggregate_hidden_verdict(
    checks: list[dict[str, Any]],
) -> HiddenVerdict:
    if not checks:
        return HiddenVerdict.INFRA_ERROR
    observed = {HiddenVerdict(str(check["verdict"])) for check in checks}
    for verdict in _PRIORITY:
        if verdict in observed:
            return verdict
    return HiddenVerdict.INFRA_ERROR
