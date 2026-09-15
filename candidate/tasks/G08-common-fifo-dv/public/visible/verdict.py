"""Strict visible-verdict classification for G08."""

from __future__ import annotations

from enum import StrEnum
import sys

sys.dont_write_bytecode = True

TB_PASS_SENTINEL = "GOLDEN12_G08_TB_PASS"
TB_FAIL_PREFIX = "GOLDEN12_G08_TB_FAIL"


class VisibleVerdict(StrEnum):
    INVALID_SUBMISSION = "invalid_submission"
    SCOPE_VIOLATION = "scope_violation"
    INFRA_ERROR = "infra_error"
    TIMEOUT = "timeout"
    COMPILE_ERROR = "compile_error"
    FUNCTIONAL_FAIL = "functional_fail"
    PASS = "pass"


def exact_line_count(text: str, expected: str) -> int:
    return sum(line.strip() == expected for line in text.splitlines())


def fail_line_count(text: str) -> int:
    return sum(
        line.strip().startswith(TB_FAIL_PREFIX)
        for line in text.splitlines()
    )


def classify_compile(
    *,
    process_status: str,
    exit_code: int | None,
) -> tuple[VisibleVerdict, str]:
    if process_status == "output_limit":
        return VisibleVerdict.FUNCTIONAL_FAIL, (
            "compiler output exceeded the public byte limit"
        )
    if process_status == "timeout":
        return VisibleVerdict.TIMEOUT, "compile timed out"
    if process_status == "infra_error" or exit_code is None:
        return VisibleVerdict.INFRA_ERROR, "compiler could not execute"
    if exit_code != 0:
        return VisibleVerdict.COMPILE_ERROR, (
            f"compile exited with status {exit_code}"
        )
    return VisibleVerdict.PASS, "compile exited successfully"


def classify_correct_simulation(
    *,
    process_status: str,
    exit_code: int | None,
    stdout: str,
    stderr: str,
) -> tuple[VisibleVerdict, str]:
    combined = f"{stdout}\n{stderr}"
    if process_status == "output_limit":
        return VisibleVerdict.FUNCTIONAL_FAIL, (
            "correct-DUT simulation output exceeded the public byte limit"
        )
    if process_status == "timeout":
        return VisibleVerdict.TIMEOUT, "correct-DUT simulation timed out"
    if process_status == "infra_error" or exit_code is None:
        return VisibleVerdict.INFRA_ERROR, (
            "correct-DUT simulator could not execute"
        )
    if exit_code != 0:
        return VisibleVerdict.FUNCTIONAL_FAIL, (
            f"correct-DUT simulation exited with status {exit_code}"
        )
    if fail_line_count(combined):
        return VisibleVerdict.FUNCTIONAL_FAIL, (
            "correct-DUT simulation emitted a failure sentinel"
        )
    count = exact_line_count(combined, TB_PASS_SENTINEL)
    if count != 1:
        return VisibleVerdict.FUNCTIONAL_FAIL, (
            "correct-DUT simulation requires one exact pass sentinel; "
            f"observed {count}"
        )
    return VisibleVerdict.PASS, (
        "correct-DUT simulation emitted one exact pass sentinel"
    )


def classify_negative_simulation(
    *,
    process_status: str,
    exit_code: int | None,
    stdout: str,
    stderr: str,
) -> tuple[VisibleVerdict, str]:
    combined = f"{stdout}\n{stderr}"
    if process_status == "output_limit":
        return VisibleVerdict.FUNCTIONAL_FAIL, (
            "negative-fixture simulation output exceeded the public byte limit"
        )
    if process_status == "timeout":
        return VisibleVerdict.TIMEOUT, "negative-fixture simulation timed out"
    if process_status == "infra_error" or exit_code is None:
        return VisibleVerdict.INFRA_ERROR, (
            "negative-fixture simulator could not execute"
        )
    if exact_line_count(combined, TB_PASS_SENTINEL):
        return VisibleVerdict.FUNCTIONAL_FAIL, (
            "negative fixture emitted the testbench pass sentinel"
        )
    failures = fail_line_count(combined)
    if exit_code == 0 or failures == 0:
        return VisibleVerdict.FUNCTIONAL_FAIL, (
            "negative fixture requires nonzero exit and a failure sentinel; "
            f"exit={exit_code}, failure_sentinels={failures}"
        )
    return VisibleVerdict.PASS, (
        "negative fixture was deterministically detected"
    )
