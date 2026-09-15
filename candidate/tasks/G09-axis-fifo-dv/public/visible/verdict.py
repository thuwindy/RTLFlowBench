#!/usr/bin/env python3
"""Fail-closed process classification for the G09 visible differential."""

from __future__ import annotations

from enum import Enum
import re


class Verdict(str, Enum):
    PASS = "pass"
    INFRA_ERROR = "infra_error"
    INVALID_SUBMISSION = "invalid_submission"
    SCOPE_VIOLATION = "scope_violation"
    TIMEOUT = "timeout"
    COMPILE_ERROR = "compile_error"
    FAIL_P2P = "fail_p2p"
    FAIL_F2P = "fail_f2p"


_COCOTB_FAILURE = re.compile(
    r"\bTESTS=\d+\s+PASS=\d+\s+FAIL=([1-9]\d*)\b"
)


def _looks_like_infrastructure_failure(output: str) -> bool:
    lowered = output.lower()
    return any(
        token in lowered
        for token in (
            "no such file or directory: 'iverilog'",
            'no such file or directory: "iverilog"',
            "unable to find executable",
            "simulator executable was not found",
            "cannot find simulator",
        )
    )


def _looks_like_compile_or_import_failure(output: str) -> bool:
    lowered = output.lower()
    if any(
        token in lowered
        for token in (
            "syntaxerror",
            "syntax error",
            "importerror",
            "modulenotfounderror",
            "module not found",
            "compile error",
            "error during collection",
        )
    ):
        return True
    return "iverilog" in lowered and "returned non-zero exit status" in lowered


def classify_process(*, subject_kind: str, process_status: str, exit_code: int | None, output: str) -> Verdict:
    if process_status == "timeout":
        return Verdict.TIMEOUT
    if process_status != "completed" or exit_code is None:
        return Verdict.INFRA_ERROR
    if exit_code != 0 and _looks_like_infrastructure_failure(output):
        return Verdict.INFRA_ERROR
    if exit_code != 0 and _looks_like_compile_or_import_failure(output):
        return Verdict.COMPILE_ERROR
    if subject_kind == "correct":
        if exit_code == 0:
            return Verdict.PASS
        return Verdict.FAIL_P2P
    if subject_kind == "public_mutant":
        if exit_code == 0:
            return Verdict.FAIL_F2P
        if _COCOTB_FAILURE.search(output):
            return Verdict.PASS
        return Verdict.INFRA_ERROR
    return Verdict.INFRA_ERROR
