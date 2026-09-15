#!/usr/bin/env python3
"""Strictly classify a G06 visible-runner process and result."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


TASK_ID = "G06-ibex-debug-csr-exception"
RESULT_SCHEMA_VERSION = "rtlflowbench.g06_visible_result.v2"
PASS_SENTINEL = "GOLDEN12_G06_VISIBLE_PASS"
FAIL_PREFIX = "GOLDEN12_G06_VISIBLE_FAIL"
SEMANTIC_NONCE = "B19F72C460AE35D8"
CASE_PASS_PREFIX = f"GOLDEN12_G06_VISIBLE_CASE_PASS_{SEMANTIC_NONCE}"
CASE_FAIL_PREFIX = f"GOLDEN12_G06_VISIBLE_CASE_FAIL_{SEMANTIC_NONCE}"
SUITE_PASS_SENTINEL = f"GOLDEN12_G06_VISIBLE_SUITE_PASS_{SEMANTIC_NONCE}"
EXPECTED_CASES = (
    "reset_state",
    "normal_exception_save",
    "fresh_debug_entry_preserves_machine_csrs",
)
NONPASS_VERDICTS = {
    "scope_violation",
    "invalid_submission",
    "infra_error",
    "timeout",
    "compile_error",
    "functional_fail",
}


def classify_simulation(
    *,
    process_status: str,
    exit_code: int | None,
    stdout: str,
    stderr: str,
) -> tuple[str, str, dict[str, Any]]:
    lines = (stdout + "\n" + stderr).splitlines()
    pass_counts = {
        case_id: sum(
            line == f"{CASE_PASS_PREFIX} case={case_id}" for line in lines
        )
        for case_id in EXPECTED_CASES
    }
    fail_lines = [line for line in lines if line.startswith(CASE_FAIL_PREFIX)]
    suite_pass_count = sum(line == SUITE_PASS_SENTINEL for line in lines)
    observed = {
        "case_pass_counts": pass_counts,
        "fail_line_count": len(fail_lines),
        "suite_pass_count": suite_pass_count,
    }
    if process_status == "timeout":
        return "timeout", "visible simulation exceeded timeout", observed
    if process_status == "output_limit":
        return "infra_error", "visible simulation output exceeded hard limit", observed
    if process_status != "completed":
        return "infra_error", "visible simulation did not complete normally", observed
    if suite_pass_count > 1 or any(count > 1 for count in pass_counts.values()):
        return "infra_error", "visible semantic markers were duplicated", observed
    if suite_pass_count and fail_lines:
        return "infra_error", "visible pass and fail markers conflict", observed
    if (
        exit_code == 0
        and suite_pass_count == 1
        and not fail_lines
        and all(count == 1 for count in pass_counts.values())
    ):
        return "pass", "all public preservation cases and suite marker agree", observed
    if exit_code == 0:
        return "functional_fail", "zero-exit simulation omitted required semantic markers", observed
    if suite_pass_count:
        return "infra_error", "visible suite pass marker conflicts with nonzero exit", observed
    return "functional_fail", "simulation failed before the complete visible pass protocol", observed


def classify(
    *,
    process_status: str,
    exit_code: int | None,
    stdout: str,
    result: dict[str, Any] | None,
) -> tuple[str, str]:
    if process_status == "timeout":
        return "timeout", "visible runner exceeded the outer timeout"
    if process_status != "completed":
        return "infra_error", "visible runner did not complete normally"
    if not isinstance(result, dict):
        return "infra_error", "visible runner result is absent or malformed"
    if result.get("schema_version") != RESULT_SCHEMA_VERSION:
        return "infra_error", "visible runner result schema version differs"
    if result.get("task_id") != TASK_ID:
        return "infra_error", "visible runner result task differs"

    pass_count = sum(line == PASS_SENTINEL for line in stdout.splitlines())
    fail_lines = [line for line in stdout.splitlines() if line.startswith(FAIL_PREFIX)]
    verdict = result.get("verdict")
    passed = result.get("pass")
    if exit_code == 0 and verdict == "pass" and passed is True and pass_count == 1 and not fail_lines:
        return "pass", "exit, result, and unique pass sentinel agree"
    if pass_count:
        return "infra_error", "pass sentinel conflicts with process or result"
    if (
        exit_code == 2
        and verdict in NONPASS_VERDICTS
        and passed is False
        and len(fail_lines) == 1
        and fail_lines[0] == f"{FAIL_PREFIX} verdict={verdict}"
    ):
        return verdict, "non-pass exit, result, and fail sentinel agree"
    return "infra_error", "process, result, and sentinel do not agree"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--process-status", choices=["completed", "timeout", "error"], required=True)
    parser.add_argument("--exit-code", type=int)
    parser.add_argument("--stdout", type=Path, required=True)
    parser.add_argument("--result", type=Path, required=True)
    args = parser.parse_args()
    try:
        stdout = args.stdout.read_text(encoding="utf-8", errors="replace")
        result = json.loads(args.result.read_text(encoding="utf-8"))
    except Exception:
        stdout = ""
        result = None
    verdict, reason = classify(
        process_status=args.process_status,
        exit_code=args.exit_code,
        stdout=stdout,
        result=result,
    )
    print(json.dumps({"verdict": verdict, "reason": reason}, sort_keys=True))
    return 0 if verdict == "pass" else 2


if __name__ == "__main__":
    raise SystemExit(main())
