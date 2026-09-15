#!/usr/bin/env python3
"""Strictly classify a G07 visible-runner process and result."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


PASS_SENTINEL = "GOLDEN12_G07_VISIBLE_PASS"
FAIL_PREFIX = "GOLDEN12_G07_VISIBLE_FAIL"
NONPASS_VERDICTS = {
    "scope_violation",
    "invalid_submission",
    "infra_error",
    "timeout",
    "compile_error",
}


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
    if result.get("schema_version") != "rtlflowbench.g07_visible_result.v1":
        return "infra_error", "visible runner result schema version differs"
    if result.get("task_id") != "G07-ibex-ifetch-error-timing":
        return "infra_error", "visible runner result task differs"

    pass_count = sum(line == PASS_SENTINEL for line in stdout.splitlines())
    fail_lines = [
        line for line in stdout.splitlines() if line.startswith(FAIL_PREFIX)
    ]
    verdict = result.get("verdict")
    passed = result.get("pass")
    if (
        exit_code == 0
        and verdict == "pass"
        and passed is True
        and pass_count == 1
        and not fail_lines
    ):
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
    parser.add_argument(
        "--process-status",
        choices=["completed", "timeout", "error"],
        required=True,
    )
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
