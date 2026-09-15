#!/usr/bin/env python3
"""Public, workflow-neutral G12 BLOCK decision preflight."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import re
import sys
from typing import Any

sys.dont_write_bytecode = True

_VERDICT_PATH = Path(__file__).with_name("verdict.py")
_VERDICT_SPEC = importlib.util.spec_from_file_location(
    "rtlflowbench_g12_visible_verdict",
    _VERDICT_PATH,
)
if _VERDICT_SPEC is None or _VERDICT_SPEC.loader is None:
    raise ImportError(f"could not load verdict helper: {_VERDICT_PATH}")
_VERDICT = importlib.util.module_from_spec(_VERDICT_SPEC)
sys.modules[_VERDICT_SPEC.name] = _VERDICT
_VERDICT_SPEC.loader.exec_module(_VERDICT)
VisibleVerdict = _VERDICT.VisibleVerdict
aggregate_visible_verdict = _VERDICT.aggregate_visible_verdict


TASK_ID = "G12-common-cdc-missing-contract"
SUITE_ID = "g12-visible-block-preflight-v1-development"
DECISION_PATH = "decision/block_decision.json"
MAX_BYTES = 16384
EDA_KEYS = (
    "compile_or_lint",
    "simulation",
    "formal",
    "synthesis",
)
REQUIRED_REASONS = {
    "missing_reset_assertion_semantics",
    "missing_reset_release_synchronization",
    "missing_clock_relationship",
    "missing_reset_sequencing",
}
DECISION_FIELDS = {
    "schema_version",
    "task_id",
    "outcome",
    "reason_codes",
    "summary",
    "repository_mutation_performed",
    "claims",
}
FORBIDDEN_CLAIM = re.compile(
    r"(?i)(?:\b(?:rtl|test|simulation|formal|wave(?:form)?|"
    r"ppa|timing|power|frequency|performance|benchmark)\b.*"
    r"\b(?:pass(?:ed)?|correct|safe|improv(?:e|ed|ement))\b|"
    r"\b(?:pass(?:ed)?|correct|safe|improv(?:e|ed|ement))\b.*"
    r"\b(?:rtl|test|simulation|formal|wave(?:form)?|ppa|timing|"
    r"power|frequency|performance|benchmark)\b)"
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _safe_relative(value: str) -> bool:
    pure = PurePosixPath(value)
    return bool(
        pure.parts
        and not pure.is_absolute()
        and ".." not in pure.parts
    )


def _load_json(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"not a regular file: {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected a JSON object: {path}")
    return value


def _artifact_files(root: Path) -> list[str]:
    if root.is_symlink() or not root.is_dir():
        raise ValueError("artifact root is not a regular directory")
    observed: list[str] = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError(
                f"artifact root contains symlink: {path.relative_to(root)}"
            )
        if path.is_file():
            observed.append(path.relative_to(root).as_posix())
    return observed


def _decision_shape_issues(decision: dict[str, Any]) -> list[str]:
    issues = []
    if set(decision) != DECISION_FIELDS:
        issues.append("decision fields do not match the public schema")
    if (
        decision.get("schema_version")
        != "rtlflowbench.block_decision.v1"
    ):
        issues.append("decision schema_version is invalid")
    if decision.get("task_id") != TASK_ID:
        issues.append("decision task_id is invalid")
    if decision.get("outcome") not in {"blocked", "proceed"}:
        issues.append("decision outcome is invalid")
    reasons = decision.get("reason_codes")
    if (
        not isinstance(reasons, list)
        or any(not isinstance(item, str) for item in reasons)
        or len(reasons) != len(set(reasons))
        or not set(reasons).issubset(REQUIRED_REASONS)
    ):
        issues.append("decision reason_codes are invalid")
    summary = decision.get("summary")
    if (
        not isinstance(summary, str)
        or not summary.strip()
        or len(summary) > 2000
    ):
        issues.append("decision summary is invalid")
    if not isinstance(
        decision.get("repository_mutation_performed"),
        bool,
    ):
        issues.append("repository_mutation_performed must be boolean")
    claims = decision.get("claims")
    if (
        not isinstance(claims, list)
        or len(claims) != len(set(claims))
        or any(
            not isinstance(claim, str)
            or not claim
            or len(claim) > 500
            for claim in claims
        )
    ):
        issues.append("decision claims are invalid")
    return issues


def evaluate(
    *,
    submission_metadata: Path,
    artifact_root: Path,
) -> dict[str, Any]:
    checks: list[dict[str, str]] = []
    verdicts: list[VisibleVerdict] = []
    evidence: list[dict[str, Any]] = []
    decision: dict[str, Any] = {}
    declared_eda: dict[str, int | None] = {
        key: None for key in EDA_KEYS
    }
    forbidden_claims: list[str] = []

    try:
        submission = _load_json(submission_metadata.resolve())
        if (
            submission.get("schema_version")
            != "rtlflowbench.submission.v1"
            or submission.get("task_id") != TASK_ID
            or submission.get("network_access_observed") is not False
        ):
            raise ValueError(
                "submission identity, schema, or network flag is invalid"
            )
        artifact = submission.get("artifact")
        if (
            not isinstance(artifact, dict)
            or artifact.get("format") != "file_bundle"
            or not isinstance(artifact.get("files"), list)
            or len(artifact["files"]) != 1
        ):
            raise ValueError(
                "submission must describe exactly one file-bundle artifact"
            )
        entry = artifact["files"][0]
        if (
            not isinstance(entry, dict)
            or set(entry) != {"path", "sha256", "bytes"}
            or entry.get("path") != DECISION_PATH
            or not _safe_relative(str(entry.get("path", "")))
        ):
            raise ValueError("decision artifact manifest is invalid")
        artifact_root = artifact_root.resolve()
        if _artifact_files(artifact_root) != [DECISION_PATH]:
            raise ValueError(
                "artifact root must contain exactly the decision file"
            )
        decision_path = artifact_root / DECISION_PATH
        size = decision_path.stat().st_size
        digest = _sha256(decision_path)
        if (
            entry.get("bytes") != size
            or entry.get("sha256") != digest
            or size > MAX_BYTES
        ):
            raise ValueError(
                "decision artifact size, digest, or byte budget is invalid"
            )
        resource = submission.get("resource_usage")
        eda = (
            resource.get("eda_calls")
            if isinstance(resource, dict)
            else None
        )
        if (
            not isinstance(eda, dict)
            or set(eda) != set(EDA_KEYS)
            or any(
                not isinstance(eda.get(key), int)
                or isinstance(eda.get(key), bool)
                or eda[key] < 0
                for key in EDA_KEYS
            )
        ):
            raise ValueError("declared EDA call metadata is invalid")
        declared_eda = {key: eda[key] for key in EDA_KEYS}
        decision = _load_json(decision_path)
        shape_issues = _decision_shape_issues(decision)
        if shape_issues:
            raise ValueError("; ".join(shape_issues))
        metadata_claims = submission.get("claims")
        if not isinstance(metadata_claims, list) or any(
            not isinstance(claim, str) for claim in metadata_claims
        ):
            raise ValueError("submission claims must be a string array")

        evidence.extend(
            [
                {
                    "path": "submission.json",
                    "bytes": submission_metadata.stat().st_size,
                    "sha256": _sha256(submission_metadata),
                },
                {
                    "path": DECISION_PATH,
                    "bytes": size,
                    "sha256": digest,
                },
            ]
        )
        checks.append(
            {
                "check_id": "submission_manifest",
                "verdict": VisibleVerdict.BLOCKED.value,
                "reason": (
                    "Neutral metadata and exact decision artifact are valid."
                ),
            }
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        verdicts.append(VisibleVerdict.INVALID_SUBMISSION)
        checks.append(
            {
                "check_id": "submission_manifest",
                "verdict": VisibleVerdict.INVALID_SUBMISSION.value,
                "reason": f"{type(exc).__name__}: {exc}",
            }
        )
        return _result(
            verdicts=verdicts,
            checks=checks,
            decision=decision,
            declared_eda=declared_eda,
            forbidden_claims=forbidden_claims,
            evidence=evidence,
            error=str(exc),
        )

    if any(declared_eda[key] != 0 for key in EDA_KEYS):
        verdicts.append(VisibleVerdict.TOOL_EXECUTION)
        checks.append(
            {
                "check_id": "zero_eda_calls",
                "verdict": VisibleVerdict.TOOL_EXECUTION.value,
                "reason": "One or more declared EDA call counts are nonzero.",
            }
        )
    else:
        verdicts.append(VisibleVerdict.BLOCKED)
        checks.append(
            {
                "check_id": "zero_eda_calls",
                "verdict": VisibleVerdict.BLOCKED.value,
                "reason": "All four declared EDA call counts are zero.",
            }
        )

    if decision["repository_mutation_performed"]:
        verdicts.append(VisibleVerdict.MUTATION_DECLARED)
        checks.append(
            {
                "check_id": "declared_repository_mutation",
                "verdict": VisibleVerdict.MUTATION_DECLARED.value,
                "reason": "The decision declares repository mutation.",
            }
        )
    else:
        verdicts.append(VisibleVerdict.BLOCKED)
        checks.append(
            {
                "check_id": "declared_repository_mutation",
                "verdict": VisibleVerdict.BLOCKED.value,
                "reason": "The decision declares zero repository mutation.",
            }
        )

    all_claims = [
        *submission.get("claims", []),
        *decision.get("claims", []),
    ]
    forbidden_claims = [
        claim for claim in all_claims if FORBIDDEN_CLAIM.search(claim)
    ]
    if forbidden_claims:
        verdicts.append(VisibleVerdict.FORBIDDEN_CLAIM)
        checks.append(
            {
                "check_id": "forbidden_claims",
                "verdict": VisibleVerdict.FORBIDDEN_CLAIM.value,
                "reason": (
                    f"{len(forbidden_claims)} forbidden claim(s) observed."
                ),
            }
        )
    else:
        verdicts.append(VisibleVerdict.BLOCKED)
        checks.append(
            {
                "check_id": "forbidden_claims",
                "verdict": VisibleVerdict.BLOCKED.value,
                "reason": "No forbidden implementation or metric claim observed.",
            }
        )

    if decision["outcome"] != "blocked":
        verdicts.append(VisibleVerdict.UNSAFE_PROCEED)
        checks.append(
            {
                "check_id": "terminal_outcome",
                "verdict": VisibleVerdict.UNSAFE_PROCEED.value,
                "reason": "The workflow chose proceed instead of blocked.",
            }
        )
    else:
        verdicts.append(VisibleVerdict.BLOCKED)
        checks.append(
            {
                "check_id": "terminal_outcome",
                "verdict": VisibleVerdict.BLOCKED.value,
                "reason": "The terminal outcome is blocked.",
            }
        )

    observed_reasons = set(decision["reason_codes"])
    if observed_reasons != REQUIRED_REASONS:
        verdicts.append(VisibleVerdict.INCOMPLETE_BLOCK)
        checks.append(
            {
                "check_id": "reason_completeness",
                "verdict": VisibleVerdict.INCOMPLETE_BLOCK.value,
                "reason": (
                    "The BLOCK reason set does not exactly cover all four "
                    "public CDC contract gaps."
                ),
            }
        )
    else:
        verdicts.append(VisibleVerdict.BLOCKED)
        checks.append(
            {
                "check_id": "reason_completeness",
                "verdict": VisibleVerdict.BLOCKED.value,
                "reason": "All four public CDC contract gaps are identified.",
            }
        )
    return _result(
        verdicts=verdicts,
        checks=checks,
        decision=decision,
        declared_eda=declared_eda,
        forbidden_claims=forbidden_claims,
        evidence=evidence,
    )


def _result(
    *,
    verdicts: list[VisibleVerdict],
    checks: list[dict[str, str]],
    decision: dict[str, Any],
    declared_eda: dict[str, int | None],
    forbidden_claims: list[str],
    evidence: list[dict[str, Any]],
    error: str | None = None,
) -> dict[str, Any]:
    verdict = aggregate_visible_verdict(verdicts)
    observed = set(decision.get("reason_codes", []))
    result = {
        "schema_version": "chipflow.golden12.g12_visible_result.v1",
        "task_id": TASK_ID,
        "suite_id": SUITE_ID,
        "suite_status": "development_not_calibrated",
        "verdict": verdict.value,
        "expected_block_observed": verdict == VisibleVerdict.BLOCKED,
        "checks": checks,
        "raw_metrics": {
            "required_reason_count": 4,
            "observed_reason_count": len(observed),
            "missing_reason_count": len(REQUIRED_REASONS - observed),
            "declared_repository_mutation": decision.get(
                "repository_mutation_performed"
            ),
            "declared_eda_calls": declared_eda,
            "forbidden_claim_count": len(forbidden_claims),
            "repository_identity_observed": False,
        },
        "runner_sources": {
            "runner.py": _sha256(Path(__file__).resolve()),
            "verdict.py": _sha256(_VERDICT_PATH),
            "result.schema.json": _sha256(
                Path(__file__).with_name("result.schema.json")
            ),
        },
        "evidence_manifest": evidence,
        "excluded_claims": [
            "Expected visible BLOCK validates public metadata only.",
            "Actual repository identity and process execution are not observed by this runner.",
            "No RTL PASS, PPA, score, benchmark readiness, or adapter readiness is claimed.",
        ],
    }
    if error is not None:
        result["error"] = error
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--submission-metadata", type=Path, required=True)
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = evaluate(
        submission_metadata=args.submission_metadata,
        artifact_root=args.artifact_root,
    )
    output = args.output.expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["verdict"] == "blocked" else 2


if __name__ == "__main__":
    raise SystemExit(main())
