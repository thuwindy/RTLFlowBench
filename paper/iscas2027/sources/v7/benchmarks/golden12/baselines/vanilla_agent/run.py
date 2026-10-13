"""CLI for the workflow-neutral same-model vanilla baseline."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from vanilla_agent.core import (  # type: ignore[import-not-found]
        InvalidProviderResponse,
        ProviderInfraError,
        run_baseline,
    )
else:
    from .core import InvalidProviderResponse, ProviderInfraError, run_baseline


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--task", type=Path, required=True)
    parser.add_argument("--public-root", type=Path, required=True)
    parser.add_argument("--repository-root", type=Path)
    parser.add_argument("--workspace-receipt", type=Path)
    parser.add_argument("--expected-workspace-receipt-sha256")
    parser.add_argument("--workflow-binding", type=Path, required=True)
    parser.add_argument("--provider-runner", type=Path, required=True)
    parser.add_argument("--run-root", type=Path, required=True)
    parser.add_argument("--submission-id", required=True)
    parser.add_argument("--attempt-id", required=True)
    parser.add_argument("--attempt-index", type=int, default=1)
    parser.add_argument("--repeat-group-id", required=True)
    parser.add_argument("--seed", type=int)
    parser.add_argument("--allow-development", action="store_true")
    parser.add_argument("--maximum-public-text-bytes", type=int, default=1048576)
    parser.add_argument(
        "--maximum-repository-text-bytes",
        type=int,
        default=4194304,
    )
    args = parser.parse_args()
    attempt = {
        "attempt_id": args.attempt_id,
        "attempt_index": args.attempt_index,
        "repeat_group_id": args.repeat_group_id,
        "seed": args.seed,
    }
    try:
        receipt = run_baseline(
            task_path=args.task,
            public_root=args.public_root,
            repository_root=args.repository_root,
            workspace_receipt_path=args.workspace_receipt,
            expected_workspace_receipt_sha256=(
                args.expected_workspace_receipt_sha256
            ),
            workflow_binding_path=args.workflow_binding,
            provider_runner=args.provider_runner,
            run_root=args.run_root,
            attempt=attempt,
            submission_id=args.submission_id,
            allow_development=args.allow_development,
            maximum_public_text_bytes=args.maximum_public_text_bytes,
            maximum_repository_text_bytes=(
                args.maximum_repository_text_bytes
            ),
        )
    except ProviderInfraError as exc:
        print(
            json.dumps(
                {"status": "provider_infra_block", "reason": str(exc)},
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 3
    except InvalidProviderResponse as exc:
        print(
            json.dumps(
                {"status": "invalid_provider_response", "reason": str(exc)},
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 4
    except (
        OSError,
        TypeError,
        ValueError,
        RuntimeError,
        subprocess.SubprocessError,
    ) as exc:
        print(
            json.dumps(
                {
                    "status": "control_plane_error",
                    "reason": f"{type(exc).__name__}: {exc}",
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2
    print(
        json.dumps(
            {
                "status": receipt["status"],
                "task_id": receipt["task_id"],
                "private_evaluator_run": receipt["private_evaluator_run"],
                "benchmark_ready": receipt["benchmark_ready"],
            },
            sort_keys=True,
        )
    )
    return 0 if receipt["visible_result"]["expected_outcome"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
