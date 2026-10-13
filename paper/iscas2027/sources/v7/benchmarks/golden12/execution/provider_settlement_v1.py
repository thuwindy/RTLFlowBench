"""Bounded wait for already admitted provider calls after workflow termination.

Final ledger closure atomically rejects queued calls that have not been admitted.
Run inside the live ControllerServer context, after stopping the workflow's
process group and closing unfinished EDA observers. Never reissue a request.
"""
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import time

def drain_provider_calls(*, state, deadline_monotonic, process_receipt_sha256,
                         output_path, poll_seconds=0.05):
    output_path = Path(output_path)
    if output_path.exists() or output_path.is_symlink():
        raise FileExistsError("refusing to overwrite provider settlement evidence")
    if not 0 < poll_seconds <= 1:
        raise ValueError("invalid settlement polling interval")
    started = time.monotonic()
    snapshot = None
    while True:
        try:
            snapshot = state.build_ledger(
                observed_at=datetime.now(timezone.utc).isoformat(),
                process_measurement_receipt_sha256=(process_receipt_sha256() if callable(process_receipt_sha256) else process_receipt_sha256),
            )
        except RuntimeError as exc:
            if str(exc) != "cannot close ledger with unfinished provider activities":
                raise
        else:
            break
        remaining = deadline_monotonic - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(poll_seconds, remaining))
    result = {
        "schema": "chipflow.provider_settlement_wait.v1",
        "status": "settled" if snapshot is not None else "unsettled_deadline",
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "wait_seconds": time.monotonic() - started,
        "new_provider_requests": 0,
        "source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "process_receipt_sha256": snapshot["process_measurement_receipt_sha256"] if snapshot is not None else None,
        "token_measurement_complete": None,
        "input_tokens": None,
        "output_tokens": None,
        "ledger": snapshot,
    }
    if snapshot is not None:
        usage = snapshot["provider_budget"]["token_usage"]
        result.update(token_measurement_complete=usage["measurement_complete"],
                      input_tokens=usage["input_tokens"], output_tokens=usage["output_tokens"])
    with output_path.open("x") as handle:
        json.dump(result, handle, indent=2)
    return result
