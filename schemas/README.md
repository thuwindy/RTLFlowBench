# RTLFlowBench neutral schemas

These Draft 2020-12 schemas are the public interoperability boundary:

- `task.schema.json` describes a frozen or explicitly draft public task;
- `submission.schema.json` describes files and workflow/resource metadata;
- `result.schema.json` records the evaluator verdict, independent oracle
  outcomes, raw metrics, trust/scope events, evidence hashes and score.

They do not expose evaluator commands, reference RTL, human patches or hidden
tests. ChipFlow, a vanilla agent and a third-party AIRTL workflow must all
produce the same submission contract before the offline evaluator runs.

The canonical verdict set keeps infrastructure, invalid instance/submission,
scope violation, timeout, compile error, F2P, P2P, formal, PPA, safe BLOCK and
PASS distinct. Adapters must not collapse these classes into a generic success
or failure. Every oracle result carries a nullable `failure_verdict`: passing
and not-run oracles must use `null`, timeout and infrastructure states map
exactly, and a failing oracle names the canonical failure it evidences. The
semantic validator rejects duplicate oracle IDs, a terminal verdict without
matching oracle/scope evidence, priority inversion, and PASS with any failing
oracle, including a non-required oracle.

The task budget separates draft calibration from a frozen comparison policy.
A draft uses `provisional_not_frozen` with null LLM-call, token, and human-
intervention maxima and therefore cannot support a comparable-run claim. A
frozen budget must set LLM-call and human-intervention limits and must choose
one token policy: enforce measured input/output maxima, or report tokens while
placing missing-provider measurements in a separate non-comparable cohort.
Frozen public packets cannot retain a provisional budget.

Schema validation alone is not sufficient. The conformance validator also
checks cross-document task/submission/result identifiers and canonical content
bindings, allowed file scope,
bundle hashes, wall/EDA/LLM/token/intervention budgets, required oracle
outcomes, all terminal verdict classes, PASS semantics and evidence references.

## Network boundary

`public_packet.network_access=false`, `budget.network_access=false`, and
`submission.network_access_observed` refer to the evaluated task workspace and
the EDA/tool subprocesses that can read or modify task files. They do not mean
that an AIRTL workflow may claim zero LLM calls or hide its model-provider
control plane. A declared model-provider call may occur only outside the task
workspace boundary and must be covered by workflow identity, LLM-call, token,
wall-time and attempt-control evidence.

A workflow that combines provider access and EDA execution in one process must
produce monitor evidence that distinguishes provider egress from workspace or
tool egress. If it cannot, isolation evidence is incomplete and the run is
non-publishable. Provider endpoints, credentials, raw responses and user IDs
must not enter a submission or public evidence bundle.

Canonical document digests are SHA256 over UTF-8 JSON serialized with keys
sorted, no insignificant whitespace, and non-ASCII characters preserved. A
submission binds the exact task descriptor and its public-packet digest; a
result binds the exact task descriptor and submission. This rejects stale
tasks and result replay even when human-readable IDs are reused. The task's
`public_packet.sha256` is deliberately non-self-referential: it hashes the
canonical manifest of regular public files excluding `external_task.json`.
Transport archive hashes remain in packaging receipts.
