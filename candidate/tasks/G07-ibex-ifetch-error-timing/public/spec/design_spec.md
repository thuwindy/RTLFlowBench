# G07 — Immediate PMP-CSR update enforcement

## Objective

Repair the pinned Ibex base so that a successful non-read operation on an
implemented PMP configuration or PMP address CSR is serialized before a later
instruction can rely on the old execute-permission decision. The editable file
is only `rtl/ibex_id_stage.sv`.

The stable task identifier contains the earlier intake wording. This document,
the acceptance specification, and the CPU interface specification define the
corrected contract.

## Public input and submission

The workflow receives the content-addressed base projection described by
`repo.lock`. The base `rtl/ibex_id_stage.sv` is editable; the other nine files
are read-only context. A submission contains exactly one replacement file at
`rtl/ibex_id_stage.sv`. It must retain the upstream module interface, headers,
and legal parameter behavior.

## Required behavior

- A valid CSR write, set, or clear operation targeting an implemented PMP
  configuration or PMP address CSR must serialize the instruction stream.
- No following instruction may execute, commit an architectural side effect,
  or escape the relevant pipeline control using an execute-permission decision
  made before that PMP operation took effect.
- The following instruction is refetched or otherwise re-evaluated through the
  existing Ibex control and PMP path. If the updated PMP state denies execute
  permission, the existing instruction-access fault behavior applies.
- If the updated PMP state permits execution, forward progress resumes through
  the existing pipeline behavior. The repair does not add an architectural
  instruction, status bit, port, or exception class.

The contract is behavioral. It does not prescribe the upstream patch shape,
an internal predicate, a signal name, or an exact number of inserted bubbles.

## Preservation requirements

- Preserve the `ibex_id_stage` module signature and every existing parameter.
- Preserve reset, ordinary fetch, branch and jump, exception, interrupt, debug,
  WFI, non-PMP CSR, data-side, and writeback behavior outside the repair.
- Preserve illegal or unimplemented CSR handling. This task must not make an
  illegal PMP access legal.
- Preserve existing behavior when PMP is disabled or has no implemented
  region; no new execute-permission semantics may be invented.
- Do not modify read-only projected files, add files, use network access, or
  depend on evaluator assets.

## Reset and timing

`clk_i` is rising-edge active. `rst_ni` is active low and asynchronous for the
affected sequential logic in the pinned base. Reset retains its existing
priority and clears the existing pipeline state. The repair may introduce only
the serialization needed for correctness; no throughput, frequency, area, or
cycle-latency improvement is claimed.

## Verification boundary

The current development visible runner covers the exact projected scope,
read-only hashes, byte budget, and partial Verilator lint only. It intentionally
does not disclose or test the required repair behavior. An evaluator-private
development suite now composes predicate, instruction-control, bounded-formal,
and full-core checks. Its current calibration observes two source-distinct
positive implementations, six killed development mutants, fail-closed tool and
syntax controls, and two-run semantic repeatability. These observations are
content locked but not independently reviewed, frozen, or admitted. Private
vectors, oracle implementation, dependency projection, and raw evidence are
not public inputs.

## Readiness

This is a reviewable public draft with a development-only partial-lint runner,
not an admitted benchmark. Rights, specification, projection, evaluator and
runner freeze, environment, scoring, workflow-adapter integration, and
independent admission gates remain open.
