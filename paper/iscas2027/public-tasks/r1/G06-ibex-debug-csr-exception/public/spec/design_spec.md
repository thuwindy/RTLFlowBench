# G06 — Ibex debug-mode exception CSR repair

## Objective

Repair the pinned Ibex base so a synchronous exception taken while the hart is
already in Debug Mode follows the existing debug-exception control-flow path
without overwriting the previously saved machine exception context. Preserve
normal exception handling, initial Debug Mode entry, Debug Mode exit, EBREAK
special handling, interrupts, reset, and all behavior outside this defect.

This is a repository repair task. The workflow receives a content-addressed
base projection, not a blank design and not a repaired revision. It may edit
only `rtl/ibex_controller.sv` and `rtl/ibex_cs_registers.sv`.

## Pinned design boundary

- Top-level integration context: `ibex_core`.
- Affected units: `ibex_controller` and `ibex_cs_registers`.
- Clock: rising edge of `clk_i`.
- Reset: active-low `rst_ni`, with asynchronous assertion as implemented by
  the pinned base.
- Existing module ports, enum encodings, legal parameters, license headers,
  and file locations must not change.

The controller supplies the CSR-save controls, exception cause/value and
Debug Mode state. The CSR block owns the architectural machine/debug register
state. A valid repair may place the guard in either editable unit or divide it
between them, provided the observable contract below is met. The specification
does not prescribe an internal predicate or reproduce an upstream patch.

## Required behavior

### Exception while already in Debug Mode

When an exception is taken while the current Debug Mode indication is active:

1. Control flow still uses the pinned debug-exception route. The repair must
   not suppress the exception, resume the faulting instruction, or redirect it
   to the normal machine trap vector.
2. The machine exception context that existed immediately before the event is
   preserved. Observable values of `mepc`, `mcause`, `mtval`, and the
   exception-related `mstatus` fields must not be replaced by the debug-mode
   exception. State used by the pinned recoverable machine-exception/NMI
   restoration path must likewise remain observationally unchanged.
3. The event must not be treated as a new Debug Mode entry. Previously saved
   debug-entry state, including the debug exception PC and debug cause, is not
   rewritten merely because the hart is already in Debug Mode.
4. The repair must not deadlock, duplicate retirement, create a new external
   interface, or leave a repair-specific pending state after reset.

The hidden evaluator is planned to exercise multiple synchronous exception
classes rather than accept a solution specialized to one opcode or cause.

### Preserved positive behavior

- A normal synchronous exception outside Debug Mode continues to update the
  machine exception context and redirect through the normal trap path.
- Initial entry to Debug Mode continues to save the pinned debug-entry
  context and cause.
- DRET continues to leave Debug Mode and restore the pinned privilege state.
- EBREAK behavior both outside and inside Debug Mode remains as defined by the
  pinned base; the repair must not turn every EBREAK into a machine exception
  or rewrite debug-entry CSRs on an in-debug re-entry.
- Interrupt, non-maskable interrupt, MRET, CSR-access, performance-counter,
  PMP, branch, LSU, fetch, and pipeline behavior outside the stated defect is
  unchanged.
- Reset retains the pinned active-low asynchronous assertion semantics.

## Submission and scope

The submission is a two-file bundle containing the two editable paths. Files
may be byte-identical to the base when a workflow elects not to change one of
them, but no other file may differ or be added. Symlinks, generated artifacts,
testbench changes, evaluator assets, and network dependencies are forbidden.

The provisional combined submission limit is 131072 bytes. The external
workflow must report wall time, token accounting when available, LLM/EDA call
counts, and human interventions through the common result protocol. Missing
measurements remain null/not-available and form a non-comparable cohort; they
are not zero.

## Verification boundary

The development public runner checks exact projection/scope, compile/lint, and
directed positive-preservation behavior without disclosing the full oracle.
Development private evaluation compares machine/debug CSR traces across
exception, normal-trap, debug-entry/exit, and regression scenarios. Bounded
formal expansion and broader mutation calibration remain open. None of those
runners or results is frozen yet.

The public packet contains no repaired RTL, reference solution, historical
repair diff, hidden test, or evaluator oracle. Passing a future public runner
will not imply benchmark PASS.

## Current maturity

This document is a reviewable draft. Rights, specification, projection,
visible/hidden oracle, environment, scoring, budget, public digest, and final
admission all remain unfrozen. Benchmark readiness is not claimed.
