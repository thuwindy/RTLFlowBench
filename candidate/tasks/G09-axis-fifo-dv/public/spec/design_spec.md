# G09 — AXI-Stream FIFO backpressure verification

## Objective

Create one independently authored cocotb/pytest verification file for the pinned
`axis_fifo` DUT. The verification must accept correct implementations and detect
semantic defects involving ready/valid backpressure, payload/metadata stability,
frame boundaries, and configured overflow/drop behavior.

The workflow receives a read-only projection containing `rtl/axis_fifo.v` and
`COPYING`. Existing upstream tests are not part of the public input. Do not edit,
replace, or copy the DUT into the submission.

## Submission contract

Submit exactly `verification/test_axis_fifo_backpressure.py`. It must be a regular
UTF-8 Python file no larger than 131072 bytes. It may import `pytest`, `cocotb`,
`cocotb_test.simulator`, and `cocotbext.axi` from the frozen runner environment.
It must read the DUT path from `G09_AXIS_FIFO_RTL` and place simulator products
under `G09_BUILD_DIR`. It must read the deterministic seed from `G09_SEED` and
bind the legal public parameter point supplied in `G09_DATA_WIDTH` and
`G09_DEPTH_BYTES`; hard-coded repository, parameter, or evaluator-private paths
are not portable and will not satisfy differential and P2P evaluation.

The submission owns its cocotb tests and pytest entry points. It must not emit or
spoof the visible runner sentinel. The evaluator determines PASS from process
outcomes across correct and mutant DUTs, not from text printed by the submission.

## Required verification behavior

- Drive and monitor AXI-Stream only on rising clock edges outside synchronous,
  active-high reset.
- Exercise independent source idle insertion and sink backpressure, including
  stalls that last multiple cycles.
- While `m_axis_tvalid && !m_axis_tready`, verify that `tvalid`, `tdata`, `tkeep`,
  `tlast`, `tid`, `tdest`, and `tuser` remain stable.
- Compare every accepted output beat with the corresponding accepted input beat;
  detect loss, duplication, reordering, data corruption, and metadata corruption.
- Check frame termination and byte-valid masks at single-beat and multi-beat frame
  boundaries, including partial final beats.
- Exercise the frozen frame-FIFO configuration and verify that complete good
  frames emerge in order. Oversized or marked-bad frames must follow the frozen
  drop/status policy rather than leaking an output prefix.
- Use deterministic seeds supplied through `G09_SEED`; log enough case identity to
  reproduce a failure without disclosing hidden evaluator assets.
- Terminate under the resource budget. Unbounded waits are failures, not PASS.

## Public and hidden evaluation boundary

The public runner uses one correct configuration and two public defect classes:
valid suppression under sink stall and inverted frame termination. Hidden
evaluation uses different transformations, schedules, parameter points, and seeds.
Passing the public fixtures alone is insufficient. The workflow must not inspect
`private/`, hidden result files, or runner implementation paths.

## Trust and readiness

This packet is a reviewable development draft. Rights review, environment and
coverage freeze, hidden F2P/P2P calibration, independent alternate audit, scoring,
and admission remain pending. Workflow-specific approval and mutation controls
belong in the adapter and are not benchmark reason codes.
