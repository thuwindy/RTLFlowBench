# G08 public design-verification brief

## Objective

Independently author two reusable SystemVerilog verification assets for the
pinned `fifo_v3` DUT:

- `verification/g08_fifo_tb.sv`: a deterministic, self-checking simulation
  testbench with top module `g08_fifo_tb`;
- `verification/g08_fifo_properties.sv`: a bindable formal-property module
  named `g08_fifo_properties`.

The assets must detect meaningful FIFO semantic defects while accepting the
correct DUT over the public legal parameter and stimulus domain. This is a
verification-generation task, not an RTL-repair task. The DUT and license files
are read-only.

## Public workspace

The workflow receives exactly the following repository projection:

- `src/fifo_v3.sv`, read-only, pinned by `repo.lock`;
- `LICENSE`, read-only, pinned by `repo.lock`;
- this public packet.

The upstream `test/fifo_tb.sv`, `formal/fifo_v3_properties.sv`,
`formal/fifo_v3.sby`, hidden mutants, evaluator harnesses, reference
verification solutions, and calibration traces are not inputs.

## DUT behavior to verify

The authoritative independently worded interface contract is
`spec/interface_spec.json`. In particular:

- `rst_ni` is an asynchronous active-low reset;
- `flush_i` is sampled synchronously and clears FIFO control state;
- accepted pushes and pops are determined from the current `full_o` and
  `empty_o`;
- a full FIFO does not accept a push merely because `pop_i` is also asserted;
- normal simultaneous accepted push/pop preserves occupancy and ordering;
- arbitrary positive, including non-power-of-two, depths are legal;
- `FALL_THROUGH=1` has defined empty push and empty push/pop behavior;
- `usage_o` is the low `ADDR_DEPTH` bits of occupancy, not an unbounded count.

Verification must not treat `data_o` as meaningful while the FIFO is empty,
except for the documented fall-through case.

## Simulation asset contract

`g08_fifo_tb` must be self-contained apart from `fifo_v3`, must instantiate the
DUT by module name, and must not use hierarchical references into DUT internal
state. It must support these evaluator compile-time macros:

- `G08_DATA_WIDTH`, default `8`;
- `G08_DEPTH`, default `5`;
- `G08_FALL_THROUGH`, default `0`;
- `G08_SEED`, default `1`.

The testbench owns the clock, reset, flush, stimulus, and an independent
transaction-level reference model. It must cover reset, fill/drain, ordering,
pointer wrap, simultaneous operations, overflow/underflow attempts, flush,
and status/usage behavior.
When `G08_FALL_THROUGH=1`, it must also check empty bypass and accepted empty
push/pop. It must use deterministic seed handling and terminate within the
runner budget.

A correct run must emit exactly one line:

`GOLDEN12_G08_TB_PASS`

On a detected discrepancy it must emit a line beginning
`GOLDEN12_G08_TB_FAIL` and exit nonzero. An exit code of zero without the exact
single pass line is not a pass.

The public runner executes the same testbench under both Icarus Verilog 12 and
the pinned Verilator 5.048 frontend before attaching the property module.
Stimulus must therefore be race-free across simulators: callers must not change
DUT inputs in the same active-region slot as a rising edge. Drive each planned
transaction at a falling edge, keep it stable through the next rising edge, and
sample post-NBA state only after a nonzero delay.

The testbench must print that task-owned failure sentinel as a standalone line
before terminating. Merely passing the sentinel text as the message argument to
`$fatal` is insufficient because simulators prefix the resulting line with
`FATAL:`; such a line does not begin with the required sentinel.

The public Icarus Verilog 12 compile gate does not accept an implicit conversion
from a `$sformatf` string result to a packed-vector task argument. Do not route
formatted strings through a generic fixed-width message task. Emit each
condition-specific diagnostic directly with `$display` or `$error`, including
cycle and expected/observed values, then terminate with `$fatal(1, "condition")`.

These are three deliberately separate sentinel layers, not alternative
spellings of one contract:

1. The submitted testbench owns `GOLDEN12_G08_TB_PASS` and
   `GOLDEN12_G08_TB_FAIL`.
2. The public visible runner owns `GOLDEN12_G08_VISIBLE_PASS`; it emits that
   line only after both correct-DUT runs, both public negative fixtures, scope,
   and property compilation pass.
3. The task-workspace monitor owns
   `RTLFLOWBENCH_G08_VISIBLE_MONITORED_PASS task=G08-common-fifo-dv`; it emits that
   line only after the runner passes inside the monitored workspace.

The submission must emit only its testbench-layer sentinel. It must not emit or
spoof either harness-owned sentinel. The visible result schema records a
structured verdict and does not redefine the testbench sentinel.

## Formal asset contract

`g08_fifo_properties` must expose the same public DUT signals as module ports
and may define local ghost state. It must not reference private DUT hierarchy.
Its parameter surface is `FALL_THROUGH`, `DATA_WIDTH`, `DEPTH`, and the derived
`ADDR_DEPTH`. All four names must be declared as overrideable module parameters
because the public bind wrapper passes each bound-instance value explicitly;
`ADDR_DEPTH` must not be hidden or redeclared as a `localparam`. This forwarding
does not override the DUT parameter: the wrapper passes `fifo_v3`'s
already-derived `ADDR_DEPTH` into the property module's same-named mirror
parameter.

The module must contain executable assertions that cover at least:

- reset/flush state;
- no illegal occupancy transition under the declared legal-input assumptions;
- full/empty consistency;
- `usage_o` encoding;
- accepted simultaneous-operation occupancy;
- preservation and eventual observation of at least one symbolic tracked item,
  sufficient to expose an ordering or pointer-wrap defect.

All push/pop combinations are legal public inputs. A push while full and a pop
while empty are individually rejected according to the pre-edge status. A
different operation accepted at the same edge still updates state: in
registered mode an empty `push_i && pop_i` accepts only the push and occupancy
becomes one, while at the full boundary it accepts only the pop and occupancy
becomes `DEPTH-1`. The documented fall-through empty transfer remains the sole
empty simultaneous transfer whose occupancy stays zero. The submitted property
module therefore must not contain `assume` statements. Initial reset sequencing
is owned by the evaluator harness rather than by the submission. An asset that
assumes away a boundary operation, disables all assertions, or only checks
compilation is invalid.

The public portability gate compiles and executes the property module with the
pinned Verilator 5.048 `--assert` frontend, and the private bounded-formal gate
parses it with Yosys `read_verilog -formal -sv`. Use the intersection profile:
procedural `always_ff`/`always` blocks containing immediate `assert` and `cover`
statements plus bounded ghost registers/counters. Named
`property`/`endproperty`, named `sequence`/`endsequence`, concurrent implication
operators, `##` sequence delays, `s_eventually`, `eventually`, dynamic delays,
and other unbounded liveness syntax are outside the accepted submission
language. Within that common parser subset, use only bare `assert(expr);` and
`cover(expr);` statements: do not attach `else`, an action block, `$error`, or
another failure statement. Put each `cover` directly in the clocked process and
encode reset/condition gating in its Boolean expression; do not nest `cover`
inside an `if` branch. The public runner coverage-instruments the bound property
cases so this shared Verilator/Yosys form is checked before submission. The
public runner also binds the submitted properties to the correct DUT for two
public parameter cases, so properties and testbench stimulus must be mutually
consistent. This portability restriction does not remove any
property category or weaken the later private bounded-formal gate.

Immediate assertions at `posedge clk_i` execute in the active region and see
the DUT state from before that edge's nonblocking assignments. On an edge where
`flush_i` is high, the property module may clear its next ghost state, but it
must not assert post-flush `empty_o`, `full_o`, or `usage_o` values in that same
event. Check the cleared DUT status on the following rising edge, when
`flush_i` is low, using a bounded one-cycle ghost flag if necessary. Apply the
same sampling discipline when reset is released: do not compare a post-NBA DUT
state against a ghost value that was advanced in the current active region.

## Scope and trust

Only the two required files may be added. The workflow must not edit the DUT,
license, public packet, runner, or evaluator paths; use network access; copy
upstream verification assets; or depend on hidden filenames or mutant details.
The final evaluator will distinguish compile errors, timeouts, infrastructure
errors, functional false negatives, correct-DUT false positives, formal
failures, and scope violations.

## Current status

This packet is a reviewable draft. Rights, specification, projection,
environment, budget, scoring, visible and hidden calibration, alternate
solution audit, and independent admission are not frozen. No PASS, coverage,
mutation, formal, performance, or readiness claim is made.
