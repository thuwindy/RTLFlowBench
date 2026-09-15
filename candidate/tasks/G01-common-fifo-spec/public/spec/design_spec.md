# G01 parameterized synchronous FIFO

## Objective

Implement a bounded, single-clock FIFO as the SystemVerilog module
`golden12_fifo`. The implementation must preserve input order, provide a
ready/valid interface on both sides, and report its occupancy. This is an
independent behavioral specification: no upstream implementation is included
or required.

The only required submission file is `rtl/golden12_fifo.sv`. The exact port and
parameter contract is normative in `interface_spec.json`. A development
visible runner is included in `visible/`; private evaluator assets remain
isolated and are not part of this public packet.

## Parameters

- `DATA_WIDTH` is the payload width. Its default is 32 and every integer value
  greater than or equal to 1 must be supported.
- `DEPTH` is the number of stored words. Its default is 4 and every integer
  value greater than or equal to 2 must be supported.
- `DEPTH` is not restricted to powers of two. Pointer or counter wraparound
  must work, for example, at depths 3, 5, and 7.
- An invalid parameter value must stop elaboration or produce an equivalent
  static failure. Runtime behavior for an invalid parameterization is not
  defined.

## Clock and reset

All state transitions occur on the rising edge of `clk_i`.

`rst_ni` is active low and synchronous. It is sampled only on a rising clock
edge; changing it between clock edges must not asynchronously change state or
outputs. A rising edge with `rst_ni == 0` has priority over all handshakes and
returns the FIFO to the reset state:

- `empty_o == 1`
- `full_o == 0`
- `fill_level_o == 0`
- `out_valid_o == 0`

`out_data_o` is unspecified whenever `out_valid_o == 0`, including after
reset. Consumers must not infer state from invalid output data.

## Handshake and ordering

An input word is accepted on a rising edge exactly when
`in_valid_i && in_ready_o` is true. An output word is removed on a rising edge
exactly when `out_valid_o && out_ready_i` is true.

Accepted input words must be produced exactly once and in acceptance order.
When `out_valid_o == 1 && out_ready_i == 0`, both `out_valid_o` and
`out_data_o` must remain stable until the word is accepted or reset is
asserted.

The FIFO is registered and non-fall-through. If it is empty before a clock edge
and accepts an input on that edge, the new word becomes a valid output only
after that edge. It cannot be consumed as a combinational same-cycle transfer.

## Empty, full, and simultaneous operation

`empty_o` is true exactly when the stored-word count is zero. `full_o` is true
exactly when the count equals `DEPTH`. `fill_level_o` is the exact count and has
width `$clog2(DEPTH + 1)`.

The ready/valid behavior is:

- When not full, `in_ready_o` is asserted.
- When full, `in_ready_o` is asserted exactly when an output transfer can be
  accepted on the same edge: `out_valid_o && out_ready_i`. This permits one
  dequeue and one enqueue without changing occupancy.
- `out_valid_o` is asserted exactly when the FIFO is not empty.
- When nonempty and both transfers are accepted on one edge, the old head is
  removed, the new word is appended at the tail, and occupancy is unchanged.
- When empty before an edge, an asserted `out_ready_i` does not create a
  dequeue. An input may still be accepted according to `in_ready_o`, with the
  registered latency stated above.

An overflow attempt (`in_valid_i && !in_ready_o`) and an underflow attempt
(`out_ready_i && !out_valid_o`) do not change FIFO state. The interface has no
error output, and no error counter or diagnostic side effect is required.

## Scope and evidence status

Only the path declared in `allowed_scope.json` may be submitted. The public
packet contains a blank scaffold, an executable development visible runner,
and its public testbench. It contains no RTL answer, reference solution,
private evaluator oracle, performance result, or benchmark PASS claim.

This module is not a CPU. The independent non-CPU `interface_spec.json` is the
normative interface contract; a CPU-specific interface projection is neither
applicable nor implied.
