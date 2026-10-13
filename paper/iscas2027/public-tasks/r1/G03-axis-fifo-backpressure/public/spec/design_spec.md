# G03 AXI-Stream frame FIFO integration specification

## Objective

Add `rtl/golden12_axis_fifo.sv` to the supplied read-only repository
projection. The file must define `golden12_axis_fifo`, a structural wrapper
around the supplied `axis_fifo` module. The wrapper configures the dependency
as a bounded frame FIFO and exposes a deliberately small AXI-Stream subset.

This is an integration task. Reimplementing the FIFO, copying a testbench, or
modifying the supplied dependency is outside scope.

## Public repository projection

The workflow receives a content-addressed projection of verilog-axis commit
`ed6130575df11b48a20c9e39b83d9a37011a3723`. The existing
`rtl/axis_fifo.v` is read-only and is the module that must be instantiated.
Upstream tests and evaluator material are intentionally absent.

## Interface and configuration

The exact ports and parameters are defined in `spec/interface_spec.json`.
`DATA_WIDTH` is a positive multiple of eight. `DEPTH_BYTES` is the payload
capacity in bytes; it must be divisible by `DATA_WIDTH/8`, and the resulting
beat capacity must be a power of two of at least two beats.

The wrapper must configure the dependency with:

- `KEEP_ENABLE=1` and `KEEP_WIDTH=DATA_WIDTH/8`;
- `LAST_ENABLE=1` and `FRAME_FIFO=1`;
- `DROP_OVERSIZE_FRAME=1`;
- `DROP_BAD_FRAME=0` and `DROP_WHEN_FULL=0`;
- ID, destination, and user propagation disabled;
- `RAM_PIPELINE=1` and `OUTPUT_FIFO_ENABLE=0`.

## Required behavior

An input beat is accepted only on `s_axis_tvalid && s_axis_tready` at a rising
edge. An output beat is consumed only on
`m_axis_tvalid && m_axis_tready`. Accepted non-oversized frames must emerge
once, in order, with `tdata`, `tkeep`, and `tlast` unchanged.

While an output beat is stalled, `m_axis_tvalid`, `m_axis_tdata`,
`m_axis_tkeep`, and `m_axis_tlast` must remain stable. Input backpressure must
not alter an unaccepted input beat; the source is responsible for holding its
beat stable until accepted.

Frame mode must prevent a partial frame from becoming visible at the output.
An accepted frame that exceeds the configured capacity is discarded as a
whole, produces no output prefix, and causes a one-cycle
`status_overflow` pulse when the dropped frame terminates. A successfully
committed frame causes a one-cycle `status_good_frame` pulse.

`rst` is active-high and synchronous. A sampled reset clears buffered and
partially received frames, deasserts output validity, and clears status pulses.
No cycle-exact first-output latency or combinational fall-through behavior is
required; functional ordering and eventual progress without reset or
backpressure are required.

## Isolation and claims

A development visible runner and public directed protocol tests are included.
Private randomized backpressure, upstream regression reuse, and parameter
sweeps have development evidence, but the evaluator, alternate implementation,
environment, scoring, and independent admission are not frozen. Nothing in
this packet is a benchmark PASS or performance claim.
