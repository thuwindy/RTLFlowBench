# G04 AXI-Lite to Wishbone split-bridge integration specification

## Objective

Add `rtl/golden12_axil_wb_split_bridge.sv` to the supplied read-only
repository projection. The file must define `golden12_axil_wb_split_bridge`,
instantiate exactly one supplied `axilrd2wbsp` and one supplied
`axilwr2wbsp`, and merge their internal Wishbone masters onto one external
Wishbone master without loss, duplication, response misrouting, or
transaction-level interleaving.

This is a repository integration task. Reimplementing either supplied bridge,
copying an upstream combined wrapper or arbiter, or modifying a dependency is
outside scope.

## Public repository projection

The workflow receives a content-addressed projection of wb2axip commit
`18895fa9531f9c273411de48369604ff61dd5959`. Only
`rtl/axilrd2wbsp.v`, `rtl/axilwr2wbsp.v`, and the public license notice are
projected. The upstream combined wrapper, arbiter, tests, formal harnesses,
reference implementation, and private evaluator are absent.

## Interface

The exact ports and parameters are frozen in `interface_spec.json`.
The pinned dependency revision is supported at `C_AXI_DATA_WIDTH=32` only.
Its source-level address slices and write-address port widths do not define a
portable contract for other data widths, so other values are illegal rather
than silently truncated or padded.
`C_AXI_ADDR_WIDTH` is the byte-address width and must exceed
`$clog2(C_AXI_DATA_WIDTH/8)`. The external Wishbone address omits byte-lane
bits and therefore has width
`C_AXI_ADDR_WIDTH-$clog2(C_AXI_DATA_WIDTH/8)`.

The AXI-Lite subset has independent AW, W, B, AR, and R channels. An AXI
transfer occurs only when the corresponding VALID and READY are both high at
a rising clock edge. The supplied write bridge is responsible for pairing an
accepted address and accepted data even if they arrive in either order; the
wrapper must not couple AWREADY to WVALID or WREADY to AWVALID. AXI PROT is
accepted but has no external Wishbone projection.

## Wishbone arbitration

The two dependency instances present separate internal Wishbone masters. The
wrapper must drive exactly one external master:

- a read-owned beat drives `o_wb_we=0`, read address, all-byte select, and
  zero write data;
- a write-owned beat drives `o_wb_we=1`, write address, data, and byte select;
- the selected master's CYC/STB/address/data/select are routed externally;
- the non-selected master observes STALL high;
- ACK and ERR are delivered only to the selected master and only while its CYC
  is active;
- external ACK or ERR while no owner is active must not create an AXI
  response.

Once ownership is granted, it remains with that internal master for the
entire asserted internal CYC, including gaps in STB and any number of accepted
but outstanding beats. Ownership must not switch at a beat boundary. A waiting
other master remains stalled until the selected CYC deasserts.

When idle and only one internal CYC is asserted, that requester is granted.
When both first assert together, reset state grants read. After a completed
owned cycle, simultaneous idle requests prefer the master that did not own
the most recently completed cycle. This deterministic cycle-level
round-robin rule is functional behavior, not a cycle-exact latency promise.

While external STALL is high for an asserted CYC/STB, external WE, address,
data, and select must remain stable. ACK and ERR are mutually exclusive
terminal inputs for a Wishbone beat. ERR is propagated through the owning
dependency to AXI SLVERR (`2'b10`); normal completion produces OKAY
(`2'b00`). Responses and read data must preserve AXI acceptance order.

## Reset and progress

`i_axi_reset_n` is active-low and synchronous to `i_clk`; changing it between
rising edges has no immediate state effect. A sampled low reset has priority
over AXI and Wishbone handshakes, clears arbitration ownership, selects read as
the next simultaneous-request preference, suppresses Wishbone CYC/STB, and
prevents any pre-reset response from later being emitted. `o_reset` is the
combinational active-high complement of `i_axi_reset_n` for compatibility and
is not a second clock-domain reset.

No cycle-exact AXI READY or response latency is required. In the absence of
reset, permanent external stall, or a missing Wishbone ACK/ERR, every accepted
AXI request must eventually receive exactly one matching AXI response.

## Isolation and claims

This public packet is an independently written behavioral contract, not a
line-by-line translation of upstream RTL. It contains no reference wrapper or
hidden oracle. Rights review, oracle calibration, environment/scoring freeze,
and independent admission remain pending. Nothing here is a benchmark PASS,
formal proof, coverage result, or performance claim.
