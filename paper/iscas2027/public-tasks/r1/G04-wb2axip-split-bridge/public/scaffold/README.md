# G04 submission scaffold

The evaluated workspace will contain the read-only files
`rtl/axilrd2wbsp.v`, `rtl/axilwr2wbsp.v`, and `README.md`. The workflow must
add exactly `rtl/golden12_axil_wb_split_bridge.sv`; no implementation is
supplied here.

The upstream combined wrapper, arbiter, tests, formal harnesses, and private
evaluator are intentionally absent. This directory contains no RTL or
testbench; workflow-specific mutation controls belong in the adapter.
