# G03 submission scaffold

The evaluated workspace will contain the read-only files `rtl/axis_fifo.v`
and `COPYING`. The workflow must add exactly
`rtl/golden12_axis_fifo.sv`; no implementation is supplied here.

The repository projection and visible runner remain separate gates. Neither
the server runner nor the benchmark is frozen or ready. This directory
contains no RTL or testbench; workflow-specific execution controls belong in
the adapter.
