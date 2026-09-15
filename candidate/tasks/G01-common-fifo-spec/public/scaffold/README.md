# Blank scaffold status

The public packet intentionally contains no RTL answer. `plan.json` describes
the blank submission workspace layout. A workflow may create only
`rtl/golden12_fifo.sv` and must obey `allowed_scope.json`; workflow-specific
approval or execution controls belong in its adapter, not in this packet.
