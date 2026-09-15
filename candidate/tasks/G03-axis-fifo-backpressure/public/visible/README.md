# G03 visible verification

This directory contains the development public runner, strict verdict parser,
directed protocol testbench, and a separate invalid-parameter probe. The
runner distinguishes invalid submission, scope violation, infrastructure
error, timeout, compile error, functional failure, and visible pass.

`--preapproval-contract-only` runs valid elaboration and the public
invalid-parameter rejection probe without running the positive protocol
simulation. An adapter may use this mode as a pre-mutation machine gate; a
wrapper that silently accepts an illegal public parameter combination is
rejected before it can enter the submission workspace.

These artifacts remain development-only. A visible pass is not hidden
F2P/P2P, benchmark admission, coverage, QoR, or an overall workflow pass.
