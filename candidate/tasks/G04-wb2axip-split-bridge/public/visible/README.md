# G04 visible verification

This directory contains the development public runner, strict verdict parser,
directed protocol testbench, and invalid-parameter probe. The runner separates
invalid submission, scope violation, infrastructure error, timeout, compile
error, functional failure, and visible pass.

`--preapproval-contract-only` runs valid elaboration and the public invalid
parameter rejection probe without executing the positive protocol simulation.
That mode is suitable as a pre-mutation contract gate; it does not authorize
edits by itself.

These artifacts have development calibration evidence but are not frozen. A
visible pass is not hidden F2P/P2P, formal proof, benchmark admission, QoR, or
an overall workflow pass.
