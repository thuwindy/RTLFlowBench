# G11 development visible preflight

`runner.py` is a development-only public preflight. It accepts a submission
directory containing exactly `picorv32.v`, checks the byte budget and upstream
notice markers, elaborates and generically synthesizes the frozen ordinary
configuration, verifies its port projection and non-empty structure, and runs
an independently written four-instruction firmware smoke with one exact pass
sentinel.

Run it in the frozen server environment (once that environment is admitted):

```text
python visible/runner.py \
  --submission-root /isolated/submission \
  --output-dir /isolated/output
```

The output directory must not already exist and must be outside the submission.
A zero tool exit is insufficient: `result.json` reports distinct scope,
infrastructure, timeout, compile, structural, and functional outcomes, and only
one exact sentinel can produce public visible PASS.

`riscv_formal_runner.py` is a separate fail-closed structural projection gate.
It defines `RISCV_FORMAL`, generically synthesizes the same frozen configuration,
and requires the exact 27 ordinary plus 29 RVFI top ports listed in
`riscv_formal_projection.json`. Its PASS does not prove RVFI observation
semantics.

The development suite has one SERVER26 baseline positive and eleven negative
controls covering scope, notice, module, syntax, interface, function, missing
tools, and timeout outcomes; all twelve matched their expected verdict and no
negative case passed. This does not freeze or admit the runner. The shared
task-neutral Yosys equivalence runner also implements the public contract at a
provisional four-step bound: identity discharged 2471 equivalence cells and one
ALU functional mutant failed with 32 unproven cells. A retained 32-step identity
proof completed, but its functional-mutant control reached the 600-second
development timeout and is not accepted as a calibrated gate result. Unified
runner orchestration, a structurally different correct alternate, and the
independent freeze remain incomplete. The RISCV_FORMAL structural projection
also has one SERVER26 baseline positive and four negative controls covering RVFI
width drift, formal-only syntax, missing Yosys, and timeout; all five matched
their expected verdict and no negative case passed. Generic cell counts are
diagnostic, not physical area, timing, PPA, QoR gain, score, hidden correctness,
or benchmark PASS. Hidden firmware, differential, physical-flow, alternate, and
mutation assets are not in this public directory.
