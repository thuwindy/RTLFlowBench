# G10 visible verification plan

The development visible runner implements:

- exact seventeen-file submission and allowlisted-scope validation;
- wrapper/module/parameter/port structural validation;
- Verilog elaboration and generic Yosys synthesis; and
- a generic netlist/interface check that reports raw structural statistics
  only; and
- an independently written four-instruction RV32I smoke that requires the
  exact `sw x2, 64(x0)` bus transaction after two `addi` instructions.

An adapter may additionally run the task-neutral public
`run_yosys_sequential_equivalence.py` gate before mutation approval. It compares
the exposed immutable baseline and candidate under
`preapproval_equivalence.json`, using `equiv_simple` plus `equiv_induct` and a
strict `equiv_status -assert` terminator. Baseline identity and one equivalent
positive pass in Yosys 0.65 and 0.33; one behavior mutant fails in both. This
development calibration is not a frozen hidden oracle, complete formal
equivalence, ISA compliance, or benchmark PASS.

The public smoke contains no upstream firmware or private evaluator asset.
SERVER26 development calibration observed the baseline pass plus seven distinct
non-pass cases: one known false-improvement functional mutant, syntax and scope
failures, three unavailable-tool paths, and one controlled process timeout.
No negative case produced PASS. This is still a single-program development
oracle, not an independently frozen runner. Historical structural-only
calibration remains recorded separately and is not silently relabelled as
evidence for this new semantic runner.

Visible PASS is only structural preflight plus this one public smoke. The
generic synthesis dry run must not label cell counts as area, timing, PPA,
improvement, or benchmark PASS. Hidden compliance, differential trace, PPA,
false-improvement, and scoring checks remain evaluator-private.
