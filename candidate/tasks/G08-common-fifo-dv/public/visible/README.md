# G08 visible verification status

The development visible runner now checks exact scope and repository digests,
three correct-DUT configurations including `DEPTH=1`, three public negative
fixtures, two standalone Verilator testbench portability cases, an
assumption-free immediate-assertion source profile, property compilation, and
two coverage-instrumented correct-DUT simulations with the submitted properties
bound. The source profile requires bare immediate `assert(expr);` and
`cover(expr);` statements with no action clause, and coverage compilation
rejects unsupported nested cover forms before private evaluation. The standalone
Verilator cases run before property binding so cross-simulator testbench races
cannot be mislabeled as property failures. Historical development observations
predate this expanded suite and do
not establish a pass for the current runner; raw evidence remains under
`outputs/` and is not a public input.

Each compiler subprocess receives an output-scoped writable tool home with
ccache disabled. This keeps the host home outside the runner trust boundary and
prevents a cleared-home compiler-launch failure from being mislabeled as an RTL
compile error.

The visible suite exposes only three independently written, openly documented
negative fixtures. The full-boundary fixture is derived from the public
simultaneous-operation rule and is not copied from a hidden mutant. Hidden
mutants, seeds, traces, signatures, thresholds, and private evaluator code
remain outside this directory. SERVER26 first returned `infra_error` because
Verilator was absent from the host path; that result remains recorded. A later
run with a content-addressed source build of Verilator 5.048 reproduced the
then-current ten-check suite. The expanded 23-check suite requires new
calibration.
Neither historical observation is a formal proof, current workflow PASS,
benchmark PASS, frozen environment, or frozen visible suite.

Sentinel ownership is layered. Submitted testbenches emit
`GOLDEN12_G08_TB_PASS` or `GOLDEN12_G08_TB_FAIL`; `runner.py` alone emits
`GOLDEN12_G08_VISIBLE_PASS`; the outer task-workspace monitor alone emits
`RTLFLOWBENCH_G08_VISIBLE_MONITORED_PASS task=G08-common-fifo-dv`. These literals
belong to different trust boundaries and must not be unified or spoofed by a
submission.
