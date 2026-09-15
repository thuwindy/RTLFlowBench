# G07 visible verification runner

`runner.py` implements a development-only exact-scope and partial Verilator
lint gate for the ten-file repository projection. `verdict.py` requires the
process exit, structured result, and one exact pass sentinel to agree. Raw tool
output is written outside the workflow workspace and hard-capped.

The runner deliberately does not disclose or test the evaluator-private
denied-instruction timing sequence, formal property, reference repair, or
mutants. Assertion and functional-coverage shims are limited to public lint;
they are not evidence of behavioral or formal correctness.

Until real reference/negative calibration, sandbox/environment freeze, and
independent review are complete, `visible_oracle_implemented` remains false
and no official visible or benchmark PASS may be reported.

A SERVER26 development calibration has exercised the base projection, a syntax
corruption, an out-of-scope file, and a missing-tool condition. The resulting
`pass`, `compile_error`, `scope_violation`, and `infra_error` classifications
are calibration evidence only; behavior-oriented visible checks remain absent.
