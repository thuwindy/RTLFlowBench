# G06 visible verification runner

`runner.py` enforces the exact seven-file projection, hashes every read-only
file, records both editable RTL hashes and their combined byte count, runs
separate Verilator component lint checks for the controller and CSR block, and
then compiles `g06_visible_tb.sv`. The public behavioral smoke checks reset,
normal illegal-instruction exception context save, and first Debug Mode entry
preservation. `verdict.py` requires all three exact case markers, the suite
marker, process exit, structured result, and one exact runner sentinel to
agree. Raw tool output is written outside the workflow workspace and
hard-capped.

The complete in-debug exception trace, preservation matrix, formal properties,
coverage, hidden mutants, positive-subject calibration, and scoring remain
evaluator-private. The public testbench never applies an exception while Debug
Mode is already active, so a public pass does not establish that the requested
repair is correct.

A SERVER26 development calibration using the content-addressed Verilator 5.048
binary observed the pinned base and two independently derived repair structures
as `pass`; a normal-exception preservation mutant as `functional_fail`; and
syntax, added-file, missing-tool, and simulation-timeout fixtures as
`compile_error`, `scope_violation`, `infra_error`, and `timeout`. The private
repairs and fixtures are not distributed in this packet. The environment and
runner remain unfrozen; there is no official benchmark PASS claim.
