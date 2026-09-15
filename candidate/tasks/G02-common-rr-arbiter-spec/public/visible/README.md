# G02 development visible suite

The public runner checks the exact one-file scope, compiles parameter values 1,
3, 4, and 5, runs directed behavior for 1 and 4 requesters, and verifies that
the illegal zero-requester instance is rejected. It uses exact PASS sentinels;
an exit code alone is never sufficient.

This suite intentionally does not contain the future hidden fairness sequences,
formal properties, mutants, evaluator reference, or alternative implementation.
Its result is development evidence only and cannot admit the benchmark.

Example (run in a controlled server environment):

```bash
python3 visible/runner.py --workspace submission --output-dir evidence
```
