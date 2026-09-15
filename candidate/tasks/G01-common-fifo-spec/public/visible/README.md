# G01 visible verification

The public packet now contains a development implementation of the deterministic
visible suite:

- `runner.py` validates the one-file scope, invokes Icarus, preserves raw
  stdout/stderr, and emits `result.json`;
- `g01_visible_tb.sv` checks reset, handshakes, ordering, output stability,
  simultaneous full replacement, capacity, and repeated non-power-of-two
  wraparound;
- `g01_invalid_parameter_probe.sv` checks that illegal parameterizations do
  not elaborate or start successfully;
- `verdict.py` requires both a zero exit status and one exact per-case PASS
  sentinel. Timeout, infrastructure failure, compile failure, functional
  failure, invalid submission, and scope violation remain distinct.

Run it with an output directory outside the submission:

```bash
python visible/runner.py \
  --submission-root /path/to/submission \
  --output-dir /path/to/evidence
```

This suite is not frozen and a visible PASS is not a hidden F2P/P2P or
benchmark PASS. The evaluator-only calibration subjects are outside the public
packet and must not be mounted into a workflow workspace.
