# G10 — Function-preserving SERV area optimization

## Objective

Starting from the repository snapshot pinned by `repo.lock`, reduce the area of
`serv_synth_wrapper` under one evaluator-controlled synthesis and timing flow.
Correctness is a mandatory gate: a functionally incorrect, interface-changing,
scope-violating, or timing-invalid submission is not eligible for an area
score, even if a synthesis report appears smaller.

The workflow submits the complete seventeen-file `rtl/` bundle. It may change
only those files. The pinned baseline is intentionally visible because this is
an optimization task; evaluator software, compliance programs, traces,
libraries, constraints, seeds, parsers, and optimized reference solutions are
not visible.

## Frozen configuration candidate

The candidate configuration is:

- top module: `serv_synth_wrapper`;
- `PRE_REGISTER=1`;
- `RESET_STRATEGY="MINI"`;
- `WITH_CSR=1`;
- `RF_WIDTH=2`;
- `RF_L2D=10`, derived from the wrapper expression for the frozen values;
- `RESET_PC=0`;
- `MDU=0`;
- `COMPRESSED=0`;
- `ALIGN=0`;
- no `RISCV_FORMAL` ports in the synthesis top.

These values are a reviewable development candidate, not an independently
frozen release. A submission must not rely on changing them.

## Functional preservation

For the same initial reset sequence and the same clock-by-clock inputs, the
submission must preserve the baseline's architecturally observable behavior
and cycle-visible wrapper behavior. This includes:

- RV32I execution for the frozen configuration and the baseline machine-mode
  CSR/timer-interrupt behavior;
- instruction-bus address/request behavior and acknowledgement/data handling;
- data-bus address, write data, byte select, write-enable, request, and
  acknowledgement/data handling;
- external serial register-file read/write request, address, data, enable, and
  ready behavior;
- reset restart at address zero;
- the baseline instruction retirement ordering, memory effects, traps, and
  timer-interrupt effects;
- no additional pipeline stage, buffering latency, speculative request, or
  externally visible cycle shift.

Equivalence will be evaluated against a private, immutable copy of the pinned
baseline. The public text intentionally does not disclose evaluator stimuli,
trace normalization, compliance subsets, or oracle thresholds.

## Reset and handshake semantics

`clk` is the only clock and sequential state is sampled on its rising edge.
`i_rst` is active high. With `RESET_STRATEGY="MINI"`, reset-controlled state is
updated synchronously; the existing combinational suppression of
`o_ibus_cyc` while `i_rst` is high is also part of the cycle-visible contract.
After reset is sampled, instruction fetch restarts from address zero.

`o_ibus_cyc` and `o_dbus_cyc` are request indicators. The corresponding
`i_*_ack` inputs complete requests and `i_*_rdt` supplies returned data.
The external register-file interface uses the wrapper's existing request,
ready, address, write-enable, and serial data behavior. Submissions must
preserve the baseline response to arbitrary evaluator-controlled acknowledgement
latency and register-file readiness.

## QoR measurement boundary

QoR can be compared only after every correctness and scope gate passes. The
eventual evaluator must run baseline and submission with the same:

- content-addressed tool/container image;
- liberty and physical or wire-load assumptions;
- top and parameter values;
- clock constraint and synthesis script;
- seeds and repeated-run policy;
- host limits and timeout policy;
- parser and unit normalization.

The current public packet does not freeze these inputs, an area unit, a timing
threshold, a minimum improvement, or a score formula. Generic Yosys cell counts
from a visible dry run, if later implemented, are diagnostic only and are not
PPA or admission evidence.

## Scope and delivery

Return all seventeen required RTL files under their original `rtl/` paths.
Do not add, delete, or rename files. Preserve the module names and the public
signature of `serv_synth_wrapper`. Do not modify the ISC notice, build context,
tests, firmware, constraints, evaluators, or benchmark metadata. Network access
is disabled.

This draft reports no functional PASS, synthesis PASS, area, timing, power,
performance, improvement, score, or readiness result.
