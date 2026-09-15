# G11 function-preserving PicoRV32 QoR optimization

Optimize the timing/area Pareto point of one frozen PicoRV32 configuration while
preserving its architectural and externally cycle-visible behavior. The input
repository is a content-addressed projection of PicoRV32 commit
`6399aeaa5981b5e77a76f5d4036d763893ab5a72`. The only editable file is
`picorv32.v`; `COPYING` and `README.md` are read-only.

This is a correctness-first task. A smaller or faster design is not useful if it
changes an instruction result, trap, memory transaction, look-ahead signal,
PCPI interaction, interrupt acknowledgement, reset sequence, trace output, or
formal observation. Functional failure makes every QoR metric ineligible.

## Frozen configuration

The evaluator instantiates `picorv32` using the upstream `top_large` feature
choices and explicit values for every public parameter:

| Parameter | Frozen value |
| --- | ---: |
| `ENABLE_COUNTERS` | `1` |
| `ENABLE_COUNTERS64` | `1` |
| `ENABLE_REGS_16_31` | `1` |
| `ENABLE_REGS_DUALPORT` | `1` |
| `LATCHED_MEM_RDATA` | `0` |
| `TWO_STAGE_SHIFT` | `1` |
| `BARREL_SHIFTER` | `1` |
| `TWO_CYCLE_COMPARE` | `0` |
| `TWO_CYCLE_ALU` | `0` |
| `COMPRESSED_ISA` | `1` |
| `CATCH_MISALIGN` | `1` |
| `CATCH_ILLINSN` | `1` |
| `ENABLE_PCPI` | `1` |
| `ENABLE_MUL` | `1` |
| `ENABLE_FAST_MUL` | `0` |
| `ENABLE_DIV` | `0` |
| `ENABLE_IRQ` | `1` |
| `ENABLE_IRQ_QREGS` | `1` |
| `ENABLE_IRQ_TIMER` | `1` |
| `ENABLE_TRACE` | `0` |
| `REGS_INIT_ZERO` | `0` |
| `MASKED_IRQ` | `32'h0000_0000` |
| `LATCHED_IRQ` | `32'hffff_ffff` |
| `PROGADDR_RESET` | `32'h0000_0000` |
| `PROGADDR_IRQ` | `32'h0000_0010` |
| `STACKADDR` | `32'hffff_ffff` |

The parameter declarations and their defaults are part of the repository
interface and must remain present even though the evaluator overrides the
feature values above explicitly.

## Interface and behavior

`clk` is the only clock and state advances on its rising edge. `resetn` is
active low and is sampled synchronously on a rising edge; asserting it between
edges has no asynchronous state effect. Reset sequencing, reset PC, trap entry,
and the first post-reset memory request must match the pinned baseline.

The native memory interface uses `mem_valid`/`mem_ready`. Instruction tagging,
addresses, write data, byte strobes, read-data consumption, request stability
under backpressure, and transaction ordering must match cycle for cycle. The
look-ahead outputs (`mem_la_*`) are also observable and must match for identical
stimuli; they are not merely optimization hints that may be removed.

The PCPI request and response interface is enabled. Preserve the request
instruction and operand values, hold behavior, `pcpi_wait`/`pcpi_ready`
interaction, writeback behavior, timeout/illegal-instruction behavior, and the
priority relationship between the enabled internal multiplier and an external
PCPI responder. Division remains disabled.

The IRQ interface is enabled. Preserve sampling, masking, latching, timer IRQ,
entry/return behavior, `eoi`, simultaneous source handling, and interaction with
memory stalls and PCPI. Preserve `trap`, `trace_valid`, and `trace_data` for the
frozen `ENABLE_TRACE=0` configuration without assuming undocumented constant
values. When compiled with `RISCV_FORMAL`, preserve the existing RVFI port set
and observation semantics used by the planned formal and differential gates.

The externally observed cycle trace is exact: no request, response, PCPI, IRQ,
trap, trace, or retirement event may be inserted, removed, reordered, or shifted
to a different cycle. Do not change a public module name, port, width,
direction, preprocessor mode, or frozen behavior.

## QoR and scoring boundary

The planned evaluator first runs scope, build/lint, firmware simulation,
formal/equivalence, and architectural plus cycle-visible differential gates.
Only a functionally eligible submission may enter the same content-addressed
physical synthesis and timing flow as the baseline. Raw per-run area, timing,
and workload-cycle observations must retain tool, library, constraint, seed,
resource-limit, unit, and parser provenance.

No canonical threshold, aggregation rule, physical environment, or score is
frozen in this draft. Generic synthesis statistics are diagnostic only and
must not be reported as physical area, timing closure, PPA improvement, or
benchmark PASS. Empty, truncated, constant-output, interface-pruned,
parser-spoofing, timed-out, or functionally incorrect designs receive no QoR
credit.

## Submission and safety

Return a neutral file bundle containing exactly `picorv32.v` plus workflow
metadata defined by the shared submission schema. Do not add, delete, or rename
files; do not modify notices or read-only context; do not include build products,
logs, waves, evaluator assets, repository metadata, or network-fetched content.
Workflow-specific approval and mutation controls belong in the adapter and
must fail closed when their own authorization requirements are not met.

This public specification does not claim that the repository projection,
visible or hidden evaluator, physical flow, scoring, environment, or benchmark
is ready.
