# G05 — PicoRV32 interrupt-pending repair

## Objective

Repair the pinned PicoRV32 repository base so an interrupt-source update cannot
erase another eligible source when timer and external events occur at the same
or closely spaced clock edges. The repair is deliberately narrow: preserve the
processor, memory interface, interrupt service path, acknowledgement encoding,
and all behavior not named by this contract.

This is a repository-repair task. The starting `picorv32.v` is supplied by the
runner from the content-addressed base in `repo.lock`; it is not copied into this
public packet. `README.md` may be supplied as read-only context.

## Interface and configuration

The top is `picorv32`, written in Verilog 2005. The repair-relevant interface is
defined in `cpu_interface_spec.json`:

- rising-edge `clk`;
- synchronous active-low `resetn`;
- 32-bit external `irq`;
- 32-bit acknowledgement `eoi`;
- `trap`;
- `ENABLE_IRQ`, `ENABLE_IRQ_TIMER`, `MASKED_IRQ`, and `LATCHED_IRQ`.

The existing timer interrupt uses its existing source bit and behavior. This
task does not allocate new IRQ numbers, add ports, or introduce a new interrupt
controller.

## Required behavior

When IRQ support is enabled, pending-state evolution must preserve the set union
of:

1. previously retained and unserved eligible sources;
2. an eligible internal timer-expiry event;
3. eligible external IRQ bits sampled at the clock edge.

Consequently, an event from one source must not overwrite an event from another.
Distinct pending sources are represented as a bit set, not as event counters.
Compile-time masking, runtime service masking, latched one-cycle events, and
non-latched level-sensitive inputs retain the semantics in the CPU interface
contract.

Reset has priority: an edge sampling `resetn` low clears pending and
acknowledgement state and does not retain coincident interrupt events.

## Preservation boundary

Only `picorv32.v` is editable. Preserve its module signatures, embedded ISC
permission notice, wrapper compatibility, instruction execution, memory
interfaces, trap behavior, IRQ instructions, service ordering, and `eoi`
encoding. Do not edit `README.md`, add files, or rely on firmware, upstream
testbenches, evaluator files, network access, or a historical repair.

The evaluator will distinguish build errors, invalid submissions, scope
violations, timeout, infrastructure errors, F2P failures, P2P regressions, and
formal failures. An exit code alone is never sufficient for PASS.

## Verification boundary

The development visible suite implements build, one external source, timer,
reset, and one bounded service-edge merge check derived from G05-A04/A05.
Private evaluator development remains separate and includes broader
simultaneous and closely spaced source sequences, masking/latching
combinations, differential state observation, firmware regression, formal
properties, mutants, and at least one independently structured correct repair.

No reference patch, repair commit, private waveform, benchmark PASS, coverage,
performance, or PPA result is included or implied by this draft.
