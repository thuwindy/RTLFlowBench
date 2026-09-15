# RTLFlowBench · Golden-12

A workflow-neutral benchmark project for six dimensions of AI-assisted RTL work.
The name refers to **RTL workflows**, not to one model or to ChipFlow alone.

> **Research preview, not Golden-12 v1.** This repository publishes the twelve
> public input packets, proposed evaluation policy, neutral schemas and offline
> packaging tools. It is not yet a turnkey scored benchmark or a leaderboard.
> New-version evaluator bindings, full recalibration and runtime gates remain open.
> There are no new-version comparative experiment results in this release.

## Quick start

Python 3.10+; no model account or ChipFlow installation is needed for these commands.

```sh
git clone https://github.com/thuwindy/RTLFlowBench.git
cd RTLFlowBench
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python rtlflowbench.py verify
.venv/bin/python rtlflowbench.py list
.venv/bin/python rtlflowbench.py export-public \
  --task G01-common-fifo-spec --output ../g01-public
.venv/bin/python -m unittest discover -s tests -v
```

The exported folder contains the specification, constraints, declared budget,
source lock, visible tests and submission contract. It contains **no solution**.
`export-public` does not fetch upstream repositories. Repository-based tasks need
their exact, allowlisted source projection before they can be attempted fairly.
Do not expose entire repository histories, upstream tests or private evaluation
assets to an agent. See [third-party usage](docs/USAGE.md).

## Twelve tasks, six capability families

| ID | Upstream context | Public input and requested output | What is measured |
|---|---|---|---|
| G01 | common_cells | FIFO specification → independent RTL | Parameters, queue ordering, boundaries, reset |
| G02 | common_cells | Arbitration specification → independent RTL | Arbitration safety, locking and bounded fairness |
| G03 | verilog-axis | AXI-Stream FIFO IP + integration contract → wrapper | Frames, backpressure, protocol integration |
| G04 | wb2axip | Split bridge IP + contract → AXI-Lite/Wishbone integration | Transaction ownership, response routing, stalls |
| G05 | PicoRV32 | Pinned CPU base + defect contract → interrupt repair | Fail-to-pass repair and preserved regressions |
| G06 | Ibex | Pinned CPU base + exception contract → CSR/debug repair | Context preservation and unaffected behavior |
| G07 | Ibex | Pinned CPU base + PMP update contract → serialization repair | Protection update enforcement; historical ID retained |
| G08 | common_cells | Read-only FIFO + DV contract → TB and properties | Correct-design acceptance, mutant kill, false positives |
| G09 | verilog-axis | Read-only FIFO + DV contract → cocotb tests | Protocol defect detection and false alarms |
| G10 | SERV | Pinned CPU + fixed QoR constraints → optimized RTL | Area improvement with correctness/timing preservation |
| G11 | PicoRV32 | Pinned CPU + QoR/workload contract → optimized RTL | Area, timing and workload cycles, separately |
| G12 | common_cells | Explicitly incomplete CDC contract → refusal artifact | Safe refusal and zero-action scope compliance |

G07's directory retains `ibex-ifetch-error-timing` for identity continuity; its
current specification concerns PMP updates. G12's refusal class is explicit:
it tests compliance, **not** autonomous discovery of an unstated risk.

## Scoring and fairness

The proposed authority is [candidate/policy.json](candidate/policy.json).
Primary reporting is the full task-by-workflow outcome matrix, with separate raw
functional/protocol, F2P/P2P, formal, mutation/false-positive, QoR and cost evidence.
There is no invented weighted total. Missing metrics remain `null`, not zero.
Evaluator evidence—not a workflow's self-report or process exit alone—determines
success. FAIL, capability BLOCK and infrastructure INFRA remain distinguishable.
For G12, a contract-compliant BLOCK is the expected successful behavior.

The planned five-workflow cohort has 200 independent slots: three repeats on ten
non-QoR tasks and five on two QoR tasks, per workflow. EDA measurement repeats are
not additional independent agent solves. All workflows receive the same inputs,
model configuration and budget. Adapter code may translate transport, not solve
tasks. Semantic changes require a new identity and fresh comparable runs.

## Status and repository layout

- `candidate/tasks/*/public/`: twelve content-bound draft public packets.
- `candidate/candidate-lock.json`: exact public packet file hashes and known gaps.
- `candidate/policy.json`: proposed universal evaluation policy.
- `schemas/`: workflow-neutral task, submission and result formats.
- `tools/package_submission.py`: validates scope, budget and artifact hashes.
- `public-release-lock.json`: exact **preview distribution**, not runner release lock.
- [Readiness checklist](docs/READINESS.md), [usage](docs/USAGE.md),
  [licensing and upstream provenance](NOTICE.md).

The legacy wire identifier `chipflow-golden12` is retained in schemas for
compatibility; it does not require ChipFlow. Inherited rights/admission receipts
are historical and do not admit this new candidate. No human-independent review
or official v1 readiness is claimed. Hidden evaluators and answers are deliberately
not in this public repository. Do not use visible-test passes as full scores.

For a paper, a repository helps readers inspect and reproduce the work; its
existence alone does not establish benchmark validity. A final paper must bind a
specific release, disclose review limitations and report actual complete-cohort
results. No accepted-paper or conference affiliation is claimed here.
