# Provenance and redistribution scope

## September public task preview

The task suite draws its project context from:

- https://github.com/pulp-platform/common_cells
- https://github.com/alexforencich/verilog-axis
- https://github.com/ZipCPU/wb2axip
- https://github.com/YosysHQ/picorv32
- https://github.com/lowRISC/ibex
- https://github.com/olofk/serv

Exact per-task revisions, notice requirements and license-evidence links are in
each public `repo.lock` and `rights_review.json`. No whole upstream repository,
reference implementation, evaluator source or hidden tests are included here.
Public verification fixtures are intentionally visible and must not be represented
as hidden evaluation. Filenames and source-code license strings in checks are not
licenses for upstream projects.

This preview does not grant or replace third-party rights. Upstream code fetched
separately retains its original license; preserve its required notices. Existing
unsigned rights receipts stay unsigned. Final redistribution/admission review is
pending. No blanket license is applied to the imported task corpus in this preview;
contact the maintainer before redistributing it. Publishing a readable repository
is not a claim that all benchmark materials have completed open-source licensing.

The newly authored preview helper `rtlflowbench.py` and its tests are available
under the MIT license in `TOOLS_LICENSE.txt`. This limited grant does not apply to
the imported packet corpus, schemas or upstream material. A complete licensing
manifest is required before the fully reusable v1 release.

## ISCAS 2027 paper source companion

The statements above describe the original `candidate/` preview and its tools.
The additive `paper/iscas2027/` directory also includes selected benchmark and
evaluator-helper source, execution-bound public packets, and source-provenance
metadata. Its file-level scope and omissions are described in
[the paper source guide](paper/iscas2027/README.md).

The copied DeerFlow-derived tools retain their original MIT notices in
[DEERFLOW_LICENSE.txt](paper/iscas2027/DEERFLOW_LICENSE.txt). This does not extend
the preview helper's limited license to the imported task corpus, schemas or
upstream RTL, nor establish new rights/admission approvals. The existing task
preview and its candidate hashes are unchanged. No hidden evaluator fixture
package, full upstream repository or raw model/execution log is distributed.

## Collaboration helpers

The newly authored `scripts/check_paper_snapshot.py` and
`tests/collaboration/test_paper_snapshot.py` are covered by the limited MIT grant
in `TOOLS_LICENSE.txt`, alongside the original preview CLI and its test file.
This extends the grant only to those two new files; task packets, imported
schemas and third-party source keep their existing licensing scope.
