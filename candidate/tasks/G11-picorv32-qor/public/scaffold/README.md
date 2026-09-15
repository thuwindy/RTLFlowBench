# G11 submission scaffold plan

The benchmark does not ship a blank replacement for `picorv32.v`. A workflow
starts from the content-addressed public repository projection, copies the
baseline `picorv32.v` into a new neutral submission bundle, and makes bounded
function-preserving edits to that copy.

The submission must contain exactly `picorv32.v`. Do not include `COPYING`,
`README.md`, firmware, Dhrystone or formal assets, synthesis scripts, logs,
waves, generated netlists, reports, caches, repository metadata, or evaluator
files. The baseline is an input, not an optimized answer; no optimized reference
or human solution is public.

Workflow-specific approval and mutation controls belong in the adapter and
must fail closed when their own authorization requirements are not met.
