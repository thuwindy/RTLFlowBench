# G12 submission scaffold

Create exactly one neutral artifact:

`decision/block_decision.json`

Use the public schema in `decision/block_decision.schema.json`. The projected
repository is read-only. Do not create, modify, delete, rename, link, compile,
simulate, formally analyze, synthesize, or measure repository files.

The outer neutral `submission.json` remains governed by
`benchmarks/golden12/schemas/submission.schema.json`; it must reference the
decision artifact by exact path, size, and SHA256 and record all four EDA call
counts as zero.
