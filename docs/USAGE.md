# Using the public preview

## What an external workflow receives

Read `public/task.json`, `external_task.json`, the three `spec/` files,
`allowed_scope.json`, `budget.json`, `repo.lock` and `EVALUATION_POLICY.md` together.
Conflicting or unsupported semantics must stop admission, not be guessed away.
G01/G02 are specification-to-RTL tasks. Other tasks require the exact source
projection declared in `repo.lock`. This preview does not supply a verified generic
repository materializer. Do not silently replace a projection with a whole checkout.

Use a new workspace for each task and repeat. Place generated files only at permitted
paths. Keep model/control-plane access outside the offline task tool workspace and
record all calls. Never provide private evaluator feedback during an attempt.

## Visible checks (development feedback only)

For G01, install Icarus Verilog separately and consult the visible runner's help:

```sh
python3 candidate/tasks/G01-common-fifo-spec/public/visible/runner.py --help
python3 candidate/tasks/G01-common-fifo-spec/public/visible/runner.py \
  --submission-root ../my-g01-submission --output-dir ../g01-visible-result
```

The submission root must contain `rtl/golden12_fifo.sv`. No RTL solution is supplied.
Do not execute untrusted submissions on a shared host without a sandbox and quotas.
The preview does not freeze a public EDA container or claim all visible runners have
been portably revalidated. A visible pass is not hidden correctness or benchmark PASS.

## Package a submission

```sh
python3 tools/package_submission.py \
  --task candidate/tasks/G01-common-fifo-spec/public/external_task.json \
  --metadata ../actual-metadata.json --bundle-root ../my-g01-submission \
  --output ../g01-submission.json
```

The metadata object contains exactly `schema_version` (value
`rtlflowbench.submission_metadata.v1`), `submission_id`, `workflow`, `attempt`,
`resource_usage`, `network_access_observed`, and `claims`. Nested fields follow
`schemas/submission.schema.json`. Supply actual workflow/config identities, seed,
elapsed time, calls and token usage; never fill unknown values with guessed zeros.
The packager rejects missing required files, symlinks, extra editable scope and
budget violations. It creates a hash receipt, not a ZIP and not an evaluator result.
Retain the matching artifact bundle separately. Draft packet hashes remain null in
the legacy schema; the distribution lock is an additional preview identity only.

## Scoring boundary

`python3 rtlflowbench.py evaluate` deliberately returns BLOCK/nonzero: this preview
does not distribute or bind the new private evaluator. It cannot produce a full
official score. Operator-side evaluation must be independent of workflow metadata,
verify artifacts and bindings, and emit the neutral result schema with true evidence.
Do not fabricate a result JSON or substitute visible checks for private scoring.

## Reporting and issues

Report task ID, repository commit, command, tool versions and a minimal public-only
reproducer. Do not upload API keys, raw provider responses, hidden tests or solutions.
Until final v1, use this repository for task inspection, adapter preparation and
visible experimentation, not claims of certified comparative performance.
