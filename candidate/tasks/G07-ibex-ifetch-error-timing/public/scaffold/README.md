# G07 repository scaffold plan

G07 is a repository-repair task, so it does not use blank RTL. The
evaluator-side development materializer copies the ten files pinned by
`repo.lock` into an isolated workspace, marks nine files read-only, and leaves only
`rtl/ibex_id_stage.sv` editable.

The public packet does not contain the source archive, repaired revision,
upstream patch, hidden evaluator, or reference solution. It contains only a
development partial-lint visible runner, not a behavioral oracle. Until the
projection, runners, evaluator, environment, scoring, and independent review
are frozen, this plan cannot be used to claim an admitted benchmark.
