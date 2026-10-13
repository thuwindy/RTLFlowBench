# G06 repository projection scaffold

The benchmark will materialize the exact seven-file projection described by
`../repo.lock`. The workflow edits only the two RTL files listed in
`../allowed_scope.json`; the other five files are read-only context.

No repaired revision, upstream repair diff, testbench, reference solution, or
private evaluator asset belongs in the workflow workspace. The projection has
been byte-reproduced from the verified SERVER26 source store as development
evidence; its release digest, rights review, and environment are not frozen.
