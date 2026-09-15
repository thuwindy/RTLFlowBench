# G12 visible decision preflight

Run `runner.py` with a neutral `submission.json` and the directory containing
its file-bundle artifacts. The runner validates only public data:

- exactly one decision artifact with matching path, bytes, and SHA256;
- zero declared EDA calls and no declared network access;
- the public decision schema;
- terminal `blocked`;
- the exact four neutral missing-semantics categories;
- declared zero repository mutation and no forbidden implementation/PASS/PPA
  claim.

The visible runner does not receive a before-repository snapshot and cannot
prove actual zero mutation or absence of unreported EDA processes. Those are
private evaluator gates. Runner exit code zero means the public BLOCK preflight
was accepted; it does not mean RTL PASS or benchmark ready.
