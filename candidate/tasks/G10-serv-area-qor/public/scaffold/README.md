# G10 submission scaffold

Start from the projected, content-addressed SERV repository. Copy all seventeen
`rtl/*.v` files into the submission bundle under their original paths, then
make only allowlisted RTL edits.

The submission is complete only as a file bundle; this directory intentionally
contains no optimized RTL, reference diff, evaluator trace, synthesis script,
cell library, timing constraint, score, or expected area number.

Before a frozen runner exists, local syntax or synthesis experiments are
diagnostic only and cannot establish correctness or QoR.
