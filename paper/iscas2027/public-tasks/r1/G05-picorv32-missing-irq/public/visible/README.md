# G05 visible verification plan

A development visible runner now provides strict scope/notice, compile, one
external latched IRQ, internal timer IRQ, one public service-edge merge
reproducer, and reset smoke checks. The public reproducer covers one bounded
instance of G05-A04/A05; broader sequence sweeps, differential traces,
firmware, formal properties, mutants, and alternate calibration remain
evaluator-private.

The earlier local/SERVER26 receipt applies only to the superseded
non-triggering smoke. This changed suite is pending fresh calibration on the
pinned base, positive repairs, and negative controls. Runner/environment
freeze and independent review are still incomplete. Visible PASS is not
benchmark PASS.
