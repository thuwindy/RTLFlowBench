# G09 visible runner

The runner validates the one-file scope, verifies the pinned DUT/notice hashes,
then executes the submitted pytest module against the correct DUT and two public
mutation classes. Correct-DUT failure, undetected public mutants, timeout, missing
tools, and invalid submissions receive distinct non-PASS verdicts.

The runner owns `GOLDEN12_G09_VISIBLE_PASS`; submissions containing that token are
rejected. Hidden mutation and coverage assets are not present here.
