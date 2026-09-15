# G02 parameterized round-robin arbiter

Implement `golden12_rr_arbiter`, a clocked, work-conserving round-robin arbiter
for `NUM_REQUESTERS` independent requesters. The public workspace is blank; the
only permitted implementation file is `rtl/golden12_rr_arbiter.sv`.

## Arbitration and progress

`req_i[k]` means requester `k` currently wants service. `grant_o` is one-hot or
zero and `grant_valid_o` is its validity. When valid, `grant_index_o` identifies
the asserted bit. A requester is served only on a rising clock edge for which
both `grant_valid_o` and `grant_accept_i` are high and the arbiter is not locked.

The reset preference is requester 0. After an accepted, unlocked grant to `k`,
the next search starts at `(k + 1) mod NUM_REQUESTERS`. With no request, grant is
zero and the search position does not change. If a grant is not accepted, the
winner and search position remain stable as long as request and lock inputs stay
unchanged.

## Lock

While `lock_i` is high, the current requesting winner is held and cannot be
preempted by a newly asserted request. `grant_accept_i` does not rotate priority
while locked. If the held requester drops its request, the arbiter immediately
selects the next eligible requester using the unchanged round-robin search
position and holds that new winner. If no request remains, grant becomes zero.
When lock is first asserted without a held winner, the ordinary round-robin
winner for that cycle becomes the held winner.

## Fairness

Lock and downstream backpressure may intentionally suspend progress. Otherwise,
for any requester that stays asserted, at most `NUM_REQUESTERS` accepted,
unlocked grants may occur before it is granted. If every requester remains
asserted, accepted grants visit requester indices cyclically without starvation.

## Reset and parameters

`rst_ni` is asynchronous, active low. While reset is asserted, every output is
zero and all held-lock state is cleared. The first post-reset search begins at
requester 0. `NUM_REQUESTERS` must be at least 1; zero is an illegal instance
and must be rejected explicitly at elaboration or time zero. Non-power-of-two
requester counts are required. The public index width is
`max(1, ceil(log2(NUM_REQUESTERS)))`; unused index encodings must never appear
with `grant_valid_o=1`.

No X/Z value is permitted on public outputs for known binary inputs outside an
illegal instance. No performance, PPA, hidden-oracle, or readiness claim is
part of this specification.
