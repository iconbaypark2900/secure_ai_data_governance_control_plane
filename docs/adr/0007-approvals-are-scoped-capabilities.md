# 0007 — An approval is a scoped, single-use capability

**Status:** accepted

## Context

The `require_approval` effect parked a decision and let a human grant it. Nothing
consumed the grant: there was no way for an enforcement point to come back and
say "this was approved, proceed". Half a feature, and the visible half was the
half that worked.

Completing it means deciding what a granted approval actually *is*, and the
obvious answer is the wrong one. If redemption were "present the approval id and
the decision becomes allow", then an approval id is a bearer token for any
request that happens to need one: get a routine export approved, keep the id, and
present it later for an exfiltration. The reviewer approved a sentence; the
holder gets a wildcard.

## Decision

A granted approval is a capability with four constraints, all enforced at
redemption:

**Bound.** `request_fingerprint` is a keyed digest of the policy-relevant inputs
— principal, action, resource URN, resolved labels, payload digest, and context.
It is computed at park time from the same pipeline stage that computes it at
redemption. If anything a reviewer was implicitly agreeing to has changed, the
digest differs and the approval does not apply.

**Single use.** `redeemed_at`, `redeemed_by`, and `redeemed_decision_id` record
the spend. "Approve this one export" must not become "approve every export until
the window closes".

**Expiring.** The existing 24-hour window is now checked at redemption, not only
at grant. An approval given on Monday's context should not be redeemable on
Friday.

**Subordinate to deny.** Redemption re-evaluates the policy set and only upgrades
`require_approval` into `allow`. A deny that now applies still denies, and the
approval is not consumed — so it still works if the deny is later lifted.

Two supporting choices:

- **Obligations are re-collected across `allow` *and* `require_approval` policies
  on upgrade.** An `allow` policy that matched but lost to the parking rule still
  said "if you permit this, redact the SSNs". Without the union, redeeming an
  approval would be a way to shed redaction another policy required.
- **Re-sending a parked request returns the existing ticket** rather than
  creating another. A retrying caller must not turn one reviewable decision into
  a hundred queue entries.

## Alternatives

**An opaque redemption token issued at grant time.** Equivalent security if the
token is bound the same way, and it adds a secret to store, transmit, and leak.
The binding is doing the work, not the opacity — so the id stays an id.

**Approve the *principal* for a window rather than the request.** Simpler and
much weaker: it is a time-boxed role grant wearing an approval's clothes, and it
authorises everything that principal might do, not the thing a human read.

**Let redemption skip re-evaluation.** Faster, and it would mean a policy
tightened after the grant — during an incident, say — could be bypassed by anyone
holding an approval issued before it. Re-evaluating is the point.

## Consequences

An approval only redeems for a byte-identical request, which is stricter than
users will expect the first time it bites. A caller that regenerates its context
map with a timestamp in it, or retries with a re-serialised payload, will find
the approval refused. That is the correct failure direction, and it makes the
`approval_error` string part of the contract: it distinguishes "still pending,
keep waiting" from "this will never work, stop retrying".

Approvals granted before this change carry an empty fingerprint and are
deliberately not redeemable. Retrofitting a binding onto a grant whose scope was
never recorded would be guessing at what a human agreed to, which is the exact
mistake the column exists to prevent.

The `redeemed_decision_id` column is not a foreign key. An approval should
outlive a decision row that retention later removes, because "this was approved,
and then used" is the fact worth keeping longest.
