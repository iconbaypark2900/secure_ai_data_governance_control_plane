# 0019 — Spending an approval and recording the decision that spent it are one act

**Status:** accepted
**Amends:** [0007](0007-approvals-are-scoped-capabilities.md)

## Context

ADR 0007 made a granted approval a capability with four constraints, all enforced
at redemption: bound, single use, expiring, subordinate to deny. Three of them
are enforced by code that runs whatever the request looks like.
`redemption_error` checks status, expiry and the request fingerprint before an
approval is allowed to apply, and `_redeemed_decision` re-evaluates the policy set
so a deny still denies.

Single use is not one of the three. Nothing in `redemption_error` can express it,
because being spent is not a property an approval has when it is presented — it
is a property it acquires from the decision that redeems it. The only thing that
confers it is `_mark_redeemed`, which writes `redeemed_at`, `redeemed_by` and
`redeemed_decision_id`. And `_mark_redeemed` lives here:

```python
if request.options.persist:
    record = await self._persist(...)
    response.decision_id = record.id
    if approval is not None:
        # Spend it. Single use: "approve this one export" must not
        # become "approve every export until the window closes".
        await self._mark_redeemed(approval, record.id, actor=actor)
```

The comment states 0007's rule exactly. The `if` above it is the exception path.

### What was measured

Against the approval-loop fixture: one export parked, granted by `user:manager`
with a ticket reference, then presented five times on requests carrying
`options.persist = false`.

| | |
|---|---|
| effect returned, each of five | `allow` |
| `approval_redeemed` reported | `true` |
| decision records written | **0** |
| audit events written | **0** |
| `approval.redeemed_at` afterwards | **`None`** |
| a sixth, ordinary redemption | `allow` — the capability was never spent |

Every constraint 0007 lists was still enforced. The fingerprint matched because
it was the same request; the status was granted; the window was open; the policy
set was re-evaluated and no deny applied. The decision was, in every sense the
reviewer would have recognised, the one they approved. It simply happened five
times, and the system that exists to record who did what recorded none of them.

That is worse than a bypass of the effect. An unapproved export would have been
denied and the denial recorded. This produced authorised exports with no
decision row, no `AuditEvent.DECISION`, no `approval.redeemed_decision_id`, and
an approval that still reads as unused in the console — so the query an operator
would run to ask "what was this approval used for" returns nothing, and is
correct to.

`SECURITY.md` lists "redeeming an approval for a request it was not granted for,
**or more than once**" as in scope for a vulnerability report. This is the second
clause, reachable by a caller setting a documented option that the shipped Python
SDK exposes as a keyword argument on the same call that takes `approval_id`.

### Why the test suite said this was correct

`test_a_simulation_does_not_spend_it` asserted precisely this behaviour —
`effect == "allow"` and `redeemed_at is None` — under the docstring *"Exploring
what an approval would do must not consume it."* The intent is right and the
property is one worth having. What the test could not express is the difference
between exploring and doing, because at the point it was written there was
nothing to express it with: `/v1/simulate` marks a hypothetical by setting
`options.persist = False` on a copy of the request, and an ordinary caller marks
"do not write a row for this" the same way. One knob, two meanings, and the
security-relevant one is not the meaning the knob is named for.

So the test was not wrong about simulation. It was reaching the simulation
exemption through the door every caller can walk through.

## Decision

**A redemption may only occur on a decision that is being recorded.** Presented
with an approval on a request that has opted out of persistence, the plane
refuses to look the approval up at all and returns the un-redeemed answer —
`require_approval`, with `approval_error` saying why.

The refusal is deliberately not a 422. ADR 0018 reserves refusal for shapes where
there is no correct answer to give; here there is one, and it is the answer the
request would have had without the approval. Every SDK already treats a non-allow
as `DecisionDenied`, so the failure is closed and loud without a new HTTP path,
and the caller is told the two ways forward.

**It does not burn the approval.** The holder presented a valid capability
through a request shape the plane will not honour it on. That is a caller
mistake, not a spend, and making a person approve the same export twice because
their enforcement point sent the wrong option would be a worse system. Sending it
again on a recorded decision works, and then single use applies normally.

**Simulation gets its own signal, and it is not on the wire.** `decide()` takes
`simulating: bool = False`, a Python argument, and `/v1/simulate` is the only
caller that passes it. It cannot be set from a request body: it is not a field on
`DecideRequest`, not a field on `DecideOptions`, and `DecideOptions` is
`extra="forbid"`, so a body claiming it is a 422. A test asserts all three,
because the entire safety of the exemption is that the party presenting the
capability cannot claim it.

The scope boundary reinforces it. `/v1/simulate` requires `POLICY_READ`;
`/v1/decide` requires `DECIDE`. A caller who can only ask hypotheticals already
cannot obtain a `DecideResponse` an enforcement point would act on.

## Consequences

**One test changes and no caller does.** Every in-repo call site was checked by
reading what it actually sends. `pep/mcp_proxy`'s `_governed_listing` sends
`persist=False` and carries no `approval_id`; a listing is never
`require_approval`. The UI simulator posts to `/v1/simulate`, not to `/v1/decide`
— its comment says simulation must never pollute the record, and it was already
right. Neither reference PEP, neither SDK's own logic, nor the CLI combines the
two. `test_a_simulation_does_not_spend_it` now reaches the exemption through
`simulating=True`, which is what it always meant.

**The out-of-tree caller this was reachable from.** `AsyncControlPlaneClient.decide`
takes `persist: bool = True` and `approval_id: str | None = None` on the same
signature, and documents `persist=False` as "evaluates without writing a decision
record". A delegating enforcement point that keeps its own ledger and turns
persistence off — which is the documented reason to turn it off — would have had
a replayable approval and no way to know. It now receives `require_approval` with
a message naming the option to change.

**A refused attempt writes nothing, and that is consistent rather than
convenient.** The caller asked not to be recorded and nothing was permitted, so
there is no decision to account for — the same reasoning by which ADR 0015's
`?outcome=unreported` excludes denials. An operator who wants a record of
attempted redemptions gets one by leaving `persist` alone, which is the default.

**What this does not do.** It does not make `persist=False` safe in general; it
makes it unable to spend a capability. And it does not address the second half of
the pair: the durable record proves what happened and names the API key that did
it, not the person. That is a separate open item.

## Alternatives

**Move `_mark_redeemed` outside the `persist` block.** The one-line fix, and it
inverts the defect: the approval is spent while no record says what it was spent
on, so `redeemed_decision_id` is null and the console shows a capability consumed
by nothing. It also silently ignores `persist=False`, writing to the database on
a request that asked for no writes.

**Refuse `persist=False` with `approval_id` at the boundary, as ADR 0018 refuses
`scan_payload=False` with a payload.** The closest precedent, and the difference
is what a correct response would say. There, a refused shape produces no
obligation to report and no response to correct, so the boundary is the only
place to catch it. Here the un-redeemed decision *is* the correct answer, and
`approval_error` is the channel built for telling a caller why an approval did
not apply — already carrying "already redeemed", "expired", "granted for a
different request". A 422 would be a second mechanism for the same sentence, and
one that a validator on `DecideRequest` could not express anyway, since it cannot
see whether the caller is `/v1/simulate`.

**Add `simulating` to `DecideOptions`.** Then the holder of the approval sets it,
and this ADR describes a defect with an extra step.

**Let simulation refuse too, and drop the exemption.** Simplest, and it removes
the one thing a policy author most needs to explore — whether a pending approval
would actually unblock the request they are looking at. Simulation would report
`require_approval` for a decision that would allow, which is a wrong answer given
confidently.

## Reversibility

The guard is four lines in `decide()` and one argument threaded from one caller.
The cost of reversing is the same as the cost of the defect: nothing observable
changes for any correct caller, which is why it lasted.
