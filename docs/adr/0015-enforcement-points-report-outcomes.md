# 0015 — Enforcement points report what they actually did

**Status:** accepted

## Context

Every record in this system said what was *decided*. None said what *happened*.

The reference proxy has four paths on which it refuses a request the control
plane permitted: an obligation it cannot discharge, a purpose it rejects, a
routed backend it has no configuration for, and a credential found mid-stream.
On all four, the decision record read `allow` behind an action that never took
place. An auditor reconciling *what was permitted* against *what occurred* had
one side of the ledger, and the README's headline claim — "proves it afterwards"
— proved only half of what it sounded like.

It had been flagged twice, in [ADR 0010](0010-declare-only-what-is-implemented.md)
and again after the routing work, without being fixed.

## Decision

`POST /v1/decisions/{id}/outcome`, reporting `enforced`, `refused`, or `partial`,
with the obligations discharged and, for anything short of enforced, a reason.
Sealed into the audit chain as `decision.outcome`, joined to the decision,
filterable, and aggregated as `permitted_but_not_enforced`.

Four things about the shape are load-bearing:

**`partial` exists.** Without it, a point that carried out three obligations and
skipped the fourth must report either "enforced", which is false, or "refused",
which is also false — and the useful signal, that a duty is going undischarged in
production, disappears into whichever it picked.

**Unreported is a state, not a default.** The column is nullable and null is
surfaced as `unreported` rather than assumed to be fine. An enforcement point
that quietly stops reporting is one that quietly stopped being observed, and the
safe reading of silence is that nothing is known.

**Write once.** An identical repeat is idempotent, so a retrying caller is not
punished. A *conflicting* report is refused and sealed as
`decision.outcome_conflict` — an attempt to restate what already happened is
exactly what a tamper-evident log exists to surface.

**Reporting never fails the caller.** By the time it runs, the action has been
taken or refused; failing the request over a bookkeeping round trip would turn a
reporting problem into an outage. A report that does not arrive shows up as
unreported, which is the detection path.

## Two bugs found by running it

**Reporting too early.** The first SDK shape reported `enforced` the moment the
obligations checked out. In the proxy, several steps follow — backend selection,
the upstream call — and a live test showed a request that was refused recorded as
`enforced`. That is precisely the failure this feature exists to prevent,
reintroduced by my own ordering.

The fix is a context manager, `client.enforcing(decision)`, which reports on exit:
enforced if the block completed, refused if it raised. Correct by construction
rather than by remembering. `client.enforce()` remains for callers where acting
*is* the last step, with the caveat in its docstring. Streaming reports from
inside the generator, because a streamed answer is finished when the last frame
goes out, not when the handler returns.

**A decision id that did not exist yet.** Reporting immediately after deciding
returned 404 about one attempt in eight. FastAPI's `yield` dependency teardown —
where the session commits — can run *after* the response has been sent, so a
caller could receive an id for a row that was not yet durable. The decide
endpoint now commits before answering.

That one is worth noting beyond this feature: it affected any caller using a
returned identifier immediately, including approval redemption. It had been
latent since the first commit and was invisible to the test suite, because the
in-process harness commits inside the request.

## Consequences

**Enforcement points must be updated to report**, or every decision they handle
shows as unreported. That is the intended failure mode: visible, not silent.

**"Permitted, then refused downstream" is now a query.** `?outcome=refused`,
`?outcome=unreported`, and `permitted_but_not_enforced` in the stats.

**The audit record carries both halves** — `permitted` alongside `outcome` — so
noticing a contradiction does not require joining two tables.

**A malicious enforcement point can still lie.** It can report `enforced` for
something it never did. Nothing here prevents that, and nothing could: the
control plane cannot observe the data path it is not on. What this changes is
that silence and refusal stop being indistinguishable from success, which is the
failure that actually happens.
