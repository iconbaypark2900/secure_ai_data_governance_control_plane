# 0017 — The control plane executes one obligation, so it declares one

**Status:** accepted
**Amends:** [0010](0010-declare-only-what-is-implemented.md)
**Amended by:** [0018](0018-an-obligation-is-discharged-per-decision.md)
**Correction (2026-08-30):** the measurement under "Two related gaps stay open"
was wrong. See the correction note in that section; the error is left in place
with the record of it, because an ADR is a record.

## Context

ADR 0010 wrote down the rule this system runs on: implement an obligation or
remove it, nothing in between. It also wrote down a count. Its first paragraph
says of the nine types then declared, *"Four were executed by the control
plane."*

One was. `redact` is the only obligation type the decision pipeline has ever
carried out. `_apply_redactions` in `control_plane/pdp.py` filters
`o.type == "redact"` and has never had a second branch; the function's own
docstring says "Execute redaction obligations against the payload" while the
name said obligations, plural and general. `annotate`, `log` and `ttl` were
declared `Executor.CONTROL_PLANE` and nothing anywhere read them. The count in
0010 was wrong on the day it was written, and the pass that removed `notify` for
having no implementation left three types beside it that had none either.

The reason it survived two removal passes is worth stating plainly, because it
is the whole argument for the test this ADR adds.

An obligation with no enforcement point behind it fails **loudly**. It lands in
`unsupported_obligations`, the SDK's `enforce()` finds a duty the caller has not
declared, and the allow becomes a refusal. Someone's traffic stops. That is the
failure 0010 was written about, and it is self-reporting.

An obligation with no control plane behind it fails **silently**, and by
construction. `pdp.py` excludes `SELF_EXECUTABLE` types from
`unsupported_obligations` — correctly, because a duty the plane has discharged is
not outstanding — so a control-plane obligation is the one kind that is reported
to nobody. The SDKs then encode the same claim from the other side:
`SATISFIED_BY_CONTROL_PLANE` names the types `enforce()` will not raise on. A
policy saying "allow, and log this at notice" produced an allow, no log line, no
warning, and an enforcement point told the duty was taken care of. The control
flowed through every layer of the system as satisfied and was never carried out
by anything.

What we measured before changing anything:

- **Three hand-maintained copies of the set**, and two sync links between them,
  both pointing away from executing code. `pdp.py:76` imports the server's set
  rather than restating it — 0010's own anti-drift measure, and it worked; the
  Python SDK restates it because it ships separately and cannot import the
  server; the TypeScript SDK restates it again, checked against a generated
  `contract.json`. Every link held. All three were consistent, and all three
  were wrong, because the chain was anchored to the schema and the schema was
  anchored to nothing.
- **One half of 0010's rule mechanised, the other left to prose.** The
  enforcement-point half has had a test since 0010:
  `KNOWN_OBLIGATIONS - CONTROL_PLANE_OBLIGATIONS == SATISFIABLE`, comparing the
  schema against what the reference proxy says it can do. The control-plane half
  had a sentence in a comment. That asymmetry is exactly the shape of what went
  wrong, and it is why `annotate` outlived `notify` by two releases.
- **Five shipped obligations making the claim.** `seed/policies.yaml` attached
  `log` to three grants and to the analysts' read-through, and `annotate` to the
  external-inference grant. The reference set is the thing people copy.
- **Three test suites pinning the false behaviour.** `test_obligations.py:33`
  asserted the four-name set; `test_sdk.py:512` asserted `discharged == ["log"]`
  on a refusal; `client.test.ts:111` asserted that a decision carrying
  `annotate` and `ttl` leaves nothing outstanding — the most explicit
  codification of the claim, written as a test of correct behaviour.
- **CI green throughout.**

## Decision

**`annotate`, `log` and `ttl` are removed.** `CONTROL_PLANE_OBLIGATIONS` becomes
`{"redact"}` — not by editing that set, which is derived and was doing its job,
but by deleting the three specs it derives from.

**The rule 0010 stated in one direction now runs in both, and both are tested.**
A `CONTROL_PLANE` entry must be a type the decision pipeline actually executes,
the way an `ENFORCEMENT_POINT` entry must appear in the reference proxy's
`SATISFIABLE`.

- `test_every_control_plane_obligation_visibly_executes`
  (`tests/integration/test_pdp.py`) drives a decision carrying each declared
  control-plane type through the real pipeline and asserts the response came
  back different from the same decision carrying no obligation at all.
  Behavioural, not a source scan: a test that greps `pdp.py` for a dispatch
  passes the first time the dispatch is refactored, and would have passed
  throughout the three releases this defect existed.
- `tests/unit/test_sdk.py` now asserts
  `SATISFIED_BY_CONTROL_PLANE == CONTROL_PLANE_OBLIGATIONS`. The test suite is
  the only place that imports both, which makes it the only place they can be
  held together. Downstream of it the chain was already mechanised — the
  contract fixture is generated from the SDK constant and CI fails on a stale
  one, and the TypeScript set is checked against the fixture — so this one
  assertion anchors server → Python SDK → contract → TypeScript to executing
  code, end to end, with no packaging change.
- `tests/integration/test_seed_policies.py` asserts that every obligation in the
  shipped set is one the control plane executes or the reference proxy declares
  satisfiable. Free, and it would have caught this.

**No enforcement point changes.** Neither PEP, neither SDK's logic, and no
behaviour in the PDP. The codebase's own encoded invariant already agreed these
three were surplus: `KNOWN_OBLIGATIONS - CONTROL_PLANE_OBLIGATIONS` was
`{limit, watermark, route, require_purpose}` before this change and is the same
set after, because 8 − 4 and 5 − 1 arrive at the same place.

## Alternatives

**Reassign them to `Executor.ENFORCEMENT_POINT`.** The tempting one: it keeps the
types, and turns a silent no-op into the loud failure 0010 preferred. One
measurement settles it. `pep/mcp_proxy/main.py` calls `cp.enforcing(...)` with no
`can_satisfy` argument at all — it has no set to widen — and the shipped set
attaches `log` to the agent read path, which is the path every governed tool call
takes. Under this option, every tool call through the MCP proxy denies, and the
enforcement-point invariant test goes red until both PEPs grow implementations of
three things nobody asked for. That is ADR 0010's own failure mode, re-created by
the fix for it.

It is also the same false claim relocated rather than retired. An enforcement
point cannot annotate a decision record it does not own. It cannot raise the
level of a log line the control plane writes. `ttl` as a `Cache-Control` header
is advice, and `model.py` says in the `Obligation` docstring that an obligation
is not advice — a duty an enforcement point may decline to honour without
denying is not an obligation, it is a suggestion with a schema.

**Implement them.** Each is a real feature and none is a few lines. `log` needs a
per-decision log channel with levels, sinks and a retention story — and note what
already exists without it: every decision writes a `DecisionRecord` carrying the
principal, effect, determining policy, matched policies, obligations,
classifications and payload digest, and seals an `AuditEvent.DECISION` against
the actor, whenever `options.persist` is set, which is the default. `ttl` needs a
storage adapter that can stamp an expiry and a sweeper that honours it. Shipping
a half version of either recreates exactly this problem.

**Implement `annotate`.** Nothing needs implementing, which is the tell.
`Obligation` is `extra="allow"`, so `note` already validates, already rides the
wire in the decision response, and already persists into the `obligations` JSON
column. `annotate` is policy metadata wearing an obligation's clothes; the field
it wants is `description`, which is stored, versioned and diffable. It cost
`enforce()` a hole in it for nothing.

## Consequences

**A stored policy using one of the three stops parsing, and it fails closed and
loud.** `policy/store.py` skips the unparseable row into `load_errors` and
`engine.py` replays those into every decision's reason, with `default_effect`
DENY. This is what 0010 accepted for `notify` and the reasoning has not changed —
a control silently absent is worse. But note the asymmetry it did not name: a
skipped *deny* policy is a gap, while a skipped *allow* policy denies traffic
that used to be permitted. `scripts/check_removed_obligations.py` ships with this
change to answer "which of my stored policies use a removed type" before an
upgrade rather than during one.

**Anyone who wanted policy-controlled logging gets nothing, and this is not a
neutral cleanup.** It forecloses `log` in the schema and reopens it as new work
with a real design behind it. That is cheaper to reverse than an implementation
nobody wanted, but it is a capability decision and not a tidy-up, which is why it
is here rather than in a commit message.

**The shipped set now reads as though auditing was removed.**
`allow-analysts-read-unredacted` is left carrying no obligations at all, and
three grants lose a line. Nothing about recording changed: the decision record
and the HMAC-sealed audit event are written by `_persist` on every decision, and
`log` never touched either. The policy's description now says what actually
records the read, because the previous wording — "every such read is recorded
against their name" — was true for a reason the reader had no way to know, and
sat directly above an obligation that was doing nothing.

**ADR 0006 gets a little quieter.** `extra="allow"` meant an `annotate` note was
carried into the durable `obligations` JSON column and read by nothing. Free-text
attached to a decision is where request content ends up eventually — the note is
written by a policy author today, but interpolation is one feature request away.
Removing the type closes that before it opens. Any future `annotate` must respect
the same boundary: policy-authored text only, never anything derived from the
payload.

**Deliberate friction, and the point of the exercise.** A new `CONTROL_PLANE`
type can no longer be prototyped in the schema ahead of an executor: the
behavioural test fails with no fixture to exercise it, and the SDK equality
assertion fails the moment the sets diverge. Adding one now means adding the code
that carries it out, in the same commit, which is the constraint 0010 imposed on
the enforcement-point half and never imposed here.

**Two related gaps stay open, named so they are not rediscovered as surprises.**
`unsupported_obligations` is a correction channel the control plane sends and
both SDKs discard — they parse the field and compute `outstanding()` from their
own set instead, so the server cannot tell a client it was wrong. And with
`apply_obligations=False` the server returns an empty obligation list while a
client still counts `redact` as applied. Neither is caused by this change;
neither is fixed by it.

> **Correction, 2026-08-30.** The second sentence misstates its own measurement,
> and in the direction that makes the hole sound smaller. The `obligations` list
> is built unconditionally at `pdp.py:280`; it is identical and non-empty at both
> settings. The field that emptied was **`unsupported_obligations`**, at
> `pdp.py:284` — `unsupported if request.options.apply_obligations else []`. The
> difference matters: an actually-empty obligation list would leave a client
> nothing to falsely discharge, whereas what really happened is that the
> obligations arrived, the correction saying nobody had executed them did not,
> and both SDKs then reported `redact` discharged. An ADR whose rule is to state
> what was measured got its one measurement of the residual hole wrong, which is
> the argument for re-running a measurement rather than restating it.
>
> The gap was also wider than "two". `redact` was reported discharged in **four**
> ordinary request shapes, not one: a request carrying **no payload**, one with
> **`apply_obligations=False`**, one with **`scan_payload=False`**, and one whose
> **`min_confidence`** filtered every finding. In the last two the response
> returned the payload with the email in cleartext. The tables in
> [0018](0018-an-obligation-is-discharged-per-decision.md) are the re-run
> measurement; the paragraph above is left as written, because a record that
> quietly acquires the right numbers afterwards is not a record.

## Reversibility

On the `route` precedent: removed for having no implementation, restored once
something honoured it, and the test is what kept the restoration honest. Each of
these three returns the same way. `ttl` is the most plausible, and most likely as
an *enforcement point* duty — a retention limit is something the holder of the
data does — once a storage adapter can stamp an expiry and something sweeps.
`log` returns when there is a log channel with levels and a sink. `annotate`
should not return; `description` is where it belongs.
