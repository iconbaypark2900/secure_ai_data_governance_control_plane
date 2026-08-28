# 0002 — Build the policy engine rather than embed OPA or Cedar

**Status:** accepted

## Context

The system needs attribute-based policy evaluation with obligations and an
explanation. Open Policy Agent (Rego) and Cedar are the obvious off-the-shelf
answers, and both are more capable than what is built here.

## Decision

A native engine: a small declarative match tree, 21 total operators, three
effects, and a combining algorithm.

## Alternatives

**OPA / Rego.** Mature, expressive, well understood. Rejected on three counts.
It is either a sidecar process — an extra deployment and an extra failure mode on
the request path — or a WASM bundle with its own build step. Rego is a language
contributors would have to learn before they could review a policy change, and
policy changes are exactly the ones that need review. And its explanation output
describes Rego evaluation, not "this policy did not apply because
`context.destination` was `internal`" — which is the sentence an auditor needs.

**Cedar.** Cleaner language, formal semantics, genuinely good. Rejected mainly
for ecosystem: the Python binding is thinner than the Rust original, and Cedar's
model is built around principal/action/resource authorisation rather than
obligations, so the redaction duties — the thing that makes "yes, but" possible —
would have to be bolted on outside it anyway.

## Consequences

**Gained.** No extra process or build step. Policies are JSON that Pydantic
validates at authoring time, so a typo in a label is a 422 when you write the
rule rather than a silent no-op at 3am. The trace is written in terms of the
policy the author wrote. The engine is a pure function — no I/O, no clock — so a
decision replays identically months later.

**Given up.** No formal verification. No policy composition beyond
`all`/`any`/`not`. No user-defined functions or datalog-style derivation. If a
policy set outgrows this, migration is a real project.

The bet is that governance policy is mostly a few dozen rules matching on
attributes and labels, and that being reviewable by whoever is on call matters
more than being expressive. That bet is wrong for some organisations.
