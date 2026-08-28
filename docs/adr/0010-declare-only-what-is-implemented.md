# 0010 — The schema declares only what something implements

**Status:** accepted

## Context

Nine obligation types were declared in `KNOWN_OBLIGATIONS` and advertised at
`GET /v1/policies/schema`. Four were executed by the control plane. Five were
not executed by anything: `limit`, `watermark`, `require_purpose`, `notify`,
`route`.

The failure mode is quiet and unpleasant. A policy author reads the schema, sees
`notify` listed, writes `{"type": "notify", "channel": "ops"}`, and the policy
validates. At decision time the obligation lands in `unsupported_obligations`,
the enforcement point calls `enforce()`, finds a duty it cannot discharge, and
denies. The author has written a well-formed policy that breaks their own
traffic, and every signpost told them it was supported.

This is the same shape as two defects already fixed in this codebase: the
`tokenize` strategy that silently produced a hash, and the adapters that could
discover but were never called. Something was declared, accepted, and not
delivered.

## Decision

**Implement or remove. Nothing in between.**

- `limit`, `watermark`, `require_purpose` are now implemented in the reference
  enforcement point (`pep/reverse_proxy/obligations.py`). All three act on the
  transport rather than the data, which is why they belong there.
- `notify` and `route` are **removed**. They need infrastructure this system does
  not have — a channel integration, a routing layer — and keeping them was a
  promise in the schema that nothing behind it kept.
- Unknown obligation types are **rejected at authoring time** rather than
  accepted and ignored at decision time. A policy attaching a duty nothing
  understands has not been written safely, and the author is the only person
  positioned to fix it.
- The set the control plane executes is **derived** from the same table the
  schema is generated from, not restated in the decision pipeline. Two copies
  would eventually disagree, and the direction they would disagree in is a duty
  silently going unenforced.

The same pass removed `CP_DECISION_CACHE_MAX_ENTRIES` (a setting nothing read),
renamed `CP_DECISION_CACHE_TTL_SECONDS` to `CP_POLICY_CACHE_TTL_SECONDS` (it
governs the policy engine cache, not a decision cache that does not exist), wired
`CP_MAX_SCAN_CHARS` into the scanner the decision pipeline actually builds, and
gave `prometheus-client` — a dependency with zero uses — a `/metrics` endpoint.

## Consequences

**Removing an obligation type is a breaking change, and it breaks loudly.** A
stored policy using `notify` now fails to parse, and a policy that fails to parse
is reported on every decision the engine makes. That is the intended behaviour:
the alternative is a control silently absent.

**`require_purpose` duplicates what a `context.purpose` match condition can
express.** Kept deliberately: the obligation re-checks at the point of use, so
the proxy stops trusting the purpose it declared a moment earlier. Thin, but it
is defence in depth rather than redundancy.

**An enforcement-point refusal is invisible to the control plane's record.** This
surfaced on the first live run and is a property of the split, not of these three
obligations: the control plane decided `allow` subject to duties, the proxy could
not discharge one, and the proxy refused. The decision record — and the metric —
say `allow`, because that is what the control plane decided. An auditor
reconciling "what was permitted" against "what actually happened" needs both
sides, and today only one of them is centrally recorded.

For `require_purpose` specifically the asymmetry is avoidable: the purpose is in
`context`, so a `context.purpose` match condition puts the same check on the
decision side where it *is* recorded. Prefer the match condition; reach for the
obligation when you want both. Closing the gap properly means the enforcement
point reporting discharge outcomes back, which is a feature this does not have.

**The reference enforcement point is now the reference for more than shape.**
`SATISFIABLE` in the proxy and the enforcement-point half of `OBLIGATION_SPECS`
must agree, and a test asserts it. Adding an obligation type now means adding an
implementation, which is the constraint this ADR exists to impose.

## Alternatives

**Keep them, documented as advisory.** An obligation that is advisory is not an
obligation — the whole model rests on an enforcement point treating one it cannot
discharge as a deny. Making some advisory would mean an enforcement point had to
know which, and that table would be the thing that drifts.

**Keep them and have the reference proxy declare it can satisfy them, doing
nothing.** Strictly worse: it converts a loud denial into a silent no-op, which
is the failure this codebase has now fixed three times.

**Implement `notify` and `route` too.** `notify` needs a channel integration with
its own credentials, retries, and failure semantics; `route` needs a routing
layer that knows about alternative models. Both are real features, neither is a
few lines, and shipping a half version of either would recreate the problem.
