# 0013 — Routing is a policy outcome, and models are catalog assets

**Status:** accepted

## Context

The engine could decide that data must not reach a given model. It had nowhere to
put the useful half of that judgement — *which model it should reach instead*.
The `route` obligation had been removed in
[ADR 0010](0010-declare-only-what-is-implemented.md) precisely because nothing
implemented it, which was right at the time and left the control plane able only
to refuse.

That is a worse position than it sounds. The argument this codebase already makes
for redaction — that a control people route around is worse than no control, so
"yes, but" beats "no" — applies just as directly to infrastructure. Refusing
every request that names the wrong model teaches people to call the model
directly.

The specification names Model & Tool Routing as a core service (§5.3) and step 6
of its headline workflow (§6.1). It was the largest capability entirely absent.

## Decision

**Routing is an obligation, resolved by the control plane.**

```yaml
obligations:
  - type: route
    require: {region: eu}
```

**Models are ordinary catalog assets** under a `model://` URN with `kind: model`,
their attributes describing where they run:

```yaml
urn: model://internal/llama-3-70b
kind: model
attributes: {region: eu, hosting: on_prem, aliases: [eu-only-llm], routing_priority: 10}
```

That reuses labelling, ownership, discovery, and audit rather than adding a
second registry to drift from the first.

**The control plane picks; the enforcement point reaches.** Which model saw the
data is a governance fact and belongs in the decision record — it is the first
question asked after an incident. The endpoint and credential for that model are
deployment configuration, and the control plane has no business holding them. So
the decision carries a resolved URN, and the proxy maps it through
`PEP_MODEL_BACKENDS`.

**Constrain by attribute, not by name.** `require: {region: eu}` beats
`to: eu-only-llm` for the common case: adding an EU model later needs no policy
change, and losing the last one is a denial rather than a silent fallback. Naming
a target is still supported for when the answer really is one specific model.

**An unsatisfiable route is a denial.** If a policy says the request may go only
somewhere that does not exist, there is no permitted way to proceed. Falling back
to the model the caller asked for would invert the policy exactly.

**Requirements from several policies intersect.** Two policies each narrowing
where data may go must both hold. Disjoint requirements satisfy nothing, which
denies — rather than silently preferring one policy's answer over the other's.

## Consequences

**Residency stopped needing any plumbing.** Before building this I assumed
jurisdiction would be structural and expensive to retrofit. It is not: asset
attributes are free-form JSONB and every selector is attribute-addressable, so an
EU-residency policy was already expressible in three lines with no code change.
What was missing was somewhere to put the *answer*, not somewhere to put the
question. Worth recording because the instinct was wrong and the check was cheap.

**The reference policy set gained a bug, and the tests caught it.** The first
draft of `route-regulated-data-to-eu-models` matched on classifications alone, so
it intercepted an analyst's ordinary database read and attached a routing
obligation to it. Routing a table read to a model is meaningless. The policy is
now scoped to `action: [infer, embed, return]`, and
`test_an_ordinary_read_of_the_same_data_is_not_routed` holds it there. This is
the second time the seed-policy suite has caught a shipped policy behaving
differently from how it reads.

**A model with no declared attributes never qualifies.** Silence about where a
model runs is not a claim that it runs anywhere acceptable.

**A backend the proxy has no configuration for is a refusal**, not a fallback to
the default — falling back would send the data to exactly the model the policy
steered it away from.

**Tool routing is not built.** The spec pairs model and tool routing; this covers
models. The MCP adapter already maps a tool to a `mcp://` URN, so the same
obligation could resolve against tool assets, and nothing here forecloses it.
That is not a claim that it works today.
