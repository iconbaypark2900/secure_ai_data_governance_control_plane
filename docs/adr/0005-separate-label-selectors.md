# 0005 — Keep catalog labels and payload findings separate

**Status:** accepted (after being got wrong once)

## Context

Two different facts about a request carry sensitivity labels:

- what the **catalog** says the store holds — `pg://clinical.*` is PHI
- what the **classifier** found in **this payload** — this prompt has an SSN in it

The first version merged them into a single `resource.classifications` selector,
on the reasoning that data in flight from a resource is that resource's data.

## The problem

The merge produced a policy that read correctly and behaved wrongly. This rule:

```yaml
- key: deny-unreviewed-agents-on-sensitive-stores
  match:
    all:
      - principal.trust_tier: {in: [untrusted]}
      - resource.classifications: {any_of: [phi, pci, pii.ssn]}
```

says "unreviewed agents may not touch the clinical schema". Under the merge it
*also* fired whenever anyone pasted an SSN into a prompt about a completely
unrelated table — because the payload finding had been folded into the store's
classification. The everyday grant became unreachable, and the reason was
invisible in the policy text.

## Decision

Three selectors:

| selector | means |
|---|---|
| `resource.classifications` | catalog labels for the store |
| `findings` | labels found in this payload |
| `classifications` | the union |

## Reasoning

They answer different questions and a policy almost always means exactly one.

"Unreviewed agents cannot touch the clinical schema" is a statement about a
store, and must not start firing on unrelated content. "Never transmit a
credential" is a statement about content, and must fire wherever it came from —
including a resource nobody registered. Only occasionally does a rule genuinely
mean "anything sensitive is involved", and that case gets its own selector rather
than being the accidental behaviour of the other two.

The general principle: a security control that reads plausibly and behaves
surprisingly is worse than one that is merely verbose. The extra selector is
cheap; the surprise is not.

## Consequences

Policy authors have to know which of the three they mean. The tables in
`docs/policy-language.md` and the schema at `GET /v1/policies/schema` exist to
make that a two-second lookup.

`tests/unit/test_policy_engine.py::TestLabelSelectors` pins the distinction, and
asserts on which policy *matched* rather than on the resulting effect — under
deny-by-default, "denied" and "no rule applied" look identical from outside, and
here the difference is the entire point.
