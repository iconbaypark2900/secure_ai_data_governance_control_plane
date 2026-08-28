# The policy language

A policy is data. It is authored as YAML, stored as JSON, versioned in the
database, and reviewable in a pull request — which is what makes "who changed the
rule that let this through, and why?" an answerable question.

```yaml
- key: deny-phi-to-external-models
  name: PHI stays inside
  description: >
    Health data must not reach a model operated by a third party. HIPAA permits
    disclosure to a business associate under an agreement; it does not permit it
    as a side effect of a prompt.
  effect: deny
  priority: 950
  tags: [hipaa, phi]
  match:
    all:
      - resource.classifications: {any_of: [phi]}
      - context.destination: external
```

Validate before deploying — this is what belongs in CI on a policy change:

```bash
cpctl policy validate seed/policies.yaml
cpctl policy sync seed/policies.yaml
```

The running service serves the authoritative reference at
`GET /v1/policies/schema`. It is generated from the code, so it cannot drift away
from what the engine actually accepts.

---

## Fields

| field | required | meaning |
|---|---|---|
| `key` | yes | stable identifier, `^[a-z0-9][a-z0-9._-]*$`. Appears in decisions and audit records; renaming one breaks the trail. |
| `name` | yes | what a human calls it. Shows up in the decision's `reason`. |
| `description` | | why it exists. Worth writing — it is what the next person reads before deciding whether to relax it. |
| `effect` | yes | `allow`, `deny`, or `require_approval`. |
| `priority` | | 0–10000, default 100. Higher is stronger. |
| `enabled` | | default true. Toggling is a versioned change; disabling a control is exactly what an auditor comes looking for. |
| `match` | | the condition tree. Omitted or empty matches everything — a blanket rule, which is a legitimate thing to author deliberately. |
| `obligations` | | duties attached to an allow. A deny cannot carry them: there is no permitted action left to constrain. |
| `tags` | | free-form, for filtering. |

---

## Matching

### Selectors

A selector is a dotted path into the request.

| root | resolves to |
|---|---|
| `principal.id` / `.type` / `.attributes.*` | who is asking. Catalog attributes are also reachable directly: `principal.trust_tier` and `principal.attributes.trust_tier` are the same thing. |
| `action` | what they want to do — `read`, `embed`, `infer`, `export`, `return`, or anything your enforcement points use. |
| `resource.urn` / `.kind` / `.attributes.*` | what they want to touch. |
| `resource.classifications` | labels the **catalog** holds for that store. |
| `findings` | labels found in **this payload**. |
| `classifications` | the union of the two. |
| `context.*` | circumstances — `destination`, `purpose`, network zone, model name, ticket reference. Whatever the enforcement point supplies. |

**The three label selectors are the part worth reading twice.** They answer
different questions, and a policy almost always means exactly one:

```yaml
# About the STORE. Must not start firing because someone pasted an SSN into an
# unrelated prompt.
- resource.classifications: {any_of: [phi]}

# About the CONTENT. Must fire wherever it came from, including a resource
# nobody registered.
- findings: {any_of: [secret]}

# Either.
- classifications: {any_of: [pii.ssn]}
```

Collapsing them into one selector makes policies read plausibly and behave
surprisingly, which is the worst property a security control can have.

### Conditions

A condition maps operators to operands. Scalars and lists are sugar for the two
common cases:

```yaml
action: read                      # {eq: read}
action: [read, embed]             # {in: [read, embed]}
action: {in: [read, embed]}       # explicit
```

### Operators

| operator | on | notes |
|---|---|---|
| `eq` / `neq` | anything | |
| `in` / `not_in` | scalar or list | prefix-aware on dotted keys — see below |
| `any_of` | list | intersects |
| `all_of` | list | every operand element must be covered |
| `none_of` | list | disjoint |
| `glob` / `not_glob` | string | `qdrant://*` |
| `regex` | string | capped at 512 characters |
| `contains` | string | substring |
| `startswith` / `endswith` | string | |
| `gt` / `gte` / `lt` / `lte` | number | |
| `count_gte` / `count_lte` | list | size |
| `exists` | anything | boolean operand |
| `empty` | list | boolean operand |

**Prefix-aware matching.** Set operators treat a dotted operand as covering its
descendants, so `{any_of: [pii]}` matches `pii.email` without enumerating the
family. Values without dots — action names, principal types, identifiers — reduce
to plain equality, so the behaviour is only ever visible where a hierarchy
exists.

A selector that resolves to nothing does not match. There is no implicit
truthiness: use `{exists: false}` to mean "absent".

### Combinators

Conditions at the same level are ANDed. `all`, `any`, and `not` nest:

```yaml
match:
  all:
    - principal.type: agent
    - any:
        - resource.urn: {glob: "qdrant://*"}
        - resource.urn: {glob: "pg://public.*"}
    - not:
        context.purpose: break_glass
```

A node may not mix combinators with selectors — wrap the selectors in an explicit
`all`. The parser refuses rather than guessing, and it names the path in the
document where it gave up.

---

## Effects and combining

| effect | means |
|---|---|
| `allow` | permitted, subject to the obligations |
| `deny` | refused; the enforcement point receives no payload |
| `require_approval` | parked for a human, with a 24-hour window |

`require_approval` exists so a rule can express "not without a person" rather
than being forced to choose between blocking legitimate work and waving through
risky work. Bulk export of a customer table is the canonical case: legitimate,
occasionally necessary, and also exactly what exfiltration looks like.

### The approval loop

```
  POST /v1/decide                    -> require_approval + approval.id
  GET  /v1/approvals/{id}            -> poll; cheap, evaluates nothing
  POST /v1/approvals/{id}/decide     -> a human grants or denies it
  POST /v1/decide  + approval_id     -> allow, and the approval is spent
```

Redeeming means re-sending **the same request** with `approval_id` set. From the
SDK:

```python
decision = await client.decide(principal_id=..., action="export", resource_urn=...)
if decision.needs_approval:
    await client.await_approval(decision.approval_id, timeout=600)
    decision = await client.decide(..., approval_id=decision.approval_id)
rows = decision.enforce()
```

A granted approval is a capability, and it is scoped like one:

| | |
|---|---|
| **Bound to the request** | A keyed fingerprint over principal, action, resource, labels, payload, and context. Change any of them — a different table, an external destination, a different payload — and it will not redeem. |
| **Single use** | Spending it records the decision it was spent on. A second attempt is refused. |
| **Expiring** | Checked at redemption, not only at grant. |
| **Subordinate to deny** | Redemption re-evaluates policy and only turns `require_approval` into `allow`. A deny that now applies still denies, and the approval is *not* consumed, so it still works if the deny is lifted. |

Redeeming also re-collects obligations across both the `allow` and
`require_approval` policies that matched. An `allow` policy that lost to the
parking rule still said "if you permit this, redact the SSNs", and an approval
must not be a way to shed that.

`approval_error` on the response says why a presented approval did not apply. It
is written to be actionable: "still awaiting a decision" means keep polling,
"granted for a different request" and "already redeemed" mean stop.

Re-sending a parked request returns the ticket it already has rather than
queueing another, so a retrying caller cannot flood the reviewer.

### Combining algorithms

| algorithm | resolution |
|---|---|
| `deny_overrides` **(default)** | any matching deny wins, whatever its priority |
| `priority_ordered` | highest-priority match wins outright; ties break toward the safest effect |
| `permit_overrides` | any matching allow wins — observation rollouts only |

Under the default, a prohibition cannot be outvoted by a permission someone added
later. `priority_ordered` is the one to reach for when you need a deliberate
break-glass exception:

```yaml
- key: break-glass-incident-response
  effect: allow
  priority: 1000
  match:
    all:
      - principal.attributes.on_call: true
      - context.purpose: break_glass
      - context.incident_id: {exists: true}
```

When nothing matches, `CP_DEFAULT_EFFECT` applies. It ships as `deny`.

---

## Obligations

An obligation is a duty attached to an allow. It is not advice: an enforcement
point that cannot carry one out must treat the decision as a deny — otherwise
"allow, but redact the SSNs" silently degrades into "allow". The SDK's
`enforce()` implements exactly that.

Obligations from every matching policy of the winning effect are unioned. They
only add constraints, so combining them can make a decision stricter and never
looser.

### `redact`

```yaml
obligations:
  - type: redact
    labels: [pii.ssn, pii.passport]
    strategy: mask
  - type: redact
    labels: [pii.email, pii.phone]
    strategy: hash
```

| strategy | output | preserves | reach for it when |
|---|---|---|---|
| `mask` | `[REDACTED:pii.ssn]` | that something was there | the default |
| `partial` | `**** **** **** 1111` | a recognisable suffix (`keep_last`) | a human must recognise their own record |
| `hash` | `<pii.email:908fde31…>` | joinability, keyed and irreversible | analytics, conversation continuity |
| `tokenize` | `tok_AadFpWU54K…` | reversibility, keyed and joinable | investigations that must re-identify |
| `synthetic` | `user402183@example.invalid` | the shape | test and eval data, so parsers still work |
| `drop` | *(nothing)* | nothing | presence itself is the leak |

Rules are tried in order and the first match wins, so put the specific one first:

```yaml
- {type: redact, labels: [pii.email], strategy: hash}   # this one
- {type: redact, labels: [pii],       strategy: mask}   # then everything else
```

`labels: ["*"]` covers everything. Labels are validated at authoring time against
the taxonomy — a typo is a 422 when you write the policy, not a silent no-op at
3am.

`tokenize` needs `CP_TOKENIZATION_KEY`. Without it the decision **denies** —
it does not fall back to `hash`, because a policy that asked for something
reversible and received something that is not has been silently downgraded.
Reverse a token through `POST /v1/detokenize`, which needs the `detokenize`
scope and records every call. There is no vault behind it: the token is the
ciphertext, so see [ADR 0009](adr/0009-tokenisation-without-a-vault.md) for what
that buys and what it costs.

### Other types

| type | fields | who executes it |
|---|---|---|
| `redact` | `labels`, `strategy`, `keep_last`, `hash_length` | control plane |
| `annotate` | `note` | control plane |
| `log` | `level` | control plane |
| `ttl` | `seconds` | control plane |
| `limit` | one of `max_rows`, `max_bytes`, `max_tokens`, `max_results` | enforcement point |
| `watermark` | `text` | enforcement point |
| `require_purpose` | `purposes` | enforcement point |
| `route` | `to` and/or `require` | enforcement point |

That is the whole list, and an unknown type is a **422 when you write the
policy** rather than a surprise at decision time. `notify` and `route` were both
removed at one point because nothing implemented them — writing one produced a
well-formed policy that denied your own traffic. `route` came back only once
something honoured it; `notify` has not. See
[ADR 0010](adr/0010-declare-only-what-is-implemented.md).

### `route`

Where a permitted request may be processed. Constrain by attribute, or name a
logical target, or both:

```yaml
obligations:
  - {type: route, require: {region: eu, hosting: [on_prem, vpc]}}
  - {type: route, to: eu-only-llm}
```

The control plane resolves this against models registered in the catalog —
ordinary assets with `kind: model` whose attributes say where they run — and
returns the chosen URN in the obligation's `resolved` field.

Prefer `require` over `to`: adding a qualifying model later then needs no policy
change, and losing the last one **denies** rather than silently falling back to
the model the policy steered away from. Requirements from several policies
intersect, so two rules each narrowing where data may go both hold.

Scope routing rules to model calls (`action: {in: [infer, embed, return]}`).
A routing rule that forgets to quietly intercepts every ordinary read of the same
data — which the first draft of the shipped policy did, and a test now prevents.

Anything in the second group appears in the response's
`unsupported_obligations`. The enforcement point must satisfy it or deny —
`enforce(can_satisfy=["watermark"])` is how it declares that it can, and the
reference proxy in `pep/reverse_proxy/` implements all three:

```yaml
obligations:
  - {type: limit, max_tokens: 500, max_bytes: 8192}   # caps the request and the reply
  - {type: watermark, text: INTERNAL USE ONLY}        # marks what is delivered
  - {type: require_purpose, purposes: [support]}      # re-checked at the point of use
```

`require_purpose` deliberately duplicates what a `context.purpose` match
condition can express. The condition is checked where the decision is made; the
obligation is checked where the data is used, by a proxy that stops trusting the
purpose it declared a moment earlier.

One asymmetry to know about: when an enforcement point refuses because it cannot
discharge an obligation, the control plane's decision record still says `allow` —
that is what it decided, and the refusal happened elsewhere. So prefer the match
condition when you want the check to appear in the audit trail, and add the
obligation when you want it enforced in both places.

---

## Testing a policy before deploying it

```bash
curl -X POST localhost:8000/v1/simulate -d '{
  "request": {
    "principal": {"id": "agent:support_bot", "type": "agent"},
    "action": "read",
    "resource": {"urn": "qdrant://kb_docs"},
    "payload": "jane.doe@acme.com"
  },
  "additional_policies": [ …the change you are proposing… ]
}'
```

The response carries both the simulated decision and the `baseline` the stored
policy set would have produced, plus `changed`. Nothing is persisted by either
run. The **Simulator** tab in the console is the same thing with the trace
rendered.

---

## Writing a policy set worth having

**Order it as a statement of posture.** Highest priorities are the things that
must never happen; lowest are the ordinary permissions that make the system
usable. Someone should be able to read it top to bottom and understand what you
are protecting.

**Prohibitions get no exception path.** `deny-credentials-anywhere` is priority
1000 and matches on `findings` alone. There is no legitimate workflow in which a
model needs to receive a live credential.

**Make the everyday grant genuinely usable.** A control people route around is
worse than no control. Redaction is what lets you say yes: the support agent
reads the ticket, and never learns the SSN.

**Choose the redaction strategy for the job.** `hash` over `mask` for contact
details keeps one customer distinguishable from another across a conversation,
which is often the difference between a working assistant and a broken one.

**Write the description.** It is what the next person reads before deciding
whether to relax the rule, and by then you will not be in the room.

The shipped set in [`seed/policies.yaml`](../seed/policies.yaml) is a worked
example, and `tests/integration/test_seed_policies.py` tests it against its own
descriptions.
