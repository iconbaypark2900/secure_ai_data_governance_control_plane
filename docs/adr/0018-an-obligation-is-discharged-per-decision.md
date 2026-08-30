# 0018 — A control-plane obligation is discharged per decision, not per type

**Status:** accepted
**Amends:** [0010](0010-declare-only-what-is-implemented.md), [0017](0017-the-control-plane-executes-one-obligation.md)

## Context

0017 established half a rule and stopped: *a `CONTROL_PLANE` entry must be a type
the decision pipeline actually executes.* It removed three types that failed it
and added `test_every_control_plane_obligation_visibly_executes` to keep the
remaining one honest.

That test asks whether the plane executes `redact` **ever**. It exercises one
request shape — payload present, scanning on, obligations applied — and passes.
The response, meanwhile, was not reporting whether the plane executed `redact`
**here**, on this decision, and the answer was often no.

### What was measured

Both tables are from the real `seed/policies.yaml` and `seed/catalog.yaml` loaded
through `PolicyStore`/`CatalogService`, exactly as
`tests/integration/test_seed_policies.py` loads them. Principal
`agent:support_bot`, action `read`, resource `qdrant://kb_support_docs`;
`allow-agents-read-redacted` determines every row.

**The obligation reported discharged in five shapes and executed in one.**

| request shape | effect | obligations | unsupported | redactions | email in cleartext |
|---|---|---|---|---|---|
| defaults | allow | `[redact]` | `[]` | 1 | no |
| clean payload | allow | `[redact]` | `[]` | 0 | n/a |
| **no payload** | allow | `[redact]` | `[]` | 0 | n/a |
| **`scan_payload=False`** | allow | `[redact]` | `[]` | 0 | **yes** |
| **`apply_obligations=False`** | allow | `[redact]` | `[]` | 0 | no (payload withheld) |
| **`min_confidence=1.0`** | allow | `[redact]` | `[]` | 0 | **yes** |

`_apply_redactions` returns `None` when the payload is `None`, when no `redact`
obligation is attached, or when there are no findings; and it is only reached at
all when `apply_obligations` is true. The scan is skipped entirely at
`pdp.py:245-246`. So in the four bolded shapes nothing redacted anything, and the
response said `obligations=[redact], unsupported_obligations=[]` — a duty
reported to nobody. Both SDKs then held `SATISFIED_BY_CONTROL_PLANE = {"redact"}`
as a **static** set consulted with no reference to the request, so `outstanding()`
returned `[]`, `enforce()` handed back the unredacted string, and
`client.enforce()` wrote `outcome=enforced, discharged=["redact"]` into the
durable record for a redaction the plane had declined to perform.

**The same caller-supplied knobs flipped deny to allow.** This is the larger
half, and it is not a reporting defect at all:

| payload | resource | options | effect | determining policy |
|---|---|---|---|---|
| AWS key | `qdrant://kb_support_docs` | defaults | **deny** | `deny-credentials-anywhere` |
| AWS key | `qdrant://kb_support_docs` | `scan_payload=False` | allow | `allow-agents-read-redacted` |
| AWS key | `qdrant://kb_support_docs` | `min_confidence=1.0` | allow | `allow-agents-read-redacted` |
| AWS key | `s3://public-datasets/reports` | defaults | **deny** | `deny-credentials-anywhere` |
| AWS key | `s3://public-datasets/reports` | `scan_payload=False` | allow | `allow-public-data-freely` also matched |

`deny-credentials-anywhere` sits at priority 1000 and its own description says
*"this is the one rule with no exception path."* A boolean in the request body of
the governed party was the exception path. `allow-public-data-freely` carries
`findings: {empty: true}` with the comment *"this second condition covers the case
where something sensitive ends up in it anyway"* — nullified by the same boolean,
because to a `findings` selector "not scanned" and "nothing found" are one value.

And `unsupported_obligations` was blanked wholesale on an authorisation-only
decision: with a `watermark` and a `require_purpose` obligation attached, the
field read `['require_purpose', 'watermark']` at `apply_obligations=True` and
`[]` at `False`, same policy, same principal. Both reference SDKs were insulated
only because they ignored the field, which is exactly why nothing in a
682-test suite could see it: `grep -rn apply_obligations tests/` returned one
line, asserting a default.

## Decision

**A response must say whether *this decision* discharged the duty**, and the
plane must refuse a request whose shape suppresses the evidence it would judge
on.

1. **`unsupported_obligations` is populated unconditionally.** It is a correction
   channel, and a channel that goes quiet under some request shapes is worse than
   none. Its sibling `route` was already set unconditionally, and the schema
   promised this one the same way.

2. **`SELF_EXECUTABLE` is gated per decision.** The set stays static; its *use*
   is conditioned on `effect is ALLOW and apply_obligations and scan_payload and
   payload is not None` — the exact conjunction under which `_apply_redactions`
   runs. Outside it, `redact` is reported outstanding.

   The predicate keys on **the pass having run**, never on `redactions` being
   non-empty. A clean payload and a payload whose findings no rule covers both
   produce zero redactions and are both executions; keying on the result would
   refuse every clean prompt through `pep/reverse_proxy` and every clean MCP tool
   call. That is 0017's own trap in new clothing — its first draft was redirected
   by precisely this measurement.

3. **Both SDKs subtract, in one line each.**
   `SATISFIED_BY_CONTROL_PLANE - set(unsupported_obligations)`. The constant is
   unchanged in both, so the chain that keeps three copies of it agreeing
   (`test_sdk.py` → `generate_sdk_contract.py` → `contract.json` →
   `contract.test.ts` → CI) is untouched. Subtraction only: the server can shrink
   what a client treats as satisfied, never grow it.

4. **The request that suppresses evidence is refused at the boundary.** A
   `model_validator` on `DecideRequest` rejects `payload is not None` with
   `scan_payload=False`, and with `min_confidence` above
   `CP_MAX_REQUEST_MIN_CONFIDENCE` (default `0.5`, identical to the schema
   default, so no request that worked before changes). "Here is the data, do not
   look at it, now tell me whether it is safe" is a contradiction that needs no
   knowledge of the policy set to refuse — and unlike everything above it, it
   produces no obligation to report and no response to correct, so the boundary
   is the only place it can be caught. A caller may still make the plane *more*
   sensitive; it may not make it less. Sending payload bytes the plane is
   forbidden to read is also a liability under [0006](0006-no-payload-persistence.md).

   Precedent: `caller.may_act_for(request.principal.id)` distrusts identity in
   the request body three lines into the same handler. Identity was checked.
   Evidentiary parameters were not.

5. **The durable record cannot be made to lie by a client.** `DecisionRecord`
   now stores `unsupported_obligations` (migration `0006`), and the outcome
   endpoint checks a report's `discharged` against it — scoped to
   `CONTROL_PLANE_OBLIGATIONS`. It records the outcome as `partial`, moves the
   contradicted types to `undischarged`, seals a
   `decision.outcome_contradicted` event, and returns 200. Not a 4xx: an outcome
   refused outright is an outcome unreported, which is the gap `outcome IS NULL`
   exists to surface.

6. **`residual_labels` reports what the obligations did not reach.** Findings no
   redaction rule covered, by label name only. It is deliberately *not* an
   unsupported obligation — an enforcement point cannot be handed a duty no
   policy assigned it.

## Consequences

**The rule, stated so it does not have to be rediscovered.** 0010 says implement
an obligation or remove it. 0017 says a `CONTROL_PLANE` entry must be a type the
pipeline executes. 0018 adds: **and every response must say whether this decision
executed it.** A capability is not a receipt.

**`require_approval` decisions carrying a `redact` obligation now report it
unsupported.** Truthful and inert: both SDKs raise `DecisionDenied` on a non-allow
before `outstanding()` is consulted.

**One in-repo call site changes behaviour and none breaks.** Every enforcement
point was checked by replicating its exact call.
`pep/mcp_proxy`'s `_governed_listing` sends `apply_obligations=False` with no
payload and now receives `unsupported=["redact"]` — it reads `decision.allowed`
and nothing else, so the listing is unchanged. It is one line from breaking: if
it ever calls `enforcing()`, every tool disappears from every agent's list.
`TestTheShapesTheEnforcementPointsActuallySend` is what that change has to walk
past. The four sites reporting `discharged=obligation_types()` needed no edit,
because each is reached only after `enforce()` returns and `enforce()` now raises
first — confirmed by test rather than by reading, in both languages, since it is
the load-bearing assumption of the SDK change.

**The change an out-of-tree caller is most likely to feel.** An
authorisation-only question — no payload — against a policy carrying a `redact`
obligation, followed by `enforce()`, now raises `ObligationUnsatisfied` where it
previously returned. That is the correct answer and it was always the correct
answer: the policy said *you may do this, with the identifiers redacted*, the
caller sent nothing to redact, and it was about to act on an allow whose
condition nobody had met. The two ways forward are both one line — send the
content, or declare `can_satisfy={"redact"}` if the enforcement point does its
own redaction — and the second is why the SDK change is a subtraction from the
satisfiable set rather than a filter on the outstanding one: the server may
shrink what a client trusts, and only the caller may widen it.

**The break is deliberate and bounded.** A non-SDK enforcement point sending
`scan_payload=False` or a raised `min_confidence` *with a payload* now receives a
422. Neither SDK, the CLI, the UI, nor either reference PEP can send those knobs
at decide time at all — `_build_body` puts exactly `{explain, apply_obligations,
persist}` in `options` and `DecideOptions` is `extra="forbid"` — so the entire
in-repo blast radius was two tests, both of which specified the defect.
`test_scanning_can_be_disabled` sent a live GitHub token with
`scan_payload=False` against a fixture set containing `deny-secrets-everywhere`
at priority 950 and asserted `effect == "allow"`. That is a written specification
of the credential bypass, and it passed for as long as it existed. Minor version
bump and a changelog entry.

**What this does not do.** It does not widen a deny. Adding
`findings: {any_of: [phi]}` to `deny-phi-to-external-models` was considered and
rejected: it selects on `resource.classifications` today and fires correctly, and
widening it to payload findings would flip live reverse-proxy and MCP traffic
carrying incidental PHI from allow to deny. Coverage was widened where data
crosses the trust boundary — `allow-agents-external-inference-scrubbed` now
redacts `[pii, pci, phi]`, verified against an MRN, an NPI and an ICD-10 code on
both the `infer` and `return` legs — and descriptions were corrected where it
does not.

**The guard for the descriptions.** `tests/integration/test_seed_policies.py`
opens with *"The shipped policy set must actually behave as its descriptions
claim"* and then asserted set membership over obligation types in all 23 tests;
`grep -n description` returned one hit, the docstring. It now carries a table of
`(policy, claim, payload, identifiers that must not survive)` driven through the
real PDP. Writing that table immediately found something no reading would have:
`phi.icd10` only fires near a context word, so a bare code in a model's answer is
never detected and cannot be redacted. The description is written to be true in
the presence of that limit, and the limit has its own test.

## Alternatives rejected

**Make `SATISFIED_BY_CONTROL_PLANE` dynamic.** It severs the chain that keeps the
Python constant, the generated fixture and the TypeScript Set agreeing — which is
the mechanism 0017 built after all three agreed with each other and none agreed
with the code. Keep the constant; subtract from it at the point of use.

**Hand the redactor unfiltered findings**, so raising `min_confidence` cannot
weaken redaction. It would silently start redacting sub-threshold matches for
every caller at default options, and `mask`/`drop` destroy data irreversibly. It
also aims at the wrong mechanism: the PHI leak at default options was not caused
by the confidence filter — `phi.mrn` scores 0.78 and reached the redactor
perfectly well. It survived because the obligation's `labels: [pii, pci]` did not
cover it. The security goal is met by the ceiling at zero cost to default
behaviour.

**Deny `apply_obligations=False` with a payload.** It deletes a documented API
mode that no in-repo caller uses but out-of-tree delegating enforcement points
plausibly do, when correct reporting achieves the same end without denying
anyone. Refusal is reserved for the shapes where there is no obligation to
report.

**Infer on the client whether the plane ran.** "Clean payload" and
`scan_payload=False` were measured byte-identical in every client-visible field,
so the inference cannot exist. It would also restate a predicate in two
languages, which is the drift shape 0017 exists about.

## Reversibility

The predicate is four lines in one function and the SDK change is one line each.
The refusals are the part with a cost to reverse: a caller that adapts to sending
`resource.classifications` instead of a payload has changed its integration, and
relaxing the validator later would not un-change it. That is the right direction
for the cost to run.
