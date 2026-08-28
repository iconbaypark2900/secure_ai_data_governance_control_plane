# Secure AI Data Governance Control Plane

A policy decision point for AI systems. It answers one question, on the data path:

> May **this principal** take **this action** on **this data**, right now — and if
> so, what has to be stripped out first?

Something asks. The control plane works out what the data actually is, evaluates
the policy set, returns an effect and the obligations attached to it, and seals
the whole exchange into a tamper-evident log.

```
   your app / agent / RAG pipeline
              │
              ▼
    ┌──────────────────────┐        POST /v1/decide
    │  enforcement point   │ ─────────────────────────────┐
    │  (proxy, SDK, hook)  │ ◄──── allow | deny |         │
    └──────────────────────┘       require_approval       │
              │                    + obligations          │
              ▼                                           ▼
       model / database                     ┌─────────────────────────────┐
                                            │       CONTROL PLANE         │
                                            │                             │
                                            │  catalog     what is this?  │
                                            │  classifier  what is in it? │
                                            │  policy      is it allowed? │
                                            │  redaction   make it safe   │
                                            │  audit       prove it       │
                                            └─────────────────────────────┘
```

---

## Why this exists

Data governance used to be a question about storage: who can read which table.
An AI system makes it a question about *movement*. A retrieval pipeline copies
governed rows into an ungoverned vector collection. An agent pastes a customer
record into a web-search tool. A prompt with a support ticket in it goes to a
third-party model, and the row-level controls on the source table never had an
opinion about any of it.

The classical answer — access control at the store — cannot see any of that. By
the time the data is in a prompt it has already left the place the controls
lived.

So the control point moves onto the data path, and it needs three things the
store never had to provide:

1. **It must know what the data is**, not just where it came from. A prompt is
   not a table; it has no schema and no owner. The only way to know it contains
   an SSN is to look.
2. **It must be able to say "yes, but"**. Blocking a support agent from reading
   the knowledge base is not a viable control — they will route around it. Letting
   them read it with the identifiers masked is.
3. **It must be able to prove what it did afterwards.** "The model saw nothing it
   shouldn't have" is a claim, and a claim without evidence is worth nothing in
   an incident review.

---

## Quick start

```bash
make install          # virtualenv, dependencies, the SDK
make secrets          # generate the two required keys into .env
make dev-db           # a local Postgres
make migrate          # schema, plus the append-only trigger on the audit table
make seed             # the reference policy set and catalog
make demo             # eight scenarios, each explaining itself
```

Or the whole stack, including the governing LLM proxy:

```bash
cp .env.example .env && make secrets
make up
```

| | |
|---|---|
| Admin console | http://localhost:8000/console |
| API reference | http://localhost:8000/docs |
| Governed LLM proxy | http://localhost:8100/v1/chat/completions |

---

## What a decision looks like

```bash
curl -X POST localhost:8000/v1/decide -H 'X-API-Key: cpk_…' -d '{
  "principal": {"id": "agent:support_bot", "type": "agent"},
  "action":    "read",
  "resource":  {"urn": "qdrant://kb_docs"},
  "context":   {"destination": "internal"},
  "payload":   "Customer jane.doe@acme.com (SSN 536-90-4432) asks about refunds."
}'
```

```json
{
  "effect": "allow",
  "determining_policy": "allow-agents-read-redacted",
  "reason": "'Agents read with identifiers masked' (priority 200) produced 'allow' under deny_overrides",
  "classifications": ["confidential.internal", "pii.email", "pii.ssn"],
  "regulations": ["CCPA", "GDPR", "GLBA"],
  "payload": "Customer <pii.email:908fde31e31568ca> (SSN [REDACTED:pii.ssn]) asks about refunds.",
  "redactions": [
    {"label": "pii.email", "strategy": "hash",  "start": 9,  "end": 26},
    {"label": "pii.ssn",   "strategy": "mask",  "start": 32, "end": 43}
  ],
  "latency_ms": 6.6
}
```

Note what happened to the two identifiers. The SSN is **masked** — gone, and the
sentence still parses. The email is **hashed** — also gone, but deterministically,
so the same customer stays recognisable as the same customer across a
conversation without the agent ever learning who they are. Choosing between those
two is what a redaction obligation is for.

---

## The six things it does

### 1. Knows what the data is

The catalog maps a URN to sensitivity labels. Registrations can be patterns:

```yaml
- urn: pg://clinical.*            # every table under this schema
  classifications: [phi.mrn, phi.icd10, pii.dob]
```

`pg://clinical.lab_results_2026` was never registered by anyone. It is still PHI.
This matters more than it sounds: the table someone created last week and forgot
to tell the data team about is *exactly* the one that leaks.

### 2. Looks inside the payload

28 detectors, each pairing a pattern with a structural check. `4111111111111111`
is a card number and `4111111111111112` is not, and only a Luhn checksum can tell
them apart. IBANs get mod-97; SSNs get the allocation rules; NPIs get the issuer
prefix.

Confidence is adjusted by context, in both directions:

```
"536-90-4432"                     → pii.ssn @ 0.85   (written the way an SSN is written)
"order 536904432"                 → nothing          (nine digits is an order number)
"SSN 536904432"                   → pii.ssn @ 0.90   (the word next to it is the evidence)
{"ssn": "536904432"}              → pii.ssn @ 0.90   (so is the field it sits in)
```

Labels are hierarchical: a policy naming `pii` covers every `pii.*` beneath it.
And the taxonomy is honest about its limits — `pii.name` is a label with no
detector, because no regex identifies a person's name, and a detector that
claimed to would be confidently wrong.

### 3. Decides, and explains

Policies are data — YAML in a repository, versioned in the database, diffable in
a pull request:

```yaml
- key: deny-phi-to-external-models
  effect: deny
  priority: 950
  match:
    all:
      - resource.classifications: {any_of: [phi]}
      - context.destination: external
```

Deny-by-default: nothing is permitted implicitly. Deny-overrides combining, so a
prohibition cannot be outvoted by a permission someone added later.

Three label selectors, deliberately distinct, because collapsing them makes
policies read plausibly and behave surprisingly:

| selector | means | for rules like |
|---|---|---|
| `resource.classifications` | what the catalog says the **store** holds | "unreviewed agents cannot touch the clinical schema" |
| `findings` | what was found in **this payload** | "never transmit a credential" |
| `classifications` | the union | "anything sensitive is involved" |

Every decision can return the full trace: each policy considered, whether it
applied, and for the ones that did not, the exact condition that ruled them out.

### 4. Makes the data safe

Six strategies, differing in what they preserve:

| strategy | keeps | for |
|---|---|---|
| `mask` | that something was there | the default |
| `partial` | a recognisable suffix | `**** **** **** 1111` on a receipt |
| `hash` | joinability, keyed and irreversible | analytics, conversation continuity |
| `tokenize` | reversibility, through a vault | pipelines that must re-identify |
| `synthetic` | the shape, so parsers still work | test and eval data |
| `drop` | nothing | when presence itself is the leak |

### 5. Can require a person

Some things should be neither blocked nor waved through. `require_approval`
parks the decision, and a human grants it in the console or over the API:

```
POST /v1/decide                 -> require_approval + approval.id
POST /v1/approvals/{id}/decide  -> a person grants it
POST /v1/decide + approval_id   -> allow, and the approval is spent
```

What comes back is a capability, scoped like one. It is **bound** by a keyed
fingerprint to the exact request a human reviewed — a different table, a
different destination, a different payload, and it will not redeem. It is
**single use**. It **expires**. And it is **subordinate to deny**: redemption
re-evaluates policy, so a prohibition added after the grant still wins, and the
approval survives unspent for when that prohibition is lifted.

Without those four properties, "approve this one export" quietly becomes
"approve anything, for anyone holding the id".

### 6. Proves it afterwards

Every decision and every policy change is sealed into a hash chain. Each record's
digest is an **HMAC** over its own content *and* its predecessor's digest.

The keying is the point. A bare hash chain proves ordering: an attacker who can
write to the table can rewrite a record and recompute every digest after it, and
the chain still verifies. Keying means forgery also requires the audit key, which
lives outside the database — so read access is enough to *detect* tampering, and
is not enough to *perform* it.

```bash
$ cpctl audit verify
chain intact across 47 record(s)

$ # after someone edits a row directly in Postgres
$ cpctl audit verify
chain verification failed: 1 record(s) with an invalid digest; 1 broken link(s)
  records with an altered digest: [23]
  records whose predecessor link is wrong: [24]
```

Detection is the backstop. Prevention comes first: a database trigger makes
`UPDATE`, `DELETE`, and `TRUNCATE` on the audit table fail outright, so the
routine causes — an accidental ORM flush, a well-meant fix to a typo in an actor
name — cannot happen at all.

And the log is deliberately thin. It records *that* something was decided, by
whom, about what. Payload content appears only as a keyed digest, which answers
"was it this exact document?" without the log becoming a copy of the document.

### Cost

Measured against the reference policy set over HTTP, on Postgres, with a payload
carrying three identifiers:

| | median | p-max over 15 calls |
|---|---|---|
| Evaluate — catalog lookup, classify, decide, redact | 6.6 ms | 12.3 ms |
| End to end, including persisting the decision and sealing its audit record | 10.4 ms | 36.7 ms |

Numbers from a laptop, not a benchmark rig; take them as an order of magnitude.
Two things keep the hot path short: the compiled policy set is cached in-process
and invalidated on write, and the SDK caches payload-free decisions — the pure
authorisation question — for a few seconds.

---

## Enforcement points

The control plane decides; something on the data path enforces. The SDK makes
that side hard to get wrong:

```python
from control_plane_sdk import AsyncControlPlaneClient

client = AsyncControlPlaneClient("http://localhost:8000", API_KEY)

decision = await client.decide(
    principal_id="agent:support_bot",
    principal_type="agent",
    action="read",
    resource_urn="qdrant://kb_docs",
    payload=retrieved_chunk,
)
safe_chunk = decision.enforce()  # raises unless it is genuinely permitted
```

Three behaviours there are requirements, not conveniences:

- **Fail closed.** If the control plane is unreachable, the client denies. An
  enforcement point that lets traffic through when its authority is unavailable
  provides no control — only the appearance of one, which is worse.
- **Obligations bind.** `enforce()` raises if the decision carries a duty the
  caller has not declared it can satisfy. "Allow, but redact the SSNs" must never
  degrade into "allow".
- **Content decisions are never cached.** The payload is part of what was decided.
  Only the pure authorisation question — no payload — is cacheable.

### The reference enforcement point

`pep/reverse_proxy/` is a governing reverse proxy for OpenAI-compatible chat
completions. Point an existing client at it instead of at the provider and every
prompt is governed, with no change to the client:

```bash
$ curl localhost:8100/v1/chat/completions -H 'X-Principal-Id: agent:support_bot' \
    -d '{"model":"gpt-4o","messages":[{"role":"user",
         "content":"Refund jane.doe@acme.com, SSN 536-90-4432, phone 415-555-0142."}]}'

the model received:
  Refund <pii.email:908fde31…>, SSN <pii.ssn:a9ae73c6…>, phone <pii.phone:043c6056…>.
```

```bash
$ # ... and with a credential in the prompt
{"error": {
  "message": "Blocked by data governance policy on the inbound path: 'Credentials never move'",
  "type": "data_governance_denied",
  "policy": "deny-credentials-anywhere"}}
```

Both directions are governed. A model given clean input can still emit a
memorised training example, a credential a tool handed it, or a row it inferred
from context — governing only the inbound half protects the provider, not the
user.

### Filling the catalog

A control plane only governs what it knows about, and a catalog maintained by
hand is a catalog with holes in it. Point it at the systems that hold data:

```bash
cpctl catalog sources                              # what is configured
cpctl catalog discover warehouse --dry-run         # reads nothing, writes nothing
cpctl catalog discover warehouse --scan            # sample and classify
```

```
warehouse via postgres: 4 asset(s) discovered, 4 new, 0 existing

  urn                          kind   registered  labels                                       sampled
  pg://clinical.encounters     table  new         phi.icd10, phi.mrn, pii.dob                  1
  pg://public.customers        table  new         pii.address, pii.email, pii.phone, pii.ssn   2
  pg://public.payment_methods  table  new         pci.card_number, pci.iban                    1

  implicates: CCPA, GDPR, GLBA, HIPAA, PCI-DSS
```

Two of those labels came from column names and comments — no data read at all.
`pii.dob` on the clinical table came from *sampling*: it was sitting in a
free-text `notes` column, where no schema inspection would have found it.

Sources are configured server-side and referred to by name, so a connection
string never travels in an API request body. Secrets interpolate from the
environment, so the file is safe to commit:

```yaml
sources:
  - name: warehouse
    adapter: postgres
    dsn: ${WAREHOUSE_DSN}
    exclude: ["pg://audit.*", "pg://public.api_keys"]   # never sampled
    scan: false                                          # opt in deliberately
```

`exclude` beats `include`, because a control that a broader rule can override is
not a control. Sampling stores masked previews and counts as evidence — never a
value — so profiling an asset does not turn the catalog into a copy of it. One
audit record is sealed per run, not per asset: cataloguing four hundred tables is
one operator action.

The same thing over HTTP: `GET /v1/catalog/sources`,
`POST /v1/catalog/sources/{name}/discover`.

### Adapters

`control_plane/adapters/` connects the catalog to systems that hold data. They
discover and sample; they never enforce, because two policy engines eventually
disagree.

- **Postgres** — enumerates tables, reads column comments, samples with
  `TABLESAMPLE` (a bare `LIMIT` reads the physically first rows, which on an
  append-ordered table are the oldest and least representative)
- **Qdrant** — enumerates collections and samples payloads, because a collection
  built from a customer table inherits its sensitivity without inheriting its
  controls
- **MCP** — maps `tool → resource`, `arguments → payload`, so an agent handing a
  customer record to a web search is a governed event
- **LibreChat** — maps users and agents to principals, uploads to assets, and
  outbound messages to `infer` decisions

The first two can back a discovery source. The last two map identifiers and build
decision requests — there is nothing to enumerate without a live client session —
so naming one as a source is refused with that explanation rather than quietly
doing nothing.

---

## Repository layout

```
control_plane/
  classification/   33-label taxonomy, 28 detectors, the scanner and its arbitration
  policy/           the policy document model, operators, and the evaluator
  redaction/        the six strategies
  audit/            the hash chain and its storage
  catalog/          assets, principals, pattern resolution, and discovery
  adapters/         Postgres, Qdrant, MCP, LibreChat
  api/v1/           38 HTTP operations
  pdp.py            the pipeline that ties it together
  cli.py            cpctl
sdk/python/         the enforcement-point client
pep/reverse_proxy/  the reference enforcement point
ui/                 the admin console (React + TypeScript)
seed/               the reference policy set and catalog
migrations/         Alembic, including the append-only trigger
tests/              354 tests
docs/               architecture, the policy language, and the decision records
```

---

## Operating it

```bash
cpctl decide --principal agent:support_bot --action read \
             --resource qdrant://kb_docs --payload "…" --explain
cpctl classify -                      # scan stdin
cpctl policy validate seed/policies.yaml   # what CI runs on a policy PR
cpctl policy sync seed/policies.yaml       # GitOps-style deployment
cpctl catalog sources                      # configured systems to discover from
cpctl catalog discover warehouse --dry-run # reads nothing, writes nothing
cpctl catalog discover warehouse --scan    # sample and classify
cpctl key issue --name gateway --scope decide --scope catalog:read
cpctl audit verify
```

`cpctl` talks to the database directly rather than through the API, so it works
before the service is running and while it is broken — which is when you need it.

### Configuration

Everything is settable through the environment with a `CP_` prefix; see
`.env.example`. Two settings decide the posture and both default to the safe
side:

| | default | |
|---|---|---|
| `CP_DEFAULT_EFFECT` | `deny` | what happens when no policy matches |
| `CP_FAIL_CLOSED` | `true` | whether an internal error denies |

Two secrets are required in production, and the service refuses to start without
them rather than generating ephemeral ones — a control plane that silently minted
a new audit key at boot would produce a chain that verifies today and fails after
the next restart.

---

## Testing

```bash
make test      # 333 tests on SQLite, no external dependencies
make test-pg   # + 7 that need real Postgres
make check     # ruff, mypy, and the suite — everything CI runs
```

The Postgres-only tests cover what SQLite cannot demonstrate: the advisory lock
that keeps twelve concurrent audit writers producing one unbroken chain, the
append-only trigger, JSONB containment, and the Postgres adapter's own queries —
which is where two real bugs were found, because query construction is not
something a fake can check.

`tests/integration/test_seed_policies.py` tests the *shipped policy set* against
its own descriptions. A reference policy set that reads well and denies the wrong
things is worse than none, because people copy it.

---

## What this is not

- **Not a scanner.** It classifies what it is shown, on the request path. Bulk
  profiling of a warehouse is a different tool with different latency budgets.
- **Not an identity provider.** It recognises identities; it does not issue them.
- **Not a guarantee about model behaviour.** It governs what reaches a model and
  what comes back. It has no opinion on what the model does in between.
- **Not a substitute for access control at the store.** It is the layer above.
  A control plane in front of a database anyone can also connect to directly is
  a suggestion, not a control.

---

## Further reading

- [`docs/architecture.md`](docs/architecture.md) — the components and the request path
- [`docs/policy-language.md`](docs/policy-language.md) — the full policy reference
- [`docs/adr/`](docs/adr/) — why the load-bearing decisions went the way they did

## Licence

Apache 2.0.
