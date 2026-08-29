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

## The nine things it does

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
| `tokenize` | reversibility, keyed and joinable | investigations that must re-identify |
| `synthetic` | the shape, so parsers still work | test and eval data |
| `drop` | nothing | when presence itself is the leak |

`tokenize` deserves a note, because the obvious implementation is the wrong one.
There is **no vault** — no table mapping tokens back to values, because that
table would be the largest concentration of sensitive data in the deployment,
inside the component meant to reduce exactly that. Instead the token *is* the
ciphertext: deterministic AES-256-GCM with a key that lives outside the database.

```
"Refund for jane.doe@acme.com, call 415-555-0142"
  ↓
"Refund for tok_AadFpWU54KX20Va67T3GYM4REVy65leB…, call tok_AeOVHifcsdRfCbtHVAka1k…"
```

Deterministic, so the same customer produces the same token across every
decision and tokenised columns still join. Reversible only with the key, through
an endpoint that has its own scope:

```bash
POST /v1/detokenize        {"tokens": ["tok_…"], "justification": "incident INC-4821"}
POST /v1/detokenize/verify {"token": "tok_…", "label": "pii.email", "value": "…"}
```

`/verify` is the one to reach for first — it answers "is this token this value?"
without disclosing anything. Every call to either is audited, including the
failures, and the audit record holds digests rather than recovered values.

> **Deployment note.** Recovered values travel in the response body. Responses
> are marked `no-store`, but a reverse proxy, load balancer, or APM agent
> configured to record response bodies would accumulate exactly the store this
> design avoids — quietly, in a component nobody thinks of as holding data.
> Exclude `/v1/detokenize` from body logging.

And it **refuses rather than degrades**: a policy requiring `tokenize` on a
deployment with no key configured produces a deny, not a quietly substituted
hash. That was a real bug — the strategy silently behaved as `hash`, and nobody
would have found out until they needed to reverse one.

### 5. Sends the request somewhere it is allowed to go

Refusing is the easy half. A policy can also say *where* data may be processed,
and the control plane resolves it:

```yaml
- key: route-regulated-data-to-eu-models
  effect: allow
  match:
    all:
      - action: {in: [infer, embed, return]}
      - classifications: {any_of: [phi, pci, pii.ssn]}
  obligations:
    - {type: route, require: {region: eu}}
```

```
agent asks for  model://openai/gpt-4o        (region: us)
policy says     region must be eu
control plane   → model://internal/llama-3-70b
                  "routed because it satisfies region='eu'"
                  rejected: model://openai/gpt-4o — region is 'us'
```

Models are **ordinary catalog assets** under a `model://` URN, so registering one
is the same act as registering a table and it inherits labelling, ownership, and
audit. Constraining by attribute rather than naming a model means adding an EU
model later needs no policy change — and losing the last one is a **denial, not a
silent fallback** to the model the policy steered away from.

The control plane picks *which*; the enforcement point knows *how to reach it*,
because endpoints and credentials are deployment configuration and have no place
in a policy database. Which model saw the data lands in the decision record,
since that is the first question anyone asks afterwards.

### 6. Attaches duties that actually bind

An obligation is not advice. Seven types, and every one of them is implemented by
something:

| | executed by | |
|---|---|---|
| `redact` | control plane | rewrite matching values before returning them |
| `annotate` `log` `ttl` | control plane | record, raise the log level, bound retention |
| `limit` | enforcement point | cap tokens in, bytes and results back |
| `watermark` | enforcement point | mark delivered content so its origin survives a paste |
| `route` | enforcement point | send the request to a model the policy permits |
| `require_purpose` | enforcement point | re-check the declared purpose at the point of use |

The list was briefly cut to six: `notify` and `route` were removed because nothing
implemented them, and `route` came back only once something did — a policy author who read the schema and wrote one got a
well-formed policy that denied their own traffic. An unknown type is now a 422
when you write the policy, not a surprise at 3am.

The SDK enforces the binding: `decision.enforce()` raises unless the caller has
declared it can discharge whatever came back, so "allow, but watermark it" can
never quietly become "allow".

### 7. Can require a person

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

### 8. Knows whether it actually happened

A decision record says what was **permitted**. On its own it does not say what
**happened** — an enforcement point that could not discharge an obligation, or
refused for its own reasons, leaves a row reading `allow` behind an action that
never took place.

So enforcement points report back:

```bash
GET /v1/decisions?outcome=refused      # permitted, then refused downstream
GET /v1/decisions?outcome=unreported   # nobody has accounted for these at all
```

Three outcomes, and the third is the one that earns its place: `enforced`,
`refused`, and **`partial`** — the action happened but a duty went undischarged.
Without it, a point that carried out three obligations and skipped the fourth has
to report something false either way, and the useful signal disappears.

**Unreported is a state, not a default.** Silence is not read as success: a point
that quietly stops reporting is one that quietly stopped being observed.

The SDK does it for you, and does it at the right moment:

```python
async with client.enforcing(decision, can_satisfy={"watermark"}) as payload:
    await send_upstream(payload)
# reported enforced here — or refused, if the block raised
```

Reporting when the obligations merely check out is premature; if a later step
fails, the record says `enforced` behind something that never happened. That was
a real bug, caught by running it.

### 9. Proves it afterwards

Every decision and every policy change is sealed into a hash chain. Each record's
digest is an **HMAC** over its own content *and* its predecessor's digest.

The keying is the point. A bare hash chain proves ordering: an attacker who can
write to the table can rewrite a record and recompute every digest after it, and
the chain still verifies. Keying means forgery also requires the audit key, which
lives outside the database — so read access is enough to *detect* tampering, and
is not enough to *perform* it.

```bash
$ cpctl audit verify
4 stream(s) intact across 1,208 record(s); checkpoint matches

$ # after someone edits a row directly in Postgres
$ cpctl audit verify
stream(s) failing verification: p2
  p2
    altered digests: [23]
    broken predecessor links: [24]
```

The log is **many chains, not one**. A single global lock meant every decision in
the system serialised behind the logging of every other one; records now belong
to a stream, each with its own chain and its own lock — worth about 2× throughput
and 3× on p50. Partitioned by actor, so one principal's history stays in one
chain and an investigator reads one stream rather than all of them.

That trade has a cost, and it is bought back rather than ignored: per-stream
verification proves each chain is internally consistent and says nothing about
how many chains there should be, so deleting one entirely would leave everything
remaining verifying perfectly. **Checkpoints** record where every stream had
reached, in a chain of their own, and `verify` holds the streams against the
latest one. Take them on a schedule; a deployment that shards and never
checkpoints is weaker than one that never sharded.

Detection is the backstop. Prevention comes first: a database trigger makes
`UPDATE`, `DELETE`, and `TRUNCATE` on the audit table fail outright, so the
routine causes — an accidental ORM flush, a well-meant fix to a typo in an actor
name — cannot happen at all.

And the log is deliberately thin. It records *that* something was decided, by
whom, about what. Payload content appears only as a keyed digest, which answers
"was it this exact document?" without the log becoming a copy of the document.

### Cost

Measured end to end over HTTP against Postgres, 8 KB payloads — the shape a
retrieval pipeline actually sends — at concurrency 16:

| | throughput | p50 | p95 |
|---|---|---|---|
| one worker | 50 req/sec | 216 ms | 843 ms |
| four workers | 107 req/sec | 106 ms | 368 ms |

A single small decision is ~10 ms end to end, including persisting it and sealing
its audit record.

**Where the time goes, and one thing that was wrong.** Authentication used to
dominate: API keys were stored as Argon2id digests costing 82 ms to verify —
fourteen times what classifying the payload cost — on every request. The source
comment asserting that cost was "small next to a policy evaluation" was written
from plausibility, and stood until something measured it. Keys carry 192 bits of
entropy, so a slow hash was defending against an attack the key length already
prevents; they now use a keyed HMAC, and throughput went up roughly 5×
([ADR 0011](docs/adr/0011-api-keys-use-a-fast-keyed-hash.md)).

What remains is classification, which is real CPU: about 0.6 ms per KB, and regex
only partially releases the GIL, so **one worker is one core**. `WEB_CONCURRENCY`
is the knob that raises throughput; threads are not (measured at 1.25×, and the
offload is kept for tail latency, not throughput). `CP_MAX_SCAN_CHARS` bounds the
worst case at 64 KiB — a payload past it is scanned to the limit and the decision
is marked `payload_truncated`, which a policy can refuse on:

```yaml
- key: deny-unscannable-payloads
  effect: deny
  match: {env.payload_truncated: true}
```

Numbers from a 32-core workstation, not a benchmark rig; take them as an order of
magnitude and measure your own shapes.

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

**TypeScript too**, for enforcement points that are not Python — a gateway
middleware, a LibreChat hook, an Express route:

```ts
const decision = await cp.decide({
  principalId: "agent://support-bot", principalType: "agent",
  action: "infer", payload: prompt,
});

await cp.enforcing(decision, async (payload) => sendUpstream(payload), {
  canSatisfy: ["route"],
});   // reported enforced here, or refused if the block threw
```

Python's context manager becomes a callback, which turns out to be the stronger
shape: there is no way to obtain the payload without also handing over the work
that uses it, so the reporting cannot be skipped by accident.

The two clients are held to the same wire contract by a fixture generated from
the Python SDK's own body builder — `tools/generate_sdk_contract.py` — and CI
regenerates it and fails if it moved. Two clients that disagree about the request
body get different decisions out of the same policy, and the one that gets used
less is the one that stays wrong. Writing the second implementation is also what
found a cache-key bug in the first: `{"external": true}` and `{"external": "True"}`
were the same key, so the second caller received the first one's decision.

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

**Streaming works.** `stream: true` is governed behind a hold-back window: text
reaches the client only once it is far enough behind the write head that nothing
still arriving could turn out to be part of it.

```
produced:  ...the key is sk-ant-api03-AbCd
                         └──────────────┘  held back
emitted:   ...the key is
```

So tokens flow, and a credential the model emits mid-answer is refused *before*
any of it goes out — verified: five frames delivered, the credential appears zero
times, and the client gets a readable error rather than a truncated answer. The
cost is latency, not correctness; the residual risk is a value longer than the
window, which stops the stream with an explicit message rather than corrupting
it. `PEP_STREAM_MODE=buffer` trades incremental delivery for no blind spot at
all.

### The second enforcement point: tool calls

`pep/mcp_proxy/` sits in front of an MCP server. Where the reverse proxy governs
what an agent *says* to a model, this governs what it *does*.

```bash
$ PEP_MCP_UPSTREAM=http://localhost:3001/mcp uvicorn pep.mcp_proxy.main:app --port 8170

tools/list   118 tools upstream -> 73 offered to this agent
tools/call   filesystem-write_file -> refused, and the tool never ran
             read_patient_file     -> ran, and the result came back as:
                 "Maria Alvarez, SSN [REDACTED:pii.ssn], mrn 4419772."
                 "Contact <pii.email:52145a6d695faf91>."
```

Verified against a live gateway fronting 118 real tools across seven MCP servers.

**Both directions, again.** Arguments are the data leaving the agent; a tool
result is data arriving that the agent never asked for by name. Text blocks are
rewritten in place — image and resource blocks pass through untouched rather than
being pretended about, and the block structure survives.

**A tool the agent may not call is not advertised.** That is a convenience, not a
control: an agent can name a tool it was never shown, and the call is decided on
its own. The filtering asks with `persist=False` and writes nothing to the audit
log, because nothing is carried out by deciding what to offer. Recording it
seemed obviously right until measurement: one `tools/list` wrote 360 decision
records with no outcome on any of them, twenty times the volume of the calls, and
buried the `?outcome=unreported` filter under questions that never had an outcome.

**A refusal is a JSON-RPC error, not an HTTP one.** An HTTP 403 kills the
session; a JSON-RPC error carrying the request's id is a normal recoverable
answer to one call.

The honest limit: a result can be withheld after the call has already run. Worth
doing — it is the difference between the agent having the data and not — but it
cannot undo a side effect, so the error says so and tells the agent not to retry.
A duty that must *prevent* something has to attach to the invocation.

Building it found a bug in the older enforcement point: the reverse proxy
declared it could satisfy a `route` obligation on the response path, where there
is nothing left to route, so the obligation was reported discharged while nothing
happened. Two enforcement points disagreeing is how the first one's assumption
became visible. Reasoning in
[ADR 0016](docs/adr/0016-a-second-enforcement-point-for-tool-calls.md).

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
  controls. Records the vector names too: a named vector is named after the
  embedding model that produced it, and if that model is hosted outside the
  boundary the collection is a record of an egress
- **MCP** — maps `tool → resource`, `arguments → payload`, so an agent handing a
  customer record to a web search is a governed event. Reads all four of MCP's
  annotation hints, and records whether the verdict was *declared* by the server
  or *inferred* from the tool name — the spec is explicit that annotations are
  hints and that clients "should never make tool use decisions based on
  ToolAnnotations received from untrusted servers", so a server's self-
  description is stored as an assertion rather than as a finding of fact
- **LibreChat** — maps users and agents to principals, uploads to assets, and
  outbound messages to `infer` decisions

The first two can back a discovery source. The last two map identifiers and build
decision requests — there is nothing to enumerate without a live client session —
so naming one as a source is refused with that explanation rather than quietly
doing nothing.

An adapter reports failure through `AdapterError`, and that is load-bearing: the
discovery runner catches it and returns a report naming the source that failed,
while anything else escapes and takes the run down with a traceback. A wrong URL,
a stale API key, and a collection deleted between enumeration and sampling all
have to arrive as adapter errors, because all three are things operators do.

---

## Repository layout

```
control_plane/
  classification/   33-label taxonomy, 28 detectors, the scanner and its arbitration
  policy/           the policy document model, operators, and the evaluator
  redaction/        the six strategies, and vault-free reversible tokenisation
  audit/            the hash chain and its storage
  catalog/          assets, principals, pattern resolution, and discovery
  routing/          choosing which model a permitted request may reach
  adapters/         Postgres, Qdrant, MCP, LibreChat
  api/v1/           40 HTTP operations, plus /metrics
  pdp.py            the pipeline that ties it together
  cli.py            cpctl
sdk/python/         the enforcement-point client
sdk/typescript/     the same client, for JS runtimes
pep/reverse_proxy/  the reference enforcement point (chat completions)
pep/mcp_proxy/      the second one (MCP tool calls)
ui/                 the admin console (React + TypeScript)
seed/               the reference policy set and catalog
migrations/         Alembic, including the append-only trigger
tests/              710 tests
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

Prometheus metrics are at `/metrics` — decision counts by effect, latency,
findings by label, redactions by strategy, and policy-load health. Deliberately
no policy key, principal, or resource label: cardinality controlled by whoever
writes policies is a way to run a monitoring system out of memory. Per-policy
counts live behind `/v1/decisions/stats`, which is authenticated.

`CP_TOKENIZATION_KEY` is required only if a policy actually uses the `tokenize`
strategy, and has no development fallback at all: an ephemeral one would mint
tokens that stop reversing at the next restart. If a stored policy needs it and
it is unset, the service says so loudly at startup rather than only in the reason
string of each denial.

---

## Testing

```bash
make test        # 666 tests on SQLite, no external dependencies
make test-pg     # + those that need real Postgres
make test-qdrant # + those that need a real Qdrant
make check       # ruff, mypy, and the suite — everything CI runs
```

The service-backed tests cover what a fake cannot demonstrate, and CI runs both
services so they never quietly go back to skipping.

Postgres: the advisory lock that keeps twelve concurrent audit writers producing
one unbroken chain, the append-only trigger, JSONB containment, and the adapter's
own queries — where two real bugs were found, because query construction is not
something a fake can check.

Qdrant: the adapter's assumptions about someone else's API, which is a different
kind of untestable. A fake written by the author of the code under test agrees
with it by construction. Pointing the adapter at a real instance found two
defects immediately, and the recorded response bodies in the unit tests come from
that instance rather than from imagination.

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

## Security

Reporting, what is in scope, and the weaknesses that are known and accepted
rather than hidden: [`SECURITY.md`](SECURITY.md).

## Licence

Apache 2.0.
