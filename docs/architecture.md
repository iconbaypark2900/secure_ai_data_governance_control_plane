# Architecture

## The split

The system is deliberately two halves, and the boundary between them is the only
interface that matters.

The **control plane** decides. It holds the catalog, the classifier, the policy
set, and the audit chain. It is stateful, it is not on anyone's critical path
except through one endpoint, and it can be scaled and restarted independently of
whatever it governs.

The **enforcement point** acts. It sits on the data path — a proxy in front of a
model, a hook in a retrieval pipeline, a wrapper around an agent's tool
dispatcher — and it does exactly two things: ask before acting, and honour the
answer.

The split is the standard PDP/PEP separation, and it is worth being explicit
about why it earns its complexity here:

- **Enforcement points are numerous and disposable.** There is one per data path.
  They should be thin enough that adding a new one is an afternoon, which means
  they cannot each carry a policy engine, a catalog, and a classifier.
- **Policy must be consistent across them.** Two enforcement points with their own
  embedded rules will diverge, and the divergence will be discovered during an
  incident.
- **The audit trail must be single and ordered.** A chain assembled from several
  independent writers is not a history.

The cost is a network hop on the data path. That is the trade, and it is the
reason the SDK caches payload-free decisions and the policy set is compiled and
held in memory.

```
┌──────────────────────────────── data path ──────────────────────────────────┐
│                                                                              │
│  caller ──▶ enforcement point ──▶ model / database / tool                    │
│                    │      ▲                                                  │
└────────────────────┼──────┼──────────────────────────────────────────────────┘
                     │      │  allow | deny | require_approval
             POST /v1/decide│  + obligations
                     ▼      │
┌──────────────────────────────── control plane ──────────────────────────────┐
│                                                                              │
│   ① catalog        urn ──▶ labels        (including pattern inheritance)     │
│   ② classifier     payload ──▶ findings  (28 detectors, structural checks)   │
│   ③ policy engine  request ──▶ effect + obligations + trace                  │
│   ④ redaction      obligations ──▶ rewritten payload                         │
│   ⑤ audit          everything ──▶ one sealed, ordered record                 │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

## The request path

One call to `PolicyDecisionPoint.decide` runs five stages. They are ordered so
that each has what it needs and nothing runs before it can be trusted.

### ① Enrich the principal

The caller asserts an identity. The catalog overwrites its attributes.

This ordering is the whole point. A request that says `{"trust_tier": "high"}`
must not be able to make that true — otherwise every attribute-based policy is
advisory. The caller may *add* context the control plane does not have; it may
not *override* what the control plane knows.

### ② Resolve the resource

A URN becomes a set of labels. Exact registrations are consulted, and so are
pattern registrations — `pg://clinical.*` classifies everything beneath it.

Patterns are applied least-specific-first so an exact registration overwrites an
inherited label rather than the reverse. Labels carry provenance: a steward's
`manual` assertion outranks a scanner's `scan` inference at the same label, so
re-running a scan can never silently erase a human decision.

The result also reports whether the URN matched anything at all. An unregistered
asset is not a safe asset; it is an unknown one, and a policy can be written to
treat it accordingly.

### ③ Classify the payload

The content in flight is scanned. This is what makes the system work on data that
has no schema and no catalog entry — a prompt, a retrieved chunk, a tool argument.

Detectors are allowed to overlap, so the scanner's real job is arbitration:
`sk-ant-api03-…` matches both the Anthropic pattern and the generic `sk-` one.
The winner is chosen by severity first, then span length, then confidence —
calling a string a private key rather than a generic API key is the safer error,
and the longer span resolves prefix collisions in favour of the more specific
detector.

Findings carry the matched value, because redaction needs it. They also carry a
masked preview, and **the preview is the only form that is ever serialised** —
into the API response, the catalog's evidence field, or the audit log.

### ④ Evaluate

Pure function. No I/O, no clock, no database. A decision can be replayed months
later against the same policy version and produce byte-identical output.

Deny-by-default. Deny-overrides combining by default, so a prohibition cannot be
outvoted by a permission someone added afterwards. `priority_ordered` is
available for deliberate break-glass exceptions, and `permit_overrides` for an
observation rollout.

Obligations from every matching policy of the winning effect are unioned, never
overridden. Obligations only add constraints, so combining them can make a
decision stricter and never looser.

A policy that fails to evaluate is recorded as an error and surfaced on the
decision — a control that silently fails to load is worse than one that fails
loudly, because the system looks compliant and is not.

### ⑤ Execute and record

Redaction obligations are applied to the payload right-to-left, so earlier
offsets stay valid while later ones are rewritten.

Then two writes, in the same transaction as the caller's:

- a `decisions` row — the operational record, indexed and queryable
- an `audit_records` row — the tamper-evident proof, hash-chained

Both or neither. An audit record for a rolled-back operation is a lie in the
other direction.

A `require_approval` result also parks the decision — or, if the caller presented
a valid approval, spends it and records what it was spent on. The redemption path
runs between evaluation and response: it can only turn `require_approval` into
`allow`, it re-collects obligations so nothing is shed on the way, and it leaves
a deny untouched. See
[ADR 0007](adr/0007-approvals-are-scoped-capabilities.md).

### Failure

The whole pipeline is wrapped. Any exception between ① and ④ produces a deny with
the failure recorded. An error means the control plane could not establish that
the request is safe, which is not the same as it being safe.

`CP_FAIL_CLOSED=false` propagates the exception instead. It exists because some
deployments genuinely prefer an outage to a false denial, and that should be a
decision someone makes explicitly rather than a default they inherit.

## Storage

Nine tables. The ones worth commenting on:

**`policies` / `policy_versions`.** The policy's whole normalised document is
stored as JSON, and the engine consumes that document directly — so what is
evaluated is exactly what was stored, with no second representation assembled
from columns and free to drift. Broken-out columns exist only so the database can
filter and sort without parsing JSON. Every write snapshots the full document, so
a decision from six months ago can be re-evaluated against the policy text that
actually governed it.

**`decisions`.** No payload content, ever. Labels and a keyed digest, which
answers "was it this exact document?" without the table becoming a copy of the
document. Credential-shaped context keys are dropped on the way in, because
callers put useful things in `context` and occasionally put a bearer token there
too.

**`audit_records`.** Append-only, enforced twice. The hash chain makes tampering
detectable; a database trigger makes `UPDATE`, `DELETE`, and `TRUNCATE` fail
outright. Those answer different questions: the trigger stops the accidental ORM
flush and the well-meant fix to a typo, while the chain catches the attacker with
enough privilege to drop the trigger — because dropping it still does not produce
valid digests without the audit key.

Appends are serialised with a Postgres transaction-scoped advisory lock. Without
it, two concurrent appends read the same head and write two records claiming the
same predecessor: each valid alone, and together not a history.

## Cross-cutting choices

**Deny by default, everywhere.** No policy match, an unreachable control plane, an
unparseable policy, an obligation the enforcement point cannot satisfy — all of
them deny.

**Sensitive values never reach durable storage.** Detectors find them, redaction
consumes them, and the process drops them. What persists is labels, offsets,
masked previews, and keyed digests. The logging configuration scrubs
credential-named fields as a processor, so a careless
`log.info("decision", **request_body)` is safe rather than a leak.

**The database is the boundary between the two backends.** The same models run on
Postgres in deployment and SQLite in the test suite. Every column type behaves
identically on both; the handful of operations that exist only on Postgres —
advisory locks, JSONB containment, the trigger — degrade deliberately rather than
crashing, and the tests that need them are marked and skipped.

## What runs where

| | | |
|---|---|---|
| `control_plane/` | the API and the engine | stateless; scale horizontally |
| Postgres | policies, catalog, decisions, audit | the one stateful component |
| `sdk/python/` | the client | in the caller's process |
| `pep/reverse_proxy/` | the reference enforcement point | one per data path |
| `ui/` | the console | static, served from `/console` or a CDN |
