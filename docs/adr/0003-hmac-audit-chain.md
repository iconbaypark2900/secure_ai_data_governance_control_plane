# 0003 — Key the audit chain with an HMAC, not a bare hash

**Status:** accepted

## Context

The audit log must let someone establish, after the fact, that it has not been
altered. The standard construction is a hash chain: each record's digest covers
its content and its predecessor's digest.

## Decision

`HMAC-SHA256` under a key held outside the database, over a canonical JSON
encoding. Plus a Postgres trigger rejecting `UPDATE`, `DELETE`, and `TRUNCATE` on
the table.

## Reasoning

A bare hash chain proves **ordering**, not **authenticity**. An attacker who can
write to the table can rewrite a record and recompute every digest after it, and
the chain still verifies — because everything needed to recompute it is public.

Keying changes what an attacker needs. Forging now requires the audit key as
well as write access, and the key lives in the process environment, not in the
database. So read access to the table is enough to *detect* tampering, and write
access to it is not enough to *perform* tampering.

The trigger and the chain answer different questions and both are wanted. The
trigger prevents the routine causes — an accidental ORM flush, a cascading
delete, a well-meant fix to a typo in an actor name. The chain catches the
attacker with enough privilege to drop the trigger, because dropping it still
does not yield valid digests.

## Alternatives

**A bare SHA-256 chain.** Simpler, no key to manage. Rejected: it does not
survive the threat model that motivates having an audit log at all, which is
someone with database access.

**External timestamping or a transparency log.** Stronger — it removes the need
to trust the operator. Rejected as disproportionate for a self-hosted control
plane, and it introduces an external dependency on the write path.

**Write-once storage.** Complementary rather than alternative; nothing here
prevents shipping records to object storage with a retention lock as well.

## Consequences

The audit key becomes operationally critical. Losing it means the existing chain
can never be verified again; rotating it has the same effect. It must be backed
up somewhere other than the database, and the service refuses to start in
production without it rather than quietly generating an ephemeral one — which
would produce a chain that verifies today and fails after the next restart.

Verification is O(n). Fine at a million records, not at a billion; the range
parameters on `/v1/audit/verify` exist so a large chain can be checked in slices.

Appends must be serialised, which is a transaction-scoped advisory lock on
Postgres. Without it, two concurrent appends read the same head and fork the
chain.
