# 0014 — The audit log is many chains, and checkpoints cover the set

**Status:** accepted

## Context

Every audit append took one global advisory lock. Since every decision writes an
audit record, every decision in the system serialised behind the logging of every
other one — measured at roughly 300 appends/sec with a p50 of 45 ms under
concurrency, and it got worse as concurrency rose.

The specification requires the logging service to scale horizontally (§8). It did
not, and the reason was a design choice rather than an implementation detail: one
chain means one lock.

## Decision

**Many chains.** Records belong to a *stream* and are keyed by `(stream, seq)`.
Each stream is an independent chain with its own head, its own sequence, and its
own lock, so appends to different streams proceed at the same time.

**Partitioned by actor**, not at random. One principal's history stays in one
chain, so an investigator following a single agent reads one stream rather than
all of them. The trade, stated because it is real: a single dominant caller does
not spread. Sharding helps a system with many callers, not one with a hot one.

**Explicit streams are supported** — pass a tenant or a period to keep that slice
independently verifiable. That is the per-tenant and per-period sharding the
requirement asked for; partitioning is the same mechanism with a default key.

**Checkpoints cover what sharding gives up.** Per-stream verification proves each
chain is internally consistent and says *nothing about how many chains there
should be*. Delete one entirely and everything remaining verifies perfectly. So a
checkpoint records where every stream had reached, sealed into a reserved chain
of its own, and `verify_all()` holds the current streams against the most recent
one. A stream that vanishes, gets truncated, or is rewritten beneath the
checkpoint now contradicts a record already written.

## Measured

Appends/sec across 64 distinct actors at concurrency 16, on Postgres, averaged
over repeated runs:

| partitions | appends/sec | p50 |
|---|---|---|
| 1 | ~300 | 45 ms |
| 4 | ~570 | 17 ms |
| 8 | ~565 | 14 ms |
| 16 | ~570 | 15 ms |

Roughly **2× throughput and 3× better p50**, saturating around four partitions —
beyond that the lock stops being the constraint and the connection pool and
Postgres itself take over. The default stays at 1, which is exactly the previous
behaviour; 4 to 8 is the useful range.

## The compatibility problem, and how it was avoided

Adding the stream to the signed body is the obvious implementation and it would
have **invalidated every record ever written**. An audit chain's entire value is
that it verifies over time; a schema change that breaks its history destroys the
thing being protected. This was caught by checking rather than assuming — the
first version of the migration note claimed compatibility that the code did not
have.

The fix: the stream is signed only when it is *not* the default. A record in
`default` signs exactly the bytes it signed before streams existed, so every
pre-existing digest keeps verifying. Moving a record between chains is still
caught in both directions, because the field appears going into a named stream
and disappears coming out of one.

Verified by writing records the old way under revision 0003, running the
migration, and confirming they still verify.

## Consequences

**Sequence numbers no longer order the log.** `seq` is per stream, so record 5 of
`p0` and record 5 of `p1` are unrelated. Listings are ordered by timestamp, which
is what a reader wanted anyway.

**Checkpoints have to be taken.** They are not automatic: `POST /v1/audit/checkpoint`
or `cpctl audit checkpoint`, on a schedule. A deployment that shards and never
checkpoints has weaker tamper-evidence than one that does not shard at all, and
that is the one genuinely sharp edge here.

**A single global "the chain" no longer exists.** "Verify the audit log" is now
"verify every stream, then check them against the checkpoint" — which
`verify_all()` does, and which is what `cpctl audit verify` runs by default.

**The append-only trigger still applies per row**, and remains the first line of
defence. The checkpoint test disables it deliberately to simulate an attacker
with exactly the privilege the hash chain exists to defend against.
