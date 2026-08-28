# 0001 — Split the decision point from the enforcement point

**Status:** accepted

## Context

Governance has to happen on the data path: by the time a prompt exists, the data
has already left the store where classical access control lived. The question is
whether the thing on that path also *owns* the policy.

## Decision

Two components. A central control plane holds the catalog, classifier, policy
set, and audit chain, and exposes one endpoint. Enforcement points sit on the
data path, ask it, and honour the answer.

## Alternatives

**A library embedded in every enforcement point.** No network hop, so the fastest
option. Rejected because the policy set and the catalog would have to be
replicated to every process, and two enforcement points with independently
cached rules will diverge — with the divergence discovered during an incident.
The audit chain would also be assembled from several independent writers, which
is not a history.

**A single mandatory gateway everything routes through.** Simple to reason about
and a single point of failure for the entire data plane. It also only governs
traffic that goes through it, and an agent's tool call does not.

## Consequences

A network hop on the data path — around 10 ms end to end against Postgres,
including persisting the decision and sealing its audit record. Mitigated by
compiling and caching the policy set in-process, and by the SDK caching
payload-free decisions.

The control plane becomes availability-critical, because everything fails closed
when it is unreachable. That is the correct behaviour and it is still an
operational burden: it must be run with the redundancy of an authentication
service, not of a reporting dashboard.

Enforcement points stay thin enough that writing a new one is an afternoon. That
is the property being bought.
