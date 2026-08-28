# 0004 — Fail closed everywhere, by default

**Status:** accepted

## Context

Every layer has a failure mode: no policy matches, the classifier throws, the
database is unreachable, a policy fails to parse, the enforcement point cannot
reach the control plane, an obligation cannot be carried out.

## Decision

All of them deny.

| situation | result |
|---|---|
| No policy matches | `CP_DEFAULT_EFFECT`, shipped as `deny` |
| Exception in the decision pipeline | deny, with the failure recorded |
| Control plane unreachable from an SDK client | deny |
| Control plane rejects the enforcement point's own credential | deny |
| Allow carrying an obligation the caller cannot satisfy | deny |
| A stored policy fails to parse | skipped, and surfaced as an error on every decision |

## Reasoning

An error means the control plane could not establish that the request is safe.
That is not the same as the request being safe, and the two must not be
collapsed.

The asymmetry of the outcomes decides it. A false denial is visible, immediate,
and someone complains. A false allow is invisible, and is discovered — if at all
— during an incident review, after the data has already moved.

The clause about a failed policy load is the subtle one. A control that silently
fails to load leaves the system looking compliant while it is not, which is worse
than one that fails loudly. So the error rides along on every decision the engine
makes until it is fixed.

## Alternatives

**Fail open on infrastructure failure.** Argued for on availability grounds. It
means an attacker who can degrade the control plane — or simply a bad
afternoon — turns every control off at once. An enforcement point that lets
traffic through when its authority is unavailable does not provide a weaker
control; it provides the appearance of one.

**A permissive observation mode for rollout.** Genuinely useful, and supported:
`CP_DEFAULT_EFFECT=allow` with `permit_overrides` combining logs what *would*
have been denied without denying it. It is opt-in and loud, not the default.

## Consequences

The control plane's availability becomes the data path's availability. Run it
accordingly.

`CP_FAIL_CLOSED=false` exists for deployments that genuinely prefer an outage to
a false denial. It propagates the exception rather than silently allowing, so
that choice stays a decision someone made rather than a default they inherited.
