# 0011 — API keys use a fast keyed hash, not a password hash

**Status:** accepted

## Context

API keys were stored as Argon2id digests, with this rationale in the source:

> Argon2id rather than SHA-256: API keys are high-entropy, so a fast hash would
> be defensible, but keys get pasted into `.env` files and reused, and the cost
> of being wrong about that is unbounded. The verification cost is paid once per
> request and is small next to a policy evaluation.

The last sentence was false, and measurably so. Argon2id at those parameters
costs **82 ms**. Classifying an 8 KB payload — the thing the control plane exists
to do — costs **6 ms**. Authentication was fourteen times the work of the actual
decision, on every authenticated request.

It showed up as a throughput ceiling nobody could explain: 9.3 requests/sec at
concurrency 16, with a p50 of 1.3 seconds. Attention went to the classifier,
which was the visible CPU cost and the wrong suspect.

## Decision

HMAC-SHA256 under an optional server-side pepper, compared in constant time.

A slow hash exists to make *guessing* expensive, and guessing is only a threat
when the secret might be guessable. These are not: `token_urlsafe(24)` is 192
bits from the OS entropy pool. An attacker holding the stored digest cannot
brute-force that at any hash speed, so the 82 ms bought nothing — it defended
against an attack the key length already prevents.

Argon2id remains correct for a *password*, which is low-entropy and chosen by a
human. There are no passwords in this system.

Digests are self-describing (`hmac-sha256$…`), so the previous scheme is
recognised, still verifies, and is re-hashed transparently on first successful
use. No key has to be reissued.

## Consequences

**Measured, end to end over HTTP, 8 KB payloads at concurrency 16:**

| | before | after |
|---|---|---|
| one worker | 9.3 req/sec, p50 1276 ms | **50.2 req/sec, p50 216 ms** |
| four workers | 20.8 req/sec, p50 530 ms | **106.7 req/sec, p50 106 ms** |

Roughly 5× on both, and workers now scale rather than being swamped by a
per-request cost that dominated everything else.

**A stolen digest is now cheap to check against a guess.** Irrelevant at 192 bits
of entropy, and `CP_API_KEY_PEPPER` closes it anyway: with a pepper set, a
database dump alone cannot be used to verify guesses offline. Optional, because
the system is secure without it; recommended, because it costs nothing.

**Changing the pepper invalidates every issued key.** Same class of hazard as the
audit and tokenization keys, and documented alongside them.

**The wrong thing was blamed first.** The classifier is real CPU cost and it is
worth bounding — that is [ADR 0012](0012-streaming-governance.md) and the scan
ceiling — but it was second-order. The lesson recorded here is that the comment
asserting authentication was cheap was written from plausibility rather than
measurement, and stood for four commits because nothing checked it.
