# 0009 — Tokenisation stores nothing; the token is the ciphertext

**Status:** accepted

## Context

The `tokenize` redaction strategy promised a reversible surrogate. It was never
wired up. When a policy asked for it, the redactor found no vault configured and
returned an HMAC digest instead — the shape of the obligation satisfied, its
meaning quietly dropped. A comment in that branch called it "fail closed", which
it was not: it was a silent downgrade, and nobody would find out until somebody
needed to reverse one.

Making it real raises a harder question than it first appears. The obvious
implementation is a vault: a table mapping tokens to the values they replaced.
That table would be the single largest concentration of sensitive data in the
deployment, inside the component introduced to reduce exactly that — and it
directly contradicts [ADR 0006](0006-no-payload-persistence.md), which says the
control plane never persists payload content.

## Decision

There is no table. **The token is the ciphertext.**

```
K_prf, K_enc = HKDF(key, info="control-plane/tokenization/v1")
nonce        = HMAC-SHA256(K_prf, label || 0x00 || value)[:12]
ciphertext   = AES-256-GCM(K_enc, nonce, value)
token        = "tok_" + base64url(version || nonce || ciphertext)
```

Deterministic authenticated encryption in the SIV style. Reversing a token
requires the key, which lives in the process environment rather than the
database, so a database dump yields nothing.

Deriving the nonce as a keyed function of the value is what makes it
deterministic, and determinism is what people actually want from tokenisation:
the same customer produces the same token across decisions, so tokenised columns
still join and an assistant can follow a conversation without ever learning who
it is about.

And the strategy now **refuses** rather than degrades. If a policy requires
`tokenize` and no key is configured, the decision denies, with the reason saying
so. A configuration error surfacing as a denial is the right direction; the
alternative is data leaving under a control everyone believes is in place.

## Consequences

**Determinism leaks equality.** Two identical tokens mean two identical inputs.
That is the property being bought, and it is exactly the leak the `hash` strategy
already has, so it changes nothing about the threat model — but it is not
semantic security and should not be described as such.

**Tokens are longer than what they replace.** This is not format-preserving
encryption. A tokenised email does not look like an email and will not fit a
column sized for one. Format-preserving encryption (FF1/FF3-1) would fix that;
implementing it correctly is real cryptographic engineering, and an unaudited
home-grown attempt would be worse than an honest length change.

**The key is the entire security boundary.** Losing it makes every existing token
permanently irreversible — there is no table to fall back on. It must be backed
up separately from the database, like the audit key. Unlike the audit and
redaction keys it has *no* development fallback: an ephemeral key would mint
tokens that stop reversing after a restart, and that failure surfaces later,
somewhere else, as data nobody can recover. Refusing to tokenise at all is the
kinder error.

**Rotation breaks joins across the boundary.** After rotating, the same value
tokenises differently. `CP_TOKENIZATION_PREVIOUS_KEYS` keeps old tokens
*readable*, which is the part that matters most, but it cannot make old and new
tokens equal. Rotate deliberately.

**Re-identification needed its own front door.** A capability that is useless
without a way to invoke it, so `POST /v1/detokenize` exists — under its own
`detokenize` scope, so an investigator can be granted reversal without being
granted the catalog. Every call is audited including the failures, with a
required justification, and the audit record holds digests rather than the
recovered values: logging those would recreate the store this design exists to
avoid. `POST /v1/detokenize/verify` answers "is this token this value?" without
disclosing anything, and is the operation to reach for first.

## Alternatives

**A mapping vault in the database.** Simplest, and it builds the honeypot.

**An external vault (HashiCorp, KMS-backed).** Correct for a large deployment and
the right thing to reach for eventually. `TokenVault` remains a protocol, so one
can be dropped in. Not worth the dependency as the default.

**Format-preserving encryption.** Better ergonomics, materially harder to
implement correctly, and rolling it by hand for a security tool is not
defensible.

**Keeping the hash fallback but warning loudly.** A warning in a log nobody is
reading is not a control. If the obligation cannot be met, the decision should
not be an allow.
