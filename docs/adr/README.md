# Decision records

Short notes on the choices that would be expensive to reverse, written when they
were made. Each says what was decided, what else was on the table, and what it
costs — the last part being the one that is never reconstructible afterwards.

| | |
|---|---|
| [0001](0001-pdp-pep-split.md) | Split the decision point from the enforcement point |
| [0002](0002-native-policy-engine.md) | Build the policy engine rather than embed OPA or Cedar |
| [0003](0003-hmac-audit-chain.md) | Key the audit chain with an HMAC, not a bare hash |
| [0004](0004-fail-closed.md) | Fail closed everywhere, by default |
| [0005](0005-separate-label-selectors.md) | Keep catalog labels and payload findings separate |
| [0006](0006-no-payload-persistence.md) | Never persist payload content |
| [0007](0007-approvals-are-scoped-capabilities.md) | Make an approval a scoped, single-use capability |
| [0008](0008-discovery-uses-named-sources.md) | Run discovery against named, server-side sources |
| [0009](0009-tokenisation-without-a-vault.md) | Make the token the ciphertext, so there is no vault to steal |
| [0010](0010-declare-only-what-is-implemented.md) | Implement an obligation or remove it; nothing in between |
| [0011](0011-api-keys-use-a-fast-keyed-hash.md) | Stop paying 82 ms of Argon2 to protect a 192-bit secret |
| [0012](0012-streaming-governance.md) | Govern streamed answers behind a hold-back window |
| [0013](0013-routing-is-a-policy-outcome.md) | Make routing an obligation, and models catalog assets |
| [0014](0014-audit-streams-and-checkpoints.md) | Split the audit log into many chains, and checkpoint the set |
