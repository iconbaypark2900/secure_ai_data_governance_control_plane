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
