# Security policy

This is a control plane: it sits on the data path, it holds the keys that seal an
audit log and reverse tokenisation, and a flaw in it is a flaw in whatever it was
protecting. Reports are welcome and taken seriously.

## Reporting a vulnerability

Use **GitHub's private vulnerability reporting** on this repository
(Security → Report a vulnerability). That keeps the report private until there is
a fix.

Please do not open a public issue for a security problem, and please do not test
against anyone's deployment but your own.

What helps: the version or commit, what an attacker would gain, and the smallest
reproduction you can manage. A proof of concept is welcome and not required — a
clear description of the flaw is enough to act on.

Expect an acknowledgement within a few days and an assessment within two weeks.
This is not a funded programme with an SLA; it is a maintained project that will
tell you honestly where a report stands.

## What counts

**In scope.** Anything that lets a decision be bypassed, forged, or silently
weakened:

- A request that should be denied being allowed, or an obligation being dropped.
- Redaction that leaks the value it was supposed to remove — including through
  a decision record, an audit entry, a log line, a metric label, or an error.
- Forging an audit record, or altering one so the chain still verifies.
- Reversing a token without the tokenisation key, or making tokens predictable.
- Authentication or scope bypass, or a key usable for a principal it is not
  bound to.
- Redeeming an approval for a request it was not granted for, or more than once.
- Reaching a model or a data source a policy routed the request away from.
- Injection through a policy document, a URN, or an adapter's query construction.

**Known and accepted**, documented rather than hidden:

- **Deterministic tokenisation and hashing leak equality.** Two identical tokens
  mean two identical inputs. That is the property being bought — it is what makes
  tokenised columns joinable — and it is stated in
  [ADR 0009](docs/adr/0009-tokenisation-without-a-vault.md).
- **A sensitive value longer than the streaming window** may have part of it
  delivered before the rest arrives to identify it. The stream then stops with an
  explicit refusal rather than splicing corrected text. Tunable via
  `PEP_STREAM_WINDOW_CHARS`; see
  [ADR 0012](docs/adr/0012-streaming-governance.md).
- **Payloads past `CP_MAX_SCAN_CHARS` are only partly classified.** The decision
  carries `payload_truncated`, and a policy can refuse on it. A clean result on a
  truncated scan is not a claim that the whole payload is clean.
- **`pii.name` and `pii.address` have no reliable detector.** No regex identifies
  a person's name. The taxonomy says so rather than shipping something
  confidently wrong.
- **Policy authors are trusted.** A policy may contain a regular expression, and
  a pathological one can be made slow. Patterns are length-capped; the real
  control is that writing policy is a privileged action.
- **An enforcement-point refusal is not in the control plane's record.** If a PEP
  cannot discharge an obligation and refuses, the decision record still says
  `allow`, because that is what the control plane decided. See
  [ADR 0010](docs/adr/0010-declare-only-what-is-implemented.md).
- **Metrics at `/metrics` are unauthenticated** by scraper convention. They carry
  counts and latencies, never principals, resources, policy keys, or payloads.
  Restrict the port at the network layer.

**Out of scope.** Findings against a deployment's own configuration rather than
this code: a missing `CP_API_KEY_PEPPER`, `CP_AUTH_DISABLED` left on outside
local development, a database reachable from the internet, or a reverse proxy
configured to log response bodies (which would defeat `/v1/detokenize`, and is
called out in the README for that reason).

## Operating it safely

The three things most worth getting right:

**Back up the keys separately from the database.** `CP_AUDIT_HMAC_KEY` seals the
audit chain and `CP_TOKENIZATION_KEY` is the only way to reverse a token — losing
either is unrecoverable, and keeping them beside the data they protect defeats
the point. The service refuses to start in production without the first.

**Leave the defaults alone unless you mean it.** `CP_DEFAULT_EFFECT=deny` and
`CP_FAIL_CLOSED=true` are what make an error a refusal rather than an
unrecorded allow.

**Do not expose `/metrics` or the database.** Neither is authenticated by design;
both assume a network boundary.

## Cryptography

| | |
|---|---|
| Audit chain | HMAC-SHA256 over a canonical encoding, chained to the predecessor |
| Tokenisation | AES-256-GCM, deterministic via an HKDF-derived SIV-style nonce |
| Pseudonymisation | HMAC-SHA256 under a separate key |
| API keys | HMAC-SHA256 under an optional pepper, constant-time compared |

API keys are 192-bit random secrets, which is why a fast hash is appropriate and
a password hash was not — see
[ADR 0011](docs/adr/0011-api-keys-use-a-fast-keyed-hash.md).

No cryptography here is hand-rolled: everything comes from `cryptography` and
`hmac`. If you find a construction that is used incorrectly, that is very much in
scope.
