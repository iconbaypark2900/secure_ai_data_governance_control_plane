# 0006 — Never persist payload content

**Status:** accepted

## Context

The control plane sees the most sensitive data in the system: every prompt, every
retrieved chunk, every tool argument. Storing that would make investigation
trivial — "show me exactly what the model was sent".

## Decision

No payload content reaches durable storage. What persists is:

- the **labels** found, not the values
- **offsets and masked previews** — `j*******@acme.com`
- a **keyed digest** of the payload

## Reasoning

A store of every prompt is a higher-value target than any single system it
governs. Building it would mean the governance layer became the largest
concentration of sensitive data in the organisation — and it would be one that
nobody performed a data protection impact assessment on, because it was
introduced as a control.

The keyed digest recovers most of the investigative value. An investigator
holding a document can confirm it was the one a decision was made about, without
the log ever holding the document.

Masked previews are enough to justify a classification — "there were three
things shaped like email addresses in this column" — without reconstituting the
data. The mask never reveals more than a first and last character.

The rule is enforced in more than one place, because it is the kind of thing that
erodes:

- `Finding.redacted_dict()` is the only serialisation path, and it omits the value
- the catalog's scan evidence stores previews and counts
- credential-shaped `context` keys are dropped before a decision row is written
- the logging configuration scrubs credential-named fields as a processor, so a
  careless `log.info("decision", **request_body)` is safe rather than a leak
- three tests assert that specific sensitive strings do not appear anywhere in
  the stored row

## Alternatives

**Store payloads encrypted.** The key has to be available to whatever decrypts
them, so it moves the problem rather than solving it, and the store remains the
target.

**Store payloads with a short TTL.** Better, and still a window during which the
concentration exists. Available to anyone who wants it as a separate,
deliberately-chosen component; not the default.

## Consequences

"What exactly did the model see?" is not answerable from the control plane. It is
answerable as "a payload with this digest, containing these labels at these
offsets" — which is enough to confirm or refute a specific document, and not
enough to browse.

Debugging a misclassification needs the payload supplied again, through
`POST /v1/classify` or the Simulator, which do not persist.
