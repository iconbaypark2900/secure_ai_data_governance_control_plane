# 0012 — Streamed answers are governed behind a hold-back window

**Status:** accepted

## Context

The reference enforcement point could not handle `stream: true`. It forwarded the
flag, the provider answered with SSE, and `response.json()` failed on the event
stream. Since essentially every chat client streams, the proxy was a
demonstration rather than something anyone could put in front of real traffic.

The difficulty is a genuine conflict. A client wants tokens as they are produced.
Governance wants the whole answer before deciding anything — a credential is only
recognisable once all of it has arrived, and by then the first half has been sent.

## Decision

Emit text only once it is far enough behind the write head that nothing still
being produced could turn out to be part of it.

```
produced:  ...the key is sk-ant-api03-AbCd
                         └──────────────┘  held back
emitted:   ...the key is
```

The whole accumulated answer is re-governed as it grows, because a value that
began earlier is only identifiable once it is complete. What may then be released
is everything up to `window_chars` before the **governed** end.

Two supporting choices:

**Governance runs in batches**, once the answer has grown by `govern_every`
characters. One decision per token would be one round trip per token.

**A refusal stops the stream and says so**, as an error event the client can
render. It cannot unsay what was already sent — but the window means the value
being refused was never among it.

`PEP_STREAM_MODE=buffer` collects the whole answer, governs it, and emits once:
no blind spot, and no incremental delivery. For callers who would rather wait.

## The bug this design had first

The initial implementation held back `window_chars` from the end of the *raw
stream* rather than from the governed end. A secret near the start of a long
answer is nowhere near that end, so the margin did not cover it: its opening
characters were released, and the corrected text was then spliced on top,
producing `sk-aACTED]` in the client's output — both a leak and a corruption.

A test written against the intended property caught it, not a test written
against the implementation. The regression case is
`TestWindowMeasuredFromTheRightEnd`.

## Consequences

**Latency, not correctness, is what the window costs.** The client sees tokens one
window behind production — 1024 characters by default, a fraction of a second at
typical rates.

**A value longer than the window is a real blind spot.** It cannot be silent: if
governance rewrites text that has already been delivered, the stream stops with
an explicit refusal saying the window was too small, rather than splicing
inconsistent output. The default is comfortably longer than anything the
detectors recognise — the longest bounded pattern is a JWT prefix at a few
hundred characters, and a PEM header is under fifty — but a policy that redacts
long free-text spans should raise it or use buffer mode.

**Each streamed answer costs several decisions rather than one.** Bounded by
`govern_every`: a 4 KB answer at the default is about eight, not eight hundred.

**Non-streamed requests are unchanged.** They keep the single inbound and single
outbound decision, and the obligation handling that goes with it.
