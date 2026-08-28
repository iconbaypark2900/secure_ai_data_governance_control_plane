"""Governing a streamed completion.

A chat client sets ``stream: true`` and expects tokens as they are produced. A
governance proxy has the opposite instinct: it wants the whole answer before
deciding anything. Reconciling the two is the only interesting problem in this
module.

**The hold-back window.** Text is emitted only once it is far enough behind the
write head that no detector could still be part-way through matching it. If the
longest thing worth catching is shorter than the window, a value can never be
emitted before it is recognised: by the time the window releases a character,
everything that character could have been part of has already been seen.

    produced so far:  ...the key is sk-ant-api03-AbCd
                                     └──────────────┘ held back
    emitted:          ...the key is

The cost is latency, not correctness: the client sees tokens one window behind
production. The residual risk is a sensitive value *longer* than the window,
which is why the window is configurable and why ``buffer`` mode exists for
callers who would rather wait than accept any blind spot at all.

**Governance runs in batches.** Asking the control plane about every token would
be one round trip per token. Instead the window is drained when it has grown by
``govern_every`` characters, which turns a long answer into a handful of
decisions rather than hundreds.

**A refusal mid-stream cannot unsay what was said.** It can only stop, and emit
an error the client can see. The window is what makes that sufficient: the thing
being refused has not been emitted yet.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Awaitable, Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "DEFAULT_GOVERN_EVERY",
    "DEFAULT_WINDOW_CHARS",
    "DONE",
    "GovernedChunk",
    "StreamGovernor",
    "delta_text",
    "parse_sse_event",
    "rebuild_delta",
    "sse",
]

#: The terminator OpenAI-compatible streams send.
DONE = "[DONE]"

#: How far behind production to emit. Comfortably longer than any value the
#: detectors recognise: the longest bounded pattern is a JWT prefix at a few
#: hundred characters, and a PEM header -- the part that gives a private key away
#: -- is under fifty.
DEFAULT_WINDOW_CHARS = 1024

#: Drain the window once it has grown by this much, to bound decisions per stream.
DEFAULT_GOVERN_EVERY = 512


def parse_sse_event(line: str) -> dict[str, Any] | str | None:
    """One SSE line: a decoded event, the ``[DONE]`` sentinel, or None to skip."""
    stripped = line.strip()
    if not stripped or not stripped.startswith("data:"):
        return None
    payload = stripped[len("data:") :].strip()
    if payload == DONE:
        return DONE
    try:
        return json.loads(payload)
    except json.JSONDecodeError:
        return None


def sse(payload: Any) -> bytes:
    """Frame a value as an SSE data line."""
    body = payload if isinstance(payload, str) else json.dumps(payload, separators=(",", ":"))
    return f"data: {body}\n\n".encode()


def delta_text(event: dict[str, Any]) -> str:
    """The text a streaming chunk carries, across the shapes providers use."""
    parts: list[str] = []
    for choice in event.get("choices") or []:
        delta = choice.get("delta") or choice.get("message") or {}
        content = delta.get("content")
        if isinstance(content, str):
            parts.append(content)
        elif isinstance(content, list):
            parts.extend(
                str(block.get("text", ""))
                for block in content
                if isinstance(block, dict) and block.get("type") == "text"
            )
    return "".join(parts)


def rebuild_delta(template: dict[str, Any], text: str) -> dict[str, Any]:
    """A chunk shaped like ``template`` but carrying ``text``.

    Reusing the provider's own envelope keeps ids, model names, and whatever
    else a client reads intact, rather than inventing a chunk that merely looks
    close enough.
    """
    rebuilt = dict(template)
    choices = template.get("choices") or [{"index": 0, "delta": {}}]
    first = dict(choices[0])
    delta = dict(first.get("delta") or {})
    delta["content"] = text
    delta.pop("role", None)
    first["delta"] = delta
    first.pop("finish_reason", None)
    first.pop("message", None)
    rebuilt["choices"] = [first]
    return rebuilt


@dataclass(frozen=True, slots=True)
class GovernedChunk:
    """Something to send to the client."""

    text: str = ""
    #: Set when governance refused; the stream must stop after emitting this.
    refusal: str | None = None

    @property
    def is_refusal(self) -> bool:
        return self.refusal is not None


#: Governs a span of text: returns the rewritten text, or None to refuse.
Governor = Callable[[str], Awaitable[tuple[str, str | None]]]


@dataclass
class StreamGovernor:
    """Accumulates a stream and releases the part that is safe to release."""

    govern: Governor
    window_chars: int = DEFAULT_WINDOW_CHARS
    govern_every: int = DEFAULT_GOVERN_EVERY

    _seen: str = ""
    _governed_at: int = 0
    _emitted: str = ""
    _refused: bool = False
    #: Kept so the caller can report the outcome: a stream that ended in a
    #: refusal did not deliver the answer, and the record should say so.
    refused_reason: str | None = field(default=None, init=False)
    decisions: int = 0
    held_back_at_end: int = field(default=0, init=False)
    #: Set if governance ever rewrote text that had already been sent, which can
    #: only happen for a value longer than the window. Surfaced rather than
    #: swallowed: it means the window was too small for what arrived.
    overran_window: bool = field(default=False, init=False)

    async def feed(self, text: str) -> GovernedChunk | None:
        """Take newly produced text; return whatever is now safe to emit."""
        if self._refused or not text:
            return None
        self._seen += text
        if len(self._seen) - self._governed_at < self.govern_every:
            return None
        return await self._drain(final=False)

    async def finish(self) -> GovernedChunk | None:
        """Flush the held-back tail once the stream is complete."""
        if self._refused:
            return None
        self.held_back_at_end = max(0, len(self._seen) - len(self._emitted))
        return await self._drain(final=True)

    async def _drain(self, *, final: bool) -> GovernedChunk | None:
        """Govern everything seen so far, and release what is safely behind.

        The whole accumulated text is governed each time, not just the new part:
        a value is only recognisable once all of it has arrived, and governing
        the tail in isolation would miss anything that began earlier.

        What may then be released is everything up to ``window_chars`` before the
        *governed* end -- not before the end of the raw stream. Holding back from
        the wrong end is the bug this replaced: a secret near the start of a long
        answer sits far from the stream's end, so a margin measured from there
        does not cover it, and its opening characters go out before the rest of
        it has arrived to identify it.
        """
        if not self._seen:
            return None
        self._governed_at = len(self._seen)
        governed, refusal = await self.govern(self._seen)
        self.decisions += 1

        if refusal is not None:
            self._refused = True
            self.refused_reason = refusal
            # Nothing further is sent. What already went out is behind the
            # window, so it cannot contain the value being refused.
            return GovernedChunk(refusal=refusal)

        if not governed.startswith(self._emitted):
            # Governance rewrote something already delivered, which means a value
            # longer than the window straddled the boundary. The client has it;
            # splicing inconsistent text on top would only obscure that.
            self._refused = True
            self.overran_window = True
            self.refused_reason = "a value longer than the streaming window was found"
            return GovernedChunk(
                refusal=(
                    "a sensitive value longer than the streaming window was found "
                    "after part of it had already been delivered; raise "
                    "PEP_STREAM_WINDOW_CHARS or use buffer mode"
                )
            )

        safe_end = len(governed) if final else max(0, len(governed) - self.window_chars)
        if safe_end <= len(self._emitted):
            return None
        fresh = governed[len(self._emitted) : safe_end]
        self._emitted = governed[:safe_end]
        return GovernedChunk(text=fresh) if fresh else None


async def govern_stream(
    events: AsyncIterator[bytes],
    governor: StreamGovernor,
    *,
    on_refusal: Callable[[str], Any],
) -> AsyncIterator[bytes]:
    """Re-emit an SSE stream, governed.

    Non-content events -- the opening role chunk, usage totals, anything a
    provider adds -- pass through untouched: they carry no model output, and
    dropping them breaks clients that read them.
    """
    template: dict[str, Any] = {}
    async for raw in events:
        for line in raw.decode("utf-8", errors="ignore").splitlines():
            event = parse_sse_event(line)
            if event is None:
                continue
            if event == DONE:
                continue
            if not isinstance(event, dict):
                continue

            template = event
            text = delta_text(event)
            if not text:
                yield sse(event)
                continue

            chunk = await governor.feed(text)
            if chunk is None:
                continue
            if chunk.is_refusal:
                yield sse(on_refusal(chunk.refusal or ""))
                yield sse(DONE)
                return
            yield sse(rebuild_delta(template, chunk.text))

    final = await governor.finish()
    if final is not None:
        if final.is_refusal:
            yield sse(on_refusal(final.refusal or ""))
        elif final.text:
            yield sse(
                rebuild_delta(template or {"choices": [{"index": 0, "delta": {}}]}, final.text)
            )
    yield sse(DONE)


def iter_lines(payload: Iterable[bytes]) -> list[str]:
    """Split raw SSE bytes into lines. Exposed for tests."""
    return [
        line for block in payload for line in block.decode("utf-8", errors="ignore").splitlines()
    ]
