"""Server-sent events and JSON-RPC, as MCP actually puts them on the wire.

A governing proxy sits in the middle of a protocol it did not design, and the
first duty is to not corrupt it. Everything here is about that: decode frames
only once they are whole, preserve what was sent, and hand the rest back
untouched.

The decoder is incremental because the proxy reads a streamed body in chunks and
an event can straddle any chunk boundary. Emitting an event before its
terminating blank line has arrived is the same mistake as governing a token
stream against the wrong end of the window -- it looks right in a test that
feeds the whole body at once, and it splits messages in production.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "SSEDecoder",
    "SSEEvent",
    "encode_sse",
    "is_notification",
    "is_request",
    "iter_sse",
    "rpc_error",
    "rpc_id",
    "rpc_method",
]

#: JSON-RPC error codes MCP inherits. -32000 to -32099 are implementation
#: defined, which is where a governance refusal belongs: it is not a malformed
#: request and not an internal fault.
INVALID_REQUEST = -32600
INTERNAL_ERROR = -32603
POLICY_DENIED = -32001

#: SSE line terminators, in spec order. A CRLF must be consumed as one break, so
#: it comes first: splitting on CR then LF would manufacture an empty line and
#: end the event early.
_LINE_BREAK = re.compile(r"\r\n|\r|\n")


@dataclass(frozen=True, slots=True)
class SSEEvent:
    """One complete server-sent event."""

    data: str
    event: str = "message"
    id: str | None = None
    retry: int | None = None

    def json(self) -> Any:
        """The data field parsed as JSON, or None if it is not JSON.

        MCP puts one JSON-RPC message in each event's data, but a comment,
        keep-alive, or a server doing something else must not raise here: the
        proxy's job is to pass through what it does not understand.
        """
        try:
            return json.loads(self.data)
        except ValueError:
            return None


@dataclass
class SSEDecoder:
    """Feed it bytes; it yields events once they are complete.

    Holds an incomplete tail across calls. ``feed`` never yields an event whose
    terminating blank line has not arrived.
    """

    _buffer: str = ""
    _fields: list[tuple[str, str]] = field(default_factory=list)

    def feed(self, chunk: str) -> Iterator[SSEEvent]:
        self._buffer += chunk
        # An event ends at a blank line. Anything after the last complete line
        # break is a partial line and stays in the buffer -- including the case
        # where the buffer ends mid-CRLF, which is why the tail is kept whole
        # rather than split eagerly.
        while True:
            match = _LINE_BREAK.search(self._buffer)
            if match is None:
                return
            if self._buffer.endswith("\r") and match.end() == len(self._buffer):
                # Could be the first half of a CRLF; wait for the next chunk.
                return
            line = self._buffer[: match.start()]
            self._buffer = self._buffer[match.end() :]
            if line == "":
                event = self._build()
                self._fields.clear()
                if event is not None:
                    yield event
                continue
            if line.startswith(":"):
                # A comment. Keep-alives arrive this way and carry no message.
                continue
            name, _, value = line.partition(":")
            # Exactly one leading space is part of the framing, not the value.
            self._fields.append((name, value[1:] if value.startswith(" ") else value))

    def close(self) -> Iterator[SSEEvent]:
        """Flush an event left unterminated when the stream ended.

        A stream that ends without a final blank line has still delivered its
        last event; dropping it would lose a whole message on a clean close.
        """
        if self._buffer:
            for line in _LINE_BREAK.split(self._buffer):
                if line and not line.startswith(":"):
                    name, _, value = line.partition(":")
                    self._fields.append((name, value[1:] if value.startswith(" ") else value))
            self._buffer = ""
        event = self._build()
        self._fields.clear()
        if event is not None:
            yield event

    def _build(self) -> SSEEvent | None:
        if not self._fields:
            return None
        data_lines = [v for k, v in self._fields if k == "data"]
        if not data_lines:
            # Fields but no data: per spec this dispatches nothing.
            return None
        name = next((v for k, v in self._fields if k == "event"), "message")
        ident = next((v for k, v in self._fields if k == "id"), None)
        retry_raw = next((v for k, v in self._fields if k == "retry"), None)
        retry = int(retry_raw) if retry_raw and retry_raw.isdigit() else None
        return SSEEvent(data="\n".join(data_lines), event=name or "message", id=ident, retry=retry)


def iter_sse(body: str) -> Iterator[SSEEvent]:
    """Decode a complete SSE body. Convenience over SSEDecoder for whole bodies."""
    decoder = SSEDecoder()
    yield from decoder.feed(body)
    yield from decoder.close()


def encode_sse(event: SSEEvent) -> str:
    """Render an event back onto the wire.

    Multi-line data becomes one ``data:`` line per line, which is how it was
    read; joining them with anything else would change the message.
    """
    out = []
    if event.event and event.event != "message":
        out.append(f"event: {event.event}")
    else:
        out.append("event: message")
    if event.id is not None:
        out.append(f"id: {event.id}")
    if event.retry is not None:
        out.append(f"retry: {event.retry}")
    out.extend(f"data: {line}" for line in event.data.split("\n"))
    return "\n".join(out) + "\n\n"


def rpc_method(message: Any) -> str | None:
    if isinstance(message, Mapping):
        method = message.get("method")
        return method if isinstance(method, str) else None
    return None


def rpc_id(message: Any) -> Any:
    return message.get("id") if isinstance(message, Mapping) else None


def is_request(message: Any) -> bool:
    """A call expecting a response: it has a method and an id."""
    return rpc_method(message) is not None and rpc_id(message) is not None


def is_notification(message: Any) -> bool:
    """A method with no id. It gets no response, so it must never be answered."""
    return rpc_method(message) is not None and rpc_id(message) is None


def rpc_error(request_id: Any, code: int, message: str, data: Any = None) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": request_id, "error": error}
