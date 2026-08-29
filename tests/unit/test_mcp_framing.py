"""SSE and JSON-RPC framing.

Written before the proxy that uses it, and written against properties rather
than against a convenient input, because the last streaming bug in this repo --
a hold-back window measured from the wrong end -- passed every test that fed it
a whole body at once and split messages the moment it saw real chunking.
"""

from __future__ import annotations

import json

import pytest

from pep.mcp_proxy.framing import (
    POLICY_DENIED,
    SSEDecoder,
    SSEEvent,
    encode_sse,
    is_notification,
    is_request,
    iter_sse,
    rpc_error,
    rpc_method,
)

#: Recorded verbatim from the gateway's initialize response, LF-terminated.
REAL_FRAME = (
    "event: message\n"
    'data: {"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":'
    '{"listChanged":true}},"serverInfo":{"name":"mcphub","version":"1.0.27"}},'
    '"jsonrpc":"2.0","id":1}\n'
    "\n"
)


class TestDecodingRealFrames:
    def test_decodes_what_the_gateway_actually_sent(self) -> None:
        events = list(iter_sse(REAL_FRAME))
        assert len(events) == 1
        assert events[0].event == "message"
        assert events[0].json()["result"]["serverInfo"]["name"] == "mcphub"

    def test_round_trips_without_altering_the_message(self) -> None:
        event = next(iter(iter_sse(REAL_FRAME)))
        assert next(iter(iter_sse(encode_sse(event)))).json() == event.json()


class TestPartialFramesAreNeverEmitted:
    """The property the last streaming bug violated."""

    @pytest.mark.parametrize("size", [1, 2, 3, 7, 13, 64, 500])
    def test_an_event_split_across_any_chunk_size_arrives_once_and_whole(self, size: int) -> None:
        decoder = SSEDecoder()
        events = []
        for i in range(0, len(REAL_FRAME), size):
            events.extend(decoder.feed(REAL_FRAME[i : i + size]))
        events.extend(decoder.close())
        assert len(events) == 1
        assert events[0].json()["id"] == 1

    def test_nothing_is_emitted_before_the_terminating_blank_line(self) -> None:
        decoder = SSEDecoder()
        assert list(decoder.feed("event: message\n")) == []
        assert list(decoder.feed('data: {"jsonrpc":"2.0","id":1}\n')) == []
        # Still nothing: the event is complete only after the blank line.
        assert list(decoder.feed("")) == []
        assert len(list(decoder.feed("\n"))) == 1

    def test_a_crlf_split_between_chunks_is_not_read_as_a_blank_line(self) -> None:
        """The subtle one: \\r then \\n arriving separately is one break, not two.

        Splitting eagerly would end the event at the \\r and emit it without its
        data line.
        """
        decoder = SSEDecoder()
        assert list(decoder.feed("data: hello\r")) == []
        events = list(decoder.feed("\ndata: world\r\n\r\n"))
        assert len(events) == 1
        assert events[0].data == "hello\nworld"


class TestSpecDetailsThatBiteLater:
    def test_multiple_data_lines_join_with_newlines(self) -> None:
        assert next(iter(iter_sse("data: a\ndata: b\n\n"))).data == "a\nb"

    def test_comments_and_keepalives_carry_no_message(self) -> None:
        assert list(iter_sse(": keep-alive\n\n")) == []

    def test_exactly_one_space_after_the_colon_is_framing(self) -> None:
        assert next(iter(iter_sse("data:  padded\n\n"))).data == " padded"

    def test_a_field_with_no_data_dispatches_nothing(self) -> None:
        assert list(iter_sse("event: ping\n\n")) == []

    def test_an_unterminated_final_event_is_not_lost(self) -> None:
        """A clean close still delivered the message."""
        events = list(iter_sse('data: {"id":9}\n'))
        assert len(events) == 1 and events[0].json()["id"] == 9

    def test_json_that_is_not_json_does_not_raise(self) -> None:
        """The proxy passes through what it does not understand."""
        assert next(iter(iter_sse("data: not json\n\n"))).json() is None

    def test_multiple_events_in_one_body(self) -> None:
        body = 'data: {"id":1}\n\ndata: {"id":2}\n\ndata: {"id":3}\n\n'
        assert [e.json()["id"] for e in iter_sse(body)] == [1, 2, 3]

    def test_encoding_multiline_data_keeps_one_data_line_per_line(self) -> None:
        wire = encode_sse(SSEEvent(data="a\nb"))
        assert wire == "event: message\ndata: a\ndata: b\n\n"


class TestJsonRpcShapes:
    def test_a_request_has_a_method_and_an_id(self) -> None:
        assert is_request({"jsonrpc": "2.0", "id": 1, "method": "tools/call"})
        assert not is_notification({"jsonrpc": "2.0", "id": 1, "method": "tools/call"})

    def test_a_notification_has_no_id_and_must_never_be_answered(self) -> None:
        notification = {"jsonrpc": "2.0", "method": "notifications/initialized"}
        assert is_notification(notification)
        assert not is_request(notification)

    def test_an_id_of_zero_is_still_an_id(self) -> None:
        """Falsy but present. Treating it as absent would answer a notification."""
        assert is_request({"jsonrpc": "2.0", "id": 0, "method": "tools/call"})
        assert not is_notification({"jsonrpc": "2.0", "id": 0, "method": "tools/call"})

    def test_a_response_is_neither(self) -> None:
        assert not is_request({"jsonrpc": "2.0", "id": 1, "result": {}})
        assert not is_notification({"jsonrpc": "2.0", "id": 1, "result": {}})

    def test_method_of_a_non_mapping_is_none(self) -> None:
        assert rpc_method(["not", "a", "message"]) is None
        assert rpc_method(None) is None

    def test_a_denial_is_a_well_formed_error_carrying_the_same_id(self) -> None:
        body = rpc_error(7, POLICY_DENIED, "denied", {"decision_id": "d_1"})
        assert body == {
            "jsonrpc": "2.0",
            "id": 7,
            "error": {
                "code": POLICY_DENIED,
                "message": "denied",
                "data": {"decision_id": "d_1"},
            },
        }
        assert json.loads(json.dumps(body)) == body
