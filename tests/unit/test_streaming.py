"""Governing a streamed completion.

The property under test throughout: nothing reaches the client until it is far
enough behind the write head that no detector could still be matching it. That is
what lets a proxy stream at all rather than buffering the whole answer.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from pep.reverse_proxy.streaming import (
    DONE,
    GovernedChunk,
    StreamGovernor,
    delta_text,
    parse_sse_event,
    rebuild_delta,
    sse,
)


def chunk(text: str, **extra) -> dict:
    return {
        "id": "chatcmpl-1",
        "model": "gpt-4o",
        "choices": [{"index": 0, "delta": {"content": text}}],
        **extra,
    }


async def passthrough(span: str) -> tuple[str, str | None]:
    return span, None


def redacting(secret: str, replacement: str = "[REDACTED]"):
    async def govern(span: str) -> tuple[str, str | None]:
        return span.replace(secret, replacement), None

    return govern


def refusing_on(trigger: str):
    async def govern(span: str) -> tuple[str, str | None]:
        if trigger in span:
            return span, "credentials never move"
        return span, None

    return govern


class TestSSEParsing:
    def test_a_data_line_decodes(self) -> None:
        assert parse_sse_event('data: {"a": 1}') == {"a": 1}

    def test_the_terminator_is_recognised(self) -> None:
        assert parse_sse_event("data: [DONE]") == DONE

    @pytest.mark.parametrize("line", ["", "   ", ": keep-alive", "event: ping", "data: {oops"])
    def test_noise_is_skipped(self, line: str) -> None:
        assert parse_sse_event(line) is None

    def test_framing_round_trips(self) -> None:
        assert sse({"a": 1}) == b'data: {"a":1}\n\n'
        assert sse(DONE) == b"data: [DONE]\n\n"

    def test_text_is_extracted_from_either_shape(self) -> None:
        assert delta_text(chunk("hello")) == "hello"
        assert (
            delta_text({"choices": [{"delta": {"content": [{"type": "text", "text": "hi"}]}}]})
            == "hi"
        )
        assert delta_text({"choices": [{"delta": {"role": "assistant"}}]}) == ""

    def test_rebuilding_keeps_the_providers_envelope(self) -> None:
        """Ids and model names are read by clients; inventing a chunk breaks them."""
        rebuilt = rebuild_delta(chunk("original", system_fingerprint="fp_1"), "governed")
        assert rebuilt["id"] == "chatcmpl-1"
        assert rebuilt["model"] == "gpt-4o"
        assert rebuilt["system_fingerprint"] == "fp_1"
        assert rebuilt["choices"][0]["delta"]["content"] == "governed"


class TestHoldBackWindow:
    async def test_nothing_is_emitted_until_the_window_fills(self) -> None:
        governor = StreamGovernor(passthrough, window_chars=20, govern_every=5)
        assert await governor.feed("x" * 10) is None

    async def test_text_flows_once_it_is_behind_the_window(self) -> None:
        governor = StreamGovernor(passthrough, window_chars=10, govern_every=5)
        assert await governor.feed("a" * 10) is None
        out = await governor.feed("b" * 10)
        assert out is not None
        assert out.text == "a" * 10

    async def test_the_tail_is_flushed_at_the_end(self) -> None:
        answer = "hello world, this is the whole answer"
        governor = StreamGovernor(passthrough, window_chars=10, govern_every=5)
        await governor.feed(answer)
        final = await governor.finish()
        assert final is not None
        assert answer.endswith(final.text)

    async def test_the_client_sees_the_whole_answer_and_nothing_twice(self) -> None:
        governor = StreamGovernor(passthrough, window_chars=8, govern_every=4)
        answer = "The refund policy allows returns within thirty days of purchase."
        seen = ""
        for i in range(0, len(answer), 3):
            out = await governor.feed(answer[i : i + 3])
            if out:
                seen += out.text
        final = await governor.finish()
        if final:
            seen += final.text
        assert seen == answer

    async def test_governance_runs_in_batches_not_per_token(self) -> None:
        """One round trip per token would make streaming unusable."""
        governor = StreamGovernor(passthrough, window_chars=16, govern_every=64)
        for _ in range(100):
            await governor.feed("token ")
        await governor.finish()
        assert governor.decisions <= 12


class TestRedaction:
    async def test_a_secret_never_reaches_the_client(self) -> None:
        """The property the whole design exists for."""
        secret = "sk-ant-api03-AbCdEfGh1234567890"
        governor = StreamGovernor(redacting(secret), window_chars=64, govern_every=16)
        answer = f"Use the key {secret} to authenticate the request and retry."

        seen = ""
        for i in range(0, len(answer), 5):
            out = await governor.feed(answer[i : i + 5])
            if out:
                seen += out.text
                assert secret not in seen
                assert secret[:20] not in seen
        final = await governor.finish()
        if final:
            seen += final.text

        assert secret not in seen
        assert "[REDACTED]" in seen

    async def test_a_secret_split_across_chunks_is_still_caught(self) -> None:
        """Token boundaries fall wherever the model puts them, not where we want."""
        secret = "sk-ant-api03-AbCdEfGh1234567890"
        governor = StreamGovernor(redacting(secret), window_chars=64, govern_every=8)
        seen = ""
        for piece in ["Here: ", "sk-ant-", "api03-", "AbCdEf", "Gh12345", "67890", " done."]:
            out = await governor.feed(piece)
            if out:
                seen += out.text
        final = await governor.finish()
        if final:
            seen += final.text
        assert secret not in seen
        assert "[REDACTED]" in seen


class TestRefusal:
    async def test_a_refusal_stops_the_stream(self) -> None:
        governor = StreamGovernor(refusing_on("AKIA"), window_chars=32, govern_every=8)
        emitted = ""
        refusal = None
        for piece in ["The key is ", "AKIAIOSFODNN7EXAMPLE", " and it works."]:
            out = await governor.feed(piece)
            if out and out.is_refusal:
                refusal = out.refusal
                break
            if out:
                emitted += out.text
        assert refusal == "credentials never move"
        assert "AKIA" not in emitted

    async def test_nothing_is_emitted_after_a_refusal(self) -> None:
        governor = StreamGovernor(refusing_on("bad"), window_chars=8, govern_every=4)
        await governor.feed("something bad happened here, and more text after it")
        assert await governor.feed("more") is None
        assert await governor.finish() is None


class TestEdges:
    async def test_an_empty_stream_produces_nothing(self) -> None:
        governor = StreamGovernor(passthrough, window_chars=16, govern_every=8)
        assert await governor.feed("") is None
        assert await governor.finish() is None

    async def test_a_response_shorter_than_the_window_still_arrives(self) -> None:
        governor = StreamGovernor(passthrough, window_chars=1024, govern_every=512)
        await governor.feed("short")
        final = await governor.finish()
        assert final is not None
        assert final.text == "short"

    def test_a_governed_chunk_reports_its_kind(self) -> None:
        assert GovernedChunk(text="x").is_refusal is False
        assert GovernedChunk(refusal="no").is_refusal is True


class TestWindowMeasuredFromTheRightEnd:
    """Regression: the margin must be measured from the governed end, not the
    end of the raw stream.

    The first implementation held back `window` characters from the end of
    everything produced so far. A secret near the *start* of a long answer sits
    far from that end, so the margin did not cover it and its opening characters
    were released before the rest had arrived to identify it -- after which the
    corrected text spliced on top, producing 'sk-aACTED]'.
    """

    async def test_a_secret_early_in_a_long_answer_is_still_caught(self) -> None:
        secret = "sk-ant-api03-AbCdEfGh1234567890"
        answer = f"Use the key {secret} to authenticate. " + ("More explanation. " * 40)
        governor = StreamGovernor(redacting(secret), window_chars=64, govern_every=16)

        seen = ""
        for i in range(0, len(answer), 5):
            out = await governor.feed(answer[i : i + 5])
            if out:
                seen += out.text
                assert secret[:8] not in seen
        final = await governor.finish()
        if final:
            seen += final.text

        assert seen == answer.replace(secret, "[REDACTED]")
        assert governor.overran_window is False

    async def test_a_value_longer_than_the_window_is_reported_not_spliced(self) -> None:
        """The residual risk, made visible instead of producing mangled output."""
        secret = "S" * 200
        answer = f"prefix {secret} suffix, and then a great deal more text. " * 3
        governor = StreamGovernor(redacting(secret), window_chars=16, govern_every=8)

        refusal = None
        for i in range(0, len(answer), 7):
            out = await governor.feed(answer[i : i + 7])
            if out and out.is_refusal:
                refusal = out.refusal
                break
        assert refusal is not None
        assert "longer than the streaming window" in refusal
        assert governor.overran_window is True
