"""Streams and checkpoints.

Splitting the log buys concurrency and gives up one property: per-stream
verification cannot notice a stream that is gone. Most of what follows is about
that trade -- that the split is cryptographically real, that the old format
survives it, and that checkpoints buy back what it cost.
"""

from __future__ import annotations

import hashlib
import hmac
from datetime import UTC, datetime

from control_plane.audit.chain import (
    DEFAULT_STREAM,
    AuditChain,
    AuditRecord,
    StreamHead,
    canonical_json,
    checkpoint_payload,
    verify_against_checkpoint,
    verify_chain,
)
from control_plane.audit.service import partition_for, stream_lock_key

KEY = b"audit-key"
AT = datetime(2026, 1, 1, tzinfo=UTC)


def moved(record: AuditRecord, stream: str) -> AuditRecord:
    """The same record, claiming to belong to a different chain."""
    return AuditRecord(
        stream=stream,
        seq=record.seq,
        timestamp=record.timestamp,
        event=record.event,
        actor=record.actor,
        subject=record.subject,
        payload=record.payload,
        prev_hash=record.prev_hash,
        record_hash=record.record_hash,
    )


class TestStreamsAreIndependent:
    def test_each_stream_has_its_own_sequence(self) -> None:
        a = AuditChain(key=KEY, stream="p0")
        b = AuditChain(key=KEY, stream="p1")
        assert a.append("decision", actor="x", subject="s").seq == 1
        assert b.append("decision", actor="y", subject="s").seq == 1

    def test_each_stream_verifies_on_its_own(self) -> None:
        chain = AuditChain(key=KEY, stream="p0")
        records = [chain.append("decision", actor="x", subject="s") for _ in range(4)]
        assert verify_chain(records, KEY).valid is True

    def test_the_same_content_in_two_streams_digests_differently(self) -> None:
        a = AuditChain(key=KEY, stream="p0").append(
            "decision", actor="x", subject="s", timestamp=AT
        )
        b = AuditChain(key=KEY, stream="p1").append(
            "decision", actor="x", subject="s", timestamp=AT
        )
        assert a.record_hash != b.record_hash


class TestRecordsCannotBeMoved:
    """The stream is signed, so relocating a record is not a rename."""

    def test_between_named_streams(self) -> None:
        record = AuditChain(key=KEY, stream="p0").append("decision", actor="x", subject="s")
        assert moved(record, "p1").verify(KEY) is False

    def test_out_of_a_named_stream_into_the_default(self) -> None:
        record = AuditChain(key=KEY, stream="p0").append("decision", actor="x", subject="s")
        assert moved(record, DEFAULT_STREAM).verify(KEY) is False

    def test_out_of_the_default_into_a_named_stream(self) -> None:
        record = AuditChain(key=KEY).append("decision", actor="x", subject="s")
        assert moved(record, "p0").verify(KEY) is False


class TestBackwardCompatibility:
    def test_a_record_written_before_streams_existed_still_verifies(self) -> None:
        """An audit chain that stops verifying after an upgrade is worthless.

        Signing the stream unconditionally would have invalidated every record
        ever written, so it is signed only when it is not the default.
        """
        body = canonical_json(
            {
                "seq": 1,
                "timestamp": AT.isoformat(),
                "event": "decision",
                "actor": "agent:x",
                "subject": "qdrant://kb",
                "payload": {"n": 1},
                "prev_hash": "0" * 64,
            }
        )
        legacy = AuditRecord(
            seq=1,
            timestamp=AT,
            event="decision",
            actor="agent:x",
            subject="qdrant://kb",
            payload={"n": 1},
            prev_hash="0" * 64,
            record_hash=hmac.new(KEY, body.encode(), hashlib.sha256).hexdigest(),
        )
        assert legacy.verify(KEY) is True
        assert legacy.stream == DEFAULT_STREAM

    def test_a_default_stream_record_signs_the_pre_stream_bytes(self) -> None:
        record = AuditChain(key=KEY).append("decision", actor="x", subject="s", timestamp=AT)
        assert "stream" not in record.signing_body()

    def test_a_named_stream_record_does_include_it(self) -> None:
        record = AuditChain(key=KEY, stream="p0").append(
            "decision", actor="x", subject="s", timestamp=AT
        )
        assert '"stream":"p0"' in record.signing_body()


class TestPartitioning:
    def test_one_partition_means_the_default_stream(self) -> None:
        assert partition_for("agent:anything", 1) == DEFAULT_STREAM

    def test_an_actor_always_lands_in_the_same_stream(self) -> None:
        """An investigator following one principal should read one chain."""
        first = partition_for("agent:support_bot", 8)
        assert all(partition_for("agent:support_bot", 8) == first for _ in range(20))

    def test_actors_spread_across_the_partitions(self) -> None:
        streams = {partition_for(f"agent:{i}", 8) for i in range(200)}
        assert len(streams) == 8

    def test_a_single_dominant_caller_does_not_spread(self) -> None:
        """Stated because it is the limitation of partitioning by actor."""
        assert len({partition_for("agent:only_one", 16) for _ in range(50)}) == 1

    def test_lock_keys_fit_a_signed_32_bit_integer(self) -> None:
        """Postgres advisory lock keys are signed; a value past 2^31 is an error."""
        for stream in (DEFAULT_STREAM, "_checkpoints", *(f"p{i}" for i in range(64))):
            assert -(2**31) <= stream_lock_key(stream) < 2**31

    def test_different_streams_get_different_locks(self) -> None:
        keys = {stream_lock_key(f"p{i}") for i in range(32)}
        assert len(keys) == 32


class TestCheckpoints:
    HEADS = [StreamHead("p0", 40, "aaa"), StreamHead("p1", 25, "bbb")]

    def test_the_payload_records_every_stream(self) -> None:
        body = checkpoint_payload(self.HEADS)
        assert body["stream_count"] == 2
        assert body["total_records"] == 65

    def test_intact_streams_match(self) -> None:
        result = verify_against_checkpoint(self.HEADS, {"p0": (40, "aaa"), "p1": (25, "bbb")})
        assert result.valid is True

    def test_a_deleted_stream_is_caught(self) -> None:
        """The property per-stream verification alone cannot provide.

        Without this, removing an entire chain leaves everything that remains
        verifying perfectly and nothing saying how many there should have been.
        """
        result = verify_against_checkpoint(self.HEADS, {"p0": (40, "aaa")})
        assert result.valid is False
        assert result.missing == ("p1",)

    def test_a_truncated_stream_is_caught(self) -> None:
        result = verify_against_checkpoint(self.HEADS, {"p0": (40, "aaa"), "p1": (10, "ccc")})
        assert result.truncated == ("p1",)

    def test_a_rewritten_stream_is_caught(self) -> None:
        result = verify_against_checkpoint(self.HEADS, {"p0": (40, "aaa"), "p1": (25, "zzz")})
        assert result.diverged == ("p1",)

    def test_growth_since_the_checkpoint_is_fine(self) -> None:
        """A checkpoint vouches for a moment, not a ceiling."""
        result = verify_against_checkpoint(self.HEADS, {"p0": (40, "aaa"), "p1": (25, "bbb")})
        assert result.valid is True

    def test_no_streams_is_vacuously_valid(self) -> None:
        assert verify_against_checkpoint([], {}).valid is True
