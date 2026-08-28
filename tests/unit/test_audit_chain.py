"""The tamper-evident audit chain."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from itertools import pairwise

from control_plane.audit.chain import (
    GENESIS_HASH,
    AuditChain,
    AuditEvent,
    AuditRecord,
    canonical_json,
    content_digest,
    verify_chain,
)

KEY = b"audit-key"
OTHER_KEY = b"attacker-key"


def build(count: int = 5, key: bytes = KEY) -> list[AuditRecord]:
    chain = AuditChain(key=key)
    start = datetime(2026, 1, 1, tzinfo=UTC)
    return [
        chain.append(
            AuditEvent.DECISION,
            actor=f"agent:{index}",
            subject="qdrant://kb",
            payload={"effect": "allow", "index": index},
            timestamp=start + timedelta(seconds=index),
        )
        for index in range(count)
    ]


def tamper(record: AuditRecord, **changes) -> AuditRecord:
    fields = {
        "seq": record.seq,
        "timestamp": record.timestamp,
        "event": record.event,
        "actor": record.actor,
        "subject": record.subject,
        "payload": record.payload,
        "prev_hash": record.prev_hash,
        "record_hash": record.record_hash,
    }
    fields.update(changes)
    return AuditRecord(**fields)


class TestChainConstruction:
    def test_first_record_links_to_genesis(self) -> None:
        assert build(1)[0].prev_hash == GENESIS_HASH

    def test_each_record_links_to_its_predecessor(self) -> None:
        records = build(4)
        for previous, current in pairwise(records):
            assert current.prev_hash == previous.record_hash

    def test_sequence_numbers_are_contiguous(self) -> None:
        assert [r.seq for r in build(4)] == [1, 2, 3, 4]

    def test_a_clean_chain_verifies(self) -> None:
        assert verify_chain(build(5), KEY).valid is True

    def test_resuming_continues_an_existing_chain(self) -> None:
        first = build(3)
        chain = AuditChain.resuming(KEY, head_hash=first[-1].record_hash, next_seq=4)
        fourth = chain.append(AuditEvent.SCAN_COMPLETED, actor="scanner", subject="pg://t")
        assert verify_chain([*first, fourth], KEY).valid is True


class TestTamperDetection:
    def test_edited_content_breaks_its_own_digest(self) -> None:
        records = build(5)
        records[2] = tamper(records[2], actor="mallory")
        result = verify_chain(records, KEY)
        assert result.valid is False
        assert result.corrupted == (3,)

    def test_resealing_with_the_wrong_key_is_caught(self) -> None:
        """An attacker with database write access but not the audit key."""
        records = build(5)
        records[2] = tamper(records[2], actor="mallory").with_hash(OTHER_KEY)
        result = verify_chain(records, KEY)
        assert result.valid is False
        assert 3 in result.corrupted
        assert 4 in result.broken_links

    def test_a_deleted_record_leaves_a_gap(self) -> None:
        records = build(5)
        del records[2]
        result = verify_chain(records, KEY)
        assert result.valid is False
        assert result.sequence_errors == (4,)
        assert result.broken_links == (4,)

    def test_a_reordered_payload_still_verifies(self) -> None:
        """Canonical encoding means key order is not part of the content."""
        record = build(1)[0]
        reordered = tamper(record, payload=dict(reversed(list(record.payload.items()))))
        assert reordered.verify(KEY) is True

    def test_every_fault_is_reported_not_just_the_first(self) -> None:
        records = build(6)
        records[1] = tamper(records[1], actor="x")
        records[4] = tamper(records[4], subject="y")
        result = verify_chain(records, KEY)
        assert set(result.corrupted) == {2, 5}


class TestCanonicalisation:
    def test_key_order_does_not_change_the_encoding(self) -> None:
        assert canonical_json({"b": 1, "a": 2}) == canonical_json({"a": 2, "b": 1})

    def test_output_is_ascii_only(self) -> None:
        encoded = canonical_json({"note": "café — naïve"})
        assert encoded.isascii()

    def test_datetimes_encode_as_utc_iso(self) -> None:
        encoded = canonical_json({"at": datetime(2026, 1, 1, tzinfo=UTC)})
        assert "2026-01-01T00:00:00+00:00" in encoded


class TestContentDigest:
    def test_same_content_same_digest(self) -> None:
        assert content_digest("secret document", KEY) == content_digest("secret document", KEY)

    def test_different_content_different_digest(self) -> None:
        assert content_digest("a", KEY) != content_digest("b", KEY)

    def test_digest_does_not_contain_the_content(self) -> None:
        assert "secret" not in content_digest("secret document", KEY)
