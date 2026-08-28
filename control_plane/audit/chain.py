"""A tamper-evident audit log.

Each record commits to the one before it: its digest covers both its own content
and its predecessor's digest. Altering any historical record therefore breaks
every digest after it, and the break is detectable by recomputation alone -- no
external timestamping service, no append-only storage engine required.

The digest is an HMAC, not a bare hash. A bare hash chain proves *ordering*: an
attacker who can write to the table can rewrite a record and recompute every
subsequent digest, and the chain still verifies. Keying the digest means that
forgery also requires the audit key, which lives outside the database. Read
access to the table is then enough to detect tampering, and is not enough to
perform it.

What is stored is deliberately thin. Audit records describe *that* something was
decided, by whom, about what -- never the sensitive content itself. Payload
content appears only as a salted digest, which answers "was it this exact
document?" without holding the document.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

__all__ = [
    "GENESIS_HASH",
    "AuditChain",
    "AuditEvent",
    "AuditRecord",
    "ChainVerification",
    "as_utc",
    "canonical_json",
    "content_digest",
    "verify_chain",
]

#: The predecessor digest of the first record in a chain.
GENESIS_HASH = "0" * 64

#: The stream every record goes to when nothing else is configured.
DEFAULT_STREAM = "default"

#: Where checkpoints live. Reserved: a checkpoint records the head of every other
#: stream, so it cannot be one of the streams it is vouching for.
CHECKPOINT_STREAM = "_checkpoints"


class AuditEvent(StrEnum):
    """The event types the control plane records."""

    DECISION = "decision"
    DECISION_OUTCOME = "decision.outcome"
    DECISION_OUTCOME_CONFLICT = "decision.outcome_conflict"
    POLICY_CREATED = "policy.created"
    POLICY_UPDATED = "policy.updated"
    POLICY_DELETED = "policy.deleted"
    POLICY_ENABLED = "policy.enabled"
    POLICY_DISABLED = "policy.disabled"
    ASSET_REGISTERED = "asset.registered"
    ASSET_UPDATED = "asset.updated"
    ASSET_CLASSIFIED = "asset.classified"
    ASSET_DELETED = "asset.deleted"
    PRINCIPAL_CREATED = "principal.created"
    PRINCIPAL_UPDATED = "principal.updated"
    APPROVAL_REQUESTED = "approval.requested"
    APPROVAL_GRANTED = "approval.granted"
    APPROVAL_DENIED = "approval.denied"
    APPROVAL_REDEEMED = "approval.redeemed"
    KEY_ISSUED = "apikey.issued"
    KEY_REVOKED = "apikey.revoked"
    CHECKPOINT = "audit.checkpoint"
    SCAN_COMPLETED = "scan.completed"
    CATALOG_DISCOVERED = "catalog.discovered"
    TOKENS_REVERSED = "tokens.reversed"
    TOKENS_VERIFIED = "tokens.verified"
    CONFIG_CHANGED = "config.changed"


def as_utc(value: datetime) -> datetime:
    """Interpret a timestamp as UTC, attaching the zone if the driver dropped it.

    The chain only ever writes UTC, but not every backend hands it back that
    way: Postgres ``timestamptz`` returns an aware value while SQLite returns a
    naive one. Calling ``astimezone`` on a naive datetime would silently
    reinterpret it in the machine's local zone, changing the signed bytes and
    breaking verification on exactly the records that round-tripped through
    storage. Normalising here keeps the digest independent of the backend and of
    the verifying host's timezone.
    """
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def canonical_json(value: Any) -> str:
    """A byte-stable JSON encoding.

    Two structurally equal payloads must produce identical bytes on any machine
    and any Python version, or the chain will fail to verify after a restart.
    Sorted keys and fixed separators give that; ``ensure_ascii`` keeps the output
    pure ASCII so no locale or normalisation difference can intrude.
    """
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=_encode_unknown,
    )


def _encode_unknown(value: Any) -> Any:
    if isinstance(value, datetime):
        return as_utc(value).isoformat()
    if isinstance(value, (set, frozenset)):
        return sorted(value, key=repr)
    if isinstance(value, bytes):
        return value.hex()
    if hasattr(value, "to_dict"):
        return value.to_dict()
    return str(value)


def content_digest(payload: Any, key: bytes = b"") -> str:
    """A keyed digest of content the log must not store verbatim.

    Lets an investigator confirm that a specific document was the one a decision
    was made about, without the log itself becoming a copy of that document.
    """
    body = payload if isinstance(payload, str) else canonical_json(payload)
    return hmac.new(key or b"content-digest", body.encode("utf-8"), hashlib.sha256).hexdigest()


@dataclass(frozen=True, slots=True)
class AuditRecord:
    """One immutable entry.

    Records belong to a *stream*, and each stream is an independent chain with
    its own sequence and head. Splitting the log this way is what lets appends
    proceed concurrently -- one lock per stream rather than one for the whole
    system -- and it is also what makes a whole stream's disappearance invisible
    to per-stream verification, which is why checkpoints exist.
    """

    seq: int
    timestamp: datetime
    event: str
    actor: str
    subject: str
    payload: Mapping[str, Any] = field(default_factory=dict)
    prev_hash: str = GENESIS_HASH
    record_hash: str = ""
    stream: str = DEFAULT_STREAM

    def signing_body(self) -> str:
        """Exactly the bytes the digest covers.

        The digest deliberately excludes any database-assigned identifier: the
        chain must verify identically whether it is read from Postgres, restored
        from a backup, or streamed to cold storage.

        The stream is covered, so a record cannot be moved from one chain to
        another and still verify -- but only when it is *not* the default. A
        record in the default stream signs exactly the bytes it signed before
        streams existed, so every digest written by an earlier version keeps
        verifying after the upgrade. An audit chain whose whole value is holding
        over time cannot afford a schema change that invalidates its history.

        Moving a record still fails either way: into a named stream the field
        appears, out of one it disappears, and both change the signed bytes.
        """
        body: dict[str, Any] = {
            "seq": self.seq,
            "timestamp": as_utc(self.timestamp).isoformat(),
            "event": self.event,
            "actor": self.actor,
            "subject": self.subject,
            "payload": self.payload,
            "prev_hash": self.prev_hash,
        }
        if self.stream != DEFAULT_STREAM:
            body["stream"] = self.stream
        return canonical_json(body)

    def compute_hash(self, key: bytes) -> str:
        return hmac.new(key, self.signing_body().encode("utf-8"), hashlib.sha256).hexdigest()

    def with_hash(self, key: bytes) -> AuditRecord:
        return AuditRecord(
            stream=self.stream,
            seq=self.seq,
            timestamp=self.timestamp,
            event=self.event,
            actor=self.actor,
            subject=self.subject,
            payload=self.payload,
            prev_hash=self.prev_hash,
            record_hash=self.compute_hash(key),
        )

    def verify(self, key: bytes) -> bool:
        """Constant-time comparison, so verification cannot be used as an oracle."""
        return hmac.compare_digest(self.record_hash, self.compute_hash(key))

    def to_dict(self) -> dict[str, Any]:
        return {
            "stream": self.stream,
            "seq": self.seq,
            "timestamp": as_utc(self.timestamp).isoformat(),
            "event": self.event,
            "actor": self.actor,
            "subject": self.subject,
            "payload": dict(self.payload),
            "prev_hash": self.prev_hash,
            "record_hash": self.record_hash,
        }


@dataclass
class AuditChain:
    """Builds successive records in one stream, carrying the digest forward."""

    key: bytes
    head_hash: str = GENESIS_HASH
    next_seq: int = 1
    stream: str = DEFAULT_STREAM

    @classmethod
    def resuming(
        cls, key: bytes, *, head_hash: str, next_seq: int, stream: str = DEFAULT_STREAM
    ) -> AuditChain:
        """Continue an existing chain read back from storage."""
        return cls(
            key=key,
            head_hash=head_hash or GENESIS_HASH,
            next_seq=max(1, next_seq),
            stream=stream,
        )

    def append(
        self,
        event: str | AuditEvent,
        *,
        actor: str,
        subject: str,
        payload: Mapping[str, Any] | None = None,
        timestamp: datetime | None = None,
    ) -> AuditRecord:
        """Seal one new record and advance the head."""
        record = AuditRecord(
            stream=self.stream,
            seq=self.next_seq,
            timestamp=timestamp or datetime.now(UTC),
            event=str(event),
            actor=actor,
            subject=subject,
            payload=dict(payload or {}),
            prev_hash=self.head_hash,
        ).with_hash(self.key)
        self.head_hash = record.record_hash
        self.next_seq += 1
        return record


@dataclass(frozen=True, slots=True)
class ChainVerification:
    """The outcome of walking a chain."""

    valid: bool
    checked: int
    #: Sequence numbers whose own digest does not match their content.
    corrupted: tuple[int, ...] = ()
    #: Sequence numbers whose prev_hash does not match their predecessor.
    broken_links: tuple[int, ...] = ()
    #: Gaps or repeats in the sequence, which indicate deletion or replay.
    sequence_errors: tuple[int, ...] = ()
    message: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "checked": self.checked,
            "corrupted": list(self.corrupted),
            "broken_links": list(self.broken_links),
            "sequence_errors": list(self.sequence_errors),
            "message": self.message,
        }


@dataclass(frozen=True, slots=True)
class StreamHead:
    """Where one stream had reached at some moment."""

    stream: str
    seq: int
    head_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {"stream": self.stream, "seq": self.seq, "head_hash": self.head_hash}

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> StreamHead:
        return cls(
            stream=str(raw.get("stream", "")),
            seq=int(raw.get("seq", 0)),
            head_hash=str(raw.get("head_hash", "")),
        )


def checkpoint_payload(heads: Iterable[StreamHead]) -> dict[str, Any]:
    """The body of a checkpoint record.

    Splitting the log into independent streams buys concurrency and gives up one
    property: per-stream verification cannot notice a stream that is *gone*. Each
    surviving chain still verifies perfectly, and nothing says how many there
    should have been.

    A checkpoint closes that. It records where every stream had reached, sealed
    into a chain of its own, so removing a stream -- or truncating one and
    letting it re-grow -- contradicts a record that was already written.
    """
    ordered = sorted(heads, key=lambda h: h.stream)
    return {
        "streams": [head.to_dict() for head in ordered],
        "stream_count": len(ordered),
        "total_records": sum(head.seq for head in ordered),
    }


@dataclass(frozen=True, slots=True)
class CheckpointVerification:
    """What a checkpoint says about the streams it covered."""

    valid: bool
    checked: int = 0
    #: Streams the checkpoint recorded that no longer exist at all.
    missing: tuple[str, ...] = ()
    #: Streams that have gone backwards -- fewer records than were vouched for.
    truncated: tuple[str, ...] = ()
    #: Streams whose record at the checkpointed sequence no longer has the
    #: digest the checkpoint recorded, meaning history was rewritten beneath it.
    diverged: tuple[str, ...] = ()
    message: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "checked": self.checked,
            "missing": list(self.missing),
            "truncated": list(self.truncated),
            "diverged": list(self.diverged),
            "message": self.message,
        }


def verify_against_checkpoint(
    recorded: Iterable[StreamHead], observed: Mapping[str, tuple[int, str]]
) -> CheckpointVerification:
    """Compare a checkpoint's claims against what the streams look like now.

    ``observed`` maps a stream to its ``(seq, digest)`` at the sequence the
    checkpoint named -- not its current head, which will have moved on.
    """
    missing: list[str] = []
    truncated: list[str] = []
    diverged: list[str] = []
    checked = 0

    for head in recorded:
        checked += 1
        current = observed.get(head.stream)
        if current is None:
            missing.append(head.stream)
            continue
        seq, digest = current
        if seq < head.seq:
            truncated.append(head.stream)
        elif digest != head.head_hash:
            diverged.append(head.stream)

    valid = not (missing or truncated or diverged)
    if valid:
        message = f"all {checked} stream(s) match the checkpoint"
    else:
        parts = []
        if missing:
            parts.append(f"{len(missing)} stream(s) missing entirely")
        if truncated:
            parts.append(f"{len(truncated)} stream(s) shorter than vouched for")
        if diverged:
            parts.append(f"{len(diverged)} stream(s) rewritten beneath the checkpoint")
        message = "checkpoint verification failed: " + "; ".join(parts)

    return CheckpointVerification(
        valid=valid,
        checked=checked,
        missing=tuple(missing),
        truncated=tuple(truncated),
        diverged=tuple(diverged),
        message=message,
    )


def verify_chain(
    records: Iterable[AuditRecord],
    key: bytes,
    *,
    expected_first_prev: str = GENESIS_HASH,
) -> ChainVerification:
    """Recompute a chain and report exactly where, if anywhere, it fails.

    Reports every fault rather than stopping at the first: an investigator needs
    the full extent of the damage, not its earliest symptom.
    """
    corrupted: list[int] = []
    broken: list[int] = []
    sequence_errors: list[int] = []

    ordered: Sequence[AuditRecord] = sorted(records, key=lambda r: r.seq)
    previous: AuditRecord | None = None

    for record in ordered:
        if not record.verify(key):
            corrupted.append(record.seq)

        expected_prev = expected_first_prev if previous is None else previous.record_hash
        if record.prev_hash != expected_prev:
            broken.append(record.seq)

        if previous is not None and record.seq != previous.seq + 1:
            sequence_errors.append(record.seq)

        previous = record

    valid = not (corrupted or broken or sequence_errors)
    if valid:
        message = f"chain intact across {len(ordered)} record(s)"
    else:
        parts: list[str] = []
        if corrupted:
            parts.append(f"{len(corrupted)} record(s) with an invalid digest")
        if broken:
            parts.append(f"{len(broken)} broken link(s)")
        if sequence_errors:
            parts.append(f"{len(sequence_errors)} sequence gap(s) or repeat(s)")
        message = "chain verification failed: " + "; ".join(parts)

    return ChainVerification(
        valid=valid,
        checked=len(ordered),
        corrupted=tuple(corrupted),
        broken_links=tuple(broken),
        sequence_errors=tuple(sequence_errors),
        message=message,
    )
