"""Split the audit log into independently verifiable streams.

Revision ID: 0004
Revises: 0003
Create Date: 2026-08-28

Every append took one global advisory lock, so every decision in the system
serialised behind the logging of every other one. That is a stronger claim than
integrity needs: a chain has to be ordered *within itself*, not against every
other record ever written.

Records now belong to a stream and are keyed by ``(stream, seq)``. Each stream is
its own chain with its own lock, so appends to different streams proceed at the
same time. The stream is part of the signed body, so a record cannot be moved
between chains and still verify.

What this gives up is bought back by checkpoints, which live in a reserved
``_checkpoints`` stream: per-stream verification proves each chain is internally
consistent and says nothing about how many chains there should be, so a stream
that vanishes entirely would leave everything remaining verifying perfectly.

Existing records move to the ``default`` stream, which is also what a deployment
with ``CP_AUDIT_PARTITIONS=1`` keeps using -- so this migration changes the
schema without changing anyone's behaviour until they ask for it.

Existing digests remain valid, and that took care rather than luck. Adding the
stream to the signed body unconditionally would have invalidated every record
ever written -- an audit chain whose whole value is holding over time cannot
afford a schema change that breaks its history. So the stream is signed only when
it is *not* the default: a record in ``default`` signs exactly the bytes it
signed before streams existed. Moving a record between chains is still caught in
either direction, because the field appears going in and disappears coming out.

Run ``cpctl audit verify`` after upgrading to confirm that on your own data.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "audit_records",
        sa.Column("stream", sa.String(length=64), nullable=False, server_default="default"),
    )
    op.create_index("ix_audit_records_stream", "audit_records", ["stream"])

    if op.get_bind().dialect.name != "postgresql":
        return

    # The primary key becomes composite: sequence numbers restart per stream, so
    # seq alone stops identifying a record.
    op.execute("ALTER TABLE audit_records DROP CONSTRAINT IF EXISTS uq_audit_records_seq")
    op.execute("ALTER TABLE audit_records DROP CONSTRAINT IF EXISTS audit_records_pkey")
    op.execute("ALTER TABLE audit_records ADD PRIMARY KEY (stream, seq)")

    # Reading a stream's head is on the append path, once per record.
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_audit_records_stream_seq "
        "ON audit_records (stream, seq DESC)"
    )


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute("DROP INDEX IF EXISTS ix_audit_records_stream_seq")
        op.execute("ALTER TABLE audit_records DROP CONSTRAINT IF EXISTS audit_records_pkey")
        # Only reversible while every record is still in one stream; more than
        # one would make seq ambiguous as a key.
        op.execute("ALTER TABLE audit_records ADD PRIMARY KEY (seq)")
        op.execute(
            "ALTER TABLE audit_records ADD CONSTRAINT uq_audit_records_seq UNIQUE (seq)"
        )
    op.drop_index("ix_audit_records_stream", table_name="audit_records")
    op.drop_column("audit_records", "stream")
