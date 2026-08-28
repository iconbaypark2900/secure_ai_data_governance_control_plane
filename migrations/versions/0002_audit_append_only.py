"""Make the audit table append-only, and index the JSONB columns we query.

Revision ID: 0002
Revises: 0001
Create Date: 2026-08-28

The hash chain makes tampering *detectable*. A database trigger makes the most
likely form of tampering -- an accidental ORM flush, a well-meant "fix" to a
typo in an actor name, a cascading delete -- impossible in the first place.

Detection and prevention answer different questions. The trigger stops the
routine mistakes; the chain catches the deliberate attacker who has enough
privilege to drop the trigger, because doing so still cannot produce valid
digests without the audit key.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


APPEND_ONLY_FUNCTION = """
CREATE OR REPLACE FUNCTION control_plane_audit_append_only()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION
        'audit_records is append-only; % was rejected for seq %',
        TG_OP, COALESCE(OLD.seq, NEW.seq)
        USING ERRCODE = 'restrict_violation';
END;
$$;
"""

TRUNCATE_GUARD_FUNCTION = """
CREATE OR REPLACE FUNCTION control_plane_audit_no_truncate()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'audit_records is append-only; TRUNCATE was rejected'
        USING ERRCODE = 'restrict_violation';
END;
$$;
"""


def upgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        # SQLite has no procedural language. The test suite relies on the
        # application never issuing these statements, and on the hash chain to
        # catch it if something else does.
        return

    op.execute(APPEND_ONLY_FUNCTION)
    op.execute(TRUNCATE_GUARD_FUNCTION)
    op.execute(
        """
        CREATE TRIGGER audit_records_append_only
        BEFORE UPDATE OR DELETE ON audit_records
        FOR EACH ROW EXECUTE FUNCTION control_plane_audit_append_only();
        """
    )
    op.execute(
        """
        CREATE TRIGGER audit_records_no_truncate
        BEFORE TRUNCATE ON audit_records
        FOR EACH STATEMENT EXECUTE FUNCTION control_plane_audit_no_truncate();
        """
    )

    # Reporting queries filter decisions by the labels involved and by which
    # policies matched. Both are JSONB arrays, so containment needs GIN.
    op.execute(
        "CREATE INDEX ix_decisions_classifications_gin "
        "ON decisions USING gin (classifications jsonb_path_ops)"
    )
    op.execute(
        "CREATE INDEX ix_decisions_matched_policies_gin "
        "ON decisions USING gin (matched_policies jsonb_path_ops)"
    )
    op.execute(
        "CREATE INDEX ix_audit_records_payload_gin "
        "ON audit_records USING gin (payload jsonb_path_ops)"
    )


def downgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    op.execute("DROP INDEX IF EXISTS ix_audit_records_payload_gin")
    op.execute("DROP INDEX IF EXISTS ix_decisions_matched_policies_gin")
    op.execute("DROP INDEX IF EXISTS ix_decisions_classifications_gin")
    op.execute("DROP TRIGGER IF EXISTS audit_records_no_truncate ON audit_records")
    op.execute("DROP TRIGGER IF EXISTS audit_records_append_only ON audit_records")
    op.execute("DROP FUNCTION IF EXISTS control_plane_audit_no_truncate()")
    op.execute("DROP FUNCTION IF EXISTS control_plane_audit_append_only()")
