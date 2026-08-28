"""Bind approvals to the request they were granted for, and record redemption.

Revision ID: 0003
Revises: 0002
Create Date: 2026-08-28

Before this, an approval could be granted but never spent: the ``require_approval``
effect parked a decision and nothing consumed the grant. Completing that loop
needs two things stored.

``request_fingerprint`` scopes the approval. An approval is a capability, and an
unscoped capability is a bearer token for any request that happens to need one --
get something innocuous approved, then present the same id for an exfiltration.
The fingerprint is a keyed digest of the principal, action, resource, labels,
payload, and context a reviewer actually saw.

The ``redeemed_*`` columns make it single use, and make "approved, then used"
a fact the audit trail can state rather than infer.

Existing rows get an empty fingerprint and are deliberately not redeemable:
they were granted before anyone was recording what they were granted *for*, and
guessing that retroactively is exactly the mistake this column exists to prevent.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "approval_requests",
        sa.Column(
            "request_fingerprint",
            sa.String(length=64),
            nullable=False,
            server_default="",
        ),
    )
    op.add_column(
        "approval_requests",
        sa.Column("redeemed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "approval_requests",
        sa.Column("redeemed_by", sa.String(length=255), nullable=True),
    )
    op.add_column(
        "approval_requests",
        sa.Column("redeemed_decision_id", sa.Uuid(), nullable=True),
    )
    # Parking looks for an open approval with a matching fingerprint on every
    # decision that needs one, so this index is on the hot path.
    op.create_index(
        "ix_approval_fingerprint", "approval_requests", ["request_fingerprint"]
    )


def downgrade() -> None:
    op.drop_index("ix_approval_fingerprint", table_name="approval_requests")
    op.drop_column("approval_requests", "redeemed_decision_id")
    op.drop_column("approval_requests", "redeemed_by")
    op.drop_column("approval_requests", "redeemed_at")
    op.drop_column("approval_requests", "request_fingerprint")
