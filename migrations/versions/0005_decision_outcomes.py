"""Record what the enforcement point actually did, not only what was permitted.

Revision ID: 0005
Revises: 0004
Create Date: 2026-08-28

A decision record said what the control plane *decided*. It did not say what
*happened*. An enforcement point that could not discharge an obligation, or
refused for its own reasons, left a row reading "allow" behind an action that
never took place -- and reconciling "what was permitted" against "what actually
occurred" is the whole reason for keeping the log.

The columns are nullable, and null means *unreported*. That is deliberately its
own state rather than a default of "enforced": an enforcement point that quietly
stops reporting is one that quietly stopped being observed, and the safe reading
of silence is that nothing is known -- not that everything went fine.

Existing rows therefore become unreported, which is exactly what they are.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None

JSON_LIST = sa.JSON().with_variant(sa.dialects.postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    op.add_column("decisions", sa.Column("outcome", sa.String(length=32), nullable=True))
    op.add_column(
        "decisions",
        sa.Column("outcome_reason", sa.Text(), nullable=False, server_default=""),
    )
    op.add_column(
        "decisions", sa.Column("outcome_reported_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column(
        "decisions", sa.Column("outcome_reported_by", sa.String(length=255), nullable=True)
    )
    op.add_column(
        "decisions",
        sa.Column("discharged", JSON_LIST, nullable=False, server_default="[]"),
    )
    op.add_column(
        "decisions",
        sa.Column("undischarged", JSON_LIST, nullable=False, server_default="[]"),
    )
    op.create_index("ix_decisions_outcome", "decisions", ["outcome"])
    # "Permitted, then refused downstream" should be a query, not a guess.
    op.create_index("ix_decisions_effect_outcome", "decisions", ["effect", "outcome"])


def downgrade() -> None:
    op.drop_index("ix_decisions_effect_outcome", table_name="decisions")
    op.drop_index("ix_decisions_outcome", table_name="decisions")
    for column in (
        "undischarged",
        "discharged",
        "outcome_reported_by",
        "outcome_reported_at",
        "outcome_reason",
        "outcome",
    ):
        op.drop_column("decisions", column)
