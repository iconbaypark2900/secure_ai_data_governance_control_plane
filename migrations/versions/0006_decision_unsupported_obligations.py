"""Record which obligations a decision handed to the enforcement point.

The ``obligations`` column has always said what was *required*. It never said
which of those the control plane discharged itself and which it passed on -- and
without that, an outcome report claiming a duty was carried out cannot be
checked against anything. A caller reporting ``discharged: ["redact"]`` against
a decision the plane recorded as having handed it ``redact`` is describing the
plane's own conduct, not its own, and this column is the only place that can be
noticed.

Existing rows get an empty list, which is honest: what those decisions handed on
was never recorded, and an empty list is read as "nothing known to be
outstanding" rather than as an assertion that nothing was.

Revision ID: 0006
Revises: 0005
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None

JSON_LIST = sa.JSON().with_variant(sa.dialects.postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    op.add_column(
        "decisions",
        sa.Column("unsupported_obligations", JSON_LIST, nullable=False, server_default="[]"),
    )


def downgrade() -> None:
    op.drop_column("decisions", "unsupported_obligations")
