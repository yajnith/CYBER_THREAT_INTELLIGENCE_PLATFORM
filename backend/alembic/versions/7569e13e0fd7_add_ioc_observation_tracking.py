"""add IOC observation tracking

Revision ID: 7569e13e0fd7
Revises: 0d6510a65636
Create Date: 2026-09-24 16:05:04.877667

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "7569e13e0fd7"
down_revision: Union[str, Sequence[str], None] = "0d6510a65636"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create IOC observation tracking table."""
    op.create_table(
        "ioc_observations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "ioc_id",
            sa.Integer(),
            sa.ForeignKey("iocs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("source", sa.String(), nullable=False),
        sa.Column("observed_at", sa.DateTime(), nullable=False),
    )

    op.create_index(
        "ix_ioc_observations_ioc_id",
        "ioc_observations",
        ["ioc_id"],
    )

    op.create_index(
        "ix_ioc_observations_source",
        "ioc_observations",
        ["source"],
    )


def downgrade() -> None:
    """Drop IOC observation tracking table."""
    op.drop_index(
        "ix_ioc_observations_source",
        table_name="ioc_observations",
    )

    op.drop_index(
        "ix_ioc_observations_ioc_id",
        table_name="ioc_observations",
    )

    op.drop_table("ioc_observations")