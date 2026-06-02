"""initial schema

Revision ID: 0001_initial
Revises:
Create Date: 2026-05-22
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0001_initial"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # The application still creates tables on startup for local development.
    # This baseline lets production deployments stamp or autogenerate from a known revision.
    pass


def downgrade() -> None:
    pass
