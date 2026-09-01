from logging.config import fileConfig
import os
import sys

from sqlalchemy import pool
from sqlalchemy import create_engine

from alembic import context
from dotenv import load_dotenv


# ---------------------------------------------------------
# Project path
# ---------------------------------------------------------

PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..")
)

sys.path.insert(0, PROJECT_ROOT)


# ---------------------------------------------------------
# Environment variables
# ---------------------------------------------------------

load_dotenv(
    os.path.join(PROJECT_ROOT, ".env")
)


# ---------------------------------------------------------
# CTIP database configuration
# ---------------------------------------------------------

from app.database.database import Base, DATABASE_URL
import app.database.models


# ---------------------------------------------------------
# Alembic configuration
# ---------------------------------------------------------

config = context.config


if config.config_file_name is not None:
    fileConfig(config.config_file_name)


# SQLAlchemy metadata used by Alembic autogenerate
target_metadata = Base.metadata


# ---------------------------------------------------------
# Offline migrations
# ---------------------------------------------------------

def run_migrations_offline() -> None:
    """Run migrations in offline mode."""

    context.configure(
        url=DATABASE_URL,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


# ---------------------------------------------------------
# Online migrations
# ---------------------------------------------------------

def run_migrations_online() -> None:
    """Run migrations in online mode."""

    connectable = create_engine(
        DATABASE_URL,
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:

        context.configure(
            connection=connection,
            target_metadata=target_metadata,
        )

        with context.begin_transaction():
            context.run_migrations()


# ---------------------------------------------------------
# Run migration
# ---------------------------------------------------------

if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()