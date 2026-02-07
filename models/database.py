"""
Database Configuration Module
=============================

Provides SQLAlchemy database engine and session management for the
Access Control System. Uses SQLite for portability while demonstrating
enterprise-grade data persistence patterns.

Security Note: In production environments, this would be replaced with
a hardened database like PostgreSQL with encrypted connections.
"""

import os
from contextlib import contextmanager
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

# Database file location
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'access_control.db')
DATABASE_URL = f"sqlite:///{DB_PATH}"

# Create engine with SQLite-specific settings
engine = create_engine(
    DATABASE_URL,
    echo=False,  # Set to True for SQL debugging
    connect_args={"check_same_thread": False}  # Required for SQLite
)

# Session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for declarative models
Base = declarative_base()


@contextmanager
def get_session():
    """
    Context manager for database sessions.

    Ensures proper session lifecycle management with automatic
    commit on success and rollback on failure.

    Usage:
        with get_session() as session:
            user = session.query(User).first()
    """
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def init_db():
    """
    Initialize the database schema.

    Creates all tables defined in the models if they don't exist.
    Safe to call multiple times.
    """
    from . import entities  # noqa: F401 - Ensure models are loaded
    Base.metadata.create_all(bind=engine)


def reset_db():
    """
    Reset the database by dropping and recreating all tables.

    WARNING: This destroys all data. Use only for development/testing.
    """
    from . import entities  # noqa: F401
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
