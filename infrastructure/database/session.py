from __future__ import annotations

import os
from collections.abc import Generator
from contextlib import contextmanager

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker


def database_url() -> str:
    return os.getenv("DATABASE_URL", "postgresql+psycopg://secpatch:change-me@localhost:5432/secpatch")


def make_engine(url: str | None = None):
    return create_engine(url or database_url(), pool_pre_ping=True)


def session_factory(url: str | None = None) -> sessionmaker[Session]:
    return sessionmaker(bind=make_engine(url), expire_on_commit=False)


def get_session() -> Generator[Session, None, None]:
    session = session_factory()()
    try:
        yield session
    finally:
        session.close()


@contextmanager
def session_scope():
    session = session_factory()()
    try:
        yield session
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
