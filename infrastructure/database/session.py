from __future__ import annotations

import os
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker


_PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATABASE_URL = "postgresql+psycopg://secpatch:change-me@localhost:5432/secpatch"


def load_dotenv(path: Path | None = None) -> None:
    """Load KEY=VALUE pairs from the project-root .env without overriding
    variables that are already set in the real environment.

    Without this, uvicorn and alembic silently ignored .env and fell back to
    the placeholder connection string.
    """
    env_path = path or _PROJECT_ROOT / ".env"
    if not env_path.is_file():
        return
    for line in env_path.read_text(encoding="utf-8-sig").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("export "):
            stripped = stripped[len("export "):]
        key, separator, value = stripped.partition("=")
        key, value = key.strip(), value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        if separator and key:
            os.environ.setdefault(key, value)


def database_url() -> str:
    load_dotenv()
    return os.getenv("DATABASE_URL", DEFAULT_DATABASE_URL)


def make_engine(url: str | None = None):
    return create_engine(url or database_url(), pool_pre_ping=True)


_factories: dict[str, sessionmaker[Session]] = {}


def session_factory(url: str | None = None) -> sessionmaker[Session]:
    # Reuse one engine (and its connection pool) per URL instead of creating
    # a new engine on every API request.
    resolved = url or database_url()
    factory = _factories.get(resolved)
    if factory is None:
        factory = sessionmaker(bind=make_engine(resolved), expire_on_commit=False)
        _factories[resolved] = factory
    return factory


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
