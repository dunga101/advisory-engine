"""Shared fixtures for tests that need a real ORM session (gate-reopening
and un-listing logic touch real joins/selects that a hand-rolled fake
session can't faithfully stand in for).

No conftest previously existed because Advisory.precheck_flags is a
Postgres-specific JSONB column, which has no SQLite equivalent — the
@compiles hook below is test-only and teaches SQLite's DDL compiler to
render JSONB as TEXT, which is enough for an in-memory functional test.
Production code is untouched; this never runs outside pytest."""
import pytest
from sqlalchemy import ARRAY, create_engine
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import sessionmaker

import common.models  # noqa: F401 - registers every model on Base.metadata
from common.db import Base


@compiles(JSONB, "sqlite")
def _jsonb_as_text_on_sqlite(element, compiler, **kw):
    return "TEXT"


@compiles(ARRAY, "sqlite")
def _array_as_text_on_sqlite(element, compiler, **kw):
    return "TEXT"


@pytest.fixture
def session():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    with session_factory() as session:
        yield session
