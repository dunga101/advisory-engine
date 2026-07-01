import os

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker


class Base(DeclarativeBase):
    pass


def get_engine():
    database_url = os.environ["DATABASE_URL"]
    return create_engine(database_url, pool_pre_ping=True)


def get_session_factory(engine=None):
    engine = engine or get_engine()
    return sessionmaker(bind=engine)
