"""Storage backends. Only SQLite exists; the registry was added for a planned Postgres port."""
import sqlite3
from abc import ABC, abstractmethod

from server.config import DATABASE_URL


class StorageBackend(ABC):
    @abstractmethod
    def query(self, sql, params=()):
        ...


class SqliteBackend(StorageBackend):
    def __init__(self, url):
        self.url = url

    def query(self, sql, params=()):
        with sqlite3.connect(self.url) as conn:
            return conn.execute(sql, params).fetchall()


BACKENDS = {"sqlite": SqliteBackend}


def backend(name="sqlite"):
    return BACKENDS[name](DATABASE_URL)
