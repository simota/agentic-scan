import sqlite3

_connection = None


def connection():
    global _connection
    if _connection is None:
        _connection = sqlite3.connect("console.db", detect_types=sqlite3.PARSE_DECLTYPES)
        _connection.row_factory = sqlite3.Row
    return _connection


def query(sql, params=()):
    return connection().execute(sql, params).fetchall()


def query_one(sql, params=()):
    row = connection().execute(sql, params).fetchone()
    return dict(row) if row is not None else None
