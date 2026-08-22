"""Tests for the blocked flag in the requests table."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from db import ProxyDB


def _insert(db: ProxyDB, request_id: str, blocked: bool) -> None:
    record = db.build_request(
        request_id=request_id,
        timestamp=None,
        method="GET",
        source_container_id=None,
        source_container_name=None,
        scheme="https",
        host="example.com",
        port=443,
        path="/",
        query=None,
        url="https://example.com/",
        headers=[],
        body=None,
        client_ip=None,
        client_port=None,
        server_ip=None,
        server_port=None,
        blocked=blocked,
    )
    db.insert_request(record)


def test_blocked_flag_persisted(tmp_path: Path) -> None:
    db_path = tmp_path / "proxy.db"
    db = ProxyDB(db_path)
    _insert(db, "req-1", blocked=True)
    _insert(db, "req-2", blocked=False)
    db.close()

    conn = sqlite3.connect(db_path)
    rows = dict(conn.execute("SELECT id, blocked FROM http_requests").fetchall())
    conn.close()
    assert rows == {"req-1": 1, "req-2": 0}


def test_blocked_defaults_to_false(tmp_path: Path) -> None:
    db = ProxyDB(tmp_path / "proxy.db")
    record = db.build_request(
        request_id="req-1",
        timestamp=None,
        method="GET",
        source_container_id=None,
        source_container_name=None,
        scheme="https",
        host="example.com",
        port=443,
        path="/",
        query=None,
        url="https://example.com/",
        headers=[],
        body=None,
        client_ip=None,
        client_port=None,
        server_ip=None,
        server_port=None,
    )
    assert record.blocked == 0
    db.close()


def test_migration_adds_blocked_column(tmp_path: Path) -> None:
    """Databases created before the blocked column gain it on open."""
    db_path = tmp_path / "proxy.db"
    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE http_requests (id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, "
        "method TEXT NOT NULL, scheme TEXT, host TEXT, port INTEGER, path TEXT, "
        "query TEXT, url TEXT, headers TEXT, body BLOB, client_ip TEXT, "
        "client_port INTEGER, server_ip TEXT, server_port INTEGER)",
    )
    conn.commit()
    conn.close()

    db = ProxyDB(db_path)
    db.close()

    conn = sqlite3.connect(db_path)
    columns = {row[1] for row in conn.execute("PRAGMA table_info(http_requests)")}
    conn.close()
    assert "blocked" in columns
