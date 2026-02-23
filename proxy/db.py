"""SQLite storage for HTTP proxy logs."""

from __future__ import annotations

import json
import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

_SCHEMA = """\
CREATE TABLE IF NOT EXISTS http_requests (
    id          TEXT PRIMARY KEY,
    timestamp   TEXT NOT NULL,
    method      TEXT NOT NULL,
    scheme      TEXT,
    host        TEXT,
    port        INTEGER,
    path        TEXT,
    query       TEXT,
    url         TEXT,
    headers     TEXT,
    body        BLOB,
    client_ip   TEXT,
    client_port INTEGER,
    server_ip   TEXT,
    server_port INTEGER
);

CREATE TABLE IF NOT EXISTS http_responses (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id  TEXT NOT NULL REFERENCES http_requests(id),
    timestamp   TEXT NOT NULL,
    status_code INTEGER,
    headers     TEXT,
    body        BLOB,
    bytes_in    INTEGER,
    bytes_out   INTEGER,
    duration_ms REAL
);

CREATE TABLE IF NOT EXISTS http_errors (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id  TEXT NOT NULL REFERENCES http_requests(id),
    timestamp   TEXT NOT NULL,
    error_type  TEXT,
    message     TEXT
);

CREATE INDEX IF NOT EXISTS idx_http_requests_ts ON http_requests(timestamp);
CREATE INDEX IF NOT EXISTS idx_http_requests_host ON http_requests(host);
CREATE INDEX IF NOT EXISTS idx_http_responses_req ON http_responses(request_id);
"""


def _iso(ts: float | None) -> str:
    value = ts if ts is not None else datetime.now(timezone.utc).timestamp()
    return datetime.fromtimestamp(value, tz=timezone.utc).isoformat()


def _json_list(items: Iterable[tuple[str, str]]) -> str:
    return json.dumps(list(items))


@dataclass
class RequestRecord:
    request_id: str
    timestamp: str
    method: str
    scheme: str | None
    host: str | None
    port: int | None
    path: str | None
    query: str | None
    url: str | None
    headers: str
    body: bytes
    client_ip: str | None
    client_port: int | None
    server_ip: str | None
    server_port: int | None


@dataclass
class ResponseRecord:
    request_id: str
    timestamp: str
    status_code: int | None
    headers: str
    body: bytes
    bytes_in: int
    bytes_out: int
    duration_ms: float | None


@dataclass
class ErrorRecord:
    request_id: str
    timestamp: str
    error_type: str | None
    message: str | None


class ProxyDB:
    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._path), check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(_SCHEMA)

    def close(self) -> None:
        self._conn.close()

    def insert_request(self, record: RequestRecord) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO http_requests "
            "(id, timestamp, method, scheme, host, port, path, query, url, headers, body, "
            "client_ip, client_port, server_ip, server_port) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                record.request_id,
                record.timestamp,
                record.method,
                record.scheme,
                record.host,
                record.port,
                record.path,
                record.query,
                record.url,
                record.headers,
                record.body,
                record.client_ip,
                record.client_port,
                record.server_ip,
                record.server_port,
            ),
        )
        self._conn.commit()

    def insert_response(self, record: ResponseRecord) -> None:
        self._conn.execute(
            "INSERT INTO http_responses "
            "(request_id, timestamp, status_code, headers, body, bytes_in, bytes_out, duration_ms) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                record.request_id,
                record.timestamp,
                record.status_code,
                record.headers,
                record.body,
                record.bytes_in,
                record.bytes_out,
                record.duration_ms,
            ),
        )
        self._conn.commit()

    def insert_error(self, record: ErrorRecord) -> None:
        self._conn.execute(
            "INSERT INTO http_errors (request_id, timestamp, error_type, message) "
            "VALUES (?, ?, ?, ?)",
            (record.request_id, record.timestamp, record.error_type, record.message),
        )
        self._conn.commit()

    @staticmethod
    def build_request(
        *,
        request_id: str,
        timestamp: float | None,
        method: str,
        scheme: str | None,
        host: str | None,
        port: int | None,
        path: str | None,
        query: str | None,
        url: str | None,
        headers: Iterable[tuple[str, str]],
        body: bytes | None,
        client_ip: str | None,
        client_port: int | None,
        server_ip: str | None,
        server_port: int | None,
    ) -> RequestRecord:
        return RequestRecord(
            request_id=request_id,
            timestamp=_iso(timestamp),
            method=method,
            scheme=scheme,
            host=host,
            port=port,
            path=path,
            query=query,
            url=url,
            headers=_json_list(headers),
            body=body or b"",
            client_ip=client_ip,
            client_port=client_port,
            server_ip=server_ip,
            server_port=server_port,
        )

    @staticmethod
    def build_response(
        *,
        request_id: str,
        timestamp: float | None,
        status_code: int | None,
        headers: Iterable[tuple[str, str]],
        body: bytes | None,
        bytes_in: int,
        bytes_out: int,
        duration_ms: float | None,
    ) -> ResponseRecord:
        return ResponseRecord(
            request_id=request_id,
            timestamp=_iso(timestamp),
            status_code=status_code,
            headers=_json_list(headers),
            body=body or b"",
            bytes_in=bytes_in,
            bytes_out=bytes_out,
            duration_ms=duration_ms,
        )

    @staticmethod
    def build_error(
        *,
        request_id: str,
        timestamp: float | None,
        error_type: str | None,
        message: str | None,
    ) -> ErrorRecord:
        return ErrorRecord(
            request_id=request_id,
            timestamp=_iso(timestamp),
            error_type=error_type,
            message=message,
        )


def get_db_path() -> Path:
    env = os.environ.get("PROXY_DB_PATH")
    return Path(env) if env else Path("/data/proxy.db")
