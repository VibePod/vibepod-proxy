"""Mitmproxy addon for logging HTTP traffic to SQLite."""

from __future__ import annotations

import json
import os
from pathlib import Path

from mitmproxy import ctx, http

from db import ProxyDB, get_db_path

_DEFAULT_MAPPING_PATH = Path("/data/containers.json")


class ContainerResolver:
    """Resolves client IPs to container metadata via a shared JSON file."""

    def __init__(self, path: Path = _DEFAULT_MAPPING_PATH) -> None:
        self._path = path
        self._mtime: float = 0.0
        self._mapping: dict[str, dict[str, str]] = {}

    def resolve(self, ip: str | None) -> tuple[str | None, str | None]:
        """Return (container_id, container_name) for the given IP."""
        if ip is None:
            return None, None
        self._maybe_reload()
        entry = self._mapping.get(ip)
        if entry is None:
            return None, None
        return entry.get("container_id"), entry.get("container_name")

    def _maybe_reload(self) -> None:
        try:
            st = os.stat(self._path)
        except OSError:
            return
        if st.st_mtime == self._mtime:
            return
        try:
            data = json.loads(self._path.read_text())
            if isinstance(data, dict):
                self._mapping = data
            self._mtime = st.st_mtime
        except (json.JSONDecodeError, OSError):
            pass


class SQLiteLogger:
    def __init__(self) -> None:
        self._db: ProxyDB | None = None
        self._resolver: ContainerResolver | None = None

    def load(self, loader):  # type: ignore[override]
        db_path = get_db_path()
        self._db = ProxyDB(db_path)
        self._resolver = ContainerResolver()
        ctx.log.info(f"Logging HTTP traffic to {db_path}")

    def done(self) -> None:
        if self._db is not None:
            self._db.close()

    def request(self, flow: http.HTTPFlow) -> None:
        if self._db is None:
            return

        query_value = None
        query_raw = getattr(flow.request, "query_string", None)
        if isinstance(query_raw, bytes):
            query_value = query_raw.decode("utf-8", errors="replace")
        elif isinstance(query_raw, str):
            query_value = query_raw
        elif flow.request.query:
            query_value = str(flow.request.query)

        client_ip = None
        client_port = None
        if flow.client_conn.address:
            client_addr = flow.client_conn.address
            client_ip = client_addr[0]
            client_port = client_addr[1] if len(client_addr) > 1 else None

        server_ip = None
        server_port = None
        if flow.server_conn.address:
            server_addr = flow.server_conn.address
            server_ip = server_addr[0]
            server_port = server_addr[1] if len(server_addr) > 1 else None

        source_container_id = None
        source_container_name = None
        if self._resolver is not None:
            source_container_id, source_container_name = self._resolver.resolve(client_ip)

        record = self._db.build_request(
            request_id=flow.id,
            timestamp=flow.request.timestamp_start,
            method=flow.request.method,
            source_container_id=source_container_id,
            source_container_name=source_container_name,
            scheme=flow.request.scheme,
            host=flow.request.host,
            port=flow.request.port,
            path=flow.request.path,
            query=query_value,
            url=flow.request.pretty_url,
            headers=flow.request.headers.items(multi=True),
            body=flow.request.raw_content,
            client_ip=client_ip,
            client_port=client_port,
            server_ip=server_ip,
            server_port=server_port,
        )
        self._db.insert_request(record)

    def response(self, flow: http.HTTPFlow) -> None:
        if self._db is None:
            return

        duration_ms = None
        if flow.request.timestamp_start and flow.response.timestamp_end:
            duration_ms = (flow.response.timestamp_end - flow.request.timestamp_start) * 1000.0

        record = self._db.build_response(
            request_id=flow.id,
            timestamp=flow.response.timestamp_start or flow.response.timestamp_end,
            status_code=flow.response.status_code,
            headers=flow.response.headers.items(multi=True),
            body=flow.response.raw_content,
            bytes_in=len(flow.request.raw_content or b""),
            bytes_out=len(flow.response.raw_content or b""),
            duration_ms=duration_ms,
        )
        self._db.insert_response(record)

    def error(self, flow: http.HTTPFlow) -> None:
        if self._db is None:
            return

        err = flow.error
        record = self._db.build_error(
            request_id=flow.id,
            timestamp=flow.request.timestamp_start,
            error_type=err.__class__.__name__ if err else None,
            message=str(err) if err else None,
        )
        self._db.insert_error(record)


addons = [SQLiteLogger()]
