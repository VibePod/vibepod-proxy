"""Mitmproxy addon for logging HTTP traffic to SQLite."""

from __future__ import annotations

import base64
import binascii
import json
import os
import re
from pathlib import Path

from container import ContainerMetadata, ContainerResolver
from db import ProxyDB, get_db_path
from mitmproxy import ctx, http, websocket
from policy import FilterDecision, PolicyStore

# NOTE: mitmproxy runs this file as a script module that is absent from
# sys.modules, which breaks @dataclass on classes with string annotations.
# Define dataclasses in a sibling module (see container.py) and import them.

_POLICY_USERNAME_RE = re.compile(r"^vp-([0-9a-f]{32})$")


def _blocked_response(host: str | None) -> http.Response:
    return http.Response.make(
        403,
        json.dumps({"error": "blocked by vibepod proxy filter", "host": host}).encode("utf-8"),
        {"content-type": "application/json"},
    )


def _pop_policy_identity(flow: http.HTTPFlow) -> tuple[str | None, bool]:
    """Consume VibePod proxy credentials and return (policy_id, invalid_reserved)."""
    raw = flow.request.headers.get("Proxy-Authorization")
    if raw is None or not raw.lower().startswith("basic "):
        return None, False
    parts = raw.split(None, 1)
    if len(parts) < 2:
        return None, False
    encoded = parts[1]
    try:
        decoded = base64.b64decode(encoded, validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        return None, False
    username = decoded.split(":", 1)[0]
    if not username.startswith("vp-"):
        # Not a VibePod identity: leave the header for an upstream proxy.
        return None, False
    del flow.request.headers["Proxy-Authorization"]
    match = _POLICY_USERNAME_RE.fullmatch(username)
    return (match.group(1), False) if match else (None, True)


class SQLiteLogger:
    def __init__(self) -> None:
        self._db: ProxyDB | None = None
        self._resolver: ContainerResolver | None = None
        self._policy: PolicyStore | None = None

    def load(self, loader):  # type: ignore[override]
        db_path = get_db_path()
        self._db = ProxyDB(db_path)
        data_dir = Path(os.environ.get("PROXY_DATA_DIR", "/data"))
        mapping_path = Path(os.environ.get("PROXY_MAPPING_PATH", data_dir / "containers.json"))
        self._resolver = ContainerResolver(mapping_path)
        self._policy = PolicyStore(data_dir)
        ctx.log.info(f"Logging HTTP traffic to {db_path}")

    def done(self) -> None:
        if self._db is not None:
            self._db.close()

    def _client_address(self, flow: http.HTTPFlow) -> tuple[str | None, int | None]:
        if not flow.client_conn.address:
            return None, None
        addr = flow.client_conn.address
        return addr[0], addr[1] if len(addr) > 1 else None

    def _request_policy(
        self,
        flow: http.HTTPFlow,
    ) -> tuple[FilterDecision, ContainerMetadata, str | None, int | None]:
        client_ip, client_port = self._client_address(flow)
        metadata = ContainerMetadata()
        if self._resolver is not None:
            metadata = self._resolver.resolve(client_ip)
        supplied_id, invalid_identity = _pop_policy_identity(flow)
        policy_id = metadata.policy_id or supplied_id
        if metadata.policy_id is None and invalid_identity:
            policy_id = "invalid"
        if self._policy is None:
            raise RuntimeError("policy store is not loaded")
        return self._policy.evaluate(flow.request.host, policy_id), metadata, client_ip, client_port

    def http_connect(self, flow: http.HTTPFlow) -> None:
        if self._db is None or self._policy is None:
            return
        host = flow.request.host
        decision, metadata, client_ip, client_port = self._request_policy(flow)
        if not decision.blocked:
            return

        # Refuse the tunnel before any persistence: a logging failure must
        # never let a blocked connection through.
        flow.response = _blocked_response(host)

        record = self._db.build_request(
            request_id=flow.id,
            timestamp=flow.request.timestamp_start,
            method="CONNECT",
            source_container_id=metadata.container_id,
            source_container_name=metadata.container_name,
            scheme=None,
            host=host,
            port=flow.request.port,
            path=None,
            query=None,
            url=f"{host}:{flow.request.port}",
            headers=[],
            body=None,
            client_ip=client_ip,
            client_port=client_port,
            server_ip=None,
            server_port=None,
            blocked=True,
            filter_mode=decision.mode,
            block_reason=decision.reason,
        )
        self._db.insert_request(record)

    def request(self, flow: http.HTTPFlow) -> None:
        if self._db is None:
            return

        # flow.request.host is the real connection target; pretty_host prefers
        # the client-controlled Host header and would be spoofable.
        decision, metadata, client_ip, client_port = self._request_policy(flow)
        blocked = decision.blocked
        if blocked:
            # Set before any persistence so logging failures never fail open.
            flow.response = _blocked_response(flow.request.host)

        query_value = None
        query_raw = getattr(flow.request, "query_string", None)
        if isinstance(query_raw, bytes):
            query_value = query_raw.decode("utf-8", errors="replace")
        elif isinstance(query_raw, str):
            query_value = query_raw
        elif flow.request.query:
            query_value = str(flow.request.query)

        server_ip = None
        server_port = None
        if flow.server_conn.address:
            server_addr = flow.server_conn.address
            server_ip = server_addr[0]
            server_port = server_addr[1] if len(server_addr) > 1 else None

        record = self._db.build_request(
            request_id=flow.id,
            timestamp=flow.request.timestamp_start,
            method=flow.request.method,
            source_container_id=metadata.container_id,
            source_container_name=metadata.container_name,
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
            blocked=blocked,
            filter_mode=decision.mode,
            block_reason=decision.reason,
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

    def websocket_message(self, flow: http.HTTPFlow) -> None:
        if self._db is None:
            return

        if flow.websocket is None or not flow.websocket.messages:
            return

        msg = flow.websocket.messages[-1]
        direction = "client_to_server" if msg.from_client else "server_to_client"
        if msg.type == websocket.Opcode.BINARY:
            msg_type = "binary"
        elif msg.type == websocket.Opcode.TEXT:
            msg_type = "text"
        else:
            return

        content: bytes
        if isinstance(msg.content, str):
            content = msg.content.encode("utf-8")
        else:
            content = msg.content or b""

        record = self._db.build_websocket_message(
            request_id=flow.id,
            timestamp=msg.timestamp,
            direction=direction,
            msg_type=msg_type,
            content=content,
        )
        self._db.insert_websocket_message(record)


addons = [SQLiteLogger()]
