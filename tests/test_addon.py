"""Integration tests: filter enforcement inside the mitmproxy addon."""

from __future__ import annotations

import base64
import contextlib
import json
import sqlite3
from pathlib import Path

import addon as addon_mod
import container as container_mod
from mitmproxy import http
from mitmproxy.test import taddons, tflow


def _setup(tmp_path: Path, monkeypatch, filter_data: dict) -> addon_mod.SQLiteLogger:
    monkeypatch.setenv("PROXY_DB_PATH", str(tmp_path / "proxy.db"))
    monkeypatch.setenv("PROXY_FILTER_PATH", str(tmp_path / "filter.json"))
    monkeypatch.setenv("PROXY_DATA_DIR", str(tmp_path))
    (tmp_path / "filter.json").write_text(json.dumps(filter_data))
    return addon_mod.SQLiteLogger()


def _flow(host: str) -> http.HTTPFlow:
    flow = tflow.tflow()
    flow.request.host = host
    flow.request.headers["Host"] = host
    return flow


def _rows(tmp_path: Path) -> list[tuple]:
    conn = sqlite3.connect(tmp_path / "proxy.db")
    rows = conn.execute("SELECT method, host, blocked FROM http_requests").fetchall()
    conn.close()
    return rows


def test_blocked_request_gets_403_and_blocked_row(tmp_path: Path, monkeypatch) -> None:
    logger = _setup(tmp_path, monkeypatch, {"mode": "deny", "deny": ["example.com"]})
    with taddons.context(logger):
        logger.load(None)
        flow = _flow("example.com")
        logger.request(flow)
        logger.done()

    assert flow.response is not None
    assert flow.response.status_code == 403
    assert json.loads(flow.response.content)["host"] == "example.com"
    assert _rows(tmp_path) == [("GET", "example.com", 1)]


def test_allowed_request_passes_and_logs_unblocked(tmp_path: Path, monkeypatch) -> None:
    logger = _setup(tmp_path, monkeypatch, {"mode": "allow", "allow": ["example.com"]})
    with taddons.context(logger):
        logger.load(None)
        flow = _flow("example.com")
        logger.request(flow)
        logger.done()

    assert flow.response is None
    assert _rows(tmp_path) == [("GET", "example.com", 0)]


def test_blocked_connect_refused_and_logged(tmp_path: Path, monkeypatch) -> None:
    logger = _setup(tmp_path, monkeypatch, {"mode": "allow", "allow": ["api.anthropic.com"]})
    with taddons.context(logger):
        logger.load(None)
        flow = _flow("example.com")
        flow.request.method = "CONNECT"
        logger.http_connect(flow)
        logger.done()

    assert flow.response is not None
    assert flow.response.status_code == 403
    assert _rows(tmp_path) == [("CONNECT", "example.com", 1)]


def test_allowed_connect_opens_tunnel(tmp_path: Path, monkeypatch) -> None:
    logger = _setup(tmp_path, monkeypatch, {"mode": "allow", "allow": ["api.anthropic.com"]})
    with taddons.context(logger):
        logger.load(None)
        flow = _flow("api.anthropic.com")
        flow.request.method = "CONNECT"
        logger.http_connect(flow)
        logger.done()

    assert flow.response is None
    assert _rows(tmp_path) == []


def test_open_mode_unchanged_behavior(tmp_path: Path, monkeypatch) -> None:
    logger = _setup(tmp_path, monkeypatch, {"mode": "open", "deny": ["example.com"]})
    with taddons.context(logger):
        logger.load(None)
        flow = _flow("example.com")
        logger.request(flow)
        logger.done()

    assert flow.response is None
    assert _rows(tmp_path) == [("GET", "example.com", 0)]


def _mode_reason_rows(tmp_path: Path) -> list[tuple]:
    conn = sqlite3.connect(tmp_path / "proxy.db")
    rows = conn.execute(
        "SELECT host, blocked, filter_mode, block_reason FROM http_requests",
    ).fetchall()
    conn.close()
    return rows


def test_deny_match_records_mode_and_reason(tmp_path: Path, monkeypatch) -> None:
    logger = _setup(tmp_path, monkeypatch, {"mode": "deny", "deny": ["example.com"]})
    with taddons.context(logger):
        logger.load(None)
        logger.request(_flow("example.com"))
        logger.done()

    assert _mode_reason_rows(tmp_path) == [("example.com", 1, "deny", "deny-match")]


def test_allow_miss_records_mode_and_reason(tmp_path: Path, monkeypatch) -> None:
    logger = _setup(tmp_path, monkeypatch, {"mode": "allow", "allow": ["api.anthropic.com"]})
    with taddons.context(logger):
        logger.load(None)
        logger.request(_flow("example.com"))
        logger.done()

    assert _mode_reason_rows(tmp_path) == [("example.com", 1, "allow", "allow-miss")]


def test_allowed_request_records_mode_without_reason(tmp_path: Path, monkeypatch) -> None:
    logger = _setup(tmp_path, monkeypatch, {"mode": "allow", "allow": ["example.com"]})
    with taddons.context(logger):
        logger.load(None)
        logger.request(_flow("example.com"))
        logger.done()

    assert _mode_reason_rows(tmp_path) == [("example.com", 0, "allow", None)]


def test_open_mode_records_mode_without_reason(tmp_path: Path, monkeypatch) -> None:
    logger = _setup(tmp_path, monkeypatch, {"mode": "open", "deny": ["example.com"]})
    with taddons.context(logger):
        logger.load(None)
        logger.request(_flow("example.com"))
        logger.done()

    assert _mode_reason_rows(tmp_path) == [("example.com", 0, "open", None)]


def test_blocked_connect_records_mode_and_reason(tmp_path: Path, monkeypatch) -> None:
    logger = _setup(tmp_path, monkeypatch, {"mode": "allow", "allow": ["api.anthropic.com"]})
    with taddons.context(logger):
        logger.load(None)
        flow = _flow("example.com")
        flow.request.method = "CONNECT"
        logger.http_connect(flow)
        logger.done()

    assert _mode_reason_rows(tmp_path) == [("example.com", 1, "allow", "allow-miss")]


def test_host_header_spoof_does_not_bypass_filter(tmp_path: Path, monkeypatch) -> None:
    """The Host header is client-controlled; blocking must use the real target."""
    logger = _setup(tmp_path, monkeypatch, {"mode": "deny", "deny": ["example.com"]})
    with taddons.context(logger):
        logger.load(None)
        flow = tflow.tflow()
        flow.request.host = "example.com"
        flow.request.headers["Host"] = "allowed.com"
        logger.request(flow)
        logger.done()

    assert flow.response is not None
    assert flow.response.status_code == 403
    assert json.loads(flow.response.content)["host"] == "example.com"


def test_blocked_connect_returns_json_body(tmp_path: Path, monkeypatch) -> None:
    logger = _setup(tmp_path, monkeypatch, {"mode": "deny", "deny": ["example.com"]})
    with taddons.context(logger):
        logger.load(None)
        flow = _flow("example.com")
        flow.request.method = "CONNECT"
        logger.http_connect(flow)
        logger.done()

    assert flow.response is not None
    assert flow.response.headers.get("content-type") == "application/json"
    assert json.loads(flow.response.content)["host"] == "example.com"


def test_connect_stays_blocked_when_logging_fails(tmp_path: Path, monkeypatch) -> None:
    """DB errors must not fail open: the 403 is set before persistence."""
    logger = _setup(tmp_path, monkeypatch, {"mode": "deny", "deny": ["example.com"]})
    with taddons.context(logger):
        logger.load(None)
        monkeypatch.setattr(
            logger._db,
            "insert_request",
            lambda record: (_ for _ in ()).throw(RuntimeError("db full")),
        )
        flow = _flow("example.com")
        flow.request.method = "CONNECT"
        with contextlib.suppress(RuntimeError):
            logger.http_connect(flow)
        logger.done()

    assert flow.response is not None
    assert flow.response.status_code == 403


def test_request_stays_blocked_when_logging_fails(tmp_path: Path, monkeypatch) -> None:
    logger = _setup(tmp_path, monkeypatch, {"mode": "deny", "deny": ["example.com"]})
    with taddons.context(logger):
        logger.load(None)
        monkeypatch.setattr(
            logger._db,
            "insert_request",
            lambda record: (_ for _ in ()).throw(RuntimeError("db full")),
        )
        flow = _flow("example.com")
        with contextlib.suppress(RuntimeError):
            logger.request(flow)
        logger.done()

    assert flow.response is not None
    assert flow.response.status_code == 403


def test_mode_and_reason_come_from_one_policy_snapshot(tmp_path: Path, monkeypatch) -> None:
    """A hot reload between decision and logging must not mix old and new policy."""
    from policy import FilterPolicy

    logger = _setup(tmp_path, monkeypatch, {"mode": "deny", "deny": ["example.com"]})
    with taddons.context(logger):
        logger.load(None)
        real_evaluate = FilterPolicy.evaluate

        def evaluate_then_reload(self, host):
            decision = real_evaluate(self, host)
            # Simulate a hot reload landing right after the decision was taken.
            self._mode = "open"
            self._deny = []
            return decision

        monkeypatch.setattr(FilterPolicy, "evaluate", evaluate_then_reload)
        flow = _flow("example.com")
        logger.request(flow)
        logger.done()

    assert flow.response is not None
    assert flow.response.status_code == 403
    assert _mode_reason_rows(tmp_path) == [("example.com", 1, "deny", "deny-match")]


def _policy_header(policy_id: str) -> str:
    credentials = base64.b64encode(f"vp-{policy_id}:vibepod".encode()).decode()
    return f"Basic {credentials}"


def _container_policy(tmp_path: Path, policy_id: str, mode: str) -> None:
    path = tmp_path / "policies" / "containers" / f"{policy_id}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "version": 2,
                "policy_id": policy_id,
                "profile": "default",
                "project_filter": {"mode": mode, "allow": [], "deny": ["example.com"]},
                "env_mode": None,
            },
        ),
    )


def test_supplied_policy_identity_applies_before_source_mapping(
    tmp_path: Path,
    monkeypatch,
) -> None:
    policy_id = "1" * 32
    logger = _setup(tmp_path, monkeypatch, {"mode": "open", "allow": [], "deny": []})
    _container_policy(tmp_path, policy_id, "deny")
    with taddons.context(logger):
        logger.load(None)
        flow = _flow("example.com")
        flow.request.headers["Proxy-Authorization"] = _policy_header(policy_id)
        logger.request(flow)
        logger.done()

    assert flow.response is not None
    assert flow.response.status_code == 403
    assert "Proxy-Authorization" not in flow.request.headers
    assert _mode_reason_rows(tmp_path) == [("example.com", 1, "deny", "deny-match")]


def test_source_mapping_overrides_conflicting_supplied_identity(
    tmp_path: Path,
    monkeypatch,
) -> None:
    mapped_id = "2" * 32
    supplied_id = "3" * 32
    logger = _setup(tmp_path, monkeypatch, {"mode": "open", "allow": [], "deny": []})
    _container_policy(tmp_path, mapped_id, "deny")
    _container_policy(tmp_path, supplied_id, "open")
    (tmp_path / "containers.json").write_text(
        json.dumps(
            {
                "127.0.0.1": {
                    "container_id": "abc123",
                    "container_name": "vibepod-claude-test",
                    "policy_id": mapped_id,
                    "profile": "default",
                },
            },
        ),
    )
    monkeypatch.setattr(container_mod, "_DEFAULT_MAPPING_PATH", tmp_path / "containers.json")
    with taddons.context(logger):
        logger.load(None)
        assert logger._resolver is not None
        logger._resolver = addon_mod.ContainerResolver(tmp_path / "containers.json")
        flow = _flow("example.com")
        flow.request.headers["Proxy-Authorization"] = _policy_header(supplied_id)
        logger.request(flow)
        logger.done()

    assert flow.response is not None
    assert _mode_reason_rows(tmp_path) == [("example.com", 1, "deny", "deny-match")]


def test_source_mapping_profile_persisted_on_request(tmp_path: Path, monkeypatch) -> None:
    logger = _setup(tmp_path, monkeypatch, {"mode": "open", "allow": [], "deny": []})
    (tmp_path / "containers.json").write_text(
        json.dumps(
            {
                "127.0.0.1": {
                    "container_id": "abc123",
                    "container_name": "vibepod-claude-test",
                    "policy_id": None,
                    "profile": "work",
                },
            },
        ),
    )
    monkeypatch.setattr(container_mod, "_DEFAULT_MAPPING_PATH", tmp_path / "containers.json")
    with taddons.context(logger):
        logger.load(None)
        assert logger._resolver is not None
        logger._resolver = addon_mod.ContainerResolver(tmp_path / "containers.json")
        flow = _flow("example.com")
        logger.request(flow)
        logger.done()

    conn = sqlite3.connect(tmp_path / "proxy.db")
    row = conn.execute("SELECT source_container_name, profile FROM http_requests").fetchone()
    conn.close()
    assert row == ("vibepod-claude-test", "work")


def test_invalid_reserved_policy_identity_fails_closed(tmp_path: Path, monkeypatch) -> None:
    logger = _setup(tmp_path, monkeypatch, {"mode": "open", "allow": [], "deny": []})
    with taddons.context(logger):
        logger.load(None)
        flow = _flow("example.com")
        flow.request.headers["Proxy-Authorization"] = _policy_header("not-a-policy-id")
        logger.request(flow)
        logger.done()

    assert flow.response is not None
    assert _mode_reason_rows(tmp_path) == [
        ("example.com", 1, "unavailable", "policy-unavailable"),
    ]


def test_empty_basic_credentials_do_not_bypass_request_filter(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """A crafted 'Basic ' header must not crash the hook and skip enforcement."""
    logger = _setup(tmp_path, monkeypatch, {"mode": "deny", "deny": ["example.com"]})
    with taddons.context(logger):
        logger.load(None)
        flow = _flow("example.com")
        flow.request.headers["Proxy-Authorization"] = "Basic "
        logger.request(flow)
        logger.done()

    assert flow.response is not None
    assert flow.response.status_code == 403
    assert _rows(tmp_path) == [("GET", "example.com", 1)]


def test_empty_basic_credentials_do_not_bypass_connect_filter(
    tmp_path: Path,
    monkeypatch,
) -> None:
    logger = _setup(tmp_path, monkeypatch, {"mode": "allow", "allow": ["api.anthropic.com"]})
    with taddons.context(logger):
        logger.load(None)
        flow = _flow("example.com")
        flow.request.method = "CONNECT"
        flow.request.headers["Proxy-Authorization"] = "Basic "
        logger.http_connect(flow)
        logger.done()

    assert flow.response is not None
    assert flow.response.status_code == 403
    assert _rows(tmp_path) == [("CONNECT", "example.com", 1)]


def test_unrelated_proxy_authorization_is_preserved(tmp_path: Path, monkeypatch) -> None:
    """Only reserved vp- credentials are consumed; other creds reach the upstream."""
    logger = _setup(tmp_path, monkeypatch, {"mode": "open", "allow": [], "deny": []})
    header = "Basic " + base64.b64encode(b"someuser:secret").decode()
    with taddons.context(logger):
        logger.load(None)
        flow = _flow("example.com")
        flow.request.headers["Proxy-Authorization"] = header
        logger.request(flow)
        logger.done()

    assert flow.request.headers.get("Proxy-Authorization") == header


def test_connect_consumes_policy_identity_header(tmp_path: Path, monkeypatch) -> None:
    policy_id = "4" * 32
    logger = _setup(tmp_path, monkeypatch, {"mode": "open", "allow": [], "deny": []})
    _container_policy(tmp_path, policy_id, "deny")
    with taddons.context(logger):
        logger.load(None)
        flow = _flow("example.com")
        flow.request.method = "CONNECT"
        flow.request.headers["Proxy-Authorization"] = _policy_header(policy_id)
        logger.http_connect(flow)
        logger.done()

    assert flow.response is not None
    assert "Proxy-Authorization" not in flow.request.headers
    assert _mode_reason_rows(tmp_path) == [("example.com", 1, "deny", "deny-match")]


# --- streaming RPCs (gRPC / Connect over HTTP/2) ---------------------------


def _rpc_flow(host: str, content_type: str = "application/connect+proto") -> http.HTTPFlow:
    flow = _flow(host)
    flow.request.method = "POST"
    flow.request.http_version = "HTTP/2.0"
    flow.request.path = "/agent.v1.AgentService/Run"
    flow.request.headers["content-type"] = content_type
    flow.request.content = None
    return flow


def _rpc_response(content_type: str = "application/connect+proto") -> http.Response:
    response = http.Response.make(200, b"", {"content-type": content_type})
    response.content = None
    return response


def test_streaming_rpc_request_is_streamed_and_logged_up_front(tmp_path: Path, monkeypatch) -> None:
    """Bidi streams must not be buffered: mitmproxy would wait for END_STREAM forever."""
    logger = _setup(tmp_path, monkeypatch, {"mode": "open"})
    with taddons.context(logger):
        logger.load(None)
        flow = _rpc_flow("api2.cursor.sh")
        logger.requestheaders(flow)
        # Row exists before the request stream ends, so early responses/errors
        # satisfy the foreign key.
        assert _rows(tmp_path) == [("POST", "api2.cursor.sh", 0)]
        logger.done()

    assert flow.request.stream
    assert flow.response is None


def test_grpc_request_is_streamed(tmp_path: Path, monkeypatch) -> None:
    logger = _setup(tmp_path, monkeypatch, {"mode": "open"})
    with taddons.context(logger):
        logger.load(None)
        flow = _rpc_flow("api2.cursor.sh", "application/grpc+proto")
        logger.requestheaders(flow)
        logger.done()

    assert flow.request.stream


def test_unary_request_is_not_streamed(tmp_path: Path, monkeypatch) -> None:
    logger = _setup(tmp_path, monkeypatch, {"mode": "open"})
    with taddons.context(logger):
        logger.load(None)
        flow = _rpc_flow("api2.cursor.sh", "application/proto")
        logger.requestheaders(flow)
        logger.done()

    assert not flow.request.stream
    assert _rows(tmp_path) == []


def test_streamed_request_and_response_bodies_are_still_logged(tmp_path: Path, monkeypatch) -> None:
    logger = _setup(tmp_path, monkeypatch, {"mode": "open"})
    with taddons.context(logger):
        logger.load(None)
        flow = _rpc_flow("api2.cursor.sh")
        logger.requestheaders(flow)
        assert flow.request.stream(b"hello ") == b"hello "
        assert flow.request.stream(b"world") == b"world"

        # Server answers before the client half-closes (bidi).
        flow.response = _rpc_response()
        logger.responseheaders(flow)
        assert flow.response.stream(b"echo") == b"echo"

        flow.request.stream(b"")
        logger.request(flow)
        flow.response.stream(b"")
        logger.response(flow)
        logger.done()

    conn = sqlite3.connect(tmp_path / "proxy.db")
    req = conn.execute("SELECT body, blocked FROM http_requests").fetchall()
    resp = conn.execute("SELECT body, bytes_in, bytes_out FROM http_responses").fetchall()
    conn.close()
    assert req == [(b"hello world", 0)]
    assert resp == [(b"echo", 11, 4)]


def test_response_streams_when_request_was_streamed(tmp_path: Path, monkeypatch) -> None:
    """Even a non-RPC content type must not be buffered on a bidi exchange."""
    logger = _setup(tmp_path, monkeypatch, {"mode": "open"})
    with taddons.context(logger):
        logger.load(None)
        flow = _rpc_flow("api2.cursor.sh")
        logger.requestheaders(flow)
        flow.response = _rpc_response("application/json")
        logger.responseheaders(flow)
        logger.done()

    assert flow.response.stream


def test_streaming_rpc_response_on_buffered_request_is_streamed(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Server-streaming RPCs send a complete request but stream the response."""
    logger = _setup(tmp_path, monkeypatch, {"mode": "open"})
    with taddons.context(logger):
        logger.load(None)
        flow = _flow("api2.cursor.sh")
        logger.request(flow)
        flow.response = _rpc_response()
        logger.responseheaders(flow)
        flow.response.stream(b"chunk")
        flow.response.stream(b"")
        logger.response(flow)
        logger.done()

    conn = sqlite3.connect(tmp_path / "proxy.db")
    resp = conn.execute("SELECT body FROM http_responses").fetchall()
    conn.close()
    assert resp == [(b"chunk",)]


def test_plain_response_is_not_streamed(tmp_path: Path, monkeypatch) -> None:
    logger = _setup(tmp_path, monkeypatch, {"mode": "open"})
    with taddons.context(logger):
        logger.load(None)
        flow = tflow.tflow(resp=True)
        logger.responseheaders(flow)
        logger.done()

    assert not flow.response.stream


def test_blocked_streaming_rpc_is_killed_not_streamed(tmp_path: Path, monkeypatch) -> None:
    """A 403 can only be sent after the client ends its stream, so reset it instead."""
    logger = _setup(tmp_path, monkeypatch, {"mode": "deny", "deny": ["api2.cursor.sh"]})
    with taddons.context(logger):
        logger.load(None)
        flow = _rpc_flow("api2.cursor.sh")
        logger.requestheaders(flow)
        logger.done()

    assert not flow.request.stream
    assert flow.error is not None
    assert not flow.live
    conn = sqlite3.connect(tmp_path / "proxy.db")
    rows = conn.execute("SELECT method, host, blocked, block_reason FROM http_requests").fetchall()
    conn.close()
    assert rows == [("POST", "api2.cursor.sh", 1, "deny-match")]


def test_blocked_streaming_rpc_stays_blocked_when_logging_fails(
    tmp_path: Path,
    monkeypatch,
) -> None:
    logger = _setup(tmp_path, monkeypatch, {"mode": "deny", "deny": ["api2.cursor.sh"]})
    with taddons.context(logger):
        logger.load(None)
        monkeypatch.setattr(
            logger._db,
            "insert_request",
            lambda record: (_ for _ in ()).throw(RuntimeError("db full")),
        )
        flow = _rpc_flow("api2.cursor.sh")
        with contextlib.suppress(RuntimeError):
            logger.requestheaders(flow)
        logger.done()

    assert not flow.request.stream
    assert not flow.live


def test_streaming_rpc_consumes_policy_identity_before_forwarding(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Streamed headers go upstream right after requestheaders: strip creds there."""
    logger = _setup(tmp_path, monkeypatch, {"mode": "open"})
    with taddons.context(logger):
        logger.load(None)
        flow = _rpc_flow("api2.cursor.sh")
        token = base64.b64encode(f"vp-{'a' * 32}:x".encode()).decode()
        flow.request.headers["Proxy-Authorization"] = f"Basic {token}"
        logger.requestheaders(flow)
        logger.done()

    assert "Proxy-Authorization" not in flow.request.headers


def test_streamed_request_end_does_not_reevaluate_policy(tmp_path: Path, monkeypatch) -> None:
    """The request hook fires after the body was forwarded; it must only log."""
    logger = _setup(tmp_path, monkeypatch, {"mode": "open"})
    with taddons.context(logger):
        logger.load(None)
        flow = _rpc_flow("api2.cursor.sh")
        logger.requestheaders(flow)
        (tmp_path / "filter.json").write_text(
            json.dumps({"mode": "deny", "deny": ["api2.cursor.sh"]}),
        )
        flow.request.stream(b"")
        logger.request(flow)
        logger.done()

    assert flow.response is None
    assert _rows(tmp_path) == [("POST", "api2.cursor.sh", 0)]
