"""Integration tests: filter enforcement inside the mitmproxy addon."""

from __future__ import annotations

import base64
import contextlib
import json
import sqlite3
from pathlib import Path

import addon as addon_mod
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
    monkeypatch.setattr(addon_mod, "_DEFAULT_MAPPING_PATH", tmp_path / "containers.json")
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
