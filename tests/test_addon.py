"""Integration tests: filter enforcement inside the mitmproxy addon."""

from __future__ import annotations

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
