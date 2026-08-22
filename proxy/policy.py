"""Allow/deny filtering policy for the proxy."""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

_DEFAULT_FILTER_PATH = Path("/data/filter.json")
VALID_MODES = frozenset({"open", "allow", "deny"})


def get_filter_path() -> Path:
    env = os.environ.get("PROXY_FILTER_PATH")
    return Path(env) if env else _DEFAULT_FILTER_PATH


def _matches(pattern: str, host: str) -> bool:
    if pattern.startswith("*."):
        # "*.example.com" matches subdomains, never the apex.
        return host.endswith(pattern[1:])
    return host == pattern


class FilterPolicy:
    """Hot-reloading allow/deny policy backed by a JSON file.

    Missing or malformed files fail open (mode "open" = no filtering).
    """

    def __init__(self, path: Path | None = None) -> None:
        self._path = path if path is not None else get_filter_path()
        # (st_mtime_ns, st_ino, st_size) of the last load; None = not loaded.
        self._revision: tuple[int, int, int] | None = None
        self._mode: str = "open"
        self._allow: list[str] = []
        self._deny: list[str] = []
        self._warned = False

    @property
    def mode(self) -> str:
        self._maybe_reload()
        return self._mode

    def is_blocked(self, host: str | None) -> bool:
        self._maybe_reload()
        if host is None or self._mode == "open":
            return False
        normalized = host.lower().rstrip(".")
        if self._mode == "allow":
            return not any(_matches(p, normalized) for p in self._allow)
        return any(_matches(p, normalized) for p in self._deny)

    def _maybe_reload(self) -> None:
        try:
            st = os.stat(self._path)
        except OSError:
            self._reset()
            return
        revision = (st.st_mtime_ns, st.st_ino, st.st_size)
        if revision == self._revision:
            return
        self._revision = revision
        try:
            data = json.loads(self._path.read_text())
        except (OSError, ValueError):
            # ValueError covers JSONDecodeError and UnicodeDecodeError alike.
            self._fail_open("unreadable or malformed filter file")
            return
        if not isinstance(data, dict):
            self._fail_open("filter file is not a JSON object")
            return
        mode = str(data.get("mode", "open")).lower()
        if mode not in VALID_MODES:
            self._fail_open(f"unknown filter mode {mode!r}")
            return
        self._mode = mode
        self._allow = self._patterns(data.get("allow"))
        self._deny = self._patterns(data.get("deny"))
        self._warned = False

    @staticmethod
    def _patterns(raw: object) -> list[str]:
        if not isinstance(raw, list):
            return []
        return [p.strip().lower().rstrip(".") for p in raw if isinstance(p, str) and p.strip()]

    def _reset(self) -> None:
        self._mode = "open"
        self._allow = []
        self._deny = []
        self._revision = None
        self._warned = False

    def _fail_open(self, reason: str) -> None:
        self._mode = "open"
        self._allow = []
        self._deny = []
        if not self._warned:
            logger.warning("Proxy filter disabled (%s); running in open mode", reason)
            self._warned = True
