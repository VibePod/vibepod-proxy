"""Allow/deny filtering policy for the proxy."""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

_DEFAULT_FILTER_PATH = Path("/data/filter.json")
VALID_MODES = frozenset({"open", "allow", "deny"})
POLICY_SCHEMA = 2
_POLICY_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_PROFILE_RE = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
_PATTERN_RE = re.compile(
    r"^(\*\.)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$",
)


def get_filter_path() -> Path:
    env = os.environ.get("PROXY_FILTER_PATH")
    return Path(env) if env else _DEFAULT_FILTER_PATH


@dataclass(frozen=True)
class FilterDecision:
    """Mode and block reason taken from one policy snapshot."""

    mode: str
    reason: str | None

    @property
    def blocked(self) -> bool:
        return self.reason is not None


@dataclass(frozen=True)
class FilterSettings:
    """Validated settings used for one policy decision."""

    mode: str
    allow: tuple[str, ...]
    deny: tuple[str, ...]


@dataclass(frozen=True)
class ContainerPolicy:
    """Launch-time policy inputs for one agent container."""

    policy_id: str
    profile: str
    project_filter: dict[str, object] | None
    env_mode: str | None


def _matches(pattern: str, host: str) -> bool:
    if pattern.startswith("*."):
        # "*.example.com" matches subdomains, never the apex.
        return host.endswith(pattern[1:])
    return host == pattern


def _evaluate_settings(settings: FilterSettings, host: str | None) -> FilterDecision:
    mode = settings.mode
    if host is None or mode == "open":
        return FilterDecision(mode, None)
    normalized = host.lower().rstrip(".")
    if mode == "allow":
        if any(_matches(pattern, normalized) for pattern in settings.allow):
            return FilterDecision(mode, None)
        return FilterDecision(mode, "allow-miss")
    if any(_matches(pattern, normalized) for pattern in settings.deny):
        return FilterDecision(mode, "deny-match")
    return FilterDecision(mode, None)


def _patterns(raw: object) -> tuple[str, ...]:
    if not isinstance(raw, list):
        raise ValueError("filter patterns must be a list")
    patterns: list[str] = []
    for entry in raw:
        if not isinstance(entry, str):
            raise ValueError("filter patterns must be strings")
        pattern = entry.strip().lower().rstrip(".")
        if not _PATTERN_RE.fullmatch(pattern):
            raise ValueError(f"invalid filter pattern {entry!r}")
        patterns.append(pattern)
    return tuple(patterns)


def _settings(raw: object, *, schema_required: bool) -> FilterSettings:
    if not isinstance(raw, dict):
        raise ValueError("filter settings must be an object")
    version = raw.get("version")
    if schema_required and version != POLICY_SCHEMA:
        raise ValueError(f"unsupported policy schema {version!r}")
    if not schema_required and version not in (None, POLICY_SCHEMA):
        raise ValueError(f"unsupported policy schema {version!r}")
    mode_raw = raw.get("mode", "open")
    if not isinstance(mode_raw, str):
        raise ValueError("filter mode must be a string")
    mode = mode_raw.strip().lower()
    if mode not in VALID_MODES:
        raise ValueError(f"unknown filter mode {mode!r}")
    return FilterSettings(
        mode=mode,
        allow=_patterns(raw.get("allow", [])),
        deny=_patterns(raw.get("deny", [])),
    )


def _settings_dict(settings: FilterSettings) -> dict[str, object]:
    return {
        "mode": settings.mode,
        "allow": list(settings.allow),
        "deny": list(settings.deny),
    }


class PolicyStore:
    """Resolve and hot-reload global, profile, and per-container policies."""

    def __init__(self, data_dir: Path = Path("/data")) -> None:
        self._data_dir = data_dir
        self._cache: dict[Path, tuple[tuple[int, int, int], object]] = {}

    def evaluate(self, host: str | None, policy_id: str | None) -> FilterDecision:
        """Evaluate *host* globally or for one identified agent launch."""
        if policy_id is None:
            try:
                return _evaluate_settings(self._global_settings(), host)
            except (OSError, ValueError):
                return FilterDecision("open", None)
        try:
            settings = self._resolved_settings(policy_id)
        except (OSError, ValueError):
            return FilterDecision("unavailable", "policy-unavailable")
        return _evaluate_settings(settings, host)

    def _read_json(self, path: Path) -> object:
        stat = path.stat()
        revision = (stat.st_mtime_ns, stat.st_ino, stat.st_size)
        cached = self._cache.get(path)
        if cached is not None and cached[0] == revision:
            return cached[1]
        data = json.loads(path.read_text(encoding="utf-8"))
        self._cache[path] = (revision, data)
        return data

    def _global_settings(self) -> FilterSettings:
        # Honor a relocated global filter file (documented PROXY_FILTER_PATH);
        # otherwise it lives at the data dir's root, next to the policies tree.
        env = os.environ.get("PROXY_FILTER_PATH")
        path = Path(env) if env else self._data_dir / "filter.json"
        return _settings(self._read_json(path), schema_required=False)

    def _container_policy(self, policy_id: str) -> ContainerPolicy:
        if not _POLICY_ID_RE.fullmatch(policy_id):
            raise ValueError("invalid policy id")
        path = self._data_dir / "policies" / "containers" / f"{policy_id}.json"
        raw = self._read_json(path)
        if not isinstance(raw, dict) or raw.get("version") != POLICY_SCHEMA:
            raise ValueError("invalid container policy")
        if raw.get("policy_id") != policy_id:
            raise ValueError("container policy id mismatch")
        profile = raw.get("profile")
        if not isinstance(profile, str) or not _PROFILE_RE.fullmatch(profile):
            raise ValueError("invalid profile")
        project_filter = raw.get("project_filter")
        if project_filter is not None and not isinstance(project_filter, dict):
            raise ValueError("invalid project filter")
        env_mode = raw.get("env_mode")
        if env_mode is not None:
            if not isinstance(env_mode, str):
                raise ValueError("invalid environment mode")
            env_mode = env_mode.strip().lower()
            if env_mode not in VALID_MODES:
                raise ValueError("invalid environment mode")
        return ContainerPolicy(policy_id, profile, project_filter, env_mode)

    def _resolved_settings(self, policy_id: str) -> FilterSettings:
        record = self._container_policy(policy_id)
        profile_path = self._data_dir / "policies" / "profiles" / f"{record.profile}.json"
        try:
            raw: dict[str, object] = _settings_dict(
                _settings(self._read_json(profile_path), schema_required=True),
            )
        except FileNotFoundError:
            # Only the inherited-profile fallback needs the global base, so a
            # missing global filter.json never blocks a valid explicit profile.
            raw = _settings_dict(self._global_settings())
            if record.project_filter is not None:
                raw.update(record.project_filter)
        if record.env_mode is not None:
            raw["mode"] = record.env_mode
        return _settings(raw, schema_required=False)


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
        return self.evaluate(host).blocked

    def block_reason(self, host: str | None) -> str | None:
        """Why a host is blocked: "deny-match", "allow-miss", or None (not blocked)."""
        return self.evaluate(host).reason

    def evaluate(self, host: str | None) -> FilterDecision:
        """Decide on *host* and report the mode from the same policy snapshot.

        Callers that log the mode alongside the decision must use this instead
        of separate block_reason()/mode calls: each of those reloads the file,
        so a hot reload in between could pair a reason with the wrong mode.
        """
        self._maybe_reload()
        mode = self._mode
        if host is None or mode == "open":
            return FilterDecision(mode, None)
        normalized = host.lower().rstrip(".")
        if mode == "allow":
            if any(_matches(p, normalized) for p in self._allow):
                return FilterDecision(mode, None)
            return FilterDecision(mode, "allow-miss")
        if any(_matches(p, normalized) for p in self._deny):
            return FilterDecision(mode, "deny-match")
        return FilterDecision(mode, None)

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
