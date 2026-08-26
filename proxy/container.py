"""Client-IP to container metadata resolution.

Lives outside addon.py on purpose: mitmproxy executes the addon script with a
module object it never puts in `sys.modules`, and `@dataclass` on a class with
string annotations (`from __future__ import annotations`) looks its own module
up there while processing fields. Regular imports like this one get a real
`sys.modules` entry, so dataclasses defined here work.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

_DEFAULT_MAPPING_PATH = Path("/data/containers.json")


@dataclass(frozen=True)
class ContainerMetadata:
    container_id: str | None = None
    container_name: str | None = None
    policy_id: str | None = None
    profile: str | None = None


class ContainerResolver:
    """Resolves client IPs to container metadata via a shared JSON file."""

    def __init__(self, path: Path = _DEFAULT_MAPPING_PATH) -> None:
        self._path = path
        self._mtime: float = 0.0
        self._mapping: dict[str, dict[str, str]] = {}

    def resolve(self, ip: str | None) -> ContainerMetadata:
        """Return mapped metadata for the given client IP."""
        if ip is None:
            return ContainerMetadata()
        self._maybe_reload()
        entry = self._mapping.get(ip)
        if entry is None:
            return ContainerMetadata()
        return ContainerMetadata(
            container_id=entry.get("container_id"),
            container_name=entry.get("container_name"),
            policy_id=entry.get("policy_id"),
            profile=entry.get("profile"),
        )

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
