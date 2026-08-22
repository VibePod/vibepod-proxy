"""Test configuration: make flat proxy-module imports work."""

from __future__ import annotations

import sys
from pathlib import Path

PROXY_DIR = Path(__file__).resolve().parents[1] / "proxy"

if str(PROXY_DIR) not in sys.path:
    sys.path.insert(0, str(PROXY_DIR))
