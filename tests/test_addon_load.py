"""Load addon.py the way mitmproxy does, not the way pytest does.

mitmproxy's script loader (`mitmproxy.addons.script.load_script`) builds the
addon module with `importlib.util.module_from_spec` + `exec_module` and never
registers it in `sys.modules`. Anything executed at import time that looks the
module up by `__module__` therefore sees `None` -- most notably
`@dataclass` on a class with string annotations, which crashes in
`dataclasses._is_type`. A plain `import addon` hides that entirely.
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import os
import sys
import types
from pathlib import Path

ADDON_PATH = Path(__file__).resolve().parents[1] / "proxy" / "addon.py"


def _load_like_mitmproxy(path: Path) -> types.ModuleType:
    """Mirror mitmproxy.addons.script.load_script, minus the error swallowing."""
    fullname = f"__mitmproxy_script__.{path.stem}"
    sys.modules.pop(fullname, None)
    oldpath = sys.path
    sys.path = [str(path.parent), *sys.path]
    try:
        loader = importlib.machinery.SourceFileLoader(fullname, str(path))
        spec = importlib.util.spec_from_loader(fullname, loader=loader)
        assert spec is not None
        module = importlib.util.module_from_spec(spec)
        loader.exec_module(module)
        return module
    finally:
        sys.path[:] = oldpath
        sys.modules.pop(fullname, None)


def test_addon_imports_outside_sys_modules() -> None:
    module = _load_like_mitmproxy(ADDON_PATH)
    assert hasattr(module, "SQLiteLogger")
    assert module.__name__ not in sys.modules


def test_addon_module_is_not_registered_by_loader() -> None:
    """Guard the assumption the other test rests on."""
    assert "__mitmproxy_script__.addon" not in sys.modules
    assert os.path.exists(ADDON_PATH)
