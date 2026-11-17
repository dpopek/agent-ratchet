"""Compatibility alias kept until 4.0: ``guard_core.X`` is the module object ``agent_ratchet.X``.

Identity (not a re-export) keeps monkeypatching and private-name imports through the old path working.
"""

from __future__ import annotations

import importlib
import importlib.abc
import importlib.machinery
import importlib.util
import sys
from types import ModuleType
import warnings

warnings.warn("guard_core is deprecated and removed in 4.0; import agent_ratchet instead (see 'agent-ratchet migrate-imports')", DeprecationWarning, stacklevel=2)

_OLD = __name__
_NEW = "agent_ratchet"


class _AliasLoader(importlib.abc.Loader):
    def __init__(self, target: str) -> None:
        self._target = target
        self._original_spec: importlib.machinery.ModuleSpec | None = None

    def create_module(self, spec: importlib.machinery.ModuleSpec) -> ModuleType:
        module = importlib.import_module(self._target)
        self._original_spec = module.__spec__
        return module

    def exec_module(self, module: ModuleType) -> None:
        # The import system stamps the alias spec on the shared module; give it back its own.
        module.__spec__ = self._original_spec


class _AliasFinder(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname: str, path: object = None, target: object = None) -> importlib.machinery.ModuleSpec | None:
        prefix = f"{_OLD}."
        if not fullname.startswith(prefix) or fullname == f"{_OLD}.__main__":
            return None
        new_name = _NEW + fullname[len(_OLD) :]
        if importlib.util.find_spec(new_name) is None:
            return None
        return importlib.util.spec_from_loader(fullname, _AliasLoader(new_name))


if not any(isinstance(finder, _AliasFinder) for finder in sys.meta_path):
    sys.meta_path.insert(0, _AliasFinder())
