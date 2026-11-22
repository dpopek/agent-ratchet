"""Classifier I: source trees, canonical AST, recognised gates, closed world, import graph, surfaces."""

from __future__ import annotations

import ast
import os
import textwrap

import pytest

from classify_fixtures import SCOPE, tree_from
from fakes import real_git
from repos import commit_files, make_bare, make_clone, push_all
from guard_fleet.classify.canonical import canonical, canonical_toml, digest
from guard_fleet.classify.closedworld import violations
from guard_fleet.classify.gating import GateSite, GateTrust, Level, gate_level
from guard_fleet.classify.graph import Edge, module_edges
from guard_fleet.classify.surfaces import compute_surfaces
from guard_fleet.classify.tree import SourceTree, TreeError, load_tree, module_name

PHP_SCAN = "src/agent_ratchet/php/scan.py"
MAGENTO_SCAN = "src/agent_ratchet/magento/scan.py"
PHP_HEADER = "from agent_ratchet.php.scope import php_profile_active\n\n\n"

# A core root (transition_scan) imports both scan modules at top level, as at v4.3.4.
BASE = {
    "src/agent_ratchet/__init__.py": "",
    "src/agent_ratchet/transition_scan.py": (
        "from agent_ratchet.php.scan import php_scan\n"
        "from agent_ratchet.magento.scan import magento_scan\n"
    ),
    "src/agent_ratchet/git_guard_io.py": "def load_guard_config_for_ref(ref):\n    return {}\n",
    "src/agent_ratchet/php/__init__.py": "",
    "src/agent_ratchet/php/scope.py": SCOPE,
    "src/agent_ratchet/php/extract.py": "TEST = 1\n",
    "src/agent_ratchet/php/codes.py": "CODES = ()\n",
    "src/agent_ratchet/php/parser.py": "PARSER = None\n",
    PHP_SCAN: PHP_HEADER + "def php_scan(cfg):\n    return []\n",
    "src/agent_ratchet/magento/__init__.py": "",
    "src/agent_ratchet/magento/compare.py": "X = 1\n",
    "src/agent_ratchet/magento/di.py": "DI = 1\n",
    "src/agent_ratchet/magento/config.py": "CONFIG = 1\n",
    MAGENTO_SCAN: "def magento_scan(cfg):\n    return []\n",
}

SCAN_WITH_EARLY_GATE = PHP_HEADER + '''def php_scan(cfg):
    if not php_profile_active(cfg):
        return []
    from agent_ratchet.php.extract import TEST
    for path in cfg.get("paths", ()):
        try:
            from agent_ratchet.php.codes import CODES
        except ImportError:
            pass
    return [TEST]
'''

SCAN_UNGATED_HELPER = PHP_HEADER + '''def _helper():
    from agent_ratchet.php.extract import TEST
    return TEST


def php_scan(cfg):
    if not php_profile_active(cfg):
        return []
    return [_helper()]
'''

GATE_THEN_NESTED_DEF = PHP_HEADER + '''def php_scan(cfg):
    if not php_profile_active(cfg):
        return []

    def nested():
        from agent_ratchet.php.extract import TEST
        return TEST

    from agent_ratchet.php.codes import CODES
    return [nested(), CODES]
'''

EARLY_GATE_WITH_ELSE = PHP_HEADER + '''def php_scan(cfg):
    if not php_profile_active(cfg):
        return []
    else:
        pass
    from agent_ratchet.php.extract import TEST
    return [TEST]
'''

EARLY_GATE_WITH_TWO_STATEMENTS = PHP_HEADER + '''def php_scan(cfg):
    if not php_profile_active(cfg):
        print("off")
        return []
    from agent_ratchet.php.extract import TEST
    return [TEST]
'''

G_BLOCK_WITH_ELIF_AND_ELSE = PHP_HEADER + '''def php_scan(cfg, other):
    if php_profile_active(cfg):
        from agent_ratchet.php.extract import TEST
    elif other:
        from agent_ratchet.php.codes import CODES
    else:
        from agent_ratchet.php.parser import PARSER
    return []
'''

MAGENTO_GATES = '''def magento_scan(cfg):
    if "magento" not in cfg.get("frameworks", ()):
        return []
    from agent_ratchet.magento.compare import X
    return [X]


def magento_block(cfg):
    if "magento" in cfg.get("frameworks", ()):
        from agent_ratchet.magento.di import DI


def near_miss(cfg):
    if "magento" not in cfg.get("frameworks", []):
        return []
    from agent_ratchet.magento.config import CONFIG
'''

# `from agent_ratchet.php import extract` is the only route to the php package and to php.extract.
FROM_PKG_IMPORT_SUBMODULE = {
    "src/agent_ratchet/__init__.py": "",
    "src/agent_ratchet/report.py": "from agent_ratchet.php import extract\n",
    "src/agent_ratchet/php/__init__.py": "",
    "src/agent_ratchet/php/extract.py": "TEST = 1\n",
    "src/agent_ratchet/php/codes.py": "CODES = ()\n",
}

PROFILE_LIKE = '''import importlib.metadata
import importlib.util

REQUIRED_MODULES = {
    "php": ("tree_sitter", "tree_sitter_php"),
    "magento": ("tree_sitter", "tree_sitter_php", "defusedxml"),
}
ORDER = ("tree_sitter",)


def require(name):
    if importlib.util.find_spec("tree_sitter") is None:
        return False
    for mod in ORDER:
        importlib.util.find_spec(mod)
    return any(importlib.util.find_spec(mod) is None for mod in REQUIRED_MODULES[name])


def version():
    try:
        return importlib.metadata.distribution("agent-ratchet").version
    except importlib.metadata.PackageNotFoundError:
        return None
'''


def surfaces(scan: str, path: str = PHP_SCAN) -> dict[str, Level]:
    """Levels over BASE with one scan module replaced."""
    return dict(compute_surfaces(tree_from({**BASE, path: scan})).level_of)


def levels(files: dict[str, str]) -> dict[str, Level]:
    return dict(compute_surfaces(tree_from(files)).level_of)


def surfaces_reason(files: dict[str, str], scripts: dict[str, str] | None = None) -> str | None:
    return compute_surfaces(tree_from(files, scripts)).all_core_reason


def gated_scan(prelude: str, arg: str = "cfg") -> str:
    """php/scan.py whose gated function runs `prelude` before a G-early on `arg`."""
    return PHP_HEADER + (
        "def php_scan(cfg, x, other):\n"
        + textwrap.indent(prelude, "    ")
        + f"    if not php_profile_active({arg}):\n"
        "        return []\n"
        "    from agent_ratchet.php.extract import TEST\n"
        "    return [TEST]\n"
    )


# -- gates and levels --------------------------------------------------------------------------------

def test_base_layout_is_open_and_core():
    m = compute_surfaces(tree_from(BASE))
    assert m.all_core_reason is None
    assert set(m.level_of.values()) == {Level.CORE}
    assert m.gates == ()


def test_g_early_gates_later_imports():                       # php.extract only behind the gate → PHP
    m = surfaces(SCAN_WITH_EARLY_GATE)
    assert m["agent_ratchet.php.extract"] is Level.PHP
    assert m["agent_ratchet.php.codes"] is Level.PHP          # later statement at depth (for → try)
    assert m["agent_ratchet.php.scan"] is Level.CORE
    assert m["agent_ratchet.php.scope"] is Level.CORE


def test_ungated_function_import_makes_module_core():
    assert surfaces(SCAN_UNGATED_HELPER)["agent_ratchet.php.extract"] is Level.CORE


def test_nested_function_after_gate_is_not_gated():
    m = surfaces(GATE_THEN_NESTED_DEF)
    assert m["agent_ratchet.php.extract"] is Level.CORE
    assert m["agent_ratchet.php.codes"] is Level.PHP          # the outer block after the nested def stays gated


def test_g_early_with_else_is_not_a_gate():
    assert surfaces(EARLY_GATE_WITH_ELSE)["agent_ratchet.php.extract"] is Level.CORE
    assert surfaces(EARLY_GATE_WITH_TWO_STATEMENTS)["agent_ratchet.php.extract"] is Level.CORE


def test_g_block_body_gated_orelse_and_elif_not():
    m = surfaces(G_BLOCK_WITH_ELIF_AND_ELSE)
    assert m["agent_ratchet.php.extract"] is Level.PHP
    assert m["agent_ratchet.php.codes"] is Level.CORE
    assert m["agent_ratchet.php.parser"] is Level.CORE


def test_magento_gate_shapes():
    m = surfaces(MAGENTO_GATES, MAGENTO_SCAN)
    assert m["agent_ratchet.magento.compare"] is Level.MAGENTO   # G-early
    assert m["agent_ratchet.magento.di"] is Level.MAGENTO        # G-block
    assert m["agent_ratchet.magento.config"] is Level.CORE       # `[]` default is not the recognised shape


def test_gate_sites_are_recorded_with_qualified_function_and_line():
    text = PHP_HEADER + '''class Scanner:
    def run(self, cfg):
        if php_profile_active(cfg):
            from agent_ratchet.php.extract import TEST
'''
    m = compute_surfaces(tree_from({**BASE, PHP_SCAN: text, MAGENTO_SCAN: MAGENTO_GATES}))
    assert m.gates == (
        GateSite("agent_ratchet.magento.scan", "magento_scan", "early", Level.MAGENTO, 2),
        GateSite("agent_ratchet.magento.scan", "magento_block", "block", Level.MAGENTO, 9),
        GateSite("agent_ratchet.php.scan", "Scanner.run", "block", Level.PHP, 6),
    )
    assert m.level_of["agent_ratchet.php.extract"] is Level.PHP


def test_module_level_and_class_body_conditions_are_not_gates():
    module_level = PHP_HEADER + "cfg = {}\nif php_profile_active(cfg):\n    from agent_ratchet.php.extract import TEST\n"
    in_class_body = PHP_HEADER + '''def php_scan(cfg):
    class Holder:
        cfg = {}
        if php_profile_active(cfg):
            from agent_ratchet.php.extract import TEST
    return []
'''
    for text in (module_level, in_class_body):
        m = compute_surfaces(tree_from({**BASE, PHP_SCAN: text}))
        assert m.level_of["agent_ratchet.php.extract"] is Level.CORE
        assert m.gates == ()


def test_class_body_after_g_early_inherits_the_gate():
    text = PHP_HEADER + '''def php_scan(cfg):
    if not php_profile_active(cfg):
        return []

    class Holder:
        from agent_ratchet.php.extract import TEST
    return []
'''
    assert surfaces(text)["agent_ratchet.php.extract"] is Level.PHP


def test_levels_compose_along_paths():
    files = {
        **BASE,
        PHP_SCAN: PHP_HEADER + "def php_scan(cfg):\n    if php_profile_active(cfg):\n"
                               "        import agent_ratchet.php.extract\n",
        # a PHP module's ungated import stays PHP; so does a magento-gated one (it is in the php closure)
        "src/agent_ratchet/php/extract.py": (
            "import agent_ratchet.php.codes\n\n\n"
            "def f(cfg):\n"
            '    if "magento" not in cfg.get("frameworks", ()):\n'
            "        return []\n"
            "    import agent_ratchet.magento.compare\n"
        ),
        "src/agent_ratchet/php/orphan.py": "import agent_ratchet.php.parser\n",   # unreachable
        "src/agent_ratchet/php/parser.py": "PARSER = None\n",
    }
    m = levels(files)
    assert m["agent_ratchet.php.extract"] is Level.PHP
    assert m["agent_ratchet.php.codes"] is Level.PHP
    assert m["agent_ratchet.magento.compare"] is Level.PHP
    assert m["agent_ratchet.php.orphan"] is Level.CORE        # reached by nothing → core
    assert m["agent_ratchet.php.parser"] is Level.CORE
    files["src/agent_ratchet/report.py"] = "import agent_ratchet.php.codes\n"   # a core route wins
    assert levels(files)["agent_ratchet.php.codes"] is Level.CORE


MAGENTO_GATED_SCAN = '''def magento_scan(cfg):
    if "magento" not in cfg.get("frameworks", ()):
        return []
    import agent_ratchet.magento.compare
'''


def test_php_gate_behind_a_magento_gate_is_php():
    # root −MAGENTO→ magento.compare −PHP→ php.extract: the php closure holds php.extract
    files = {**BASE, MAGENTO_SCAN: MAGENTO_GATED_SCAN,
             "src/agent_ratchet/magento/compare.py": PHP_HEADER + (
                 "def f(cfg):\n    if not php_profile_active(cfg):\n        return []\n"
                 "    import agent_ratchet.php.extract\n")}
    m = levels(files)
    assert m["agent_ratchet.magento.compare"] is Level.MAGENTO
    assert m["agent_ratchet.php.extract"] is Level.PHP


def test_magento_gate_behind_a_php_gate_is_php():
    # root −PHP→ php.extract −MAGENTO→ magento.compare: magento.compare is in the php closure
    files = {**BASE, PHP_SCAN: SCAN_WITH_EARLY_GATE,
             "src/agent_ratchet/php/extract.py": (
                 "TEST = 1\n\n\ndef f(cfg):\n"
                 '    if "magento" not in cfg.get("frameworks", ()):\n'
                 "        return []\n"
                 "    import agent_ratchet.magento.compare\n")}
    m = levels(files)
    assert m["agent_ratchet.php.extract"] is Level.PHP
    assert m["agent_ratchet.magento.compare"] is Level.PHP


def test_parent_packages_and_from_import_submodule():          # `from agent_ratchet.php import extract` adds php, php.extract
    m = levels(FROM_PKG_IMPORT_SUBMODULE)
    assert m["agent_ratchet.php"] is Level.CORE and m["agent_ratchet.php.extract"] is Level.CORE
    assert set(m) == {"agent_ratchet", "agent_ratchet.cli", "agent_ratchet.report", "agent_ratchet.php",
                      "agent_ratchet.php.extract", "agent_ratchet.php.codes"}


def test_script_target_inside_a_surface_package_is_a_core_root():
    files = {**FROM_PKG_IMPORT_SUBMODULE, "src/agent_ratchet/report.py": "X = 1\n",
             "src/agent_ratchet/php/tool.py": "import agent_ratchet.php.codes\n"}
    t = tree_from(files, scripts={"agent-ratchet": "agent_ratchet.cli:main", "php-tool": "agent_ratchet.php.tool:main"})
    m = compute_surfaces(t)
    assert m.all_core_reason is None
    assert m.level_of["agent_ratchet.php.tool"] is Level.CORE
    assert m.level_of["agent_ratchet.php.codes"] is Level.CORE
    assert m.level_of["agent_ratchet.php"] is Level.CORE        # the parent package runs before the target


@pytest.mark.parametrize("snippet", [
    "cfg = other()\n", "cfg = cfg\n", "for cfg in x: pass\n", "del cfg\n",
    "cfg += 1\n", "cfg: dict = {}\n", "with x as cfg: pass\n", "(cfg := 1)\n", "import cfg\n",
    "def cfg(): pass\n", "try:\n    pass\nexcept Exception as cfg:\n    pass\n",
    "def inner():\n    nonlocal cfg\n    cfg = 1\n",
])
def test_rebound_or_computed_gate_argument_is_ungated(snippet):
    assert surfaces(gated_scan(snippet))["agent_ratchet.php.extract"] is Level.CORE


def test_gate_argument_shapes():
    assert surfaces(gated_scan("pass\n"))["agent_ratchet.php.extract"] is Level.PHP             # parameter
    assert surfaces(gated_scan("cfg: dict\n"))["agent_ratchet.php.extract"] is Level.PHP        # annotation only
    assert surfaces(gated_scan("pass\n", 'cfg["x"]'))["agent_ratchet.php.extract"] is Level.CORE  # computed
    assert surfaces(gated_scan("pass\n", "missing"))["agent_ratchet.php.extract"] is Level.CORE   # unbound


def loader_scan(header: str, prelude: str) -> str:
    return header + PHP_HEADER + (
        "def php_scan(ref):\n"
        + textwrap.indent(prelude, "    ")
        + "    if not php_profile_active(cfg):\n"
        "        return []\n"
        "    from agent_ratchet.php.extract import TEST\n"
    )


LOADER_IMPORT = "from agent_ratchet.git_guard_io import load_guard_config_for_ref\n"


@pytest.mark.parametrize("header,prelude,level", [
    (LOADER_IMPORT, "cfg = load_guard_config_for_ref(ref)\n", Level.PHP),
    ("", "cfg = load_guard_config_for_ref(ref)\n", Level.CORE),                          # loader not imported
    ("from x import load_guard_config_for_ref\n", "cfg = load_guard_config_for_ref(ref)\n", Level.CORE),
    (LOADER_IMPORT + "load_guard_config_for_ref = dict\n", "cfg = load_guard_config_for_ref(ref)\n", Level.CORE),
    (LOADER_IMPORT, "cfg = load_guard_config_for_ref(ref)\ncfg = load_guard_config_for_ref(ref)\n", Level.CORE),
    (LOADER_IMPORT, "cfg = x = load_guard_config_for_ref(ref)\n", Level.CORE),
    (LOADER_IMPORT, "cfg = dict(load_guard_config_for_ref(ref))\n", Level.CORE),
])
def test_loader_bound_gate_argument(header, prelude, level):
    assert surfaces(loader_scan(header, prelude))["agent_ratchet.php.extract"] is level


@pytest.mark.parametrize("header,tail", [
    ("from x import php_profile_active\n", ""),
    (PHP_HEADER, "php_profile_active = lambda cfg: True\n"),
    (PHP_HEADER, "def other(php_profile_active):\n    return php_profile_active\n"),
    (PHP_HEADER + PHP_HEADER, ""),
    (PHP_HEADER, "from os.path import *\n"),
    ("try:\n    from agent_ratchet.php.scope import php_profile_active\nexcept ImportError:\n    pass\n", ""),
    ("from agent_ratchet.php.scope import php_profile_active as active\nphp_profile_active = active\n", ""),
])
def test_predicate_rebound_or_bound_by_other_import_is_untrusted(header, tail):
    body = "def php_scan(cfg):\n    if not php_profile_active(cfg):\n        return []\n" \
           "    from agent_ratchet.php.extract import TEST\n"
    assert surfaces(header + body + tail)["agent_ratchet.php.extract"] is Level.CORE


def test_magento_gate_does_not_need_the_predicate():
    text = "from x import php_profile_active\n\n\n" + MAGENTO_GATES
    assert surfaces(text, MAGENTO_SCAN)["agent_ratchet.magento.compare"] is Level.MAGENTO


def test_gate_level_shapes_directly():
    trusted = GateTrust(predicate_ok=True, bound_once=lambda name: name == "cfg")
    early = ast.parse("if not php_profile_active(cfg):\n    return []\n").body[0]
    block = ast.parse("if php_profile_active(cfg):\n    pass\n").body[0]
    mag_early = ast.parse('if "magento" not in cfg.get("frameworks", ()):\n    return []\n').body[0]
    mag_block = ast.parse('if "magento" in cfg.get("frameworks", ()):\n    pass\n').body[0]
    assert gate_level(early, early=True, trust=trusted) is Level.PHP
    assert gate_level(early, early=False, trust=trusted) is None
    assert gate_level(block, early=False, trust=trusted) is Level.PHP
    assert gate_level(block, early=True, trust=trusted) is None
    assert gate_level(mag_early, early=True, trust=trusted) is Level.MAGENTO
    assert gate_level(mag_block, early=False, trust=trusted) is Level.MAGENTO
    untrusted_predicate = GateTrust(predicate_ok=False, bound_once=lambda name: True)
    assert gate_level(early, early=True, trust=untrusted_predicate) is None
    assert gate_level(mag_early, early=True, trust=untrusted_predicate) is Level.MAGENTO
    rebound = GateTrust(predicate_ok=True, bound_once=lambda name: False)
    assert gate_level(block, early=False, trust=rebound) is None
    assert gate_level(ast.parse("x = 1\n").body[0], early=True, trust=trusted) is None
    wrong_key = ast.parse('if "magento" in cfg.get("languages", ()):\n    pass\n').body[0]
    keyword = ast.parse("if php_profile_active(cfg=cfg):\n    pass\n").body[0]
    assert gate_level(wrong_key, early=False, trust=trusted) is None
    assert gate_level(keyword, early=False, trust=trusted) is None


# -- import graph ------------------------------------------------------------------------------------

KNOWN = frozenset({"agent_ratchet", "agent_ratchet.php", "agent_ratchet.php.scan", "agent_ratchet.php.extract"})


def test_import_edges_cover_parents_and_known_only():
    tree = ast.parse("import os\nimport agent_ratchet.php.scan\n")
    assert module_edges("m", tree, KNOWN) == [
        Edge("m", "agent_ratchet", Level.CORE, 2),
        Edge("m", "agent_ratchet.php", Level.CORE, 2),
        Edge("m", "agent_ratchet.php.scan", Level.CORE, 2),
    ]


def test_from_import_edges_add_known_submodules():
    tree = ast.parse("def f():\n    from agent_ratchet.php import extract, CONST\n")
    assert sorted(e.dst for e in module_edges("m", tree, KNOWN)) == [
        "agent_ratchet", "agent_ratchet.php", "agent_ratchet.php.extract"]
    assert all(e.level is Level.CORE and e.lineno == 2 for e in module_edges("m", tree, KNOWN))


def test_gated_edge_carries_the_gate_level():
    tree = ast.parse(PHP_HEADER + "def f(cfg):\n    if php_profile_active(cfg):\n"
                     "        import agent_ratchet.php.extract\n")
    edges = module_edges("m", tree, KNOWN | {"agent_ratchet.php.scope"})
    assert Edge("m", "agent_ratchet.php.extract", Level.PHP, 6) in edges
    assert Edge("m", "agent_ratchet.php.scope", Level.CORE, 1) in edges


# -- closed world ------------------------------------------------------------------------------------

@pytest.mark.parametrize("src,reason", [
    ("from . import x\n", "relative import"),
    ("from agent_ratchet.php import *\n", "star import"),
    ("import agent_ratchet.php.scope as s\ns.php_profile_active = f\n", "assignment to agent_ratchet.php.scope"),
    ("from agent_ratchet.php import scope\nscope.x = 1\n", "assignment to agent_ratchet.php.scope"),
    ("import agent_ratchet.php.scope\ndel agent_ratchet.php.scope.x\n", "assignment to agent_ratchet.php.scope"),
    ("from agent_ratchet.php.scope import php_profile_active\nphp_profile_active.__code__ = c\n",
     "assignment to agent_ratchet.php.scope"),
    ("import agent_ratchet.php.scope as s\ns.__dict__['x'] = 1\n", "assignment to agent_ratchet.php.scope"),
    ("x = __import__\n", "__import__"), ("exec\n", "exec"), ("eval('1')\n", "eval"), ("compile\n", "compile"),
    ("__builtins__\n", "__builtins__"), ("import runpy\n", "runpy"), ("import pickle\n", "pickle"),
    ("setattr(a, 'b', 1)\n", "setattr"), ("delattr(a, 'b')\n", "delattr"), ("globals()\n", "globals"),
    ("vars()\n", "vars"), ("from os import eval\n", "eval"),
    ("import builtins\n", "builtins"), ("from pkgutil import walk_packages\n", "pkgutil"),
    ("import pydoc as p\n", "pydoc"),
    ("import sys\nsys.executable\n", "sys.executable"), ("import sys\nsys.modules['x'] = m\n", "sys.modules"),
    ("from sys import executable\n", "sys.executable"),
    ("from importlib import import_module\n", "importlib.import_module"),
    ("import importlib\nimportlib.import_module('x')\n", "importlib.import_module"),
    ("import importlib.util as u\nu.module_from_spec(s)\n", "importlib.util.module_from_spec"),
    ("import importlib.machinery\n", "importlib.machinery"),
    ("import importlib.util\nimportlib.util.find_spec('a.b')\n", "find_spec"),
    ("from importlib.util import find_spec as fs\nfs(name)\n", "find_spec"),
    ("import importlib.util\nimportlib.util.find_spec('a', None)\n", "find_spec"),
    ("import importlib.util\nf = importlib.util.find_spec\n", "find_spec"),
    ("import importlib.util\nT = ('a.b',)\nfor m in T:\n    importlib.util.find_spec(m)\n", "find_spec"),
    ("import importlib.util\nT = ('a',)\nT = ('b',)\nfor m in T:\n    importlib.util.find_spec(m)\n", "find_spec"),
    ("import importlib.util\nT = ['a']\nT.append('a.b')\nfor m in T:\n    importlib.util.find_spec(m)\n",
     "find_spec"),
    ("import importlib.util\nT = ('a',)\nfor m in T:\n    m = 'a.b'\n    importlib.util.find_spec(m)\n", "find_spec"),
    ("import importlib.util\nfor m in names():\n    importlib.util.find_spec(m)\n", "find_spec"),
    ("import importlib.util\nT = ('a',)\ndef f():\n    T = ('a.b',)\n    for m in T:\n"
     "        importlib.util.find_spec(m)\n", "find_spec"),
    # a guarded module object used as a value escapes the alias tracking of the checks above
    ("import agent_ratchet.php.scope\ns = agent_ratchet.php.scope\ns.php_profile_active = f\n",
     "module object agent_ratchet.php.scope used as a value"),
    ("from agent_ratchet.php import scope as sc\ndef f(m=sc):\n    m.php_profile_active = g\n",
     "module object agent_ratchet.php.scope used as a value"),
    ("import importlib\nil = importlib\nil.import_module('x')\n", "module object importlib used as a value"),
    ("import sys\ns = sys\ns.modules['x'] = m\n", "module object sys used as a value"),
    ("import importlib\ngetattr(importlib, 'import_module')('x')\n", "module object importlib used as a value"),
    ("from importlib import util\nT = [util]\n", "module object importlib.util used as a value"),
    ("import sys\ndef f():\n    return sys\n", "module object sys used as a value"),
    ("def f(:\n", "parse error"),
    ("x = 1\0\n", "parse error"),
])
def test_closed_world_makes_release_core(src, reason):
    assert reason in surfaces_reason({"src/agent_ratchet/x.py": src})


def test_allowed_forms_stay_open():          # re.compile, importlib.util.find_spec("tree_sitter"), REQUIRED_MODULES loop
    assert surfaces_reason({"src/agent_ratchet/profile.py": PROFILE_LIKE,
                            "src/agent_ratchet/r.py": "import re\nre.compile('x')\nimport sys\nsys.argv\n"}) is None


def test_violation_format_names_module_and_line():
    assert violations("agent_ratchet.x", ast.parse("x = 1\neval\nimport runpy\n")) == [
        "agent_ratchet.x:L2 name eval", "agent_ratchet.x:L3 import runpy"]
    assert violations("agent_ratchet.x", ast.parse(PROFILE_LIKE)) == []


def test_first_reason_wins_and_names_the_module():
    reason = surfaces_reason({"src/agent_ratchet/b.py": "import pickle\n", "src/agent_ratchet/a.py": "eval\n"})
    assert reason == "agent_ratchet.a:L1 name eval"


def test_missing_script_root_makes_release_core():
    assert "missing root" in surfaces_reason({}, scripts={"agent-ratchet": "agent_ratchet.nope:main"})
    assert "agent_ratchet.nope" in surfaces_reason({}, scripts={"agent-ratchet": "agent_ratchet.nope:main"})


def test_missing_cli_module_makes_release_core():
    t = SourceTree("c" * 40, {"src/agent_ratchet/x.py": b"X = 1\n"}, {"src/agent_ratchet/x.py": "100644"}, {})
    assert compute_surfaces(t).all_core_reason == "missing root agent_ratchet.cli"


@pytest.mark.parametrize("path,mode", [("src/agent_ratchet/link.py", "120000"),
                                       ("src/agent_ratchet/php2", "120000"),
                                       ("src/vendored", "160000")])
def test_non_regular_entry_under_src_makes_release_core(path, mode):
    t = tree_from({"src/agent_ratchet/x.py": "X = 1\n"})
    t = SourceTree(t.commit, {**t.files, path: b"cli.py"}, {**t.modes, path: mode}, t.scripts)
    reason = compute_surfaces(t).all_core_reason
    assert reason is not None and path in reason and mode in reason


# -- canonical AST -----------------------------------------------------------------------------------

def test_digest_ignores_falsy_is_lazy_and_positions():
    parsed = ast.parse("from x import y\n").body[0]
    moved = ast.parse("\n\nfrom x import y\n").body[0]
    absent = ast.ImportFrom(module="x", names=[ast.alias("y")], level=0)      # no is_lazy attribute at all
    falsy = ast.ImportFrom(module="x", names=[ast.alias("y")], level=0)
    falsy.is_lazy = False
    assert not hasattr(absent, "is_lazy") or absent.is_lazy is None
    expected = digest(canonical(parsed))
    assert digest(canonical(moved)) == expected
    assert digest(canonical(absent)) == expected
    assert digest(canonical(falsy)) == expected
    if "is_lazy" in ast.ImportFrom._fields:                                  # Python ≥ 3.15: a lazy import differs
        lazy = ast.ImportFrom(module="x", names=[ast.alias("y")], level=0)
        lazy.is_lazy = 1
        assert digest(canonical(lazy)) != expected


def test_canonical_shape_drops_empty_fields_and_type_comments():
    assert canonical(ast.Name("a", ast.Load())) == ("Name", (("id", ("str", "a")), ("ctx", ("Load", ()))))
    assert canonical(ast.Return()) == ("Return", ())
    plain = ast.parse("x = 1\n")
    commented = ast.parse("x = 1  # type: int\n", type_comments=True)
    assert commented.body[0].type_comment == "int"
    assert canonical(commented) == canonical(plain)
    assert canonical(ast.parse("x = 2\n")) != canonical(plain)
    assert canonical(ast.parse("x = True\n")) != canonical(ast.parse("x = 1\n"))


def test_digest_is_sha256_of_repr():
    import hashlib

    obj = ("Name", (("id", ("str", "a")),))
    assert digest(obj) == hashlib.sha256(repr(obj).encode()).hexdigest()
    assert len(digest(obj)) == 64


def test_canonical_toml_is_type_tagged_and_key_sorted():
    assert canonical_toml({"b": 1, "a": [True, 1.0, "s"]}) == ("dict", (
        ("a", ("list", (("bool", True), ("float", 1.0), ("str", "s")))),
        ("b", ("int", 1)),
    ))
    assert canonical_toml({"v": 1}) != canonical_toml({"v": True}) != canonical_toml({"v": 1.0})
    assert canonical_toml({"a": 1, "b": 2}) == canonical_toml({"b": 2, "a": 1})


# -- source trees ------------------------------------------------------------------------------------

@pytest.mark.parametrize("path,name", [
    ("src/agent_ratchet/php/scan.py", "agent_ratchet.php.scan"),
    ("src/agent_ratchet/__init__.py", "agent_ratchet"),
    ("src/agent_ratchet/php/__init__.py", "agent_ratchet.php"),
    ("src/guard_core/x.py", "guard_core.x"),
    ("src/agent_ratchet/data.json", None),
    ("tests/test_x.py", None),
    ("src/__init__.py", None),
    ("src/agent_ratchet/my-mod.py", None),
])
def test_module_name(path, name):
    assert module_name(path) == name


PYPROJECT = b'[project]\nname = "agent-ratchet"\n\n[project.scripts]\nagent-ratchet = "agent_ratchet.cli:main"\n'


def test_load_tree_reads_src_and_scripts_at_the_commit(tmp_path):
    bare = make_bare(tmp_path, "alpha")
    work = make_clone(bare, tmp_path / "alpha")
    first = commit_files(work, "c1", {
        "pyproject.toml": PYPROJECT,
        "src/agent_ratchet/__init__.py": "",
        "src/agent_ratchet/cli.py": "def main():\n    return 0\n",
        "src/agent_ratchet/data.bin": b"\x00\xff\n",
        "src/agent_ratchet/empty.py": "",
        "tests/test_cli.py": "import agent_ratchet.cli\n",
        "README.md": "readme\n",
        "srcfile.py": "X = 1\n",
    })
    commit_files(work, "c2", {"src/agent_ratchet/run.py": "X = 2\n"}, mode="100755")
    os.symlink("cli.py", work / "src/agent_ratchet/link.py")
    second = commit_files(work, "c3", {
        "src/agent_ratchet/cli.py": "def main():\n    return 1\n",
        "pyproject.toml": PYPROJECT + b'extra = "agent_ratchet.extra:run"\n',
    })
    push_all(work)
    git = real_git()

    t1 = load_tree(git, bare, first)
    assert t1.commit == first
    assert set(t1.files) == {"src/agent_ratchet/__init__.py", "src/agent_ratchet/cli.py",
                             "src/agent_ratchet/data.bin", "src/agent_ratchet/empty.py"}
    assert t1.files["src/agent_ratchet/cli.py"] == b"def main():\n    return 0\n"
    assert t1.files["src/agent_ratchet/data.bin"] == b"\x00\xff\n"
    assert t1.files["src/agent_ratchet/empty.py"] == b""
    assert set(t1.modes.values()) == {"100644"}
    assert t1.scripts == {"agent-ratchet": "agent_ratchet.cli:main"}
    assert compute_surfaces(t1).all_core_reason is None

    t2 = load_tree(git, bare, second)
    assert t2.files["src/agent_ratchet/cli.py"] == b"def main():\n    return 1\n"
    assert t2.modes["src/agent_ratchet/run.py"] == "100755"
    assert t2.modes["src/agent_ratchet/link.py"] == "120000"
    assert t2.files["src/agent_ratchet/link.py"] == b"cli.py"
    assert t2.scripts == {"agent-ratchet": "agent_ratchet.cli:main", "extra": "agent_ratchet.extra:run"}
    reason = compute_surfaces(t2).all_core_reason
    assert reason is not None and "src/agent_ratchet/link.py" in reason


def test_load_tree_without_pyproject_or_src(tmp_path):
    bare = make_bare(tmp_path, "alpha")
    work = make_clone(bare, tmp_path / "alpha")
    sha = commit_files(work, "c1", {"README.md": "x\n"})
    push_all(work)
    t = load_tree(real_git(), bare, sha)
    assert (dict(t.files), dict(t.modes), dict(t.scripts)) == ({}, {}, {})
    assert compute_surfaces(t).all_core_reason == "missing root agent_ratchet.cli"


@pytest.mark.parametrize("pyproject", [b"[project\n", b"\xff\xfe", b'[project]\nscripts = "x"\n',
                                       b'[project.scripts]\nx = 1\n'])
def test_load_tree_rejects_a_malformed_pyproject(tmp_path, pyproject):
    bare = make_bare(tmp_path, "alpha")
    work = make_clone(bare, tmp_path / "alpha")
    sha = commit_files(work, "c1", {"pyproject.toml": pyproject, "src/agent_ratchet/cli.py": ""})
    push_all(work)
    with pytest.raises(TreeError, match="pyproject.toml"):
        load_tree(real_git(), bare, sha)
