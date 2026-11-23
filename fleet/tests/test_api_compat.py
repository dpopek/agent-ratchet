"""G7: static agent_ratchet references at BASE must resolve under T's src/."""

import pytest

from fakes import real_git
from guard_fleet.api_compat import Reference, check, collect, read_files
from repos import _git, commit_files, make_bare, make_clone, make_upstream, sha_of

T_FILES = {
    "src/agent_ratchet/__init__.py": b"from agent_ratchet.version import VERSION\n",
    "src/agent_ratchet/version.py": b"VERSION = '4.0.1'\n",
    "src/agent_ratchet/cli.py": (b"import json\nfrom .version import VERSION as V\n"
                                 b"try:\n    import tomllib\nexcept ImportError:\n    tomllib = None\n"
                                 b"def main():\n    return 0\nclass Runner:\n    pass\nLIMIT: int = 3\n"
                                 b"a, (b, c) = 1, (2, 3)\nfrom agent_ratchet.version import *\n"),
    "src/agent_ratchet/php/__init__.py": b"",
    "src/agent_ratchet/php/scan.py": b"def scan():\n    return []\n",
    "src/agent_ratchet/ns/inner.py": b"X = 1\n",   # a namespace package (no __init__)
}


@pytest.fixture
def api_env(tmp_path, fleet_home):
    up = make_upstream(tmp_path / "up", {"v4.0.1": T_FILES})
    t = sha_of(up, "v4.0.1")
    counter = iter(range(100))

    def make(consumer_imports=None, files=None):
        repo = make_clone(make_bare(tmp_path / "gh", f"c{next(counter)}"), tmp_path / f"repo{next(counter)}")
        tree = {"README": "x\n", **(files or {})}
        if consumer_imports is not None:
            tree["tests/test_use.py"] = consumer_imports
        commit_files(repo, "base", tree)
        base = _git(repo, "rev-parse", "HEAD")
        commit_files(repo, "later", {"tests/test_late.py": "from agent_ratchet.gone_later import x\n"})
        make.repo, make.base = repo, base
        return check(real_git(), repo, up, base=base, t=t)
    return make


def test_g7_missing_module_or_name_at_t_fails(api_env):
    assert "agent_ratchet.gone" in api_env(consumer_imports="from agent_ratchet.gone import x\n").reason
    r = api_env(consumer_imports="from agent_ratchet.cli import nope\n")
    assert r.verdict == "FAIL" and "agent_ratchet.cli.nope" in r.reason and "tests/test_use.py:1" in r.reason


def test_g7_dynamic_reference_is_not_checked(api_env):
    assert "not checked" in api_env(consumer_imports="m = 'agent_ratchet' + '.cli'\n").reason
    r = api_env(consumer_imports="import agent_ratchet.cli\nname = f'agent_ratchet.{x}'\n")
    assert r.verdict == "PASS" and "not checked: tests/test_use.py:2" in r.reason


@pytest.mark.parametrize("source", [
    "import agent_ratchet\n",
    "import agent_ratchet.php.scan as s\n",
    "from agent_ratchet import cli, php, ns\n",                     # submodules and a namespace package
    "from agent_ratchet.cli import main, Runner, LIMIT, V, tomllib, json, a, c, VERSION\n",
    "from agent_ratchet.ns.inner import X\n",
    "from agent_ratchet.cli import (\n    main,\n    Runner,\n)\n",
    "def f():\n    from agent_ratchet.php.scan import scan\n",
    "import importlib\nmod = importlib.import_module('agent_ratchet.php.scan')\n",
])
def test_g7_resolvable_references_pass(api_env, source):
    r = api_env(consumer_imports=source)
    assert r.verdict == "PASS", r.reason
    assert "not checked" not in r.reason


@pytest.mark.parametrize("path, text, missing", [
    ("scripts/run.sh", "python -m agent_ratchet.gone scan\n", "agent_ratchet.gone"),
    ("Makefile", "check:\n\tpython3 -m agent_ratchet.missing\n", "agent_ratchet.missing"),
    (".github/workflows/ci.yml", "run: uv run python -m agent_ratchet.nothere\n", "agent_ratchet.nothere"),
    ("pyproject.toml", "[tool.x]\ncmd = \"python -m agent_ratchet.absent\"\n", "agent_ratchet.absent"),
    (".vscode/launch.json", '{"args": ["-m", "agent_ratchet.vanished"]}\n', "agent_ratchet.vanished"),
    ("bin/tool", "#!/bin/sh\nexec python3 -m agent_ratchet.lost \"$@\"\n", "agent_ratchet.lost"),
    ("tests/test_dyn.py", "import importlib\nimportlib.import_module(\"agent_ratchet.dropped\")\n",
     "agent_ratchet.dropped"),
])
def test_g7_dash_m_and_importlib_literals_are_checked(api_env, path, text, missing):
    r = api_env(files={path: text})
    assert r.verdict == "FAIL" and missing in r.reason and path in r.reason


def test_g7_no_reference_is_na_not_pass(api_env):
    r = api_env(files={"requirements-dev.txt": "agent-ratchet @ git+https://github.com/dpopek/agent-ratchet@x\n",
                       "notes.md": "python -m agent_ratchet.cli\n"})   # .md is not read
    assert r.verdict == "n/a"


def test_g7_reads_base_not_later_commits(api_env):
    r = api_env(consumer_imports="import agent_ratchet.cli\n")
    assert r.verdict == "PASS" and "gone_later" not in r.reason


def test_collect_returns_references_with_origins_and_read_files(api_env):
    api_env(consumer_imports="import os\nfrom agent_ratchet.cli import main as m, Runner\n# agent_ratchet note\n",
            files={"scripts/run.sh": "python -m agent_ratchet.cli\n", "docs/x.md": "agent_ratchet\n",
                   "agent_ratchet_extra.py": "import agent_ratchet_extra\n"})
    refs, unchecked = collect(real_git(), api_env.repo, api_env.base)
    assert sorted(refs, key=lambda r: r.origin) == [
        Reference("agent_ratchet.cli", None, "scripts/run.sh:1"),
        Reference("agent_ratchet.cli", "main", "tests/test_use.py:2"),
        Reference("agent_ratchet.cli", "Runner", "tests/test_use.py:2"),
    ]
    assert unchecked == ["not checked: tests/test_use.py:3"]
    assert read_files(real_git(), api_env.repo, api_env.base) == ["scripts/run.sh", "tests/test_use.py"]


def test_g7_unparseable_python_is_not_checked(api_env):
    r = api_env(consumer_imports="import agent_ratchet.cli\ndef broken(:\n")
    assert r.verdict == "PASS" and "not checked: tests/test_use.py:1" in r.reason
