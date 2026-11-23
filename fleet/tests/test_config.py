from pathlib import Path

import pytest

from guard_fleet.config import ConfigError, Consumer, expand, load_config
from guard_fleet.exits import UsageError

ALPHA_IF_RUN = '''
[[consumer]]
short = "alpha"
dir = "{root}/repos/alpha"
slug = "owner/alpha"
default_branch = "main"
pin_kind = "req"
pin_file = "requirements-dev.txt"
ring = 1
venvs = ["{dir}/venv"]
'''

BETA_REQUIRED = '''
[[consumer]]
short = "beta"
dir = "{root}/repos/beta"
slug = "owner/beta"
default_branch = "master"
pin_kind = "pyproject"
pin_file = "pyproject.toml"
ring = 1
ci = "required"
ci_wait_min = 30
'''

GAMMA_RING2 = '''
[[consumer]]
short = "gamma"
dir = "{root}/repos/gamma"
slug = "owner/gamma"
default_branch = "main"
pin_kind = "none"
ring = 2
'''


def write(tmp_path: Path, *snippets: str) -> Path:
    text = f'worktree_root = "{tmp_path}/wt"\n' + "".join(s.replace("{root}", str(tmp_path)) for s in snippets)
    path = tmp_path / "consumers.toml"
    path.write_text(text)
    return path


def test_config_loads_and_orders_canaries_first(tmp_path):
    cfg = load_config(write(tmp_path, ALPHA_IF_RUN, BETA_REQUIRED, GAMMA_RING2), home=tmp_path)
    assert [c.short for c in cfg.ring_order(1)] == ["beta", "alpha"]
    assert [c.short for c in cfg.ring_order(2)] == ["gamma"]
    assert cfg.by_short("alpha").venvs == (tmp_path / "repos/alpha/venv",)   # from "{dir}/venv"
    assert cfg.worktree_root == tmp_path / "wt"


def test_config_defaults_and_values(tmp_path):
    cfg = load_config(write(tmp_path, ALPHA_IF_RUN, BETA_REQUIRED), home=tmp_path)
    a, b = cfg.by_short("alpha"), cfg.by_short("beta")
    assert isinstance(a, Consumer)
    assert (a.ci, a.ci_wait_min, a.node_modules, a.confirm_note) == ("if-run", 15, False, "")
    assert a.deploy_workflows == () and a.quiet_before_merge == () and a.hook_needs == ()
    assert dict(a.commit_env) == {} and a.surfaces == frozenset()
    assert a.dir == tmp_path / "repos/alpha" and a.pin_kind == "req" and a.pin_file == "requirements-dev.txt"
    assert (b.ci, b.ci_wait_min, b.pin_file) == ("required", 30, "pyproject.toml")
    assert cfg.by_short("beta").default_branch == "master"


def test_canaries_are_required_ci_consumers_of_the_ring(tmp_path):
    cfg = load_config(write(tmp_path, ALPHA_IF_RUN, BETA_REQUIRED, GAMMA_RING2), home=tmp_path)
    assert [c.short for c in cfg.canaries(1)] == ["beta"]
    assert cfg.canaries(2) == ()


def test_by_short_unknown_is_config_error(tmp_path):
    cfg = load_config(write(tmp_path, ALPHA_IF_RUN), home=tmp_path)
    with pytest.raises(ConfigError, match="nope"):
        cfg.by_short("nope")
    assert issubclass(ConfigError, UsageError)


def test_config_rejects_duplicate_short_and_relative_dir(tmp_path):
    with pytest.raises(ConfigError, match=r"duplicate short 'alpha'"):
        load_config(write(tmp_path, ALPHA_IF_RUN, ALPHA_IF_RUN), home=tmp_path)
    relative = ALPHA_IF_RUN.replace('dir = "{root}/repos/alpha"', 'dir = "repos/alpha"')
    with pytest.raises(ConfigError, match=r"alpha: dir 'repos/alpha' is not absolute"):
        load_config(write(tmp_path, relative), home=tmp_path)


def test_config_rejects_unknown_key_and_bad_ring(tmp_path):
    with pytest.raises(ConfigError, match=r"alpha: unknown key 'rnig'"):
        load_config(write(tmp_path, ALPHA_IF_RUN + 'rnig = 1\n'), home=tmp_path)
    with pytest.raises(ConfigError, match=r"alpha: ring 3 not in \{1, 2\}"):
        load_config(write(tmp_path, ALPHA_IF_RUN.replace("ring = 1", "ring = 3")), home=tmp_path)


def test_config_rejects_unknown_top_level_key(tmp_path):
    path = write(tmp_path, ALPHA_IF_RUN)
    path.write_text('extra = 1\n' + path.read_text())
    with pytest.raises(ConfigError, match=r"unknown key 'extra'"):
        load_config(path, home=tmp_path)


@pytest.mark.parametrize("key", ["HUSKY", "SKIP", "GIT_DIR", "PRE_COMMIT_HOME", "LEFTHOOK", "ALLOW_X", "GLOBAL_PRE_COMMIT_ACTIVE"])
def test_config_rejects_forbidden_commit_env_keys(tmp_path, key):
    with pytest.raises(ConfigError, match=rf"alpha: commit_env key '{key}'"):
        load_config(write(tmp_path, ALPHA_IF_RUN + f'commit_env = {{ {key} = "0" }}\n'), home=tmp_path)


def test_config_accepts_allowed_commit_env(tmp_path):
    cfg = load_config(write(tmp_path, ALPHA_IF_RUN + 'commit_env = { FOO = "1" }\n'), home=tmp_path)
    assert dict(cfg.by_short("alpha").commit_env) == {"FOO": "1"}


def test_config_expands_dir_and_home_in_commit_env_values(tmp_path):
    # spec 6.2: paths expand {dir} and ~; a hook reads the variable and must get the absolute interpreter path
    cfg = load_config(write(tmp_path, ALPHA_IF_RUN + 'commit_env = { ALPHA_HOOK_PYTHON = "{dir}/venv/bin/python", '
                                                     'ALPHA_TOOL = "~/bin/tool", FOO = "1" }\n'), home=tmp_path)
    alpha = cfg.by_short("alpha")
    assert dict(alpha.commit_env) == {"ALPHA_HOOK_PYTHON": f"{alpha.dir}/venv/bin/python",
                                      "ALPHA_TOOL": f"{tmp_path}/bin/tool", "FOO": "1"}


def test_config_pin_file_rules(tmp_path):
    with pytest.raises(ConfigError, match="pin_file"):
        load_config(write(tmp_path, ALPHA_IF_RUN.replace('pin_file = "requirements-dev.txt"\n', "")), home=tmp_path)
    with pytest.raises(ConfigError, match="pin_file"):
        load_config(write(tmp_path, GAMMA_RING2 + 'pin_file = "x.txt"\n'), home=tmp_path)


@pytest.mark.parametrize("old,new,needle", [
    ('short = "alpha"', 'short = "Alpha"', r"alpha|Alpha"),
    ('slug = "owner/alpha"', 'slug = "alpha"', r"slug 'alpha'"),
    ('ring = 1', 'ring = "1"', r"ring"),
    ('ring = 1', 'ring = true', r"ring"),
    ('pin_kind = "req"', 'pin_kind = "git"', r"pin_kind 'git'"),
])
def test_config_rejects_bad_values(tmp_path, old, new, needle):
    with pytest.raises(ConfigError, match=needle):
        load_config(write(tmp_path, ALPHA_IF_RUN.replace(old, new)), home=tmp_path)


@pytest.mark.parametrize("extra,needle", [
    ('ci = "sometimes"\n', r"ci 'sometimes'"),
    ('ci_wait_min = 0\n', r"ci_wait_min 0"),
    ('ci_wait_min = 121\n', r"ci_wait_min 121"),
    ('surfaces = ["php", "go"]\n', r"surfaces.*go"),
    ('node_modules = "yes"\n', r"node_modules"),
    ('deploy_workflows = "a.yml"\n', r"deploy_workflows"),
    ('hook_needs = ["rel/tool"]\n', r"hook_needs.*rel/tool.*not absolute"),
    ('commit_env = { A = 1 }\n', r"commit_env"),
])
def test_config_rejects_bad_optional_values(tmp_path, extra, needle):
    with pytest.raises(ConfigError, match=rf"alpha: .*{needle}"):
        load_config(write(tmp_path, ALPHA_IF_RUN + extra), home=tmp_path)


def test_config_rejects_relative_venv_and_worktree_root(tmp_path):
    with pytest.raises(ConfigError, match=r"alpha: venvs entry 'venv' is not absolute"):
        load_config(write(tmp_path, ALPHA_IF_RUN.replace('"{dir}/venv"', '"venv"')), home=tmp_path)
    path = write(tmp_path, ALPHA_IF_RUN)
    path.write_text(path.read_text().replace(f'"{tmp_path}/wt"', '"wt"'))
    with pytest.raises(ConfigError, match=r"worktree_root 'wt' is not absolute"):
        load_config(path, home=tmp_path)


def test_hook_needs_bare_names_pass_and_paths_expand(tmp_path):
    extra = 'hook_needs = ["node", "{dir}/bin/tool", "~/bin/x"]\nsurfaces = ["php", "magento"]\n'
    c = load_config(write(tmp_path, ALPHA_IF_RUN + extra), home=tmp_path).by_short("alpha")
    assert c.hook_needs == ("node", f"{tmp_path}/repos/alpha/bin/tool", f"{tmp_path}/bin/x")
    assert c.surfaces == frozenset({"php", "magento"})


def test_expand_only_dir_and_leading_tilde(tmp_path):
    d = tmp_path / "d"
    assert expand("{dir}/v", dir=d, home=tmp_path) == f"{d}/v"
    assert expand("~/x", dir=None, home=tmp_path) == f"{tmp_path}/x"
    assert expand("a/~/x", dir=None, home=tmp_path) == "a/~/x"
    assert expand("{other}/x", dir=d, home=tmp_path) == "{other}/x"
    with pytest.raises(ConfigError, match=r"\{dir\}"):
        expand("{dir}/x", dir=None, home=tmp_path)


def test_missing_required_key_and_missing_file(tmp_path):
    with pytest.raises(ConfigError, match=r"alpha: missing key 'slug'"):
        load_config(write(tmp_path, ALPHA_IF_RUN.replace('slug = "owner/alpha"\n', "")), home=tmp_path)
    with pytest.raises(ConfigError, match="consumers.toml"):
        load_config(tmp_path / "absent" / "consumers.toml", home=tmp_path)
