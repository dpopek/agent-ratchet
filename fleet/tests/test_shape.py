"""G8: the strict shape of BASE..H, checked against fresh fixture commits."""

import pytest

from guard_fleet.lockfile import render_lock
from guard_fleet.shape import check, uvlock_equal
from repos import _git, commit_files
from test_roll import C1_MSG, NEW_SHIM, OLD_SHIM, PIN_URL, build_env, uv_lock_text

PIN = "# dev tools\npytest==8\nagent-ratchet[php] @ " + PIN_URL + "@P@\n"


def c2_msg(env):
    return f"chore(guard): bump agent-ratchet to v4.0.1 ({env.t})"


@pytest.fixture
def shape_env(tmp_path, fleet_home):
    """Builds BASE..H by hand in a worktree of alpha (or beta / gamma) and runs `shape.check` on it."""
    def make(name="alpha", *, mutate_pin=None, c1_extra=None, c2_extra=None, extra_commit=False, lock=None,
             shim=NEW_SHIM, shim_mode="755", uv_lock=None):
        env = build_env(tmp_path, fleet_home, name, extra_files={"requirements-dev.txt": PIN} if name == "alpha"
                        else None)
        ctx, consumer, row = env
        p, t = env.p, env.t
        wt = tmp_path / "w"
        _git(env.clone, "worktree", "add", "-q", "-b", "topic", str(wt), row.d)
        if consumer.pin_kind != "none":
            pin = (wt / consumer.pin_file).read_text().replace(p, t)
            if mutate_pin == "extra byte at end":
                pin += " "
            elif mutate_pin == "second changed line":
                pin = pin.replace("pytest==8", "pytest==9")
            elif mutate_pin == "changed comment":
                pin = pin.replace("# dev tools", "# dev tools!")
            files = {consumer.pin_file: pin, **(c1_extra or {})}
            if consumer.pin_kind == "pyproject":
                files["uv.lock"] = uv_lock if uv_lock is not None else uv_lock_text(t)
            commit_files(wt, C1_MSG, files)
        lock_bytes = render_lock(t, "none" if lock == "no-extras" else row.extras)
        commit_files(wt, c2_msg(env), {"guard.lock": lock_bytes, **(c2_extra or {})})
        commit_files(wt, c2_msg(env) + " shim", {"scripts/guard": shim}, mode=shim_mode)
        _git(wt, "reset", "-q", "--soft", "HEAD~2")   # fold lock + shim into one C2 commit
        _git(wt, "commit", "-q", "-m", c2_msg(env))
        if extra_commit:
            commit_files(wt, "later", {"README": "changed\n"})
        head = _git(wt, "rev-parse", "HEAD")
        return check(ctx.git, wt, env.up, consumer, base=row.d, head=head, p=p, t=t, extras=row.extras)
    return make


@pytest.mark.parametrize("name", ["alpha", "beta", "gamma"])
def test_a_true_bump_passes(shape_env, name):
    r = shape_env(name)
    assert (r.gate, r.verdict) == ("G8", "PASS"), r.reason


@pytest.mark.parametrize("mutation", ["extra byte at end", "second changed line", "changed comment"])
def test_strict_g8_pin_file(shape_env, mutation):
    r = shape_env(mutate_pin=mutation)
    assert r.verdict == "FAIL" and "requirements-dev.txt" in r.reason


@pytest.mark.parametrize("kw, word", [
    ({"c1_extra": {"guard.lock": "x\n"}}, "guard.lock"),       # C1 touches the lock
    ({"c2_extra": {"requirements-dev.txt": "y\n"}}, "C2"),     # C2 touches the pin file
    ({"c2_extra": {"other.txt": "z\n"}}, "other.txt"),          # a path outside the bump
    ({"extra_commit": True}, "commits"),
    ({"lock": "no-extras"}, "guard.lock"),                      # the EXTRAS line was dropped
    ({"shim": OLD_SHIM + b"# edited\n"}, "scripts/guard"),
    ({"shim_mode": "644"}, "100755"),
])
def test_g8_rejects_every_other_shape(shape_env, kw, word):
    r = shape_env(**kw)
    assert r.verdict == "FAIL" and word in r.reason, r.reason


def test_g8_pyproject_uv_lock_must_match_after_dropping_agent_ratchet(shape_env):
    r = shape_env("beta", uv_lock='name = "agent-ratchet"\nsource = { git = "elsewhere" }\n')
    assert r.verdict == "FAIL" and "uv.lock" in r.reason


def test_g8_counts_one_commit_for_pin_kind_none(shape_env):
    assert shape_env("gamma", extra_commit=True).verdict == "FAIL"


# -- uvlock_equal ----------------------------------------------------------------

P, T = "a" * 40, "b" * 40
AR_ENTRY = f'''[[package]]
name = "agent-ratchet"
version = "4.0.0"
source = {{ git = "https://github.com/dpopek/agent-ratchet?rev={P}#{P}" }}

'''
BASE_LOCK = f'''version = 1

{AR_ENTRY}[[package]]
name = "demo"
version = "0.1.0"
source = {{ editable = "." }}
dependencies = [{{ name = "agent-ratchet" }}, {{ name = "pytest" }}]

[package.metadata]
requires-dist = [{{ name = "agent-ratchet", git = "https://github.com/dpopek/agent-ratchet?rev={P}" }}]

[[package]]
name = "pytest"
version = "8.0.0"
'''


def test_g8_uv_lock_ignores_only_agent_ratchet_entry():
    head = BASE_LOCK.replace(P, T).replace('version = "4.0.0"', 'version = "4.0.1"')
    assert uvlock_equal(BASE_LOCK.encode(), head.encode(), P, T)
    # the agent-ratchet entry may change in any way, even disappear
    entry = AR_ENTRY.replace(P, T).replace('version = "4.0.0"', 'version = "4.0.1"')
    assert entry in head
    assert uvlock_equal(BASE_LOCK.encode(), head.replace(entry, "").encode(), P, T)


@pytest.mark.parametrize("edit", [
    lambda h: h.replace('version = "8.0.0"', 'version = "8.1.0"'),        # another package moved
    lambda h: h.replace(f"rev={T}\" }}]", f"rev={P}\" }}]"),               # P left behind outside the entry
    lambda h: h + '\n[[package]]\nname = "extra"\nversion = "1"\n',       # a new package
    lambda h: h.replace("version = 1", "version = 2"),
])
def test_g8_uv_lock_any_other_difference_fails(edit):
    head = edit(BASE_LOCK.replace(P, T))
    assert head != BASE_LOCK.replace(P, T)
    assert not uvlock_equal(BASE_LOCK.encode(), head.encode(), P, T)


@pytest.mark.parametrize("base, head", [(b"[[package]", b"version = 1\n"), (b"version = 1\n", b"\xff\xfe"),
                                        (b"version = 1\n", b"version = = 1\n")])
def test_g8_uv_lock_unparseable_is_not_equal(base, head):
    assert not uvlock_equal(base, head, P, T)
