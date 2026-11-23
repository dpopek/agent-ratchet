from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "bin" / "guard-fleet"
SHA = "a" * 40
FAKE = '#!/bin/sh\nprintf "%s" "{name}"\nfor a in "$@"; do printf " %s" "$a"; done\nprintf "\\n"\n'


@pytest.fixture
def launcher(tmp_path):
    def run(*, lock, uvx=True, caffeinate=True, uname="Linux", args=()):
        home = tmp_path / "home-l"
        home.mkdir(exist_ok=True)
        if lock is not None:
            (home / ".config" / "guard-fleet").mkdir(parents=True, exist_ok=True)
            (home / ".config" / "guard-fleet" / "self.lock").write_text(lock)
        bin_dir = tmp_path / "fakebin"
        bin_dir.mkdir(exist_ok=True)
        for name, present in (("uvx", uvx), ("caffeinate", caffeinate)):
            path = bin_dir / name
            if present:
                path.write_text(FAKE.format(name=name))
                path.chmod(0o755)
            else:
                path.unlink(missing_ok=True)
        un = bin_dir / "uname"
        un.write_text(f'#!/bin/sh\nprintf "%s\\n" "{uname}"\n')
        un.chmod(0o755)
        env = {"HOME": str(home), "PATH": f"{bin_dir}:/usr/bin:/bin"}
        # keep real uvx/caffeinate (if installed under /usr/bin) out of the "absent" cases
        if not uvx or not caffeinate:
            env["PATH"] = f"{bin_dir}:{_sysbin(tmp_path)}"
        return subprocess.run(["/bin/sh", str(SCRIPT), *args], env=env, capture_output=True, text=True,
                              timeout=20, stdin=subprocess.DEVNULL)
    return run


def _sysbin(tmp_path):
    """A PATH dir with only the tools the launcher needs, so no real uvx/caffeinate leaks in."""
    d = tmp_path / "sysbin"
    d.mkdir(exist_ok=True)
    for tool in ("wc", "grep", "cat", "tr", "dirname"):
        link = d / tool
        if not link.exists():
            for base in ("/usr/bin", "/bin"):
                if os.path.exists(f"{base}/{tool}"):
                    link.symlink_to(f"{base}/{tool}")
                    break
    return str(d)


def test_missing_lock_prints_bootstrap_and_exits_10(launcher):
    r = launcher(lock=None)
    assert r.returncode == 10 and "refs/tags/v4.4.0^{}" in r.stderr
    assert r.stderr.startswith("guard-fleet: ~/.config/guard-fleet/self.lock is missing.\n")
    assert "git ls-remote https://github.com/dpopek/agent-ratchet 'refs/tags/v4.4.0^{}'" in r.stderr
    assert r.stdout == ""


@pytest.mark.parametrize("content", ["abc\n", "", "a" * 40 + "\n" + "b" * 40 + "\n", "A" * 40 + "\n",
                                     "a" * 40 + " \n", "a" * 41 + "\n", "a" * 40 + "\n\n"])
def test_malformed_lock_exits_11(launcher, content):
    r = launcher(lock=content)
    assert r.returncode == 11 and r.stderr.strip() and r.stdout == ""


def test_lock_without_trailing_newline_is_accepted(launcher):
    assert launcher(lock=SHA).returncode == 0


def test_no_uvx_exits_12(launcher):
    r = launcher(lock=SHA + "\n", uvx=False)
    assert r.returncode == 12 and "uvx" in r.stderr


def test_darwin_execs_caffeinate_with_exact_argv(launcher):
    r = launcher(lock=SHA + "\n", uname="Darwin", args=["plan", "v4.4.1"])
    assert r.returncode == 0
    assert r.stdout.split("\n")[0] == ("caffeinate -i uvx --isolated --no-config --from "
        f"git+https://github.com/dpopek/agent-ratchet@{SHA}#subdirectory=fleet guard-fleet --expect-sha {SHA} plan v4.4.1")


def test_darwin_without_caffeinate_runs_uvx(launcher):
    r = launcher(lock=SHA + "\n", uname="Darwin", caffeinate=False, args=["plan"])
    assert r.stdout.split("\n")[0].startswith("uvx --isolated")


def test_linux_execs_uvx_directly(launcher):
    r = launcher(lock=SHA + "\n", uname="Linux", args=["status"])
    assert r.stdout.split("\n")[0] == ("uvx --isolated --no-config --from "
        f"git+https://github.com/dpopek/agent-ratchet@{SHA}#subdirectory=fleet guard-fleet --expect-sha {SHA} status")


def test_launcher_is_executable_in_git():
    root = SCRIPT.parents[2]
    out = subprocess.run(["git", "-C", str(root), "ls-files", "-s", "fleet/bin/guard-fleet"],
                         capture_output=True, text=True, timeout=20).stdout
    assert out.startswith("100755 "), out
