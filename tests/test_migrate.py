import os

import pytest

from agent_ratchet.migrate import main, plan_file


def kinds(plan):
    return [(i.line, i.kind) for i in plan.items]


def test_from_import_rewritten():
    plan = plan_file("from guard_core.ai_slop_scanner import scan\n", "a.py")
    assert plan.new_source == "from agent_ratchet.ai_slop_scanner import scan\n"
    assert kinds(plan) == [(1, "rewrite")]
    assert plan.items[0].text == "from guard_core.ai_slop_scanner import scan"
    assert plan.items[0].path == "a.py"


def test_from_top_level_package_rewritten():
    plan = plan_file("from guard_core import cli\n", "a.py")
    assert plan.new_source == "from agent_ratchet import cli\n"


def test_parenthesised_multiline_import_keeps_layout_and_comments():
    src = "from guard_core.git_guard_io import (  # keep\n    a,  # first\n    b as c,\n)\n"
    plan = plan_file(src, "a.py")
    assert plan.new_source == src.replace("guard_core", "agent_ratchet")
    assert kinds(plan) == [(1, "rewrite")]


def test_import_as_rewritten():
    plan = plan_file("import guard_core.cli as gc\nimport os\n", "a.py")
    assert plan.new_source == "import agent_ratchet.cli as gc\nimport os\n"
    assert kinds(plan) == [(1, "rewrite")]


def test_bare_import_is_manual():
    src = "import guard_core\nimport guard_core.cli\n"
    plan = plan_file(src, "a.py")
    assert plan.new_source == src
    assert kinds(plan) == [(1, "manual-import"), (2, "manual-import")]


def test_guard_version_from_refactoring_guard_becomes_rules_version_alias():
    src = "from guard_core.refactoring_guard import (\n    GUARD_VERSION,\n    x,\n)\n"
    plan = plan_file(src, "a.py")
    assert plan.new_source == "from agent_ratchet.refactoring_guard import (\n    RULES_VERSION as GUARD_VERSION,\n    x,\n)\n"
    assert kinds(plan) == [(1, "rewrite")]


def test_guard_version_from_git_guard_io_becomes_rules_version_alias():
    plan = plan_file("from guard_core.git_guard_io import GUARD_VERSION\n", "a.py")
    assert plan.new_source == "from agent_ratchet.git_guard_io import RULES_VERSION as GUARD_VERSION\n"


def test_guard_version_from_version_becomes_version_alias():
    plan = plan_file("from guard_core.version import GUARD_VERSION\n", "a.py")
    assert plan.new_source == "from agent_ratchet.version import VERSION as GUARD_VERSION\n"


def test_existing_alias_kept():
    plan = plan_file("from guard_core.version import GUARD_VERSION as GV\n", "a.py")
    assert plan.new_source == "from agent_ratchet.version import VERSION as GV\n"
    plan = plan_file("from guard_core.refactoring_guard import GUARD_VERSION as GV\n", "a.py")
    assert plan.new_source == "from agent_ratchet.refactoring_guard import RULES_VERSION as GV\n"


def test_already_agent_ratchet_guard_version_still_rewritten():
    plan = plan_file("from agent_ratchet.refactoring_guard import GUARD_VERSION\n", "a.py")
    assert plan.new_source == "from agent_ratchet.refactoring_guard import RULES_VERSION as GUARD_VERSION\n"
    assert kinds(plan) == [(1, "rewrite")]


def test_self_skip_and_release_tag_pattern_are_manual():
    src = "from guard_core.git_guard_io import SELF_SKIP_NAMES\nfrom agent_ratchet.lock_policy import RELEASE_TAG_PATTERN, x\n"
    plan = plan_file(src, "a.py")
    assert plan.new_source == src
    assert kinds(plan) == [(1, "manual-import"), (2, "manual-import")]


def test_dash_m_string_is_manual_runtime():
    src = 'cmd = [sys.executable, "-m", "guard_core", "x"]\nother = "guard-core"\n'
    plan = plan_file(src, "a.py")
    assert plan.new_source == src
    assert kinds(plan) == [(1, "manual-runtime"), (2, "manual-runtime")]
    assert plan.items[0].text == 'cmd = [sys.executable, "-m", "guard_core", "x"]'


def test_comment_docstring_and_identifier_are_mentions():
    src = '"""Uses guard_core."""\n# see guard-core docs\nguard_core_path = 1\nlabel = "run guard_core now"\n'
    plan = plan_file(src, "a.py")
    assert plan.new_source == src
    assert kinds(plan) == [(1, "mention"), (2, "mention"), (3, "mention"), (4, "mention")]


def test_reported_line_is_not_also_a_mention():
    plan = plan_file("from guard_core import x  # guard_core\n", "a.py")
    assert kinds(plan) == [(1, "rewrite")]


def test_crlf_and_bom_preserved(tmp_path):
    raw = b"\xef\xbb\xbffrom guard_core.cli import main\r\nx = 1\r\n"
    f = tmp_path / "a.py"
    f.write_bytes(raw)
    assert main(["--write", str(f)]) == 0
    assert f.read_bytes() == b"\xef\xbb\xbffrom agent_ratchet.cli import main\r\nx = 1\r\n"


def test_non_ascii_columns():
    src = 'x = "żółć"; from guard_core.cli import main as m\n'
    plan = plan_file(src, "a.py")
    assert plan.new_source == 'x = "żółć"; from agent_ratchet.cli import main as m\n'


def test_second_run_is_noop():
    src = "from guard_core.version import GUARD_VERSION\nimport guard_core.cli as c\n"
    first = plan_file(src, "a.py")
    second = plan_file(first.new_source, "a.py")
    assert second.new_source == first.new_source
    assert second.items == []


def test_check_mode_exit_1_and_no_write(tmp_path, capsys):
    f = tmp_path / "a.py"
    f.write_text("from guard_core.cli import main\n", encoding="utf-8")
    assert main([str(tmp_path)]) == 1
    out = capsys.readouterr().out
    assert f"{tmp_path}/a.py:1: rewrite: from guard_core.cli import main" in out
    assert out.splitlines()[-1] == "agent-ratchet migrate-imports: 1 rewrite(s), 0 manual, 0 mention(s)"
    assert f.read_text(encoding="utf-8") == "from guard_core.cli import main\n"


def test_write_then_check_exit_0(tmp_path, capsys):
    f = tmp_path / "a.py"
    f.write_text("from guard_core.cli import main\n", encoding="utf-8")
    assert main(["--write", str(tmp_path)]) == 0
    assert "1 rewrite(s)" in capsys.readouterr().out
    assert f.read_text(encoding="utf-8") == "from agent_ratchet.cli import main\n"
    assert main([str(tmp_path)]) == 0
    assert capsys.readouterr().out.splitlines()[-1] == "agent-ratchet migrate-imports: 0 rewrite(s), 0 manual, 0 mention(s)"


def test_write_with_manual_items_exit_1(tmp_path, capsys):
    f = tmp_path / "a.py"
    f.write_text("from guard_core.cli import main\nimport guard_core\n", encoding="utf-8")
    assert main(["--write", str(tmp_path)]) == 1
    out = capsys.readouterr().out
    assert "a.py:1: rewrite:" in out
    assert "a.py:2: manual-import: import guard_core" in out
    assert out.splitlines()[-1] == "agent-ratchet migrate-imports: 1 rewrite(s), 1 manual, 0 mention(s)"
    assert f.read_text(encoding="utf-8") == "from agent_ratchet.cli import main\nimport guard_core\n"


def test_mentions_do_not_affect_exit_code(tmp_path):
    (tmp_path / "a.py").write_text("# guard_core\n", encoding="utf-8")
    assert main([str(tmp_path)]) == 0


def test_unparseable_file_exit_2_others_untouched(tmp_path, capsys):
    bad = tmp_path / "bad.py"
    bad.write_text("def (:\n", encoding="utf-8")
    nonutf = tmp_path / "latin.py"
    nonutf.write_bytes(b"# \xff\xfe\nfrom guard_core import x\n")
    good = tmp_path / "good.py"
    good.write_text("from guard_core import x\n", encoding="utf-8")
    assert main(["--write", str(tmp_path)]) == 2
    out = capsys.readouterr().out
    assert f"{tmp_path}/bad.py:0: error: " in out
    assert f"{tmp_path}/latin.py:0: error: " in out
    assert bad.read_text(encoding="utf-8") == "def (:\n"
    assert nonutf.read_bytes() == b"# \xff\xfe\nfrom guard_core import x\n"
    assert good.read_text(encoding="utf-8") == "from agent_ratchet import x\n"


def test_skips_venv_and_symlinks(tmp_path, capsys):
    real = tmp_path / "real.py"
    real.write_text("from guard_core import x\n", encoding="utf-8")
    for skipped in (".git", ".venv", "venv", "node_modules", "__pycache__"):
        d = tmp_path / skipped
        d.mkdir()
        (d / "m.py").write_text("from guard_core import x\n", encoding="utf-8")
    os.symlink(real, tmp_path / "link.py")
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "n.py").write_text("from guard_core import y\n", encoding="utf-8")
    os.symlink(sub, tmp_path / "linkdir")
    (tmp_path / "notes.txt").write_text("from guard_core import x\n", encoding="utf-8")
    assert main([str(tmp_path)]) == 1
    lines = [ln for ln in capsys.readouterr().out.splitlines() if ": rewrite:" in ln]
    assert [ln.split(":")[0] for ln in lines] == [f"{tmp_path}/real.py", f"{tmp_path}/sub/n.py"]


def test_explicit_file_path_is_processed(tmp_path):
    f = tmp_path / ".venv" / "m.py"
    f.parent.mkdir()
    f.write_text("from guard_core import x\n", encoding="utf-8")
    assert main(["--write", str(f)]) == 0
    assert f.read_text(encoding="utf-8") == "from agent_ratchet import x\n"


def test_cli_dispatch(tmp_path, capsys):
    from agent_ratchet import cli

    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    assert cli.main(["migrate-imports", str(tmp_path)]) == 0
    assert "migrate-imports: 0 rewrite(s)" in capsys.readouterr().out


@pytest.mark.parametrize(
    "src",
    [
        'mock.patch("guard_core.version.installed_sha")\n',
        'importlib.import_module("guard_core.cli")\n',
        'x = "python -m guard_core scan"\n',
    ],
)
def test_runtime_reference_in_longer_string_is_manual_runtime(src, tmp_path):
    assert kinds(plan_file(src, "a.py")) == [(1, "manual-runtime")]
    (tmp_path / "a.py").write_text(src, encoding="utf-8")
    assert main([str(tmp_path)]) == 1


def test_prose_string_mentioning_guard_core_stays_mention(tmp_path):
    src = 'x = "migrated from guard_core last year"\n'
    assert kinds(plan_file(src, "a.py")) == [(1, "mention")]
    (tmp_path / "a.py").write_text(src, encoding="utf-8")
    assert main([str(tmp_path)]) == 0


@pytest.mark.parametrize(
    "value",
    [
        "guard_core", "guard-core", "guard_core.cli", "guard_core.version.installed_sha",
        "guard-core scan", "guard-core==3.0", "guard-core @ git+https://x/y",
        "guard-core[php]", "python -m guard_core scan", "-m guard_core.cli", "x -m\tguard_core",
        "guard-core is deprecated",  # accepted false positive (spec)
    ],
)
def test_runtime_strings_are_manual(value):
    assert kinds(plan_file(f"x = {value!r}\n", "a.py")) == [(1, "manual-runtime")]


@pytest.mark.parametrize(
    "value",
    [
        "guard-core-legacy", "guard-core's docs", "guard-coredump", "guard-core.lock",
        "python -m guard_core_extras", "guard_core_path", "guard_core.", "rerun-m guard_core",
    ],
)
def test_prose_and_lookalikes_are_mentions(value):
    assert kinds(plan_file(f"x = {value!r}\n", "a.py")) == [(1, "mention")]


def test_replace_failure_exit_2_original_untouched_and_temp_removed(tmp_path, capsys, monkeypatch):
    a = tmp_path / "a.py"
    a.write_text("from guard_core.cli import main\n", encoding="utf-8")
    b = tmp_path / "b.py"
    b.write_text("from guard_core.cli import main\n", encoding="utf-8")
    real = os.replace

    def fake(src, dst):
        if str(dst).endswith("a.py"):
            raise PermissionError("denied")
        return real(src, dst)

    monkeypatch.setattr(os, "replace", fake)
    assert main(["--write", str(tmp_path)]) == 2
    out = capsys.readouterr().out
    assert f"{a.as_posix()}:0: error: denied" in out
    assert a.read_text(encoding="utf-8") == "from guard_core.cli import main\n"
    assert b.read_text(encoding="utf-8") == "from agent_ratchet.cli import main\n"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["a.py", "b.py"]


@pytest.mark.skipif(os.name == "nt", reason="POSIX modes")
def test_write_preserves_executable_mode(tmp_path):
    f = tmp_path / "a.py"
    f.write_text("from guard_core.cli import main\n", encoding="utf-8")
    f.chmod(0o755)
    assert main(["--write", str(tmp_path)]) == 0
    assert f.stat().st_mode & 0o777 == 0o755
    assert f.read_text(encoding="utf-8") == "from agent_ratchet.cli import main\n"


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlinks")
def test_explicit_symlink_write_updates_target_keeps_link(tmp_path):
    real = tmp_path / "real.py"
    real.write_text("from guard_core import x\n", encoding="utf-8")
    link = tmp_path / "link.py"
    os.symlink(real, link)
    assert main(["--write", str(link)]) == 0
    assert os.path.islink(link) and os.readlink(link) == str(real)
    assert real.read_text(encoding="utf-8") == "from agent_ratchet import x\n"


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlinks")
def test_symlink_chain_rewritten_once_links_intact(tmp_path, capsys):
    real = tmp_path / "real.py"
    real.write_text("from guard_core import x\n", encoding="utf-8")
    b = tmp_path / "b.py"
    os.symlink(real, b)
    a = tmp_path / "a.py"
    os.symlink(b, a)
    assert main([str(a), str(b), str(real)]) == 1
    rewrites = [ln for ln in capsys.readouterr().out.splitlines() if ": rewrite:" in ln]
    assert len(rewrites) == 1 and rewrites[0].startswith(f"{a.as_posix()}:")
    assert main(["--write", str(a), str(b), str(real)]) == 0
    assert os.path.islink(a) and os.path.islink(b)
    assert real.read_text(encoding="utf-8") == "from agent_ratchet import x\n"


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlinks")
def test_explicit_symlinked_directory_walked_link_survives(tmp_path):
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "n.py").write_text("from guard_core import y\n", encoding="utf-8")
    linkdir = tmp_path / "linkdir"
    os.symlink(sub, linkdir)
    assert main(["--write", str(linkdir)]) == 0
    assert os.path.islink(linkdir)
    assert (sub / "n.py").read_text(encoding="utf-8") == "from agent_ratchet import y\n"


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlinks")
def test_symlink_target_write_failure_exit_2_untouched(tmp_path, monkeypatch, capsys):
    (tmp_path / "t").mkdir()
    (tmp_path / "l").mkdir()
    real = tmp_path / "t" / "real.py"
    real.write_text("from guard_core import x\n", encoding="utf-8")
    link = tmp_path / "l" / "link.py"
    os.symlink(real, link)

    def fake(src, dst):
        raise PermissionError("denied")

    monkeypatch.setattr(os, "replace", fake)
    assert main(["--write", str(link)]) == 2
    assert "error: denied" in capsys.readouterr().out
    assert os.path.islink(link)
    assert real.read_text(encoding="utf-8") == "from guard_core import x\n"
    assert sorted(p.name for p in real.parent.iterdir()) == ["real.py"]
    assert sorted(p.name for p in link.parent.iterdir()) == ["link.py"]
