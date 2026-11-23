from __future__ import annotations

from pathlib import Path

import pytest

from fakes import FakeGh, FakeRunner, Route
from guard_fleet.gh import Gh, GhAuthError, GhError, GhNetworkError, GhNotFound
from repos import _git, commit_files, make_bare, make_clone, push_all, sha_of

SLUG = "owner/alpha"


def _resp(status: int, body: bytes = b"{}", headers: str = "") -> bytes:
    return f"HTTP/2.0 {status} X\r\ncontent-type: application/json\r\n{headers}\r\n".encode() + body


@pytest.fixture
def gh_with(tmp_path):
    def build(status=200, body=b"{}", headers="", rc=None, stdout=None, stderr=b"", record_sleeps=False):
        out = _resp(status, body, headers) if stdout is None else stdout
        runner = FakeRunner([Route(("gh",), rc=(0 if status < 400 else 1) if rc is None else rc,
                                   stdout=out, stderr=stderr)])
        sleeps: list[float] = []
        g = Gh(runner, {}, sleeps.append, tmp_path)
        return (g, sleeps) if record_sleeps else g
    return build


@pytest.fixture
def fake_gh_env(tmp_path, fleet_home):
    bare = make_bare(tmp_path / "bares", "alpha")
    work = make_clone(bare, tmp_path / "work")
    commit_files(work, "init", {"guard.lock": "lock\n"})
    push_all(work)
    fake = FakeGh({SLUG: bare})
    runner = FakeRunner([fake.route()])
    g = Gh(runner, {"HOME": str(fleet_home)}, lambda s: None, tmp_path)
    g.fake, g.bare, g.work = fake, bare, work
    return g, runner


def test_api_401_is_auth_error(gh_with):
    with pytest.raises(GhAuthError):
        gh_with(status=401).user_login()


def test_api_404_is_not_found_and_403_plain_is_plain_error(gh_with):
    with pytest.raises(GhNotFound):
        gh_with(status=404).repo_visible(SLUG)
    with pytest.raises(GhError) as ei:
        gh_with(status=403, body=b'{"message":"no"}').repo_visible(SLUG)
    assert ei.value.status == 403 and not isinstance(ei.value, GhNetworkError)


def test_api_retries_429_then_network_error(gh_with):
    g, sleeps = gh_with(status=429, record_sleeps=True)
    with pytest.raises(GhNetworkError):
        g.default_branch(SLUG)
    assert sleeps == [1, 2, 4, 8, 16]


def test_api_retries_5xx_and_rate_limited_403(gh_with):
    g, sleeps = gh_with(status=502, record_sleeps=True)
    with pytest.raises(GhNetworkError) as ei:
        g.repo_visible(SLUG)
    assert ei.value.status == 502 and len(sleeps) == 5
    g, sleeps = gh_with(status=403, headers="x-ratelimit-remaining: 0\r\n", record_sleeps=True)
    with pytest.raises(GhNetworkError):
        g.repo_visible(SLUG)
    assert len(sleeps) == 5


def test_api_no_status_and_failing_process_is_network_error(gh_with):
    g, sleeps = gh_with(rc=1, stdout=b"", stderr=b"error connecting to api.github.com", record_sleeps=True)
    with pytest.raises(GhNetworkError):
        g.user_login()
    assert sleeps == [1, 2, 4, 8, 16]


def test_api_exit_4_is_auth_error_without_retry(gh_with):
    g, sleeps = gh_with(rc=4, stdout=b"", stderr=b"gh auth login", record_sleeps=True)
    with pytest.raises(GhAuthError):
        g.user_login()
    assert sleeps == []


def test_api_recovers_after_a_transient_failure(tmp_path):
    answers = [_resp(502), _resp(200, b'{"login": "operator"}')]

    def effect(argv, cwd, env):
        from guard_fleet.proc import Result
        out = answers.pop(0)
        return Result(argv, 0, out, b"", False)

    sleeps: list[float] = []
    g = Gh(FakeRunner([Route(("gh",), effect=effect)]), {}, sleeps.append, tmp_path)
    assert g.user_login() == "operator" and sleeps == [1]


def test_api_argv_and_response_parsing(gh_with, tmp_path):
    g = gh_with(status=200, body=b'{"a": 1}', headers="ETag: abc\r\n")
    r = g.api("repos/owner/alpha", method="HEAD", accept="application/x")
    assert g.run.calls[-1][0] == ("gh", "api", "-i", "-X", "HEAD", "-H", "Accept: application/x", "repos/owner/alpha")
    assert r.status == 200 and r.headers["etag"] == "abc" and r.json() == {"a": 1}
    g.api("user")
    assert g.run.calls[-1][0] == ("gh", "api", "-i", "user")


def test_contents_404_is_none(gh_with):
    assert gh_with(status=404).contents_raw(SLUG, "guard.lock", "a" * 40) is None


def test_contents_raw_argv(gh_with):
    g = gh_with(status=200, body=b"raw bytes")
    assert g.contents_raw(SLUG, "guard.lock", "b" * 40) == b"raw bytes"
    assert g.run.calls[-1][0] == ("gh", "api", "-i", "-H", "Accept: application/vnd.github.raw+json",
                                  f"repos/{SLUG}/contents/guard.lock?ref={'b' * 40}")


def test_pr_merge_argv_is_exact(fake_gh_env):
    g, runner = fake_gh_env
    g.pr_merge(SLUG, 7, "c" * 40)
    assert runner.calls[-1][0] == ("gh", "pr", "merge", "7", "--repo", SLUG, "--merge",
                                   "--match-head-commit", "c" * 40)
    with pytest.raises(ValueError):
        g.pr_merge(SLUG, 7, "c" * 7)
    with pytest.raises(ValueError):
        g.pr_merge(SLUG, 7, "C" * 40)


@pytest.mark.parametrize("flag", ["--admin", "--auto", "--squash", "--rebase", "-d", "--delete-branch", "--draft"])
def test_fake_gh_rejects_forbidden_flags(fake_gh_env, flag):
    g, runner = fake_gh_env
    with pytest.raises(AssertionError):
        runner(["gh", "pr", "merge", "1", "--repo", SLUG, flag], cwd=Path("."), env={}, timeout=5)


def test_fake_gh_rejects_pr_checks(fake_gh_env):
    _, runner = fake_gh_env
    with pytest.raises(AssertionError):
        runner(["gh", "pr", "checks", "1", "--repo", SLUG], cwd=Path("."), env={}, timeout=5)


def test_every_gh_call_names_the_repo(fake_gh_env, tmp_path):
    g, runner = fake_gh_env
    body = tmp_path / "body.md"
    body.write_text("b", encoding="utf-8")
    g.pr_list(SLUG, head="b", base="main")
    g.pr_list_open(SLUG, base="main")
    g.merge_commit_allowed(SLUG)
    g.repo_visible(SLUG)
    g.default_branch(SLUG)
    g.user_login()
    g.contents_raw(SLUG, "guard.lock", "main")
    g.compare(SLUG, "main", "main")
    g.run_list(SLUG, commit="a" * 40)
    g.check_run_annotations(SLUG, 5)
    g.fake.jobs[9] = {"id": 9}
    g.job(SLUG, 9)
    g.fake.workflows[(SLUG, "ci.yml")] = "active"
    g.workflow_state(SLUG, "ci.yml")
    url = g.pr_create(SLUG, head="b", base="main", title="t", body_file=body)
    g.pr_view(SLUG, 1, ["number"])
    g.pr_close(SLUG, 1, "bye")
    assert url.endswith("/pull/1")
    assert len(runner.calls) >= 15
    for argv, _, _ in runner.calls:
        assert "--repo" in argv or any(a.startswith("repos/") or a == "user" for a in argv)


def test_non_api_failures_are_classified(tmp_path):
    def build(rc, stderr):
        sleeps: list[float] = []
        return Gh(FakeRunner([Route(("gh",), rc=rc, stderr=stderr)]), {}, sleeps.append, tmp_path), sleeps

    g, _ = build(4, b"auth")
    with pytest.raises(GhAuthError):
        g.pr_list(SLUG, head="b", base="main")
    g, _ = build(1, b"GraphQL: Could not resolve to a PullRequest")
    with pytest.raises(GhNotFound):
        g.pr_view(SLUG, 3, ["number"])
    g, sleeps = build(1, b"HTTP 503: unavailable")
    with pytest.raises(GhNetworkError):
        g.pr_list(SLUG, head="b", base="main")
    assert len(sleeps) == 5
    g, sleeps = build(1, b"HTTP 422: nope")
    with pytest.raises(GhError) as ei:
        g.pr_close(SLUG, 3, "x")
    assert ei.value.status == 422 and sleeps == []


def test_pr_argv_shapes(tmp_path):
    runner = FakeRunner([Route(("gh",), stdout=b"[]")])
    g = Gh(runner, {}, lambda s: None, tmp_path)
    g.pr_list(SLUG, head="h", base="main")
    assert runner.calls[-1][0] == ("gh", "pr", "list", "--repo", SLUG, "--head", "h", "--base", "main",
                                   "--state", "open", "--json",
                                   "number,url,headRefOid,isCrossRepository,author,headRefName")
    g.pr_list_open(SLUG, base="main")
    argv = runner.calls[-1][0]
    assert "--head" not in argv and argv[argv.index("--limit") + 1] == "100"
    g.run_list(SLUG, commit="a" * 40, workflow="ci.yml", branch="b", event="push")
    argv = runner.calls[-1][0]
    assert argv[:4] == ("gh", "run", "list", "--repo")
    for flag, value in (("--commit", "a" * 40), ("--workflow", "ci.yml"), ("--branch", "b"), ("--event", "push")):
        assert argv[argv.index(flag) + 1] == value
    assert argv[argv.index("--json") + 1] == "databaseId,status,conclusion,workflowName,headSha,event,createdAt"


def test_fake_gh_serves_repo_facts_from_the_bare(fake_gh_env):
    g, _ = fake_gh_env
    sha = sha_of(g.work, "HEAD")
    assert g.contents_raw(SLUG, "guard.lock", sha) == b"lock\n"
    assert g.contents_raw(SLUG, "missing", sha) is None
    assert g.default_branch(SLUG) == "main"
    assert g.merge_commit_allowed(SLUG) is True
    g.fake.merge_commit_allowed[SLUG] = False
    assert g.merge_commit_allowed(SLUG) is False
    assert g.user_login() == "operator"
    with pytest.raises(GhNotFound):
        g.repo_visible("owner/unknown")
    assert g.compare(SLUG, sha, sha)["status"] == "identical"


def _open_pr(g) -> tuple[int, str]:
    _git(g.work, "checkout", "-q", "-b", "feature")
    head = commit_files(g.work, "feature", {"f.txt": "f"})
    _git(g.work, "push", "-q", "origin", "feature")
    url = g.pr_create(SLUG, head="feature", base="main", title="t", body_file=Path("unused"))
    return int(url.rsplit("/", 1)[1]), head


def test_fake_gh_merge_makes_a_real_merge_commit(fake_gh_env):
    g, _ = fake_gh_env
    main_before = sha_of(g.bare, "main")
    number, head = _open_pr(g)
    assert g.pr_list(SLUG, head="feature", base="main")[0]["headRefOid"] == head
    result = g.pr_merge(SLUG, number, head)
    assert result.rc == 0
    view = g.pr_view(SLUG, number, ["state", "mergeCommit"])
    assert view["state"] == "MERGED"
    merge = view["mergeCommit"]["oid"]
    assert sha_of(g.bare, "main") == merge
    parents = _git(g.bare, "rev-list", "--parents", "-n1", merge).split()
    assert parents[1:] == [main_before, head]
    assert g.pr_list(SLUG, head="feature", base="main") == []


def test_fake_gh_merge_with_stale_head_leaves_pr_open(fake_gh_env):
    g, _ = fake_gh_env
    main_before = sha_of(g.bare, "main")
    number, _head = _open_pr(g)
    result = g.pr_merge(SLUG, number, "d" * 40)
    assert result.rc == 1
    assert g.pr_view(SLUG, number, ["state"])["state"] == "OPEN"
    assert sha_of(g.bare, "main") == main_before


def test_fake_gh_close_runs_and_jobs(fake_gh_env):
    g, _ = fake_gh_env
    number, _ = _open_pr(g)
    g.pr_close(SLUG, number, "superseded")
    assert g.pr_view(SLUG, number, ["state"])["state"] == "CLOSED"
    assert g.fake.closed_comments[(SLUG, number)] == "superseded"
    g.fake.runs[SLUG] = [
        {"databaseId": 1, "headSha": "a" * 40, "event": "push", "workflowName": "ci", "headBranch": "main",
         "status": "completed", "conclusion": "success", "createdAt": "t"},
        {"databaseId": 2, "headSha": "b" * 40, "event": "pull_request", "workflowName": "ci",
         "headBranch": "feature", "status": "queued", "conclusion": None, "createdAt": "t"}]
    assert [r["databaseId"] for r in g.run_list(SLUG, commit="a" * 40)] == [1]
    assert [r["databaseId"] for r in g.run_list(SLUG, branch="feature", event="pull_request")] == [2]
    assert len(g.run_list(SLUG)) == 2
    g.fake.jobs[77] = {"id": 77, "conclusion": "failure"}
    assert g.job(SLUG, 77)["conclusion"] == "failure"
    with pytest.raises(GhNotFound):
        g.job(SLUG, 78)
    g.fake.annotations[5] = [{"message": "boom"}]
    assert g.check_run_annotations(SLUG, 5) == [{"message": "boom"}]
    g.fake.workflows[(SLUG, "ci.yml")] = "disabled_manually"
    assert g.workflow_state(SLUG, "ci.yml") == "disabled_manually"
    assert g.fake.argvs[0][:3] == ("gh", "pr", "create")


@pytest.mark.parametrize("raw", [
    b"HTTP/1.1 200 OK\r\nContent-Type: x\r\n\r\nbody",
    b"HTTP/2.0 200 OK\ncontent-type: x\n\nbody",
    b"HTTP/2 200\r\n\r\nbody",
])
def test_api_parses_http_versions_and_line_endings(gh_with, raw):
    r = gh_with(stdout=raw, rc=0).api(f"repos/{SLUG}")
    assert r.status == 200 and r.body == b"body"


def test_api_body_with_blank_lines_is_kept_whole(gh_with):
    body = b"line1\n\nline2\r\n\r\nline3"
    r = gh_with(body=body).api(f"repos/{SLUG}")
    assert r.body == body


def test_api_malformed_output_with_rc_0_raises(gh_with):
    with pytest.raises(GhError) as ei:
        gh_with(stdout=b"<html>not gh</html>", rc=0).api(f"repos/{SLUG}")
    assert ei.value.status is None and not isinstance(ei.value, GhNetworkError)


def test_api_success_status_with_failing_process_raises_not_truncated_success(gh_with):
    g, sleeps = gh_with(status=200, body=b"part", rc=1, record_sleeps=True)
    with pytest.raises(GhNetworkError):
        g.contents_raw(SLUG, "guard.lock", "a" * 40)
    assert len(sleeps) == 5


def test_api_success_status_without_separator_raises(gh_with):
    with pytest.raises(GhError):
        gh_with(stdout=b"HTTP/2.0 200 OK\r\ncontent-type: x", rc=0).contents_raw(SLUG, "guard.lock", "a" * 40)


def test_pr_create_is_single_attempt_on_timeout_class_failure(tmp_path):
    runner = FakeRunner([Route(("gh",), rc=1, stderr=b"read tcp: i/o timeout")])
    sleeps: list[float] = []
    g = Gh(runner, {}, sleeps.append, tmp_path)
    with pytest.raises(GhNetworkError):
        g.pr_create(SLUG, head="b", base="main", title="t", body_file=tmp_path / "b.md")
    assert len(runner.calls) == 1 and sleeps == []


def test_pr_close_and_non_get_api_are_single_attempt(tmp_path):
    runner = FakeRunner([Route(("gh",), rc=1, stderr=b"HTTP 503: unavailable", stdout=_resp(503))])
    g = Gh(runner, {}, lambda s: None, tmp_path)
    with pytest.raises(GhNetworkError):
        g.pr_close(SLUG, 1, "x")
    with pytest.raises(GhNetworkError):
        g.api(f"repos/{SLUG}/x", method="POST")
    assert len(runner.calls) == 2


def test_pr_list_state_parameter_reaches_argv_and_fake(fake_gh_env):
    g, runner = fake_gh_env
    number, head = _open_pr(g)
    g.pr_list(SLUG, head="feature", base="main", state="merged")
    argv = runner.calls[-1][0]
    assert argv[argv.index("--state") + 1] == "merged"
    assert g.pr_list(SLUG, head="feature", base="main", state="merged") == []
    g.pr_merge(SLUG, number, head)
    assert [p["number"] for p in g.pr_list(SLUG, head="feature", base="main", state="merged")] == [number]
    assert g.pr_list(SLUG, head="feature", base="main") == []


def test_run_jobs_lists_the_jobs_of_one_run(fake_gh_env):
    g, runner = fake_gh_env
    g.fake.jobs[11] = {"id": 11, "run_id": 5, "name": "a", "conclusion": "success"}
    g.fake.jobs[12] = {"id": 12, "run_id": 6, "name": "b", "conclusion": "failure"}
    assert [j["id"] for j in g.run_jobs(SLUG, 5)] == [11]
    assert runner.calls[-1][0][-1] == f"repos/{SLUG}/actions/runs/5/jobs?per_page=100"
