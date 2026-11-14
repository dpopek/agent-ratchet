"""Conformance test suite for Guard Core 2.3.3 Git/CI snapshot contracts and baseline integrity."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from guard_core.git_guard_io import (
    default_remote_refs,
    resolve_trusted_base_ref,
    verify_audit_guard_config_monotonicity,
)
from guard_core.test_baseline_integrity import evaluate_baseline_diff

sys.path.insert(0, str(Path(__file__).resolve().parent))
from guard_repo_harness import (
    _commit_files,
    _git,
    _init_guard_repo,
    _json_bytes,
    _run_baseline_guard,
    _run_scanner,
    _sha256_bytes,
    _write_files,
)


class TestGuardGitCiAndBaselineConformance(unittest.TestCase):
    def test_baseline_diff_allows_variant_ceilings_shrink_2_to_1_and_blocks_growth(self) -> None:
        base = {"metric": "refactoring_slop", "version": "2.0.0", "ceiling": 2, "exemptions": [{"file": "src/domain/v.py", "symbol": "build", "kind": "excessive_parameter_list", "ceiling": 8, "variant_ceilings": [8, 7]}]}
        shrunk = {"metric": "refactoring_slop", "version": "2.0.0", "ceiling": 1, "exemptions": [{"file": "src/domain/v.py", "symbol": "build", "kind": "excessive_parameter_list", "ceiling": 8}]}
        res_ok = evaluate_baseline_diff(base, shrunk)
        self.assertTrue(res_ok.is_valid, res_ok.reason)
        grown = {"metric": "refactoring_slop", "version": "2.0.0", "ceiling": 2, "exemptions": [{"file": "src/domain/v.py", "symbol": "build", "kind": "excessive_parameter_list", "ceiling": 8, "variant_ceilings": [8, 8]}]}
        self.assertFalse(evaluate_baseline_diff(base, grown).is_valid)

    def test_partial_stage_isolates_code_config_baseline_and_guard_lock_from_dirty_worktree(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _init_guard_repo(tmp)
            _commit_files(repo, "chore: initial", {
                "src/domain/svc.py": "def compute(a, b):\n    return a + b\n",
                "tests/baselines/refactoring_slop.json": _json_bytes({"metric": "refactoring_slop", "version": "2.0.0", "ceiling": 0, "exemptions": []}),
            }, include_guards=True)
            _write_files(repo, {"src/domain/svc.py": "def compute(a: int, b: int) -> int:\n    return a + b + 1\n"})
            _git(repo, "add", "src/domain/svc.py")
            _write_files(repo, {
                "src/domain/svc.py": "def broken(a,b,c,d,e,f,g,h,i:\n",
                "scripts/audit/audit_guard_config.json": "{corrupt_json",
                "tests/baselines/refactoring_slop.json": _json_bytes({"metric": "refactoring_slop", "version": "2.0.0", "ceiling": 999, "exemptions": []}),
                "guard.lock": "NOT-A-SHA\r\n",
                "scripts/guard": "#!/bin/sh\nexit 0\n",
            })
            r_scan = _run_scanner(repo, "--staged-only")
            self.assertEqual(r_scan.returncode, 0, r_scan.stderr + r_scan.stdout)
            r_base = _run_baseline_guard(repo, "--enforce-policy-isolation")
            self.assertEqual(r_base.returncode, 0, r_base.stderr + r_base.stdout)

    def test_staged_only_isolates_dirty_tracked_guard_lock_shim_config_and_unstaged_app_edits(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _init_guard_repo(tmp)
            _commit_files(repo, "chore: initial", {
                "src/domain/svc.py": "def ok(x):\n    return x\n",
                "tests/baselines/refactoring_slop.json": _json_bytes({"metric": "refactoring_slop", "version": "2.2.0", "ceiling": 0, "exemptions": []}),
                "guard.lock": "1" * 40 + "\n",
                "scripts/guard": "#!/bin/sh\nexec uvx guard-core \"$@\"\n",
            }, include_guards=True)
            _write_files(repo, {"src/domain/svc.py": "def ok(x: int) -> int:\n    return x + 1\n"})
            _git(repo, "add", "src/domain/svc.py")
            _write_files(repo, {
                "guard.lock": "2" * 40 + "\n",
                "scripts/guard": "#!/bin/sh\nexit 0\n",
                "scripts/audit/audit_guard_config.json": "{corrupt",
                "src/domain/svc.py": "import os\ndef bad(): return os.environ['X']\n",
            })
            self.assertEqual(_run_scanner(repo, "--staged-only").returncode, 0)
            self.assertEqual(_run_baseline_guard(repo, "--enforce-policy-isolation").returncode, 0)

    def test_legacy_loc_waiver_handles_intermediate_hash_change_in_range_and_blocks_next_growth_or_merge_bloat(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _init_guard_repo(tmp)
            h1_bytes = ("const y = 2;\n" + ("const x = 1;\n" * 719)).encode("utf-8")
            cfg = {"extra_slop_rules": [], "legacy_loc_waivers": [{"file": "src/domain/big.ts", "base_blob_sha256": _sha256_bytes(h1_bytes), "max_loc": 725, "max_delta": 5, "approved_by": "@owner", "ticket": "MS-101"}]}
            c0 = _commit_files(repo, "chore: c0", {
                "src/domain/big.ts": "const x = 1;\n" * 720,
                "scripts/audit/audit_guard_config.json": _json_bytes(cfg),
                "tests/baselines/refactoring_slop.json": _json_bytes({"metric": "refactoring_slop", "version": "2.0.0", "ceiling": 0, "exemptions": []}),
            }, include_guards=True)
            _commit_files(repo, "fix: c1 same loc", {"src/domain/big.ts": h1_bytes})
            c2b = _commit_files(repo, "feat: c2b waived growth", {"src/domain/big.ts": "const y = 2;\n" + ("const x = 1;\n" * 724)})

            self.assertEqual(_run_scanner(repo, "--commit-range", f"{c0}..{c2b}").returncode, 0)
            self.assertEqual(_run_baseline_guard(repo, "--require-base-ref", "--enforce-policy-isolation", "--commit-range", f"{c0}..{c2b}").returncode, 0)

            _git(repo, "checkout", "-q", "-b", "side", c0)
            _commit_files(repo, "feat: side", {"src/domain/side.py": "y = 1\n"})
            _git(repo, "checkout", "-q", "-")
            _git(repo, "merge", "--no-commit", "--no-ff", "side")
            merge_sha = _commit_files(repo, "Merge branch 'side'", {"src/domain/big.ts": "const y = 2;\n" + ("const x = 1;\n" * 725)})
            self.assertEqual(_run_scanner(repo, "--commit-range", f"{c0}..{merge_sha}").returncode, 1)

            _git(repo, "reset", "--hard", c2b)
            c3 = _commit_files(repo, "feat: unapproved c3", {"src/domain/big.ts": "const y = 2;\n" + ("const x = 1;\n" * 725)})
            self.assertEqual(_run_scanner(repo, "--commit-range", f"{c0}..{c3}").returncode, 1)

    def test_git_mv_end_to_end_across_scanner_baseline_integrity_and_policy_isolation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _init_guard_repo(tmp)
            c0 = _commit_files(repo, "chore: init old_eval", {
                "src/domain/old_eval.py": '"""Legacy evaluation module."""\nDEFAULT_OFFSET = 0\ndef evaluate(a, b, c, d, e, f, g, h):\n    total = a + b + c + d\n    extra = e + f + g + h\n    return total + extra + DEFAULT_OFFSET\n',
                "tests/baselines/refactoring_slop.json": _json_bytes({"metric": "refactoring_slop", "version": "2.0.0", "ceiling": 1, "exemptions": [{"file": "src/domain/old_eval.py", "symbol": "evaluate", "kind": "excessive_parameter_list", "ceiling": 8}]}),
            }, include_guards=True)

            _git(repo, "mv", "src/domain/old_eval.py", "src/domain/new_eval.py")
            _write_files(repo, {
                "src/domain/new_eval.py": '"""Legacy evaluation module."""\nDEFAULT_OFFSET = 0\ndef evaluate(a: int, b: int, c, d, e, f, g, h):\n    total = a + b + c + d\n    extra = e + f + g + h\n    return total + extra + DEFAULT_OFFSET + 1\n',
                "tests/baselines/refactoring_slop.json": _json_bytes({"metric": "refactoring_slop", "version": "2.0.0", "ceiling": 1, "exemptions": [{"file": "src/domain/new_eval.py", "symbol": "evaluate", "kind": "excessive_parameter_list", "ceiling": 8}]}),
            })
            _git(repo, "add", "src/domain/new_eval.py", "tests/baselines/refactoring_slop.json")
            self.assertEqual(_run_scanner(repo, "--staged-only").returncode, 0)
            self.assertEqual(_run_baseline_guard(repo, "--enforce-policy-isolation").returncode, 0)
            _git(repo, "commit", "-q", "-m", "refactor: rename old_eval to new_eval")
            c1 = _git(repo, "rev-parse", "HEAD")
            self.assertEqual(_run_scanner(repo, "--commit-range", f"{c0}..{c1}").returncode, 0)
            self.assertEqual(_run_baseline_guard(repo, "--require-base-ref", "--enforce-policy-isolation", "--commit-range", f"{c0}..{c1}").returncode, 0)

    def test_commit_range_allows_fix_then_ratchet_sequence_blocks_mixed_commit_and_catches_8_to_7_to_8(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _init_guard_repo(tmp)
            ex_param = {"file": "src/domain/pred.py", "symbol": "evaluate", "kind": "excessive_parameter_list", "ceiling": 8}
            ex_imp = {"file": "src/domain/pred.py", "symbol": "evaluate", "kind": "domain_impurity", "ceiling": 1}
            stage_a_bytes = _json_bytes({"metric": "refactoring_slop", "version": "2.1.0", "ceiling": 2, "exemptions": [ex_imp, ex_param]})
            base_sha = _commit_files(repo, "chore: base v2.1.0", {
                "src/domain/pred.py": "import time\ndef evaluate(a, b, c, d, e, f, g, h):\n    return time.time() + a\n",
                "tests/baselines/refactoring_slop.json": stage_a_bytes,
            }, include_guards=True)

            _write_files(repo, {"src/domain/pred.py": "def evaluate(a, b, c, d, e, f, g, h):\n    return a\n"})
            _git(repo, "add", "src/domain/pred.py")
            self.assertEqual(_run_baseline_guard(repo, "--base-ref", base_sha, "--enforce-policy-isolation").returncode, 0)
            _git(repo, "commit", "-q", "-m", "refactor: stage B")

            _write_files(repo, {"tests/baselines/refactoring_slop.json": _json_bytes({"metric": "refactoring_slop", "version": "2.1.0", "ceiling": 1, "exemptions": [ex_param]})})
            _git(repo, "add", "tests/baselines/refactoring_slop.json")
            self.assertEqual(_run_baseline_guard(repo, "--base-ref", base_sha, "--enforce-policy-isolation").returncode, 0)
            _git(repo, "commit", "-q", "-m", "chore: stage C")
            stage_c_sha = _git(repo, "rev-parse", "HEAD")

            self.assertEqual(_run_scanner(repo, "--commit-range", f"{base_sha}..{stage_c_sha}").returncode, 0)
            self.assertEqual(_run_baseline_guard(repo, "--require-base-ref", "--enforce-policy-isolation", "--commit-range", f"{base_sha}..{stage_c_sha}").returncode, 0)

            _write_files(repo, {"tests/baselines/refactoring_slop.json": stage_a_bytes})
            _git(repo, "add", "tests/baselines/refactoring_slop.json")
            self.assertEqual(_run_baseline_guard(repo, "--base-ref", base_sha, "--enforce-policy-isolation").returncode, 1)
            _git(repo, "reset", "--hard", stage_c_sha)

            _commit_files(repo, "refactor: 8 to 7", {"src/domain/pred.py": "def evaluate(a, b, c, d, e, f, g):\n    return a\n"})
            reg_sha = _commit_files(repo, "feat: 7 back to 8", {"src/domain/pred.py": "def evaluate(a, b, c, d, e, f, g, h):\n    return a\n"})
            self.assertEqual(_run_scanner(repo, "--commit-range", f"{stage_c_sha}..{reg_sha}").returncode, 1)

            mixed_sha = _commit_files(repo, "chore: mixed policy and src", {
                "src/domain/pred.py": "def evaluate(a, b, c, d, e, f, g):\n    return a + 1\n",
                "scripts/audit/audit_guard_config.json": json.dumps({"extra_slop_rules": [], "legacy_loc_waivers": []}, indent=4) + "\n",
            })
            self.assertEqual(_run_baseline_guard(repo, "--require-base-ref", "--enforce-policy-isolation", "--commit-range", f"{reg_sha}..{mixed_sha}").returncode, 1)

    def test_baseline_version_bump_is_rejected_without_a_migration_catalogue(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _init_guard_repo(tmp)
            bf_rel = "tests/baselines/refactoring_slop.json"
            ex_leg6 = {"file": "src/domain/svc.py", "symbol": "legacy_fn", "kind": "excessive_parameter_list", "ceiling": 6}
            ex_imp1 = {"file": "src/domain/svc.py", "symbol": "legacy_fn", "kind": "domain_impurity", "ceiling": 1}
            base_sha = _commit_files(repo, "chore: base 2.0.0", {
                "src/domain/svc.py": "import time\ndef legacy_fn(a, b, c, d, e, f):\n    return time.time()\n",
                bf_rel: _json_bytes({"metric": "refactoring_slop", "version": "2.0.0", "ceiling": 1, "exemptions": [ex_leg6]}),
            }, include_guards=True)
            for bumped in (
                {"metric": "refactoring_slop", "version": "2.1.0", "ceiling": 2, "exemptions": [ex_imp1, ex_leg6]},
                {"metric": "refactoring_slop", "version": "2.1.0", "ceiling": 1, "exemptions": [ex_leg6]},
                {"metric": "refactoring_slop", "version": "9.9.9", "ceiling": 0, "exemptions": []},
            ):
                _git(repo, "reset", "-q", "--hard", base_sha)
                _write_files(repo, {bf_rel: _json_bytes(bumped)})
                _git(repo, "add", bf_rel)
                res = _run_baseline_guard(repo, "--base-ref", base_sha)
                self.assertEqual(res.returncode, 1, res.stderr + res.stdout)
                _git(repo, "commit", "-q", "-m", "chore: bump baseline version")
                self.assertEqual(_run_baseline_guard(repo, "--require-base-ref", "--commit-range", f"{base_sha}..HEAD").returncode, 1)

    def test_analysis_failures_return_exit_code_2_never_silent_pass(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _init_guard_repo(tmp)
            _commit_files(repo, "chore: init", {
                "src/domain/ok.py": "def f(a):\n    return a\n",
                "tests/test_sample.py": "def test_ok():\n    assert 1 == 1\n",
                "tests/baselines/refactoring_slop.json": _json_bytes({"metric": "refactoring_slop", "version": "2.0.0", "ceiling": 0, "exemptions": []}),
            }, include_guards=True)
            for rel, broken, runner in (
                ("src/domain/ok.py", "def broken(:\n", lambda r: _run_scanner(r, "--staged-only")),
                ("tests/test_sample.py", "def test_ok(:\n", lambda r: _run_scanner(r, "--staged-only")),
                ("tests/baselines/refactoring_slop.json", "{bad", lambda r: _run_baseline_guard(r)),
            ):
                _write_files(repo, {rel: broken})
                _git(repo, "add", rel)
                self.assertEqual(runner(repo).returncode, 2)
                _git(repo, "reset", "--hard", "HEAD")
            self.assertEqual(_run_baseline_guard(repo, "--require-base-ref", "--base-ref", "deadbeef" * 5).returncode, 2)

    def test_baseline_file_deletion_blocked_in_staged_and_commit_range_and_no_worktree_leak(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _init_guard_repo(tmp)
            bf_rel = "tests/baselines/refactoring_slop.json"
            base_sha = _commit_files(repo, "chore: baseline init", {bf_rel: _json_bytes({"metric": "refactoring_slop", "version": "2.0.0", "ceiling": 3, "exemptions": []})}, include_guards=True)

            _git(repo, "rm", "-q", "--cached", bf_rel)
            self.assertTrue((repo / bf_rel).exists())
            staged_del = _run_baseline_guard(repo, "--enforce-policy-isolation")
            self.assertEqual(staged_del.returncode, 1)
            self.assertIn("baseline_deleted", staged_del.stderr)

            (repo / bf_rel).unlink()
            _git(repo, "commit", "-q", "-m", "chore: delete baseline")
            local_del = _run_baseline_guard(repo, "--base-ref", base_sha)
            self.assertEqual(local_del.returncode, 1)
            self.assertIn("baseline_deleted", local_del.stderr)
            range_del = _run_baseline_guard(repo, "--require-base-ref", "--enforce-policy-isolation", "--commit-range", f"{base_sha}..HEAD")
            self.assertEqual(range_del.returncode, 1)
            self.assertIn("baseline_deleted", range_del.stderr)

    def test_commit_range_enforces_running_ratchet_and_merge_commit_integrity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _init_guard_repo(tmp)
            bf_rel = "tests/baselines/refactoring_slop.json"
            ex_imp = {"file": "src/domain/svc.py", "symbol": "ok", "kind": "domain_impurity", "ceiling": 1}
            mig_b_bytes = _json_bytes({"metric": "refactoring_slop", "version": "2.1.0", "ceiling": 1, "exemptions": [ex_imp]})
            ratcheted_b_bytes = _json_bytes({"metric": "refactoring_slop", "version": "2.1.0", "ceiling": 0, "exemptions": []})

            master_base = _commit_files(repo, "chore: master base", {"src/domain/svc.py": "import time\ndef ok(a):\n    return time.time()\n", bf_rel: mig_b_bytes}, include_guards=True)

            _git(repo, "checkout", "-q", "-b", "feat/multi-stage")
            stage_a = _commit_files(repo, "docs: stage a", {"docs/notes.md": "stage a\n"})

            _commit_files(repo, "refactor: stage b", {"src/domain/svc.py": "def ok(a):\n    return a + 1\n"})
            stage_c = _commit_files(repo, "chore: stage c", {bf_rel: ratcheted_b_bytes})

            _git(repo, "checkout", "-q", master_base)
            _git(repo, "checkout", "-q", "-b", "master-sim")
            master_before_merge = _commit_files(repo, "feat: master unrelated", {"src/domain/other.py": "def other(x):\n    return x\n"})

            _git(repo, "merge", "--no-ff", "-q", stage_c, "-m", "Merge feat/multi-stage")
            clean_merge = _run_baseline_guard(repo, "--require-base-ref", "--enforce-policy-isolation", "--commit-range", f"{master_before_merge}..HEAD")
            self.assertEqual(clean_merge.returncode, 0, clean_merge.stderr)

            _git(repo, "checkout", "-q", "-b", "side-at-a", stage_a)
            side_sha = _commit_files(repo, "feat: side", {"src/domain/side.py": "def s(x):\n    return x\n"})

            _git(repo, "checkout", "-q", "-b", "evil-ratchet-merge", stage_c)
            _git(repo, "merge", "--no-ff", "--no-commit", "-q", side_sha)
            _commit_files(repo, "Merge side with regressed ceiling", {bf_rel: mig_b_bytes})
            self.assertEqual(_run_baseline_guard(repo, "--require-base-ref", "--enforce-policy-isolation", "--commit-range", f"{master_base}..HEAD").returncode, 1)

            _git(repo, "checkout", "-q", "-b", "evil-gov-merge", master_before_merge)
            _git(repo, "merge", "--no-ff", "--no-commit", "-q", stage_c)
            _commit_files(repo, "Merge with sneaky governance edit", {"scripts/audit/audit_guard_config.json": _json_bytes({"extra_slop_rules": [], "legacy_loc_waivers": [{"sneaky": 1}]})})
            self.assertEqual(_run_baseline_guard(repo, "--require-base-ref", "--enforce-policy-isolation", "--commit-range", f"{master_before_merge}..HEAD").returncode, 1)

    def test_diamond_dag_history_o_a_b_m_is_order_independent_and_preserves_exemption_deletions_on_merge(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _init_guard_repo(tmp)
            bf_rel = "tests/baselines/refactoring_slop.json"
            ex1 = {"file": "src/domain/a.py", "symbol": "fa", "kind": "excessive_parameter_list", "ceiling": 8}
            ex2_8 = {"file": "src/domain/b.py", "symbol": "fb", "kind": "excessive_parameter_list", "ceiling": 8}
            ex2_7 = {"file": "src/domain/b.py", "symbol": "fb", "kind": "excessive_parameter_list", "ceiling": 7}
            o_sha = _commit_files(repo, "chore: O", {bf_rel: _json_bytes({"metric": "refactoring_slop", "version": "2.0.0", "ceiling": 2, "exemptions": [ex1, ex2_8]})}, include_guards=True)

            _git(repo, "checkout", "-q", "-b", "branch-a", o_sha)
            a_sha = _commit_files(repo, "chore: A deletes ex1", {bf_rel: _json_bytes({"metric": "refactoring_slop", "version": "2.0.0", "ceiling": 1, "exemptions": [ex2_8]})})

            _git(repo, "checkout", "-q", "-b", "branch-b", o_sha)
            b_sha = _commit_files(repo, "chore: B lowers ex2 to 7", {bf_rel: _json_bytes({"metric": "refactoring_slop", "version": "2.0.0", "ceiling": 2, "exemptions": [ex1, ex2_7]})})

            for idx, (first_p, second_p) in enumerate(((a_sha, b_sha), (b_sha, a_sha))):
                for bad_idx, bad_payload in enumerate((
                    {"metric": "refactoring_slop", "version": "2.0.0", "ceiling": 1, "exemptions": [ex2_8]},
                    {"metric": "refactoring_slop", "version": "2.0.0", "ceiling": 1, "exemptions": [ex1, ex2_7]},
                )):
                    _git(repo, "checkout", "-q", "-b", f"bad-merge-{idx}-{bad_idx}", first_p)
                    _git(repo, "merge", "--no-ff", "--no-commit", "-q", second_p)
                    _commit_files(repo, "Merge with regressed ratchet", {bf_rel: _json_bytes(bad_payload)})
                    self.assertEqual(_run_baseline_guard(repo, "--require-base-ref", "--commit-range", f"{o_sha}..HEAD").returncode, 1)

                _git(repo, "checkout", "-q", "-b", f"good-merge-{idx}", first_p)
                _git(repo, "merge", "--no-ff", "--no-commit", "-q", second_p)
                _commit_files(repo, "Merge with joined ratchet", {bf_rel: _json_bytes({"metric": "refactoring_slop", "version": "2.0.0", "ceiling": 1, "exemptions": [ex2_7]})})
                res_ok = _run_baseline_guard(repo, "--require-base-ref", "--commit-range", f"{o_sha}..HEAD")
                self.assertEqual(res_ok.returncode, 0, res_ok.stderr)

    def test_unborn_head_initial_commit_and_added_deleted_files_do_not_raise_analysis_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _init_guard_repo(tmp)
            _write_files(repo, {
                "src/domain/first.py": "def f(x):\n    return x\n",
                "tests/baselines/refactoring_slop.json": _json_bytes({"metric": "refactoring_slop", "version": "2.2.0", "ceiling": 0, "exemptions": []}),
            })
            _git(repo, "add", "scripts/audit/audit_guard_config.json", "src/domain/first.py", "tests/baselines/refactoring_slop.json")
            self.assertEqual(_run_scanner(repo, "--staged-only").returncode, 0)
            self.assertEqual(_run_baseline_guard(repo, "--enforce-policy-isolation").returncode, 0)
            _git(repo, "commit", "-q", "-m", "chore: root commit")

            _write_files(repo, {"src/domain/second.py": "def g(y):\n    return y\n"})
            _git(repo, "rm", "-q", "src/domain/first.py")
            _git(repo, "add", "src/domain/second.py")
            self.assertEqual(_run_scanner(repo, "--staged-only").returncode, 0)

    def test_import_roots_config_change_triggers_a2_cycle_scan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _init_guard_repo(tmp)
            c0 = _commit_files(repo, "chore: c0 dormant cycle", {
                "src/custom_root/pkg/__init__.py": "",
                "src/custom_root/pkg/a.py": "from pkg import b\n",
                "src/custom_root/pkg/b.py": "from pkg import a\n",
                "tests/baselines/refactoring_slop.json": _json_bytes({"metric": "refactoring_slop", "version": "2.2.0", "ceiling": 0, "exemptions": []}),
            }, include_guards=True)

            _write_files(repo, {"scripts/audit/audit_guard_config.json": _json_bytes({"extra_slop_rules": [], "legacy_loc_waivers": [], "import_roots": [".", "src", "src/custom_root"]})})
            _git(repo, "add", "scripts/audit/audit_guard_config.json")
            r_staged = _run_scanner(repo, "--staged-only")
            self.assertEqual(r_staged.returncode, 1)
            self.assertIn("import_cycle", r_staged.stderr)

            _git(repo, "commit", "-q", "-m", "ci: activate custom_root")
            c1 = _git(repo, "rev-parse", "HEAD")
            r_range = _run_scanner(repo, "--commit-range", f"{c0}..{c1}")
            self.assertEqual(r_range.returncode, 1)
            self.assertIn("import_cycle", r_range.stderr)

    def test_removing_a_custom_import_root_is_a_monotonicity_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _init_guard_repo(tmp)
            cfg = {"extra_slop_rules": [], "legacy_loc_waivers": []}
            base_sha = _commit_files(repo, "chore: custom root", {
                "src/custom_root/pkg/__init__.py": "",
                "scripts/audit/audit_guard_config.json": _json_bytes({**cfg, "import_roots": [".", "src", "src/custom_root/"]}),
                "tests/baselines/refactoring_slop.json": _json_bytes({"metric": "refactoring_slop", "version": "2.2.0", "ceiling": 0, "exemptions": []}),
            }, include_guards=True)

            for roots in ([".", "src"], ["src"]):
                _write_files(repo, {"scripts/audit/audit_guard_config.json": _json_bytes({**cfg, "import_roots": roots})})
                _git(repo, "add", "scripts/audit/audit_guard_config.json")
                errors = verify_audit_guard_config_monotonicity(base_sha, "", cwd=str(repo))
                self.assertEqual(errors, ["import_roots entry removed: 'src/custom_root' (narrows import-cycle detection)"])
                r = _run_scanner(repo, "--staged-only")
                self.assertEqual(r.returncode, 1)
                self.assertIn("import_roots entry removed", r.stderr)

            for roots in (["src/custom_root"], ["src/custom_root", "backend", "extra"], ["src", ".", "/src/custom_root"]):
                _write_files(repo, {"scripts/audit/audit_guard_config.json": _json_bytes({**cfg, "import_roots": roots})})
                _git(repo, "add", "scripts/audit/audit_guard_config.json")
                self.assertEqual(verify_audit_guard_config_monotonicity(base_sha, "", cwd=str(repo)), [], roots)

    def test_worktree_scan_loads_extra_slop_rules_and_fails_closed_on_corrupt_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _init_guard_repo(tmp)
            cfg = {"extra_slop_rules": [{"pattern": r"\.cardsV2\[\d+\]\.card\.header\.(title|subtitle)", "category": "brittle_card_traversal", "message": "Use card_helpers.js instead.", "test_only": True}], "legacy_loc_waivers": []}
            _write_files(repo, {
                "scripts/audit/audit_guard_config.json": _json_bytes(cfg),
                "src/app.js": "const t = res.cardsV2[0].card.header.title;\n",
                "test/card.test.js": "const t = res.cardsV2[0].card.header.title;\nexpect(t).toBe('ok');\n",
            })
            r_src = _run_scanner(repo, "src")
            self.assertEqual(r_src.returncode, 0, r_src.stderr + r_src.stdout)
            r_both = _run_scanner(repo, "src", "test")
            self.assertEqual(r_both.returncode, 1)
            self.assertIn("brittle_card_traversal", r_both.stderr)

            _write_files(repo, {"scripts/audit/audit_guard_config.json": "{corrupt_json"})
            self.assertEqual(_run_scanner(repo, "src", "test").returncode, 2)

    def test_monorepo_prefixes_and_husky_gitlab_governance_isolation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _init_guard_repo(tmp)
            _commit_files(repo, "chore: init monorepo", {
                ".husky/pre-commit": "#!/bin/sh\nexit 0\n",
                ".gitlab-ci.yml": "stages: [quality]\n",
                "backend/service.py": "x = 1\n" * 650,
            }, include_guards=True)

            _write_files(repo, {".husky/pre-commit": "#!/bin/sh\n# edit\nexit 0\n", "backend/service.py": "x = 1\n" * 805})
            _git(repo, "add", ".husky/pre-commit", "backend/service.py")
            self.assertEqual(_run_baseline_guard(repo, "--enforce-policy-isolation").returncode, 1)

            _git(repo, "reset", "-q", "HEAD", ".husky/pre-commit")
            _write_files(repo, {".husky/pre-commit": "#!/bin/sh\nexit 0\n"})
            r_loc = _run_scanner(repo, "--staged-only")
            self.assertEqual(r_loc.returncode, 1)
            self.assertIn("modified_file_loc_buffer", r_loc.stderr)

    def test_audit_guard_config_loc_waiver_expansion_rejected_against_base_ref(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _init_guard_repo(tmp)
            b0 = ("x = 1\n" * 720).encode("utf-8")
            r0 = {"category": "custom_rule", "pattern": "FORBIDDEN_CALL", "message": "no", "test_only": False}
            w0 = {"file": "src/domain/big.py", "base_blob_sha256": _sha256_bytes(b0), "max_loc": 730, "max_delta": 10, "approved_by": "@owner", "reason": "legacy"}
            base_sha = _commit_files(repo, "chore: base waiver", {
                "src/domain/big.py": b0,
                "scripts/audit/audit_guard_config.json": _json_bytes({"extra_slop_rules": [r0], "legacy_loc_waivers": [w0]}),
                "tests/baselines/refactoring_slop.json": _json_bytes({"metric": "refactoring_slop", "version": "2.2.0", "ceiling": 0, "exemptions": []}),
            }, include_guards=True)

            _git(repo, "rm", "-q", "scripts/audit/audit_guard_config.json")
            self.assertTrue(verify_audit_guard_config_monotonicity(base_sha, "", cwd=str(repo)))
            self.assertEqual(_run_baseline_guard(repo, "--base-ref", base_sha).returncode, 1)
            _git(repo, "reset", "--hard", base_sha)

            bigger = ("x = 1\n" * 726).encode("utf-8")
            for bad_rules, bad_waivers, new_big in (
                ([], [w0], b0),
                ([{**r0, "test_only": True}], [w0], b0),
                ([r0], [w0, {**w0, "file": "src/domain/other.py"}], b0),
                ([r0], [{**w0, "max_loc": 740}], b0),
                ([r0], [{**w0, "max_delta": 15}], b0),
                ([r0], [{**w0, "base_blob_sha256": _sha256_bytes(bigger)}], bigger),
            ):
                _write_files(repo, {"src/domain/big.py": new_big, "scripts/audit/audit_guard_config.json": _json_bytes({"extra_slop_rules": bad_rules, "legacy_loc_waivers": bad_waivers})})
                _git(repo, "add", "src/domain/big.py", "scripts/audit/audit_guard_config.json")
                self.assertTrue(verify_audit_guard_config_monotonicity(base_sha, "", cwd=str(repo)))
                self.assertEqual(_run_baseline_guard(repo, "--base-ref", base_sha).returncode, 1)

            _git(repo, "reset", "--hard", base_sha)
            _commit_files(repo, "feat: spend 6 lines", {"src/domain/big.py": bigger})
            _commit_files(repo, "feat: re-arm waiver", {
                "src/domain/big.py": ("x = 1\n" * 730).encode("utf-8"),
                "scripts/audit/audit_guard_config.json": _json_bytes({"extra_slop_rules": [r0], "legacy_loc_waivers": [{**w0, "base_blob_sha256": _sha256_bytes(bigger)}]}),
            })
            self.assertNotEqual(_run_baseline_guard(repo, "--require-base-ref", "--commit-range", f"{base_sha}..HEAD").returncode, 0)
            self.assertNotEqual(_run_scanner(repo, "--commit-range", f"{base_sha}..HEAD").returncode, 0)

            _git(repo, "reset", "--hard", base_sha)
            _write_files(repo, {"src/domain/big.py": b0, "scripts/audit/audit_guard_config.json": _json_bytes({"extra_slop_rules": [r0], "legacy_loc_waivers": [{**w0, "max_loc": 725}]})})
            _git(repo, "add", "src/domain/big.py", "scripts/audit/audit_guard_config.json")
            self.assertEqual(verify_audit_guard_config_monotonicity(base_sha, "", cwd=str(repo)), [])
            self.assertEqual(_run_baseline_guard(repo, "--base-ref", base_sha).returncode, 0)

    def test_policy_isolation_allows_atomic_baseline_tightening_with_src_fix(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _init_guard_repo(tmp)
            bf_rel = "tests/baselines/refactoring_slop.json"
            ex = {"file": "src/domain/svc.py", "symbol": "f", "kind": "excessive_parameter_list", "ceiling": 6}
            base_sha = _commit_files(repo, "chore: base debt", {
                "src/domain/svc.py": "def f(a, b, c, d, e, f6):\n    return a\n",
                "tests/test_svc.py": "def test_f():\n    assert 1 == 1\n",
                bf_rel: _json_bytes({"metric": "refactoring_slop", "version": "2.2.0", "scope": ["src/domain", "src/application"], "ceiling": 1, "exemptions": [ex]}),
            }, include_guards=True)

            _write_files(repo, {
                "src/domain/svc.py": "def f(a, b):\n    return a + b\n",
                "tests/test_svc.py": "def test_f():\n    assert 1 + 1 == 2\n",
                bf_rel: _json_bytes({"metric": "refactoring_slop", "version": "2.2.0", "scope": ["src/domain", "src/application"], "ceiling": 0, "exemptions": []}),
            })
            _git(repo, "add", "src/domain/svc.py", "tests/test_svc.py", bf_rel)
            res_staged = _run_baseline_guard(repo, "--enforce-policy-isolation")
            self.assertEqual(res_staged.returncode, 0, res_staged.stderr)
            _git(repo, "commit", "-q", "-m", "refactor: pay down f params and ratchet baseline")
            res_range = _run_baseline_guard(repo, "--require-base-ref", "--enforce-policy-isolation", "--commit-range", f"{base_sha}..HEAD")
            self.assertEqual(res_range.returncode, 0, res_range.stderr)

    def test_policy_isolation_blocks_baseline_loosening_and_protected_governance_prefixes(self) -> None:
        self.assertFalse(evaluate_baseline_diff({"scope": ["src/domain", "src/application"], "ceiling": 1}, {"scope": ["src/domain"], "ceiling": 1}).is_valid)
        self.assertTrue(evaluate_baseline_diff({"ceiling": 0}, {"ceiling": 0, "double_cast_ceiling": 71}).is_valid)
        self.assertFalse(evaluate_baseline_diff({"ceiling": 1}, {"ceiling": 1, "unexpected": 1}).is_valid)
        self.assertFalse(evaluate_baseline_diff({"ceiling": 1}, {"ceiling": 1, "bad_ceiling": -1}).is_valid)
        self.assertFalse(evaluate_baseline_diff({"ceiling": 1}, {"ceiling": 1, "bad_ceiling": True}).is_valid)
        self.assertFalse(evaluate_baseline_diff({"ceiling": 1}, {"ceiling": 1, "bad_ceiling": "71"}).is_valid)
        self.assertFalse(evaluate_baseline_diff({"ceiling": 1}, {"ceiling": 1, "bad_ceiling": [1]}).is_valid)
        self.assertFalse(evaluate_baseline_diff({"ceiling": 1}, {"ceiling": 1, "scope": ["src"]}).is_valid)
        with tempfile.TemporaryDirectory() as tmp:
            repo = _init_guard_repo(tmp)
            bf_rel = "tests/baselines/refactoring_slop.json"
            b22 = _json_bytes({"metric": "refactoring_slop", "version": "2.2.0", "scope": ["src/domain", "src/application"], "ceiling": 1, "exemptions": []})
            gov_files = {
                "scripts/hooks/session_stop_guard.py": "X = 1\n",
                "scripts/ci/verify_agent_state.py": "Y = 1\n",
                "scripts/audit/test_quality_auditor.py": "Z = 1\n",
                ".githooks/commit-msg": "#!/bin/sh\nexit 0\n",
            }
            base_sha = _commit_files(repo, "chore: base", {bf_rel: b22, "src/domain/svc.py": "A = 1\n", "tests/test_app.py": "def test_ok():\n    assert 1 == 1\n", **gov_files}, include_guards=True)

            for gov_rel in ("scripts/hooks/session_stop_guard.py", "scripts/ci/verify_agent_state.py", "scripts/audit/test_quality_auditor.py", ".githooks/commit-msg"):
                _git(repo, "reset", "--hard", base_sha)
                _write_files(repo, {gov_rel: "# edited\n", "src/domain/svc.py": "A = 2\n"})
                _git(repo, "add", gov_rel, "src/domain/svc.py")
                self.assertEqual(_run_baseline_guard(repo, "--enforce-policy-isolation").returncode, 1)

            _git(repo, "reset", "--hard", base_sha)
            shrunk_scope = _json_bytes({"metric": "refactoring_slop", "version": "2.2.0", "scope": ["src/domain"], "ceiling": 1, "exemptions": []})
            _write_files(repo, {"src/domain/svc.py": "A = 2\n", bf_rel: shrunk_scope})
            _git(repo, "add", "src/domain/svc.py", bf_rel)
            self.assertEqual(_run_baseline_guard(repo, "--enforce-policy-isolation").returncode, 1)

        with tempfile.TemporaryDirectory() as tmp2:
            repo2 = _init_guard_repo(tmp2)
            b21 = _json_bytes({"metric": "refactoring_slop", "version": "2.1.0", "scope": ["src/domain", "src/application"], "ceiling": 1, "exemptions": []})
            b21_sha = _commit_files(repo2, "chore: base 2.1", {bf_rel: b21, "scripts/helper.py": "X = 1\n"}, include_guards=True)
            _write_files(repo2, {"scripts/helper.py": "X = 2\n", bf_rel: b22})
            _git(repo2, "add", "scripts/helper.py", bf_rel)
            r2 = _run_baseline_guard(repo2, "--base-ref", b21_sha, "--enforce-policy-isolation")
            self.assertEqual(r2.returncode, 1)
            self.assertIn("Policy isolation violation", r2.stderr)

    def test_base_ref_prefers_origin_head_then_the_default_branch_closest_to_head(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _init_guard_repo(tmp)
            stale = _commit_files(repo, "chore: base", {"src/domain/svc.py": "A = 1\n"}, include_guards=True)
            fresh = _commit_files(repo, "feat: next", {"src/domain/svc.py": "A = 2\n"})
            _git(repo, "update-ref", "refs/remotes/origin/master", stale)
            _git(repo, "update-ref", "refs/remotes/origin/main", fresh)
            self.assertEqual(default_remote_refs(str(repo)), ["origin/main", "origin/master"])
            self.assertEqual(resolve_trusted_base_ref(str(repo)), "origin/main")
            env = {k: v for k, v in os.environ.items() if not k.startswith("CI_")}
            probe = "from guard_core.test_baseline_integrity import resolve_base_ref; print(resolve_base_ref())"
            out = subprocess.run([sys.executable, "-c", probe], cwd=repo, env=env, capture_output=True, text=True, check=True).stdout.strip()
            self.assertEqual(out, fresh)
            _git(repo, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/master")
            self.assertEqual(default_remote_refs(str(repo)), ["origin/master", "origin/main"])


if __name__ == "__main__":
    unittest.main()
