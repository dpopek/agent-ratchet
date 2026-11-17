"""Conformance test suite for Guard Core 2.3.3 AST, file budget (SLOC / cognitive), and text-delta contracts."""

from __future__ import annotations

from pathlib import Path
import subprocess
import tempfile
import unittest

from agent_ratchet.ai_slop_scanner import (
    _new_or_worsened_text_slop,
    check_staged_test_tampering,
    scan_diff_for_shortcut_escapes,
    scan_text_for_slop,
)
from agent_ratchet.cognitive_complexity import COGNITIVE_MODULE_CEILING
from agent_ratchet.git_guard_io import (
    RULES_VERSION,
    count_effective_sloc,
    evaluate_loc_transition,
)
from agent_ratchet.refactoring_guard import (
    RULES_VERSION as AST_RULES_VERSION,
    BranchKind,
    ScopeKind,
    collect_full_scan_violations,
    collect_refactoring_slop_entries,
    compare_ast_snapshots,
    extract_ast_snapshot,
)


PACKAGE_DIR = Path(__file__).resolve().parent.parent / "src" / "agent_ratchet"


class TestGuardAstConformance(unittest.TestCase):
    def test_guard_version_is_2_3_3(self) -> None:
        self.assertEqual(AST_RULES_VERSION, "2.3.3")
        self.assertEqual(RULES_VERSION, "2.3.3")
        self.assertEqual(ScopeKind.CLASS.value, "class")
        self.assertEqual(BranchKind.TYPE_CHECKING.value, "type_checking")

    def test_all_core_guard_files_at_most_750_loc(self) -> None:
        ceiling = 680
        for path in sorted(PACKAGE_DIR.glob("*.py")):
            loc = len(path.read_text(encoding="utf-8").splitlines())
            self.assertLessEqual(loc, ceiling, f"{path.name} has {loc} LOC (> {ceiling} ceiling)")

    def test_new_function_over_limit_blocked_including_single_line_and_decorated(self) -> None:
        code = (
            "from abc import abstractmethod\n"
            "from contextlib import contextmanager\n"
            "def dec(fn):\n    return fn\n"
            "def one_liner(a, b, c, d, e, f): return a + b\n"
            "@dec\ndef decorated_one_liner(a, b, c, d, e, f): return a * b\n"
            "def module_level_self_not_exempt(self, a, b, c, d, e): return a\n"
            "class BasePort:\n"
            "    @abstractmethod\n    def port_op(self, a, b, c, d, e, f): ...\n"
            "    @contextmanager\n    def managed_op(self, a, b, c, d, e, f):\n        yield a\n"
            "    def allowed_method(self, a, b, c, d, e):\n        return a\n"
        )
        violations = compare_ast_snapshots(None, code, "src/domain/sample.py")
        param_msgs = [v.message for v in violations if v.category == "excessive_parameter_list"]
        self.assertEqual(len(param_msgs), 5)
        for name in (
            "one_liner",
            "decorated_one_liner",
            "module_level_self_not_exempt",
            "BasePort.port_op",
            "BasePort.managed_op",
        ):
            self.assertTrue(any(name in m for m in param_msgs), f"Missing violation for {name}: {param_msgs}")
        self.assertFalse(any("allowed_method" in m for m in param_msgs))

    def test_legacy_body_comment_and_type_annotation_edits_allowed(self) -> None:
        base = (
            "class Evaluator:\n"
            "    def evaluate(self, a, b, c, d, e, f, g, h):\n"
            "        val = getattr(self, 'fallback', 0)\n"
            "        return a + b + val\n"
        )
        target_clean_edit = (
            "class Evaluator:\n"
            "    # Updated domain documentation comment\n"
            "    def evaluate(self, a: int, b: int, c: int, d: int, e: int, f: int, g: int, h: int = 0) -> int:\n"
            "        '''Docstring added during bugfix.'''\n"
            "        val = getattr(self, 'fallback', 0)\n"
            "        return (a * 2) + b + val\n"
        )
        self.assertEqual(compare_ast_snapshots(base, target_clean_edit, "src/domain/eval.py"), [])

        target_worsened_body = target_clean_edit.replace(
            "return (a * 2) + b + val",
            "extra = getattr(self, 'other', 1)\n        return (a * 2) + b + val + extra",
        )
        worsened = compare_ast_snapshots(base, target_worsened_body, "src/domain/eval.py")
        self.assertEqual([v.category for v in worsened], ["defensive_getattr_slop"])

    def test_gradual_parameter_reduction_allowed_and_worsening_blocked(self) -> None:
        base_8 = "def compute(a, b, c, d, e, f, g, h):\n    return a\n"
        target_7 = "def compute(a, b, c, d, e, f, g):\n    return a\n"
        target_9 = "def compute(a, b, c, d, e, f, g, h, i):\n    return a\n"
        self.assertEqual(compare_ast_snapshots(base_8, target_7, "src/domain/calc.py"), [])

        v_9 = compare_ast_snapshots(base_8, target_9, "src/domain/calc.py")
        self.assertEqual([v.category for v in v_9], ["excessive_parameter_list"])

        base_5 = "def small(a, b, c, d, e):\n    return a\n"
        target_6 = "def small(a, b, c, d, e, f):\n    return a\n"
        v_6 = compare_ast_snapshots(base_5, target_6, "src/domain/calc.py")
        self.assertEqual([v.category for v in v_6], ["excessive_parameter_list"])

        target_varargs = "def small(a, *args, **kwargs):\n    return a\n"
        v_var = compare_ast_snapshots(base_5, target_varargs, "src/domain/calc.py")
        self.assertEqual([v.category for v in v_var], ["excessive_parameter_list"])

    def test_conditional_variants_allow_branch_inversion_and_block_5_to_8_worsening(self) -> None:
        base = (
            "if USE_FAST:\n    def compute(a, b, c, d, e, f, g, h):\n        return a + b\n"
            "else:\n    def compute(a, b, c, d, e):\n        return a - b\n"
        )
        inverted = (
            "if not USE_FAST:\n    def compute(a, b, c, d, e):\n        return a - b\n"
            "else:\n    def compute(a, b, c, d, e, f, g, h):\n        return a + b\n"
        )
        self.assertEqual(compare_ast_snapshots(base, inverted, "src/domain/cond.py"), [])

        worsened_both_8 = (
            "if USE_FAST:\n    def compute(a, b, c, d, e, f, g, h):\n        return a + b\n"
            "else:\n    def compute(a, b, c, d, e, f, g, h):\n        return a + b\n"
        )
        violations = compare_ast_snapshots(base, worsened_both_8, "src/domain/cond.py")
        self.assertEqual([v.category for v in violations], ["excessive_parameter_list"])

    def test_variant_debt_reduction_2_to_1_preserves_stable_baseline_item_id(self) -> None:
        two_variants = (
            "if MODE:\n    def build(a, b, c, d, e, f, g, h):\n        return a\n"
            "else:\n    def build(a, b, c, d, e, f, g):\n        return a\n"
        )
        one_variant_fixed = (
            "if MODE:\n    def build(a, b, c, d, e, f, g, h):\n        return a\n"
            "else:\n    def build(a, b, c, d, e):\n        return a\n"
        )
        self.assertEqual(compare_ast_snapshots(two_variants, one_variant_fixed, "src/domain/v.py"), [])

        entries_before = collect_refactoring_slop_entries(two_variants, "src/domain/v.py")
        entries_after = collect_refactoring_slop_entries(one_variant_fixed, "src/domain/v.py")
        self.assertEqual(len(entries_before), 1)
        self.assertEqual(len(entries_after), 1)
        self.assertEqual(
            (entries_before[0]["file"], entries_before[0]["symbol"], entries_before[0]["kind"]),
            ("src/domain/v.py", "build", "excessive_parameter_list"),
        )
        self.assertEqual(
            (entries_after[0]["file"], entries_after[0]["symbol"], entries_after[0]["kind"]),
            ("src/domain/v.py", "build", "excessive_parameter_list"),
        )
        self.assertEqual(entries_before[0]["variant_ceilings"], [8, 7])
        self.assertEqual(entries_after[0].get("variant_ceilings", [entries_after[0]["ceiling"]]), [8])

    def test_overload_insertion_reordering_and_annotation_edit_preserve_legacy_identity(self) -> None:
        base = (
            "from typing import overload\n"
            "@overload\ndef parse(a, b, c, d, e, f): ...\n"
            "@overload\ndef parse(a, b): ...\n"
            "def parse(a, b=None, c=None, d=None, e=None, f=None):\n    return a\n"
        )
        prepended_and_typed = (
            "from typing import overload\n"
            "@overload\ndef parse(a: str) -> str: ...\n"
            "@overload\ndef parse(a: int, b: int) -> int: ...\n"
            "@overload\ndef parse(a: int, b: int, c: int, d: int, e: int, f: int = 0) -> int: ...\n"
            "def parse(a, b=None, c=None, d=None, e=None, f=None):\n    return a\n"
        )
        self.assertEqual(compare_ast_snapshots(base, prepended_and_typed, "src/domain/ov.py"), [])

        added_bad_overload = prepended_and_typed.replace(
            "def parse(a: str) -> str: ...",
            "def parse(x: int, y: int, z: int, u: int, v: int, w: int) -> int: ...",
        )
        violations = compare_ast_snapshots(base, added_bad_overload, "src/domain/ov.py")
        self.assertEqual([v.category for v in violations], ["excessive_parameter_list"])

    def test_staticmethod_import_and_assignment_aliases_counted_without_receiver_subtraction(self) -> None:
        alias_import = "from builtins import staticmethod as sm\nclass Svc:\n    @sm\n    def run(a, b, c, d, e, f):\n        return a\n"
        alias_assign = "sm = staticmethod\nclass Svc:\n    @sm\n    def run(a, b, c, d, e, f):\n        return a\n"
        shadowed = "def staticmethod(fn):\n    return fn\nclass Svc:\n    @staticmethod\n    def run(self, a, b, c, d, e):\n        return a\n"
        self.assertEqual(
            [v.category for v in compare_ast_snapshots(None, alias_import, "src/domain/sm1.py")],
            ["excessive_parameter_list"],
        )
        self.assertEqual(
            [v.category for v in compare_ast_snapshots(None, alias_assign, "src/domain/sm2.py")],
            ["excessive_parameter_list"],
        )
        self.assertEqual(compare_ast_snapshots(None, shadowed, "src/domain/sm3.py"), [])

    def test_removing_wraps_evasion_allowed_and_historical_wraps_spoof_blocked(self) -> None:
        legacy_spoof = (
            "from typing import TYPE_CHECKING\n"
            "if TYPE_CHECKING:\n    def wraps(wrapped):\n        ...\n"
            "else:\n    from functools import wraps\n"
            "class PredictionOutcomeEvaluator:\n"
            "    def evaluate_input(self, dto):\n        return dto\n"
            "    @wraps(evaluate_input)\n"
            "    def evaluate(self, a, b, c, d, e, f, g, h):\n"
            "        return self.evaluate_input((a, b, c, d, e, f, g, h))\n"
        )
        cleaned = (
            "class PredictionOutcomeEvaluator:\n"
            "    def evaluate_input(self, dto):\n        return dto\n"
            "    def evaluate(self, a, b, c, d, e, f, g, h):\n"
            "        return self.evaluate_input((a, b, c, d, e, f, g, h))\n"
        )
        self.assertEqual(compare_ast_snapshots(legacy_spoof, cleaned, "src/domain/prediction_outcome.py"), [])

        new_spoof_violations = compare_ast_snapshots(None, legacy_spoof, "src/domain/new_spoof.py")
        cats = [v.category for v in new_spoof_violations]
        self.assertIn("excessive_parameter_list", cats)
        self.assertIn("nested_or_late_import", cats)

        legit = (
            "from functools import wraps\n"
            "def wraps_helper(text: str) -> str:\n    return text.strip()\n"
            "def trace_calls(fn):\n"
            "    @wraps(fn)\n    def _inner(*args, **kwargs):\n        return fn(*args, **kwargs)\n"
            "    return _inner\n"
        )
        self.assertEqual(compare_ast_snapshots(None, legit, "src/domain/legit.py"), [])

    def test_deleting_old_violation_never_compensates_new_violation_in_other_symbol(self) -> None:
        base = "def old_legacy(a, b, c, d, e, f):\n    return getattr(a, 'x', None)\ndef clean_fn(x):\n    return x\n"
        target = "def clean_fn(x):\n    return getattr(x, 'y', None)\ndef brand_new_bad(a, b, c, d, e, f):\n    return a\n"
        violations = compare_ast_snapshots(base, target, "src/domain/no_comp.py")
        cats = sorted(v.category for v in violations)
        self.assertEqual(cats, ["defensive_getattr_slop", "excessive_parameter_list"])

    def test_import_scopes_nested_type_checking_inheritance_orelse_and_top_level_fallbacks(self) -> None:
        nested_tc_and_fallback = (
            "from typing import TYPE_CHECKING\n"
            "try:\n    import tomllib\nexcept ImportError:\n    import json as tomllib\n"
            "if TYPE_CHECKING:\n"
            "    if True:\n        from src.domain.a import _PrivateTypeA\n"
            "    else:\n        from src.domain.b import _PrivateTypeB\n"
            "def run() -> int:\n    return 1\n"
        )
        self.assertEqual(compare_ast_snapshots(None, nested_tc_and_fallback, "src/domain/imp_ok.py"), [])
        snap = extract_ast_snapshot(nested_tc_and_fallback, "src/domain/imp_ok.py")
        self.assertEqual(snap.parse_error, None)

        outer_else_import = "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    import math\nelse:\n    import os\n"
        v_else = compare_ast_snapshots(None, outer_else_import, "src/domain/imp_else.py")
        self.assertEqual([v.category for v in v_else], ["nested_or_late_import"])

        shadowed_tc = "TYPE_CHECKING = True\nif TYPE_CHECKING:\n    from src.domain.secret import _hidden\n"
        v_shadow = compare_ast_snapshots(None, shadowed_tc, "src/domain/imp_shadow.py")
        self.assertGreaterEqual(len([v for v in v_shadow if v.category == "nested_or_late_import"]), 1)
        self.assertGreaterEqual(len(collect_full_scan_violations(shadowed_tc, "src/domain/imp_shadow.py")), 1)

    def test_ast_assign_unpacking_subscript_dunder_dict_and_module_if_try_blocks(self) -> None:
        tuple_spoof = (
            "from typing import TYPE_CHECKING\n"
            "TYPE_CHECKING, _ = True, False\n"
            "if TYPE_CHECKING:\n    from src.domain.secret import _hidden\n"
        )
        v_tuple = compare_ast_snapshots(None, tuple_spoof, "src/domain/tuple_spoof.py")
        self.assertIn("nested_or_late_import", [v.category for v in v_tuple])

        if_spoof = (
            "from typing import TYPE_CHECKING\n"
            "if True:\n    TYPE_CHECKING = True\n"
            "if TYPE_CHECKING:\n    from src.domain.secret import _hidden\n"
        )
        v_if_spoof = compare_ast_snapshots(None, if_spoof, "src/domain/if_spoof.py")
        self.assertIn("nested_or_late_import", [v.category for v in v_if_spoof])

        dunder_dict_writes = (
            "class Holder:\n    pass\n"
            "holder = Holder()\nholder.__dict__ = {}\n"
            "def mutate(item: Holder) -> None:\n    item.__dict__['k'] = 1\n"
        )
        v_dict = compare_ast_snapshots(None, dunder_dict_writes, "src/domain/dunder_dict.py")
        self.assertEqual([v.category for v in v_dict].count("defensive_getattr_slop"), 2)

        cond_module_slop = (
            "if True:\n    _default_x_factory = None\n"
            "if True:\n    class NewSvc:\n        pass\n"
            "if True:\n    OldSvc = NewSvc\n"
        )
        v_cond = compare_ast_snapshots(None, cond_module_slop, "src/domain/cond_mod.py")
        cats = [v.category for v in v_cond]
        self.assertIn("global_monkeypatch_state", cats)
        self.assertIn("symbol_alias_bloat", cats)

    def test_conditional_variants_survive_top_of_file_import_shift_and_branch_consolidation(self) -> None:
        base_8_5 = (
            "if COND:\n    def compute(a, b, c, d, e, f, g, h):\n        return a\n"
            "else:\n    def compute(a, b, c, d, e):\n        return a\n"
        )
        shifted_improved_7_5 = (
            "import os\nFLAG = bool(os.name)\n"
            "if FLAG:\n    MODE = 1\n"
            "if COND:\n    def compute(p1, p2, p3, p4, p5, p6, p7):\n        return p1\n"
            "else:\n    def compute(a, b, c, d, e):\n        return a\n"
        )
        self.assertEqual(compare_ast_snapshots(base_8_5, shifted_improved_7_5, "src/domain/cond_shift.py"), [])

        base_8_7 = (
            "if COND:\n    def merge_fn(a, b, c, d, e, f, g, h):\n        return a\n"
            "else:\n    def merge_fn(a, b, c, d, e, f, g):\n        return a\n"
        )
        consolidated_6 = "def merge_fn(p1, p2, p3, p4, p5, p6):\n    return p1\n"
        self.assertEqual(compare_ast_snapshots(base_8_7, consolidated_6, "src/domain/cond_merge.py"), [])

        shifted_worsened_8_6 = (
            "if OTHER:\n    X = 1\n"
            "if COND:\n    def compute(p1, p2, p3, p4, p5, p6, p7, p8):\n        return p1\n"
            "else:\n    def compute(p1, p2, p3, p4, p5, p6):\n        return p1\n"
        )
        v_worse = compare_ast_snapshots(base_8_5, shifted_worsened_8_6, "src/domain/cond_shift.py")
        self.assertEqual([v.category for v in v_worse], ["excessive_parameter_list"])

    def test_text_slop_delta_uses_per_kind_line_multiset_without_tail_slice_masking(self) -> None:
        taut_stmt = "assert " + "True"
        conv_comment = "# As an AI " + "language model, I updated this"
        base_dummy = "def test_legacy_stub():\n    pass\n"
        target_cross_rule = f"def test_real():\n    {taut_stmt}\n"
        delta_cross = _new_or_worsened_text_slop(base_dummy, target_cross_rule, "tests/test_x.py", ())
        self.assertEqual([(v.category, v.line) for v in delta_cross], [("tautological_assertion", 2)])

        filler = "".join(f"x_{i} = {i}\n" for i in range(20))
        base_tail = f"{filler}def test_old():\n    {taut_stmt}\n"
        target_top_insert = f"{conv_comment}\n{base_tail}"
        delta_top = _new_or_worsened_text_slop(base_tail, target_top_insert, "tests/test_y.py", ())
        self.assertEqual([(v.category, v.line) for v in delta_top], [("conversational_marker", 1)])

    def test_new_function_with_unjustified_varargs_blocked_without_none_dereference(self) -> None:
        v = compare_ast_snapshots(None, "def f(*args, **kwargs):\n    return 1\n", "src/domain/v.py")
        self.assertEqual([x.category for x in v], ["excessive_parameter_list"])

    def test_a4_domain_impurity_blocks_io_clock_env_and_invalid_or_unverified_prng_seeds(self) -> None:
        bad_src = (
            "from datetime import datetime\nfrom os import environ\nimport os\n"
            "from pathlib import Path\nfrom random import Random, SystemRandom\n"
            "import secrets\nimport uuid\n"
            "def f(seed_param):\n"
            "    a = datetime.now()\n    b = os.environ['K']\n    c = environ.get('K')\n"
            "    d = open('x.txt')\n    p = Path('x.txt')\n    e = p.read_text()\n"
            "    r0 = Random()\n    r1 = Random(None)\n    r2 = Random((1, 2))\n"
            "    r3 = Random(seed_param)\n    r4 = SystemRandom(42)\n"
            "    s = secrets.token_hex(8)\n    u = uuid.uuid4()\n"
            "    return a, b, c, d, e, r0, r1, r2, r3, r4, s, u\n"
        )
        full_imp = [x for x in collect_full_scan_violations(bad_src, "src/domain/impure.py") if x.category == "domain_impurity"]
        self.assertEqual(len(full_imp), 12)
        v = [x for x in compare_ast_snapshots(None, bad_src, "src/domain/impure.py") if x.category == "domain_impurity"]
        self.assertEqual(len(v), 1)
        self.assertIn("(0 -> 12)", v[0].message)
        self.assertEqual(
            [x for x in compare_ast_snapshots(None, bad_src, "src/infrastructure/ok.py") if x.category == "domain_impurity"],
            [],
        )

    def test_a4_domain_purity_counterexamples_class_scope_bypass_try_else_and_local_annassign(self) -> None:
        pure_src = (
            "from random import Random\nimport secrets\nimport uuid\n"
            "def pure_fn(a: str, b: str) -> bool:\n"
            "    r1 = Random(42)\n    r2 = Random(-42)\n"
            "    r3 = Random(x='seed_const')\n    r4 = Random(bytearray(b'seed'))\n"
            "    u = uuid.uuid5(uuid.NAMESPACE_DNS, 'example.com')\n"
            "    return secrets.compare_digest(a, b) and bool(r1 and r2 and r3 and r4 and u)\n"
            "def local_open_shadow(open):\n    return open('ok')\n"
            "def local_annassign_shadow():\n    open: object\n    return open('ok')\n"
        )
        self.assertEqual(
            [x for x in compare_ast_snapshots(None, pure_src, "src/domain/pure.py") if x.category == "domain_impurity"],
            [],
        )

        class_bypass = "import time\nclass S:\n    time = object()\n    def f(self):\n        return time.time()\n"
        self.assertEqual(
            [x.category for x in compare_ast_snapshots(None, class_bypass, "src/domain/cls_scope.py")],
            ["domain_impurity"],
        )

        try_else_src = (
            "def f():\n    try:\n        from datetime import datetime as C\n"
            "    except ImportError:\n        return None\n"
            "    else:\n        return C.now()\n"
        )
        v_try_else = [x.category for x in compare_ast_snapshots(None, try_else_src, "src/domain/try_else.py")]
        self.assertIn("domain_impurity", v_try_else)

        annassign_keeps_binding = "def f():\n    import time\n    time: object\n    return time.time()\n"
        self.assertIn(
            "domain_impurity",
            [x.category for x in compare_ast_snapshots(None, annassign_keeps_binding, "src/domain/ann.py")],
        )

        comp_and_rhs_order = (
            "from datetime import datetime\n"
            "def f(xs):\n"
            "    vals = [datetime for datetime in xs]\n"
            "    t1 = datetime.now()\n"
            "    datetime = datetime.now()\n"
            "    return vals, t1, datetime\n"
        )
        full_comp = [x for x in collect_full_scan_violations(comp_and_rhs_order, "src/domain/comp.py") if x.category == "domain_impurity"]
        self.assertEqual(len(full_comp), 2)
        imp_comp = [x for x in compare_ast_snapshots(None, comp_and_rhs_order, "src/domain/comp.py") if x.category == "domain_impurity"]
        self.assertEqual(len(imp_comp), 1)
        self.assertIn("(0 -> 2)", imp_comp[0].message)

    def test_c1_nesting_depth_threshold_4_elif_ladder_trystar_match_and_inner_def_isolation(self) -> None:
        ok_depth_4 = (
            "def f(x):\n"
            "    if x == 1:\n        for i in range(3):\n            while i > 0:\n                with ctx():\n                    return 1\n"
            "    elif x == 2:\n        return 2\n"
            "    elif x == 3:\n"
            "        def inner():\n            if a:\n                if b:\n                    if c:\n                        if d:\n                            return 0\n"
            "        return 3\n"
            "    return 0\n"
        )
        self.assertEqual(compare_ast_snapshots(None, ok_depth_4, "src/domain/d4.py"), [])

        bad_depth_5 = (
            "def f(x):\n"
            "    try:\n        match x:\n            case 1:\n                if x > 0:\n"
            "                    for i in range(2):\n                        while i:\n                            return 1\n"
            "    except* ValueError:\n        return 0\n"
        )
        v5 = compare_ast_snapshots(None, bad_depth_5, "src/domain/d5.py")
        self.assertEqual([x.category for x in v5], ["excessive_nesting_depth"])
        self.assertEqual(compare_ast_snapshots(bad_depth_5, bad_depth_5, "src/domain/d5.py"), [])

    def test_c5_query_mutation_blocks_self_param_copy_method_cached_suffix_intermediate_try_alias_and_finally(self) -> None:
        cases = [
            "class S:\n    def get_user_cached(self):\n        self.counter += 1\n        return 1\n",
            "def get_sorted(items):\n    items = items.copy()\n    items.sort()\n    return items\n",
            "import copy\ndef get_sorted(items):\n    items = copy.deepcopy(items)\n    items.sort()\n    return items\n",
            "def get_sorted(items):\n    items = items or []\n    items.sort()\n    return items\n",
            "def get_sorted(items, cond):\n    if cond:\n        items = list(items)\n    items.sort()\n    return items\n",
            (
                "def get_values(items, other, fail):\n    items = list(items)\n"
                "    try:\n        items = other\n        if fail:\n            raise ValueError\n        items = []\n"
                "    except ValueError:\n        items.append(1)\n    return items\n"
            ),
            (
                "def get_tuple_alias(items, other, fail):\n    items = list(items)\n"
                "    try:\n        tag, items = 'k', other\n        if fail:\n            raise ValueError\n        items = []\n"
                "    except ValueError:\n        items.append(tag)\n    return items\n"
            ),
            (
                "def get_trystar_chain(items, other):\n    items = list(items)\n"
                "    try:\n        raise ValueError\n    except* ValueError:\n        items = other\n"
                "    except* TypeError:\n        items.append(1)\n    return items\n"
            ),
            "def get_merged(p, q):\n    p.update(q.copy())\n    return p\n",
            "def get_orders_with_items(orders):\n    orders.append(1)\n    return orders\n",
            "def check_stock_and_price(stock):\n    stock['a'] = 1\n    return True\n",
            "class S:\n    def get_cache(self):\n        self.state = 1\n        return self.state\n",
        ]
        for idx, src in enumerate(cases):
            v = [x for x in compare_ast_snapshots(None, src, f"src/domain/q_{idx}.py") if x.category == "query_mutation_side_effect"]
            self.assertEqual(len(v), 1, f"case {idx} failed: {src}")

        finally_src = (
            "class S:\n    def get_val(self, cond):\n"
            "        try:\n            if cond:\n                return 1\n"
            "        except RuntimeError:\n            return 2\n"
            "        finally:\n            self.x = 3\n        return 0\n"
        )
        v_fin = [x for x in compare_ast_snapshots(None, finally_src, "src/domain/q_fin.py") if x.category == "query_mutation_side_effect"]
        self.assertEqual(len(v_fin), 1)

    def test_c5_query_mutation_allows_builtin_constructors_try_else_try_finally_return_isolation_and_cache_writes(self) -> None:
        ok_src = (
            "class Repo:\n"
            "    def get_sorted(self, items, **kwargs):\n"
            "        kwargs.pop('flag', None)\n        items = list(items)\n        items.sort()\n        return items\n"
            "    def get_try_else(self, items):\n"
            "        try:\n            items = list(items)\n        except TypeError:\n            return []\n"
            "        else:\n            items.sort()\n            return items\n"
            "    def get_try_finally(self, items):\n"
            "        try:\n            items = list(items)\n        except TypeError:\n            return []\n"
            "        finally:\n            pass\n        items.sort()\n        return items\n"
            "    def get_cached_item(self, k, v):\n"
            "        self._cache = {}\n        self._cache[k] = v\n"
            "        self._cache_map.setdefault(k, v)\n        return self._cache.get(k)\n"
            "    def get_or_create_user(self, k, v):\n        self.users[k] = v\n        return v\n"
        )
        self.assertEqual(
            [x for x in compare_ast_snapshots(None, ok_src, "src/domain/q_ok.py") if x.category == "query_mutation_side_effect"],
            [],
        )

    def test_variant_pairing_prioritizes_same_context_blocking_4_5_to_5_4_branch_swap(self) -> None:
        base_4_5 = (
            "if FEATURE:\n    def f(a, b, c, d):\n        return a\n"
            "else:\n    def f(a, b, c, d, e, f6):\n        return a\n"
        )
        swapped_6_4 = (
            "if FEATURE:\n    def f(a, b, c, d, e, f6):\n        return a\n"
            "else:\n    def f(a, b, c, d):\n        return a\n"
        )
        v = compare_ast_snapshots(base_4_5, swapped_6_4, "src/domain/swap.py")
        self.assertEqual([x.category for x in v], ["excessive_parameter_list"])

    def test_sloc_counter_excludes_python_docstrings_and_comments(self) -> None:
        py_src = (
            '"""Module docstring\nspanning lines.\n"""\n'
            "# Top comment\n\n"
            "class Calc:\n"
            '    """Class docstring."""\n'
            "    def run(self, x: int) -> int:\n"
            '        """Function docstring\n        with details.\n        """\n'
            "        # Inline comment\n"
            "        return x + 1\n"
            "    async def arun(self, x: int) -> int:\n"
            '        """Async docstring."""\n'
            "        return x * 2\n"
        )
        self.assertEqual(count_effective_sloc("src/domain/calc.py", py_src), 5)
        ts_src = (
            "/**\n * JSDoc block\n */\n"
            "// Line comment\n"
            "export const a = 1; /* block\ncomment */ export const b = 2;\n"
        )
        self.assertEqual(count_effective_sloc("src/ui/calc.ts", ts_src), 2)
        ts_mime = 'const m = "image/*";\n' + ("const x = 1;\n" * 700) + "/* doc */\n"
        self.assertEqual(count_effective_sloc("src/ui/mime.ts", ts_mime), 701)
        jsx_line_comment = "// /* not a block open\nexport const v = 1;\n/* closed */\n"
        self.assertEqual(count_effective_sloc("src/ui/View.jsx", jsx_line_comment), 1)

        base_670 = ("x = 1\n" * 670).encode("utf-8")
        target_with_docs = ('"""Doc\n' + ("detail\n" * 50) + '"""\n# note\n' + ("x = 1\n" * 670)).encode("utf-8")
        v_ok, ceil_ok = evaluate_loc_transition("src/domain/doc.py", "M", base_670, target_with_docs)
        self.assertEqual(v_ok, [])
        self.assertEqual(ceil_ok, COGNITIVE_MODULE_CEILING)
        v_ts_ok, ceil_ts_ok = evaluate_loc_transition("src/ui/doc.ts", "M", b"const a = 1;\n" * 10, b"const a = 1;\n" * 20)
        self.assertEqual(v_ts_ok, [])
        self.assertEqual(ceil_ts_ok, 680)

        v_jsx, _ = evaluate_loc_transition(
            "src/ui/View.jsx", "M", ("const a = 1;\n" * 670).encode("utf-8"), ts_mime.encode("utf-8")
        )
        self.assertEqual([x.category for x in v_jsx], ["modified_file_loc_buffer"])

        over_raw_950 = ("# comment\n" * 300 + ("x = 1\n" * 660)).encode("utf-8")
        v_raw, _ = evaluate_loc_transition("src/domain/doc.py", "M", base_670, over_raw_950)
        self.assertEqual([x.category for x in v_raw], ["modified_file_loc_buffer"])

        v_py_sloc_backstop, _ = evaluate_loc_transition("src/domain/doc.py", "M", base_670, ("x = 1\n" * 805).encode("utf-8"))
        self.assertEqual([x.category for x in v_py_sloc_backstop], ["modified_file_loc_buffer"])
        v_py_flat_growth, _ = evaluate_loc_transition("src/domain/doc.py", "M", base_670, ("x = 1\n" * 790).encode("utf-8"))
        self.assertEqual(v_py_flat_growth, [])

    def test_slop_scanner_rejects_ts_nocheck_and_empty_js_it_blocks(self) -> None:
        ts_nocheck_src = "// @ts-nocheck\nexport const val = 42;\n"
        v_text = scan_text_for_slop(ts_nocheck_src, "src/app.ts")
        self.assertEqual([x.category for x in v_text], ["unjustified_lint_escape"])
        self.assertIn("@ts-nocheck", v_text[0].message)

        diff_bad = (
            "+++ b/src/app.ts\n"
            "+// @ts-nocheck -- file wide suppression\n"
            "+// @ts-ignore word -- ok\n"
            "+// @ts-expect-error -- short\n"
        )
        self.assertEqual(len(scan_diff_for_shortcut_escapes(diff_bad)), 3)
        diff_good = (
            "+++ b/src/app.ts\n"
            "+// @ts-expect-error TS2345 -- legacy SDK type mismatch\n"
            "+// @ts-ignore -- valid reason over eight chars\n"
        )
        self.assertEqual(scan_diff_for_shortcut_escapes(diff_good), [])

        js_tests = (
            "it('empty arrow', () => {});\n"
            "test(\"async comment only\", async () => { // todo\n});\n"
            "it(`block comment`, (ctx) => { /* noop */ });\n"
            "it('fn expr', function() {});\n"
            "it('bare arg', x => {});\n"
            "it.each([1, 2])('each %s', (x) => {});\n"
            "it('real test', () => { expect(1).toBe(1); });\n"
        )
        v_js = [x for x in scan_text_for_slop(js_tests, "tests/widget.test.jsx") if x.category == "empty_dummy_test"]
        self.assertEqual(len(v_js), 6)

    def test_assertion_ratchet_allows_dto_equality_consolidation_when_t1_zero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            for cmd in (["init", "-q"], ["config", "core.hooksPath", "/dev/null"], ["config", "user.email", "t@e.com"], ["config", "user.name", "T"]):
                subprocess.run(["git", *cmd], cwd=tmp, check=True)
            py_f, ts_f = Path(tmp) / "test_dto.py", Path(tmp) / "dto.test.ts"
            base_py = (
                "import pytest\n"
                "def test_keep():\n    assert k == OrderDto(a=1)\n"
                "def test_o():\n    assert r.a == 1\n    assert r.b == 2\n    assert r.c == 3\n"
                "@pytest.mark.parametrize('v', [1, 2, 3])\n"
                "def test_p(v):\n    assert p.v == v\n    assert p.ok is True\n"
            )
            base_ts = (
                "it('keep', () => { expect(k).toEqual({ a: 1 }); });\n"
                "it('o', () => { expect(r.a).toBe(1); expect(r.b).toBe(2); });\n"
                "it.each([1, 2, 3])('p', (v) => { expect(p.v).toBe(v); expect(p.ok).toBe(true); });\n"
            )
            py_f.write_text(base_py, encoding="utf-8")
            ts_f.write_text(base_ts, encoding="utf-8")
            subprocess.run(["git", "add", "test_dto.py", "dto.test.ts"], cwd=tmp, check=True)
            subprocess.run(["git", "commit", "-q", "-m", "init"], cwd=tmp, check=True)

            ok_py = (
                "import pytest\n"
                "def test_keep():\n    assert k == OrderDto(a=1)\n"
                "def test_o():\n    assert r == OrderDto(a=1, b=2, c=3)\n"
                "@pytest.mark.parametrize('v', [1, 2, 3])\n"
                "def test_p(v):\n    assert p == ItemDto(v=v, ok=True)\n"
            )
            ok_ts = (
                "it('keep', () => { expect(k).toEqual({ a: 1 }); });\n"
                "it('o', () => { expect(r).toEqual({ a: 1, b: 2 }); });\n"
                "it.each([1, 2, 3])('p', (v) => { expect(p).toEqual({ v, ok: true }); });\n"
            )
            py_f.write_text(ok_py, encoding="utf-8")
            ts_f.write_text(ok_ts, encoding="utf-8")
            subprocess.run(["git", "add", "test_dto.py", "dto.test.ts"], cwd=tmp, check=True)
            self.assertEqual(check_staged_test_tampering(cwd=tmp), [])

            for bad_py in (
                ok_py.replace("assert r == OrderDto(a=1, b=2, c=3)", "assert r.a == 1"),
                ok_py.replace("assert r == OrderDto(a=1, b=2, c=3)", "run_code()"),
                ok_py.replace("[1, 2, 3]", "[1]"),
                ok_py.replace("assert r == OrderDto(a=1, b=2, c=3)", "assert [] == []"),
                ok_py.replace("assert r == OrderDto(a=1, b=2, c=3)", "assert add(1, 2) == 3"),
            ):
                py_f.write_text(bad_py, encoding="utf-8")
                ts_f.write_text(ok_ts, encoding="utf-8")
                subprocess.run(["git", "add", "test_dto.py", "dto.test.ts"], cwd=tmp, check=True)
                self.assertEqual([v.category for v in check_staged_test_tampering(cwd=tmp)], ["test_assertion_reduction"])

            py_f.write_text(ok_py, encoding="utf-8")
            for bad_ts in (
                ok_ts.replace("expect(r).toEqual({ a: 1, b: 2 })", "expect(r.a).toBe(1)"),
                ok_ts.replace("expect(r).toEqual({ a: 1, b: 2 })", "runCode()"),
                ok_ts.replace("[1, 2, 3]", "[1]"),
                ok_ts.replace("expect(r).toEqual({ a: 1, b: 2 })", "expect(r).toEqual(-1)"),
                ok_ts.replace("expect(r).toEqual({ a: 1, b: 2 })", "expect(r).toEqual({})"),
            ):
                ts_f.write_text(bad_ts, encoding="utf-8")
                subprocess.run(["git", "add", "test_dto.py", "dto.test.ts"], cwd=tmp, check=True)
                self.assertEqual([v.category for v in check_staged_test_tampering(cwd=tmp)], ["test_assertion_reduction"])


if __name__ == "__main__":
    unittest.main()
