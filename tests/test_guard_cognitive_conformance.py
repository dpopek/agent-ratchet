"""Guard Core 2.3.0 conformance: cognitive complexity file budget for Python and C5 call-result aliasing."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest

from guard_core.cognitive_complexity import (
    COGNITIVE_FUNCTION_CEILING,
    COGNITIVE_MODULE_CEILING,
    function_cognitive_scores,
)
from guard_core.git_guard_io import RUNTIME_SCANNER_FILES, SYNCHRONIZED_GUARD_FILES, evaluate_loc_transition
from guard_core.refactoring_guard import collect_full_scan_violations


class TestGuardCognitiveConformance(unittest.TestCase):
    def test_cognitive_module_is_a_synchronized_runtime_scanner(self) -> None:
        self.assertIn("scripts/audit/cognitive_complexity.py", RUNTIME_SCANNER_FILES)
        self.assertIn("tests/ci/test_guard_cognitive_conformance.py", SYNCHRONIZED_GUARD_FILES)

    def test_cognitive_complexity_scores_follow_nesting_increments(self) -> None:
        src = (
            "def f(a, b):\n"
            "    if a and b:\n"
            "        for x in a:\n"
            "            if x:\n"
            "                pass\n"
            "    elif a:\n"
            "        pass\n"
            "    else:\n"
            "        pass\n"
            "    return 1 if a else 2\n"
            "class K:\n"
            "    def m(self, xs):\n"
            "        try:\n"
            "            return [x for x in xs if x]\n"
            "        except ValueError:\n"
            "            return []\n"
            "    def flat(self):\n"
            "        return 1\n"
        )
        scores = {q: s.score for q, s in function_cognitive_scores(src).items()}
        self.assertEqual(scores, {"f": 10, "K.m": 3, "K.flat": 0})
        nested = "def outer(a):\n    def inner(b):\n        if b:\n            return b\n    return inner\n"
        self.assertEqual(function_cognitive_scores(nested)["outer"].score, 2)

    @staticmethod
    def _complex_function(name: str, branches: int) -> str:
        body = "".join(f"    if x == {i}:\n        if y:\n            return {i}\n" for i in range(branches))
        return f"def {name}(x, y):\n{body}    return -1\n"

    def test_cognitive_function_budget_blocks_new_or_grown_functions_only(self) -> None:
        legacy = self._complex_function("legacy", 6)
        legacy_score = function_cognitive_scores(legacy)["legacy"].score
        self.assertGreater(legacy_score, COGNITIVE_FUNCTION_CEILING)
        base = legacy.encode("utf-8")

        v_new, _ = evaluate_loc_transition("src/domain/budget.py", "A", None, base)
        self.assertEqual([x.category for x in v_new], ["cognitive_complexity_budget"])
        self.assertIn("legacy", v_new[0].message)

        edited_same = legacy.replace("return -1", "return -2").encode("utf-8")
        self.assertEqual(evaluate_loc_transition("src/domain/budget.py", "M", base, edited_same)[0], [])

        grown = self._complex_function("legacy", 7).encode("utf-8")
        v_grown, _ = evaluate_loc_transition("src/domain/budget.py", "M", base, grown)
        self.assertEqual([x.category for x in v_grown], ["cognitive_complexity_budget"])

        v_tests, _ = evaluate_loc_transition("tests/test_budget.py", "A", None, base)
        self.assertEqual(v_tests, [])

    def test_cognitive_module_budget_ratchets_from_base(self) -> None:
        def module(n_funcs: int) -> bytes:
            return "".join(self._complex_function(f"f{i}", 2) for i in range(n_funcs)).encode("utf-8")

        per_func = function_cognitive_scores(module(1).decode())["f0"].score
        self.assertLessEqual(per_func, COGNITIVE_FUNCTION_CEILING)
        at_limit = COGNITIVE_MODULE_CEILING // per_func
        v_ok, ceil_ok = evaluate_loc_transition("src/domain/mod.py", "A", None, module(at_limit))
        self.assertEqual(v_ok, [])
        self.assertEqual(ceil_ok, COGNITIVE_MODULE_CEILING)

        v_over, _ = evaluate_loc_transition("src/domain/mod.py", "M", module(at_limit), module(at_limit + 1))
        self.assertEqual([x.category for x in v_over], ["cognitive_complexity_budget"])

        legacy = module(at_limit + 3)
        self.assertEqual(evaluate_loc_transition("src/domain/mod.py", "M", legacy, module(at_limit + 2))[0], [])
        v_legacy_grew, ceil_legacy = evaluate_loc_transition("src/domain/mod.py", "M", legacy, module(at_limit + 4))
        self.assertEqual([x.category for x in v_legacy_grew], ["cognitive_complexity_budget"])
        self.assertEqual(ceil_legacy, (at_limit + 3) * per_func)

        v_override, _ = evaluate_loc_transition("src/domain/mod.py", "M", legacy, module(at_limit + 3), ceiling_override=COGNITIVE_MODULE_CEILING)
        self.assertEqual([x.category for x in v_override], ["cognitive_complexity_budget"])

        broken = b"def f(:\n    pass\n"
        self.assertEqual(evaluate_loc_transition("src/domain/mod.py", "M", module(1), broken)[0], [])

    def test_c5_ignores_call_results_and_load_or_build_queries(self) -> None:
        fresh_from_call = (
            "class Svc:\n"
            "    def get_metrics(self, ticker):\n"
            "        metrics, as_of = self._load(ticker)\n"
            "        metrics['x'] = 1\n"
            "        return metrics, as_of\n"
        )
        self.assertNotIn("query_mutation_side_effect", [v.category for v in collect_full_scan_violations(fresh_from_call, "src/application/svc.py")])
        aliased = (
            "class Svc:\n"
            "    def get_metrics(self, pair):\n"
            "        metrics, as_of = pair\n"
            "        metrics['x'] = 1\n"
            "        return metrics, as_of\n"
        )
        self.assertIn("query_mutation_side_effect", [v.category for v in collect_full_scan_violations(aliased, "src/application/svc.py")])
        cache = (
            "class Cache:\n"
            "    def get_or_load(self, key, build):\n"
            "        self._entries[key] = build()\n"
            "        return self._entries[key]\n"
        )
        self.assertNotIn("query_mutation_side_effect", [v.category for v in collect_full_scan_violations(cache, "src/application/cache.py")])

    @staticmethod
    def _c5_lines(body: str, head: str = "class F:\n    def get_svc(self, cfg):\n") -> list[int]:
        src = head + "".join(f"        {line}\n" for line in body.splitlines()) + "        return 1\n"
        return [v.line for v in collect_full_scan_violations(src, "src/domain/f.py") if v.category == "query_mutation_side_effect"]

    def test_c5_blocks_nested_attribute_chains_rooted_at_protected_names(self) -> None:
        blocked = [
            "self._svc._reader = 1",
            "if self._svc._reader is None:\n    if cfg:\n        self._svc._reader = cfg",
            "self._a.n += 1",
            "self._a.n: int = 1",
            "self._a.b['k'] = 1",
            "self._a.b.items.append(1)",
            "cfg.a.b = 1",
            "self._a[0].b = 1",
        ]
        for body in blocked:
            with self.subTest(body=body):
                self.assertEqual(len(self._c5_lines(body)), 1)

    def test_c5_allows_nested_cache_chains_and_local_objects(self) -> None:
        allowed = [
            "self._cache_a.n = 1",
            "self._lazy_svc.reader = 1",
            "self._cache_map.d.setdefault('k', 1)",
            "x = Foo()\nx.a.b = 1",
            "self.make().a = 1",
        ]
        for body in allowed:
            with self.subTest(body=body):
                self.assertEqual(self._c5_lines(body), [])
        self.assertEqual(len(self._c5_lines("self._cache_a.n += 1")), 1)


if __name__ == "__main__":
    unittest.main()
