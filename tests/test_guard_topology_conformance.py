"""Guard Core 2.3.3 conformance: static import graph and Tarjan SCC cycle guard (Vector A2)."""

from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from guard_core.ast_topology_guard import (
    build_snapshot_import_graph,
    compare_import_cycles,
    extract_module_import_facts,
    find_import_cycles,
    tarjan_scc,
)
from guard_core.git_guard_io import is_protected_governance_path


class TestGuardTopologyConformance(unittest.TestCase):
    def test_legacy_topology_suite_copy_stays_a_protected_governance_path(self) -> None:
        self.assertTrue(is_protected_governance_path("tests/ci/test_guard_topology_conformance.py"))

    def test_a2_tarjan_blocks_self_loop_new_cycle_expanded_scc_and_import_error_handler_cycle(self) -> None:
        base_files = {
            "src/pkg/__init__.py": "from . import a\n",
            "src/pkg/a.py": "from . import b\nfrom ....outside import ignored\n",
            "src/pkg/b.py": "from . import a\n",
            "src/pkg/c.py": "x = 1\n",
        }
        base_g = build_snapshot_import_graph(base_files)
        self.assertNotIn("src/pkg/__init__.py", base_g.get("src/pkg/__init__.py", set()))
        self.assertEqual(compare_import_cycles(base_g, base_g), [])

        self_loop_files = dict(base_files)
        self_loop_files["src/pkg/c.py"] = "from src.pkg import c\n"
        self_loop_files["src/pkg/a.py"] = "from . import a, b\n"
        loop_g = build_snapshot_import_graph(self_loop_files)
        v_loop = compare_import_cycles(base_g, loop_g)
        self.assertEqual({v.file for v in v_loop}, {"src/pkg/a.py", "src/pkg/c.py"})
        self.assertTrue(all(v.category == "import_cycle" for v in v_loop))

        expanded_files = dict(base_files)
        expanded_files["src/pkg/b.py"] = "from . import a, c\n"
        expanded_files["src/pkg/c.py"] = "try:\n    import missing_opt\nexcept ImportError:\n    from . import a\n"
        exp_g = build_snapshot_import_graph(expanded_files)
        v_exp = compare_import_cycles(base_g, exp_g)
        self.assertEqual({v.file for v in v_exp}, {"src/pkg/a.py", "src/pkg/b.py", "src/pkg/c.py"})

    def test_a2_package_attribute_vs_annotation_only_submodule_collision_and_separate_indices(self) -> None:
        attr_files = {
            "src/pkg/__init__.py": "name = 42\n",
            "src/pkg/name.py": "from src import consumer\n",
            "src/consumer.py": "from src.pkg import name\n",
        }
        g_attr = build_snapshot_import_graph(attr_files)
        self.assertEqual(compare_import_cycles({}, g_attr), [])

        ann_only_files = {
            "src/pkg/__init__.py": "name: object\n",
            "src/pkg/name.py": "from src import consumer\n",
            "src/consumer.py": "from src.pkg import name\n",
        }
        g_ann = build_snapshot_import_graph(ann_only_files)
        v_ann = compare_import_cycles({}, g_ann)
        self.assertEqual({v.file for v in v_ann}, {"src/pkg/name.py", "src/consumer.py"})

        dyn_files = {
            "src/pkg/__init__.py": "def __getattr__(k):\n    return k\n",
            "src/pkg/name.py": "from src import consumer\n",
            "src/consumer.py": "from src.pkg import name\n",
        }
        g_dyn = build_snapshot_import_graph(dyn_files)
        self.assertEqual(compare_import_cycles({}, g_dyn), [])

    def test_a2_rename_inside_existing_scc_and_type_checking_context_switch(self) -> None:
        base_scc = {"src/pkg/a.py": "from . import b\n", "src/pkg/b.py": "from . import a\n"}
        target_renamed = {"src/pkg/c.py": "from . import b\n", "src/pkg/b.py": "from . import c\n"}
        g_base = build_snapshot_import_graph(base_scc)
        g_target = build_snapshot_import_graph(target_renamed)
        self.assertEqual(
            compare_import_cycles(g_base, g_target, rename_map={"src/pkg/a.py": "src/pkg/c.py"}),
            [],
        )

        tc_base = {
            "src/pkg/x.py": "import typing as t\nif t.TYPE_CHECKING:\n    from . import y\n",
            "src/pkg/y.py": "from . import x\n",
        }
        tc_target = {
            "src/pkg/x.py": "import typing as t\nif ENABLE_OTHER:\n    from . import y\n",
            "src/pkg/y.py": "from . import x\n",
        }
        self.assertNotEqual(
            extract_module_import_facts(tc_base["src/pkg/x.py"], "src/pkg/x.py"),
            extract_module_import_facts(tc_target["src/pkg/x.py"], "src/pkg/x.py"),
        )
        v_tc = compare_import_cycles(build_snapshot_import_graph(tc_base), build_snapshot_import_graph(tc_target))
        self.assertEqual({v.file for v in v_tc}, {"src/pkg/x.py", "src/pkg/y.py"})
        self.assertEqual(len(tarjan_scc(build_snapshot_import_graph(tc_target))), 1)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for rel, txt in tc_target.items():
                p = root / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(txt, encoding="utf-8")
            self.assertEqual(find_import_cycles(root), [["src/pkg/x.py", "src/pkg/y.py"]])


if __name__ == "__main__":
    unittest.main()
