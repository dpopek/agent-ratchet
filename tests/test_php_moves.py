"""Cross-file suppression moves (4.3.1 F3) and the F2 docblock boundary: the pairing must prove the code moved."""

from __future__ import annotations

from php_support import require_php

IGN = "        // phpcs:ignore Generic.Sample.Rule\n"
STAN = "        // @phpstan-ignore-next-line\n"


def _cls(name: str, body: str) -> str:
    return f"<?php\nnamespace Acme\\Shop\\Model;\n\nclass {name}\n{{\n{body}\n}}\n"


def _meth(name: str, inner: str, sig: str = "array $data") -> str:
    return f"    public function {name}({sig}): string\n    {{\n{inner}\n    }}"


def _run(entries, exceptions=(), with_moves: bool = True):
    """(path, BASE src | None, TARGET src | None) per entry, through the scan's per-entry + `moves.violations` path."""
    require_php()
    from agent_ratchet.php import compare as C

    moves = C.PointMoves() if with_moves else None
    out = []
    for path, base, target in entries:
        b = base.encode() if base is not None else None
        t = target.encode() if target is not None else None
        if b is not None and b == t:
            continue
        ban, tan = C.analyze_pair(b, t, path if b is not None else None, path)
        out += [v for v in C.compare_php_analyses(ban, tan, path, list(exceptions), moves=moves) if v.category != C.REMOVED]
    if moves is not None:
        out += moves.violations(list(exceptions))
    return sorted((v.file, v.category, v.message) for v in out)


def _added(found) -> list[str]:
    return [f for f, cat, _ in found if cat == "php_suppression_added"]


def test_deleted_file_does_not_fund_unrelated_new_method():  # P1
    found = _run([
        ("app/Legacy.php", _cls("Legacy", _meth("old", "        $result = 'a';\n" + IGN + "        return $result;")), None),
        ("app/Fresh.php", None, _cls("Fresh", _meth("brandNew", "        $result = evil($data);\n" + IGN + "        return $result;"))),
    ])
    assert _added(found) == ["app/Fresh.php"]


def test_deleted_method_does_not_fund_new_method_in_other_existing_file():  # P10
    keep = _meth("keep", "        return 'k';")
    b = _meth("b", "        return 'b';")
    found = _run([
        ("app/A.php", _cls("A", keep + "\n\n" + _meth("old", IGN + "        return $result;")), _cls("A", keep)),
        ("app/B.php", _cls("B", b), _cls("B", b + "\n\n" + _meth("unrelated", "        $result = evil();\n" + IGN + "        return $result;"))),
    ])
    assert _added(found) == ["app/B.php"]


def test_bare_phpstan_ignore_does_not_migrate_to_other_method():  # P3
    found = _run([
        ("app/Legacy.php", _cls("Legacy", _meth("old", STAN + "        return $this->value;")), None),
        ("app/Fresh.php", None, _cls("Fresh", _meth("other", STAN + "        return $this->value;", sig="int $x"))),
    ])
    assert _added(found) == ["app/Fresh.php"]


def test_empty_line_anchor_never_pairs_across_files():  # P4
    doc = "    // phpcs:ignore Generic.Sample.Rule\n    /** Doc. */\n"
    found = _run([
        ("app/Legacy.php", _cls("Legacy", _meth("run", IGN + "\n        return 'x';")), None),
        ("app/Fresh.php", None, _cls("Fresh", doc + _meth("run", "        return 'y';", sig="int $a, int $b"))),
    ])
    assert _added(found) == ["app/Fresh.php"]


def test_one_gone_funds_at_most_one_new():  # P2
    moved = _meth("old", IGN + "        return $result;")
    found = _run([
        ("app/Legacy.php", _cls("Legacy", moved), None),
        ("app/One.php", None, _cls("One", moved)),
        ("app/Two.php", None, _cls("Two", moved)),
    ])
    assert len(_added(found)) == 1


def test_same_named_method_moved_whole_passes():  # the 22c/22f shape, kept green
    moved = _meth("token", IGN + "        return md5(serialize($data));")
    found = _run([("app/Legacy.php", _cls("Legacy", moved), None), ("app/Fresh.php", None, _cls("Fresh", moved))])
    assert found == []


def test_move_with_ignored_row_edited_is_flagged():  # P7
    found = _run([
        ("app/Legacy.php", _cls("Legacy", _meth("old", IGN + "        return md5($data);")), None),
        ("app/Fresh.php", None, _cls("Fresh", _meth("old", IGN + "        return sha1($data);"))),
    ])
    assert _added(found) == ["app/Fresh.php"]


def test_unknown_anchor_is_not_collected():
    require_php()
    from agent_ratchet.php import compare as C

    body = "        // phpcs:foo\n        $a = 1;\n" + IGN + "        return 'x';"  # phpcs-unknown + known
    blank = "    public function gap(): void\n    {\n" + IGN + "\n        x();\n    }"  # EMPTY_LINE anchor
    moves = C.PointMoves()
    for path, base, target in [
        ("app/Legacy.php", _cls("Legacy", _meth("old", body) + "\n\n" + blank), None),
        ("app/Fresh.php", None, _cls("Fresh", _meth("old", body) + "\n\n" + blank)),
    ]:
        b, t = (base.encode() if base else None), (target.encode() if target else None)
        ban, tan = C.analyze_pair(b, t, path if b else None, path)
        C.compare_php_analyses(ban, tan, path, [], moves=moves)
    gone = [(f.identity["tool"], f.payload["anchor_norm_hash"]) for f in moves.gone]
    new = [(f.identity["tool"], f.payload["anchor_norm_hash"]) for _, f in moves.new]
    assert len(gone) == len(new) == 1 and gone == new and gone[0][0] == "phpcs" and gone[0][1] != "empty-line"


def test_exception_honoured_on_moves_path():
    exc = {"path": "app/Fresh.php", "symbol": "Acme\\Shop\\Model\\Fresh::brandNew", "tool": "phpcs",
           "codes": ["Generic.Sample.Rule"], "reason": "legacy"}
    found = _run([
        ("app/Legacy.php", _cls("Legacy", _meth("old", IGN + "        return $result;")), None),
        ("app/Fresh.php", None, _cls("Fresh", _meth("brandNew", IGN + "        return $result;"))),
    ], exceptions=[exc])
    assert found == []


def test_without_moves_matches_per_entry_behaviour():
    moved = _meth("token", IGN + "        return md5(serialize($data));")
    entries = [("app/Legacy.php", _cls("Legacy", moved), None), ("app/Fresh.php", None, _cls("Fresh", moved))]
    assert _added(_run(entries, with_moves=False)) == ["app/Fresh.php"]


def test_ignore_above_docblock_still_sees_signature_change():  # P5 (I1)
    doc = "    // phpcs:ignore Squiz.Commenting.FunctionComment.MissingParamTag\n    /** Run it. */\n"
    found = _run([(
        "app/Run.php",
        _cls("Run", doc + _meth("run", "        return 'y';", sig="int $a")),
        _cls("Run", doc + _meth("run", "        return 'y';", sig="int $a, int $b")),
    )])
    assert [c for _, c, _ in found] == ["php_suppression_rebound"]


def test_common_name_execute_does_not_fund_unrelated_method():  # R1 (C1')
    keep = _meth("keep", "        return 'k';")
    b = _meth("b", "        return 'b';")
    found = _run([
        ("app/A.php", _cls("A", keep + "\n\n" + _meth("execute", "        $result = 'a';\n" + IGN + "        return $result;")), _cls("A", keep)),
        ("app/B.php", _cls("B", b), _cls("B", b + "\n\n" + _meth(
            "execute", "        $result = evil($_GET['x']);\n" + IGN + "        return $result;", sig="int $x, string $y"))),
    ])
    assert _added(found) == ["app/B.php"]


def test_common_name_construct_from_deleted_file_is_flagged():  # R2 (C1')
    legacy = "    public function __construct(private int $v)\n    {\n" + STAN + "        $this->init();\n    }"
    fresh = "    public function __construct(array $danger)\n    {\n        eval($danger[0]);\n" + STAN + "        $this->init();\n    }"
    found = _run([
        ("app/Legacy.php", _cls("Legacy", legacy), None),
        ("app/Fresh.php", None, _cls("Fresh", fresh).replace("Acme\\Shop\\Model", "Other\\Pkg")),
    ])
    assert _added(found) == ["app/Fresh.php"]


def test_common_name_get_data_other_namespace_is_flagged():  # R3 (C1')
    found = _run([
        ("app/Old.php", _cls("Old", _meth("getData", IGN + "        return $result;")), None),
        ("app/Neu.php", None, _cls("Neu", _meth(
            "getData", "        $result = unserialize($data);\n" + IGN + "        return $result;", sig="string $data"))),
    ])
    assert _added(found) == ["app/Neu.php"]


def test_rename_out_of_scope_is_a_deleted_donor():
    require_php()
    from agent_ratchet.php.scan import pair_entries

    pairs = pair_entries([("R100", "app/Legacy.php", "vendor/acme/Legacy.php"), ("A", "", "app/Fresh.php")], ["app"])
    assert pairs == [("app/Legacy.php", None, False), (None, "app/Fresh.php", False)]
    found = _run([
        ("app/Legacy.php", _cls("Legacy", _meth("run", IGN + "        return $result;")), None),
        ("app/Fresh.php", None, _cls("Fresh", _meth("run", "        $result = evil();\n" + IGN + "        return $result;"))),
    ])
    assert _added(found) == ["app/Fresh.php"]


def test_none_anchor_is_not_collected():
    require_php()
    from agent_ratchet.php import compare as C

    src = "<?php\nnamespace Acme;\n\nclass K\n{\n    // phpcs:ignore Generic.Sample.Rule\n}\n"  # nothing to anchor to
    moves = C.PointMoves()
    ban, tan = C.analyze_pair(src.encode(), None, "app/K.php", "app/K.php")
    assert any(f.payload.get("anchor_norm_hash") is None for f in ban.facts if f.kind == C.POINT)
    C.compare_php_analyses(ban, tan, "app/K.php", [], moves=moves)
    assert moves.gone == []


def test_moves_require_violations_call():  # M1 contract: deferred facts surface only through `violations`
    require_php()
    from agent_ratchet.php import compare as C

    moves = C.PointMoves()
    fresh = _cls("Fresh", _meth("brandNew", IGN + "        return $result;")).encode()
    ban, tan = C.analyze_pair(None, fresh, None, "app/Fresh.php")
    per_entry = C.compare_php_analyses(ban, tan, "app/Fresh.php", [], moves=moves)
    assert [v.category for v in per_entry] == [] and len(moves.new) == 1
    assert [v.category for v in moves.violations([])] == ["php_suppression_added"]


def test_ignore_above_docblock_with_inner_slash_star():  # `/** a/*b */` is still the attached docblock
    doc = "    // phpcs:ignore Squiz.Commenting.FunctionComment.MissingParamTag\n    /** Run a/*b it. */\n"
    found = _run([(
        "app/Run.php",
        _cls("Run", doc + _meth("run", "        return 'y';", sig="int $a")),
        _cls("Run", doc + _meth("run", "        return 'y';", sig="int $a, int $b")),
    )])
    assert [c for _, c, _ in found] == ["php_suppression_rebound"]


def test_copy_source_does_not_fund_new_file(monkeypatch):  # M2: a copied-from file keeps its suppressions
    require_php()
    from agent_ratchet.php import scan

    body = IGN + "        return $result;"
    legacy = _cls("Legacy", _meth("run", body))
    blobs = {
        "BASE:app/Legacy.php": legacy.encode(),
        ":app/Copy.php": _cls("Legacy", _meth("go", "        return $result;")).encode(),
        ":app/Fresh.php": _cls("Fresh", _meth("run", body)).encode(),
    }
    monkeypatch.setattr(scan, "git_cat_bytes", lambda spec, cwd=None: blobs.get(spec))
    cfg = {"languages": ["php"], "frameworks": [], "php_paths": ["app/"]}
    entries = [("C100", "app/Legacy.php", "app/Copy.php"), ("A", "", "app/Fresh.php")]
    found = scan.php_transition_violations(entries, "BASE", "", cfg, cfg)
    assert "app/Fresh.php" in {v.file for v in found if v.category == "php_suppression_added"}


_GAP_PROP = "    public $broken = ;\n"  # a class-level parse gap: its innermost symbol is the class


def test_deleted_file_with_gap_around_method_does_not_fund_move():  # a gap in the class makes its facts incomplete
    moved = _meth("token", IGN + "        return md5(serialize($data));")
    found = _run([
        ("app/Legacy.php", _cls("Legacy", _GAP_PROP + moved), None),
        ("app/Fresh.php", None, _cls("Fresh", moved)),
    ])
    assert _added(found) == ["app/Fresh.php"]


def test_deleted_file_with_file_level_gap_does_not_fund_move():  # M3: a top-level gap taints every symbol
    moved = _meth("token", IGN + "        return md5(serialize($data));")
    found = _run([
        ("app/Legacy.php", _cls("Legacy", moved) + "foo(;\n", None),
        ("app/Fresh.php", None, _cls("Fresh", moved)),
    ])
    assert _added(found) == ["app/Fresh.php"]


def test_changed_file_with_file_level_gap_does_not_fund_move():  # M3 on the in-entry gone path
    keep = _meth("keep", "        return 'k';")
    moved = _meth("token", IGN + "        return md5(serialize($data));")
    found = _run([
        ("app/Legacy.php", _cls("Legacy", keep + "\n\n" + moved) + "foo(;\n", _cls("Legacy", keep) + "foo(;\n"),
        ("app/Fresh.php", None, _cls("Fresh", moved)),
    ])
    assert _added(found) == ["app/Fresh.php"]


def test_gap_elsewhere_in_changed_file_still_funds_move():  # the filter is per symbol, not per file
    other = _meth("other", "        return foo(;")
    moved = _meth("token", IGN + "        return md5(serialize($data));")
    found = _run([
        ("app/Legacy.php", _cls("Legacy", other + "\n\n" + moved), _cls("Legacy", other)),
        ("app/Fresh.php", None, _cls("Fresh", moved)),
    ])
    assert _added(found) == []
