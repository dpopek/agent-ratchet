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
