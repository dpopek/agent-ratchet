from __future__ import annotations

import subprocess
import sys

from php_support import require_php


def _first_statement(blob: bytes):
    from agent_ratchet.php.parser import parse_php

    parsed = parse_php(blob)
    stmt = next(c for c in parsed.tree.root_node.children if c.type == "expression_statement")
    return stmt, parsed.source


def test_clean_file_has_no_error_spans():
    require_php()
    from agent_ratchet.php.parser import parse_php

    assert parse_php(b"<?php function f() { return 1; }").error_spans == ()


def test_error_and_missing_spans_reported():
    require_php()
    from agent_ratchet.php.parser import parse_php

    assert parse_php(b"<?php function f( { $x = ; }").error_spans


def test_crlf_and_reindent_keep_anchor():
    require_php()
    from agent_ratchet.php.parser import norm_hash

    variants = [
        b"<?php\n$a = foo( 1 );",
        b"<?php\r\n$a = foo( 1 );",
        b"<?php\n\n      $a   =\n foo( 1 );",
        b"<?php\n$a = foo( /* c */ 1 ); // tail",
    ]
    hashes = {norm_hash(*_first_statement(v)) for v in variants}
    assert len(hashes) == 1


def test_norm_hash_differs_for_different_tokens():
    require_php()
    from agent_ratchet.php.parser import norm_hash

    assert norm_hash(*_first_statement(b"<?php foo(1);")) != norm_hash(*_first_statement(b"<?php foo(2);"))


def test_node_text_roundtrip():
    require_php()
    from agent_ratchet.php.parser import node_text

    stmt, src = _first_statement(b"<?php foo(1);")
    assert node_text(stmt, src) == "foo(1);"


def test_core_import_does_not_load_tree_sitter():
    code = "import agent_ratchet.php.scope, agent_ratchet.php.parser, agent_ratchet.ai_slop_scanner, sys; print('tree_sitter' in sys.modules)"
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True).stdout
    assert out.strip() == "False"
