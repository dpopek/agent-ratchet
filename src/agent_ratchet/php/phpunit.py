"""PHPUnit test identity: test classes and methods with assertion/expectation counts (spec R5)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from agent_ratchet.php.directives import PhpDecodeError, namespace_resolver, symbol_path
from agent_ratchet.php.parser import ParsedPhp

EXPECT_EXCEPTION = {
    n.lower(): n
    for n in (
        "expectException",
        "expectExceptionMessage",
        "expectExceptionCode",
        "expectExceptionMessageMatches",
        "expectExceptionObject",
    )
}
_TEST_DIRS = frozenset({"Test", "tests"})
_TEST_TAG = re.compile(r"@test(?![\w-])")
_PROVIDER_TAG = re.compile(r"@dataProvider[ \t]+([^\s*]+)")
_NAMES = {"name", "qualified_name"}


@dataclass(frozen=True)
class TestFacts:
    __test__ = False  # not a pytest class

    class_fqn: str
    method: str
    assertions: int
    expects: int
    expect_exception: tuple[str, ...]
    skips: int
    incompletes: int
    data_providers: tuple[str, ...]
    line: int
    span: tuple[int, int] = (0, 0)


def _text(node: Any, source: bytes) -> str:
    try:
        return source[node.start_byte : node.end_byte].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PhpDecodeError("non-UTF-8 text in PHP test source") from exc


def _walk(node: Any):
    stack = [node]
    while stack:
        cur = stack.pop()
        yield cur
        stack.extend(reversed(cur.children))


def _aliases(root: Any, source: bytes) -> dict[str, str]:
    """Lower-cased alias -> full name from every class-kind `use` declaration of the file."""
    out: dict[str, str] = {}

    def add(clause: Any, prefix: str) -> None:
        name = next((c for c in clause.children if c.type in _NAMES), None)
        if name is None:
            return
        full = prefix + _text(name, source).lstrip("\\")
        names = [c for c in clause.children if c.type == "name"]
        alias = _text(names[-1], source) if any(c.type == "as" for c in clause.children) else full.rsplit("\\", 1)[-1]
        out[alias.lower()] = full

    for decl in (n for n in _walk(root) if n.type == "namespace_use_declaration"):
        if any(c.type in ("function", "const") for c in decl.children):
            continue
        prefix = next((_text(c, source).lstrip("\\") + "\\" for c in decl.children if c.type == "namespace_name"), "")
        for clause in (n for n in _walk(decl) if n.type == "namespace_use_clause"):
            add(clause, prefix)
    return out


def _resolve(name: str, aliases: dict[str, str]) -> str:
    if name.startswith("\\"):
        return name[1:]
    head, sep, rest = name.partition("\\")
    full = aliases.get(head.lower())
    return f"{full}{sep}{rest}" if full is not None else name


def _last(name: str) -> str:
    return name.rsplit("\\", 1)[-1]


def _is_test_class(cls: Any, source: bytes, aliases: dict[str, str], path: str) -> bool:
    base = next((c for c in cls.children if c.type == "base_clause"), None)
    parent = next((c for c in (base.children if base is not None else ()) if c.type in _NAMES), None)
    if parent is not None and _last(_resolve(_text(parent, source), aliases)).endswith("TestCase"):
        return True
    name = cls.child_by_field_name("name")
    return name is not None and _text(name, source).endswith("Test") and bool(_TEST_DIRS.intersection(path.split("/")[:-1]))


def _docblock(method: Any, source: bytes) -> str:
    parts: list[str] = []
    prev = method.prev_sibling
    while prev is not None and prev.type == "comment":
        parts.append(_text(prev, source))
        prev = prev.prev_sibling
    return "\n".join(parts)


def _attr_arg(arg: Any, source: bytes) -> str:
    text = _text(arg, source).strip()
    return text[: -len("::class")] if text.endswith("::class") else text.strip("'\"")


def _attributes(method: Any, source: bytes, aliases: dict[str, str]) -> list[tuple[str, list[str]]]:
    out: list[tuple[str, list[str]]] = []
    for lst in (c for c in method.children if c.type == "attribute_list"):
        for attr in (n for n in _walk(lst) if n.type == "attribute"):
            name = next((c for c in attr.children if c.type in _NAMES), None)
            args = next((c for c in attr.children if c.type == "arguments"), None)
            vals = [_attr_arg(a, source) for a in (args.children if args is not None else ()) if a.type == "argument"]
            if name is not None:
                out.append((_last(_resolve(_text(name, source), aliases)), vals))
    return out


def _is_public(method: Any, source: bytes) -> bool:
    vis = next((c for c in method.children if c.type == "visibility_modifier"), None)
    return vis is None or _text(vis, source).lower() == "public"


def _scope_ok(call: Any, source: bytes, aliases: dict[str, str], *, assertions: bool) -> bool:
    scope = call.child_by_field_name("scope")
    if scope is None:
        return False
    if scope.type == "relative_scope":
        return True
    return assertions and scope.type in _NAMES and _last(_resolve(_text(scope, source), aliases)) == "Assert"


def _count_body(body: Any, source: bytes, aliases: dict[str, str]) -> dict[str, Any]:
    c: dict[str, Any] = {"a": 0, "e": 0, "x": [], "s": 0, "i": 0}
    for node in _walk(body):
        if node.type not in ("member_call_expression", "scoped_call_expression"):
            continue
        name_node = node.child_by_field_name("name")
        if name_node is None:
            continue
        name = _text(name_node, source).lower()
        if node.type == "member_call_expression":
            obj = node.child_by_field_name("object")
            on_this = obj is not None and obj.type == "variable_name" and _text(obj, source) == "$this"
            if name == "expects":
                c["e"] += 1
            if not on_this:
                continue
            assert_ok = other_ok = True
        else:
            assert_ok = _scope_ok(node, source, aliases, assertions=True)
            other_ok = _scope_ok(node, source, aliases, assertions=False)
        if assert_ok and name.startswith("assert"):
            c["a"] += 1
        if other_ok and name in EXPECT_EXCEPTION:
            c["x"].append(EXPECT_EXCEPTION[name])
        if other_ok and name == "marktestskipped":
            c["s"] += 1
        if other_ok and name == "marktestincomplete":
            c["i"] += 1
    return c


def _providers(method: Any, source: bytes, aliases: dict[str, str]) -> tuple[str, ...]:
    found = _PROVIDER_TAG.findall(_docblock(method, source))
    for name, vals in _attributes(method, source, aliases):
        if name == "DataProvider" and vals:
            found.append(vals[0])
        elif name == "DataProviderExternal" and len(vals) >= 2:
            found.append(f"{vals[0]}::{vals[1]}")
    return tuple(sorted(found))


def _is_test_method(method: Any, name: str, source: bytes, aliases: dict[str, str]) -> bool:
    if name.startswith("test") or _TEST_TAG.search(_docblock(method, source)):
        return True
    return any(attr == "Test" for attr, _ in _attributes(method, source, aliases))


def collect_tests(parsed: ParsedPhp, path: str = "") -> list[TestFacts]:
    """Tests of every PHPUnit test class in the file; `path` only feeds the `Test/`/`tests/` name heuristic."""
    source = parsed.source
    root = parsed.tree.root_node
    aliases = _aliases(root, source)
    ns_at = namespace_resolver(root, source)
    out: list[TestFacts] = []
    for cls in (n for n in _walk(root) if n.type == "class_declaration"):
        if not _is_test_class(cls, source, aliases, path):
            continue
        class_fqn = symbol_path(cls, source, ns_at(cls.start_byte))
        for method in (n for n in _walk(cls) if n.type == "method_declaration"):
            name_node = method.child_by_field_name("name")
            body = method.child_by_field_name("body")
            if name_node is None or body is None or not _is_public(method, source):
                continue
            name = _text(name_node, source)
            if not _is_test_method(method, name, source, aliases):
                continue
            c = _count_body(body, source, aliases)
            out.append(
                TestFacts(
                    class_fqn=class_fqn,
                    method=name,
                    assertions=c["a"],
                    expects=c["e"],
                    expect_exception=tuple(sorted(c["x"])),
                    skips=c["s"],
                    incompletes=c["i"],
                    data_providers=_providers(method, source, aliases),
                    line=method.start_point.row + 1,
                    span=(method.start_byte, method.end_byte),
                )
            )
    return out
