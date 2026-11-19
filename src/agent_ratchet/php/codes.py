"""Suppression code-set coverage, the one rule shared by pairing, window growth and window closing.

PHPCS codes are hierarchical (probed on PHPCS 3.13.5 and 4.0.4): `Generic` and `Generic.PHP` cover
`Generic.PHP.ForbiddenFunctions` for `disable`, `ignore` and `enable` alike. Other tools (phpstan identifiers, psalm
issues, PHPMD rules, unparsed `phpcs-unknown`) keep the exact rule, the stricter choice without verified hierarchy.
An empty code list means every code.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence


def covers(outer: Iterable[str], code: str) -> bool:
    """`code` is one of `outer` or a dotted code under one of them."""
    return any(code == h or code.startswith(h + ".") for h in outer)


def within(inner: Sequence[str], outer: Sequence[str], hierarchical: bool) -> bool:
    """Everything `inner` suppresses, `outer` suppresses too."""
    if not outer:
        return True
    if not inner:
        return False
    if hierarchical:
        return all(covers(outer, c) for c in inner)
    return set(inner) <= set(outer)
