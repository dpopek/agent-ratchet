"""Directive keywords and code lists inside one comment line (spec R4; PHPCS parsing per probes G2, G5, G6, C1)."""

from __future__ import annotations

import re

_DIRECTIVE = re.compile(
    r"(?P<stan>@phpstan-ignore(?P<suffix>-next-line|-line)?(?![\w-]))"
    r"|phpcs:(?P<cs>[a-z]+)"
    r"|@codingStandardsIgnore(?P<legacy>Line|Start|End|File)\b"
    r"|(?P<psalm>@psalm-suppress\b)",
    re.IGNORECASE,
)
# PHPCS prefix-matches its keywords in this order (Tokenizer::createPositionMap); `set` is not modelled.
_PHPCS_FORMS = (("set", None), ("ignorefile", "file"), ("disable", "disable"), ("enable", "enable"), ("ignore", "point"))
# PHPCS 4 honours no legacy annotation; `End` closes nothing, so only the stricter forms are modelled (I1, 19.11).
_LEGACY_FORMS = {"line": "point", "start": "disable", "end": None, "file": "file"}
_PAREN = re.compile(r"\([^)]*\)")
_PHP_TRIM = " \t\n\r\0\x0b"  # PHP trim() default set


def _split_codes(text: str) -> tuple[str, ...]:
    text = text.split("--", 1)[0]
    text = _PAREN.sub(" ", text)
    return tuple(sorted({c for c in re.split(r"[,\s]+", text) if c}))


def _phpcs_codes(text: str) -> tuple[str, ...]:
    """PHPCS code list: reason from the first ` --` on, then split on `,` only and trimmed (G5)."""
    text = text.split(" --", 1)[0]
    return tuple(sorted({c.strip(_PHP_TRIM) for c in text.split(",") if c.strip(_PHP_TRIM)}))


def comment_lines(text: str) -> list[tuple[int, str]]:
    """Comment lines trimmed exactly as PHPCS trims them; NBSP and other Unicode spaces stay (G2/G6).

    Other tools match their directives anywhere in the line and split codes on `\\s`, so they are unaffected.
    """
    return [(i, line.lstrip(" \t/*#").rstrip(" */\t\r\n")) for i, line in enumerate(text.split("\n"))]


def _mid_text(line: str, start: int) -> bool:
    """The `phpcs:` at `start` does not open the line's text (after ` \\t/*#` and an optional `@`)."""
    prefix = line[:start].removesuffix("@")
    return bool(prefix.strip(" \t/*#"))


def scan_line(line: str) -> list[tuple[str, str, tuple[str, ...], str]]:
    """Return (form, tool, codes, row_rule) for every directive on a line, in order.

    `row_rule`: "next" for `@phpstan-ignore-next-line`, "end" for `@phpstan-ignore-line`, "" otherwise.
    """
    matches = list(_DIRECTIVE.finditer(line))
    out: list[tuple[str, str, tuple[str, ...], str]] = []
    for i, m in enumerate(matches):
        end = matches[i + 1].start() if i + 1 < len(matches) else len(line)
        rest = line[m.end() : end]
        if m.group("stan") is not None:
            suffix = (m.group("suffix") or "").lower()
            codes = () if suffix else _split_codes(rest)
            out.append(("point", "phpstan", codes, {"-next-line": "next", "-line": "end"}.get(suffix, "")))
        elif m.group("cs") is not None:  # PHPCS reads codes to the end of the line, past any later match (G5)
            word = line[m.start("cs") :].split(" --", 1)[0]
            rest = line[m.end() :]
            keyword, form = next(
                ((k, f) for k, f in _PHPCS_FORMS if word.lower().startswith(k)), ("", None)
            )
            if form == "enable" and _mid_text(line, m.start()):
                continue  # PHPCS ignores a mid-text enable (G6); other mid-text keywords over-report, so they stay
            if form is None:
                out.append(("unknown", "phpcs-unknown", _split_codes(rest), ""))
            else:  # PHPCS skips exactly one character after the keyword, whatever it is
                out.append((form, "phpcs", _phpcs_codes(word[len(keyword) + 1 :]), ""))
        elif m.group("legacy") is not None:
            form = _LEGACY_FORMS[m.group("legacy").lower()]
            if form is not None:
                out.append((form, "phpcs", (), ""))
        else:
            out.append(("point", "psalm", _split_codes(rest), ""))
    return out
