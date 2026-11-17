#!/usr/bin/env python3
"""Fail-closed AST parsing and visiting: pathological depth is a guard analysis error, never a traceback or a silent pass."""

from __future__ import annotations

import ast
from typing import Callable, TypeVar

T = TypeVar("T")


class GuardAnalysisError(RuntimeError):
    """Raised when AST parsing, Git resolution, or config/lock validation fails."""


def parse_python(source: str | bytes, filename: str) -> ast.Module:
    """ast.parse that maps RecursionError and MemoryError to GuardAnalysisError; SyntaxError passes through unchanged."""
    try:
        return ast.parse(source, filename=filename)
    except (RecursionError, MemoryError) as exc:
        raise GuardAnalysisError(f"{filename}: AST too deep to analyse") from exc


def visit_bounded(fn: Callable[[], T], filename: str) -> T:
    """Run a visitor or recursive walker, mapping RecursionError to GuardAnalysisError."""
    try:
        return fn()
    except RecursionError as exc:
        raise GuardAnalysisError(f"{filename}: AST too deep to analyse") from exc
