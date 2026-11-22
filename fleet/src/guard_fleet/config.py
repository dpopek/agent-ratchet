"""consumers.toml: strict loading and validation of the fleet's consumer list."""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Mapping

from .env import forbidden_env_key
from .exits import UsageError

SHORT_RE = re.compile(r"^[a-z][a-z0-9-]{0,15}$")
SLUG_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
PIN_KINDS = ("req", "pyproject", "none")
CI_MODES = ("if-run", "required")
SURFACES = frozenset({"php", "magento"})
TOP_KEYS = frozenset({"worktree_root", "consumer"})
REQUIRED_KEYS = ("short", "dir", "slug", "default_branch", "pin_kind", "ring")
OPTIONAL_KEYS = ("pin_file", "ci", "ci_wait_min", "deploy_workflows", "quiet_before_merge",
                 "commit_env", "node_modules", "hook_needs", "venvs", "surfaces", "confirm_note")


class ConfigError(UsageError):
    """consumers.toml is invalid; the message names the consumer, the key and the value."""


@dataclass(frozen=True)
class Consumer:
    short: str
    dir: Path
    slug: str
    default_branch: str
    pin_kind: Literal["req", "pyproject", "none"]
    pin_file: str | None
    ring: int
    ci: Literal["if-run", "required"]
    ci_wait_min: int
    deploy_workflows: tuple[str, ...]
    quiet_before_merge: tuple[str, ...]
    commit_env: Mapping[str, str]
    node_modules: bool
    hook_needs: tuple[str, ...]
    venvs: tuple[Path, ...]
    surfaces: frozenset[str]
    confirm_note: str


@dataclass(frozen=True)
class FleetConfig:
    worktree_root: Path
    consumers: tuple[Consumer, ...]

    def ring_order(self, ring: int) -> tuple[Consumer, ...]:
        members = [c for c in self.consumers if c.ring == ring]
        return tuple([c for c in members if c.ci == "required"] + [c for c in members if c.ci != "required"])

    def by_short(self, short: str) -> Consumer:
        for c in self.consumers:
            if c.short == short:
                return c
        raise ConfigError(f"unknown consumer {short!r}")

    def canaries(self, ring: int) -> tuple[Consumer, ...]:
        return tuple(c for c in self.consumers if c.ring == ring and c.ci == "required")


def expand(value: str, *, dir: Path | None, home: Path) -> str:
    """Substitute `{dir}` and a leading `~`; nothing else."""
    if "{dir}" in value:
        if dir is None:
            raise ConfigError(f"{{dir}} is not available in {value!r}")
        value = value.replace("{dir}", str(dir))
    if value == "~" or value.startswith("~/"):
        value = str(home) + value[1:]
    return value


def _fail(who: str, message: str) -> ConfigError:
    return ConfigError(f"{who}: {message}")


def _str(who: str, raw: Mapping[str, Any], key: str, default: str | None = None) -> str:
    value = raw.get(key, default)
    if not isinstance(value, str):
        raise _fail(who, f"{key} {value!r} must be a string")
    return value


def _int(who: str, raw: Mapping[str, Any], key: str, default: int | None = None) -> int:
    value = raw.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int):
        raise _fail(who, f"{key} {value!r} must be an integer")
    return value


def _strs(who: str, raw: Mapping[str, Any], key: str) -> tuple[str, ...]:
    value = raw.get(key, [])
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise _fail(who, f"{key} {value!r} must be a list of strings")
    return tuple(value)


def _absolute(who: str, key: str, text: str) -> Path:
    path = Path(text)
    if not path.is_absolute():
        raise _fail(who, f"{key} {text!r} is not absolute")
    return path


def _consumer(raw: dict, index: int, home: Path) -> Consumer:
    short = raw.get("short")
    who = short if isinstance(short, str) and short else f"consumer #{index + 1}"
    for key in raw:
        if key not in REQUIRED_KEYS and key not in OPTIONAL_KEYS:
            raise _fail(who, f"unknown key {key!r}")
    for key in REQUIRED_KEYS:
        if key not in raw:
            raise _fail(who, f"missing key {key!r}")
    short = _str(who, raw, "short")
    if not SHORT_RE.match(short):
        raise _fail(who, f"short {short!r} does not match {SHORT_RE.pattern}")
    slug = _str(who, raw, "slug")
    if not SLUG_RE.match(slug):
        raise _fail(who, f"slug {slug!r} does not match {SLUG_RE.pattern}")
    dir_ = _absolute(who, "dir", expand(_str(who, raw, "dir"), dir=None, home=home))
    pin_kind = _str(who, raw, "pin_kind")
    if pin_kind not in PIN_KINDS:
        raise _fail(who, f"pin_kind {pin_kind!r} not in {PIN_KINDS}")
    pin_file = raw.get("pin_file")
    if pin_kind == "none":
        if pin_file is not None:
            raise _fail(who, f"pin_file {pin_file!r} is not allowed with pin_kind 'none'")
    elif not isinstance(pin_file, str) or not pin_file:
        raise _fail(who, f"pin_file {pin_file!r} is required for pin_kind {pin_kind!r}")
    ring = _int(who, raw, "ring")
    if ring not in (1, 2):
        raise _fail(who, f"ring {ring} not in {{1, 2}}")
    ci = _str(who, raw, "ci", "if-run")
    if ci not in CI_MODES:
        raise _fail(who, f"ci {ci!r} not in {CI_MODES}")
    wait = _int(who, raw, "ci_wait_min", 15)
    if not 1 <= wait <= 120:
        raise _fail(who, f"ci_wait_min {wait} not in 1..120")
    surfaces = _strs(who, raw, "surfaces")
    if not set(surfaces) <= SURFACES:
        raise _fail(who, f"surfaces {list(surfaces)!r} not a subset of {sorted(SURFACES)}")
    node_modules = raw.get("node_modules", False)
    if not isinstance(node_modules, bool):
        raise _fail(who, f"node_modules {node_modules!r} must be a boolean")
    commit_env = raw.get("commit_env", {})
    if not isinstance(commit_env, dict):
        raise _fail(who, f"commit_env {commit_env!r} must be a table")
    for key, value in commit_env.items():
        if not isinstance(value, str):
            raise _fail(who, f"commit_env key {key!r} value {value!r} must be a string")
        if forbidden_env_key(key):
            raise _fail(who, f"commit_env key {key!r} (value {value!r}) is forbidden")
    venvs = tuple(_absolute(who, "venvs entry", expand(v, dir=dir_, home=home)) for v in _strs(who, raw, "venvs"))
    hook_needs = []
    for need in _strs(who, raw, "hook_needs"):
        expanded = expand(need, dir=dir_, home=home)
        if "/" in expanded:
            _absolute(who, "hook_needs entry", expanded)
        hook_needs.append(expanded)
    return Consumer(
        short=short, dir=dir_, slug=slug, default_branch=_str(who, raw, "default_branch"),
        pin_kind=pin_kind, pin_file=pin_file, ring=ring, ci=ci, ci_wait_min=wait,  # type: ignore[arg-type]
        deploy_workflows=_strs(who, raw, "deploy_workflows"),
        quiet_before_merge=_strs(who, raw, "quiet_before_merge"),
        commit_env=dict(commit_env), node_modules=node_modules, hook_needs=tuple(hook_needs),
        venvs=venvs, surfaces=frozenset(surfaces), confirm_note=_str(who, raw, "confirm_note", ""))


def load_config(path: Path, *, home: Path) -> FleetConfig:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError(f"cannot read {path}: {exc.strerror or exc}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path}: invalid TOML: {exc}") from exc
    for key in data:
        if key not in TOP_KEYS:
            raise ConfigError(f"unknown key {key!r} at top level of {path}")
    root_text = data.get("worktree_root")
    if not isinstance(root_text, str):
        raise ConfigError(f"worktree_root {root_text!r} must be a string")
    root = Path(expand(root_text, dir=None, home=home))
    if not root.is_absolute():
        raise ConfigError(f"worktree_root {root_text!r} is not absolute")
    entries = data.get("consumer", [])
    if not isinstance(entries, list) or not all(isinstance(e, dict) for e in entries):
        raise ConfigError("consumer must be an array of tables")
    consumers: list[Consumer] = []
    seen: set[str] = set()
    for index, raw in enumerate(entries):
        consumer = _consumer(raw, index, home)
        if consumer.short in seen:
            raise ConfigError(f"duplicate short {consumer.short!r}")
        seen.add(consumer.short)
        consumers.append(consumer)
    return FleetConfig(worktree_root=root, consumers=tuple(consumers))
