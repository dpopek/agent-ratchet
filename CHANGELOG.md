# Changelog

## 3.5.1

### Fixed

- `migrate-imports --write` on an explicitly given symlink rewrites the target
  and keeps the link; each target file is processed once per run.
- Runtime-string detection uses word boundaries: `guard-core-…`,
  `guard-core's` and `-m guard_core_x` are mentions now. Prose starting
  `guard-core ` is still reported as manual.

## 3.5.0

### Deprecated

All removed in 4.0. Using one warns, naming the replacement: the `guard_core`
import warns once per process and the CLI paths print a note on stderr.

- The `guard_core` package (import, `python -m guard_core`, the `guard-core`
  console script): use `agent_ratchet`, `python -m agent_ratchet`,
  `agent-ratchet`.
- `agent_ratchet.version.GUARD_VERSION`: use `VERSION`.
- `agent_ratchet.git_guard_io.GUARD_VERSION` and
  `agent_ratchet.refactoring_guard.GUARD_VERSION`: use `RULES_VERSION`.
- `agent_ratchet.git_guard_io.SELF_SKIP_NAMES`: use `is_self_skipped()`.
- `agent_ratchet.lock_policy.RELEASE_TAG_PATTERN`: use
  `RELEASE_TAG_PATTERNS`.
- `from agent_ratchet.{version,git_guard_io,lock_policy} import *` no longer
  binds the deprecated names; import them explicitly.

### Added

- `agent-ratchet migrate-imports [--write] [PATH ...]` rewrites `guard_core`
  imports to `agent_ratchet`. Exit 0 when nothing is pending, 1 when rewrites
  not yet applied (without `--write`) or manual items remain, 2 on errors.
  Exact or runtime-looking `guard_core` strings are manual items (exit 1);
  other strings and comments are mentions (no effect on the exit code).
  `scripts/guard` is the consumer's vendored shim. See "Migrating off
  guard_core" in the README.
- `agent_ratchet.refactoring_guard.RULES_VERSION`.

### Changed

- `CanonicalFact` is hashable; its identity and payload are deep-frozen and
  read-only. A non-Mapping payload raises `CanonicalEncodingError`.
- `FactState` requires `identity_hash` and `payload_hash` unless its status is
  `absent` or `not_applicable`.
- `LockSpec` rejects non-str SHA and `extras` values with `ValueError`.
- Default scan output is unchanged from 3.4.0.

## 3.4.0

### Added

- `AGENT_RATCHET_SHADOW=1` prints one `agent-ratchet shadow: ...` line to
  stderr. Stdout and the exit code are unchanged. Any other value is off.
- New modules, dormant in this release: `agent_ratchet.facts` (CanonicalFact
  v1, canonical encoding with domain-separated SHA-256 hashes, LanguagePlugin
  registry, legacy adapter) and `agent_ratchet.transitions` (BASE/HEAD
  transition engine). Nothing calls them and no plugin is registered.

### Changed

- Blob reads go through one `git cat-file --batch` process per scan. On a
  40-file commit range this takes git subprocesses from 273 to 26. The cache
  budget is 64 MiB; blobs over 8 MiB (1/8 of the budget) are read but not
  cached. Missing objects are read through the one-shot path; a read that
  takes over 30 s switches the rest of the scan to it. Error text is
  unchanged.
- `LockSpec` validates its SHA (40 lowercase hex) and `extras` on construction
  and raises `ValueError`.
- No change to findings; `RULES_VERSION` stays `2.3.3`.

### Fixed

- The A2 probe no longer swallows non-syntax analysis errors (for example an
  AST that is too deep); they fail closed with exit 2. In practice an earlier
  check already failed closed for these.

## 3.3.0

### Added

- Annotated `v4.x.y` release tags are accepted in the lock policy next to
  `v3.x.y`.
- Optional `EXTRAS=none|php|magento` line in `guard.lock`. Any `EXTRAS` line
  is rejected as malformed by 3.2.0 and earlier, and values other than `none`
  require a `v4.x.y` release. The POSIX shim honours it.
- `agent_ratchet.__version__` and `agent_ratchet.version.VERSION`.

### Changed

- A `RecursionError` while parsing, visiting or analysing a file's AST (or the
  SCC graph) now exits 2 with `guard_analysis_error` instead of being skipped or crashing with a traceback.
  This can surface analysis errors in files with extreme nesting depth.
- The POSIX shim's malformed-lock error text differs from 3.2.0; match on
  "malformed" rather than the exact old wording.
- The release-tag error text differs from 3.2.0 (was "carries no annotated
  v3.x.y release tag", now "no annotated v3.x.y/v4.x.y release tag peels to
  <sha>"); match on "release tag".
- `GuardAnalysisError` is defined in `agent_ratchet.ast_safety`. It is still
  importable from `agent_ratchet.git_guard_io` and is the same class.
- `RULES_VERSION` stays `2.3.3`.

### Deprecated (removed in 4.0)

- `RELEASE_TAG_PATTERN` in `lock_policy`; use `RELEASE_TAG_PATTERNS`.
- `agent_ratchet.version.GUARD_VERSION`; use `VERSION` or `__version__`.

### Upgrade

See "Upgrading to 4.x" in the README. Do not add `EXTRAS` in the bump that
moves the base off 3.2.0 or earlier.

## 3.2.0

### Changed

- Files named like guard modules are skipped only under `scripts/audit/`, and
  files named like guard tests only under `tests/`. Elsewhere they are now
  scanned, so new findings may appear in such files. `RULES_VERSION` stays
  `2.3.3`.

### Fixed

- Excessively nested guard config or baseline JSON exits 2 with
  `guard_analysis_error` instead of a traceback.

### Deprecated (removed in 4.0)

- `SELF_SKIP_NAMES`; use `is_self_skipped(path)`.

## 3.1.0

### Changed

- Renamed to `agent-ratchet`: distribution, import package `agent_ratchet`,
  command `agent-ratchet` and repository `github.com/dpopek/agent-ratchet`.
  The PyPI name `guard-core` belongs to an unrelated project. Findings are
  unchanged.
- The rule-set version constant is `RULES_VERSION`.

### Deprecated (removed in 4.0)

- `import guard_core...`, `python -m guard_core`, the `guard-core` command and
  `GUARD_VERSION` in `git_guard_io` / `refactoring_guard`. They still work.

### Upgrade

In the bump pull request, besides `guard.lock` and `scripts/guard`:

- Change the dev-dependency pin to
  `agent-ratchet @ git+https://github.com/dpopek/agent-ratchet@SHA`. pip
  rejects the old name for this release.
- Update the expected pin in tests that assert it.

## 3.0.3

### Fixed

- Removing a custom (non-default) entry from `import_roots` in
  `audit_guard_config.json` is a monotonicity violation; it narrowed
  import-cycle detection unnoticed.

### Changed

- A plain file `scan` prints a note on stderr that it runs text rules and
  syntax checks only; the diff modes run the full checks.
- `--help` of `scan` and `baseline-integrity` no longer shows a stale version.

## 3.0.2

### Fixed

- A `guard.lock` in the base that is not a regular file now fails the lock
  check instead of being treated as absent.
- Case variants of `guard.lock` and `scripts/guard` are governance paths.
- `--expect-sha` given more than once exits 3.
- An unreadable `consumer/guard` in guard-core is reported as such, not as a
  shim mismatch.
- Adoption exemptions accept uppercase manifest hashes and no longer crash on a
  deeply nested manifest.

### Changed

- The shim passes `--no-config` to `uv run` and `uvx`, so repository uv
  configuration does not affect the guard install.
- A `guard.lock` change now also requires `scripts/guard` to match
  `consumer/guard` at the new SHA, not only a shim change.
- Upgrade: 3.0.2 changes the shim (`--no-config`), so copy `consumer/guard` to
  `scripts/guard` in the bump pull request.
- README: lock gate, CI bootstrap, release steps and shim usage clarified.

## 3.0.1

### Fixed

- The change that adopts `guard.lock` can delete the vendored guard files
  listed in `scripts/audit/guard_manifest.json`, including their tests, when
  each deleted file still matches its manifest SHA-256. Other test deletions
  are judged as before.

## 3.0.0

First release as an installable package.

### Added

- `guard-core` command with `scan`, `baseline-integrity` and `version`, and
  `--expect-sha` to verify the installed commit.
- `guard.lock` pin and the `consumer/guard` shim. Without `--lock-from` the
  shim reads the lock from the index.
- Lock-change policy: a new pin must be an annotated `v3.*` release that
  descends from the previous pin.
- `tools/differential_findings.py` to compare findings with the vendored 2.3.3
  guard.

### Changed

- `guard.lock` replaces `scripts/audit/guard_manifest.json`. The 2.3.3 findings
  "SHA-256 does not match guard_manifest.json" and "version-mismatched" no
  longer appear.
- The build backend is pinned exactly.

### Removed

- Manifest-based baseline migrations.

### Expected differences vs 2.3.3

- A commit range that includes historical `guard_manifest.json` sync commits
  yields one finding per such commit, not one in total.
- A baseline version bump that relied on a manifest migration is now rejected
  (`Baseline version changed without authorized migration`).
