# Changelog

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
