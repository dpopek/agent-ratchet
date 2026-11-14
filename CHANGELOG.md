# Changelog

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
