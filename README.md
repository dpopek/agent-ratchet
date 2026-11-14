# guard-core

Shared quality and refactoring guards for Python repositories: the AI-slop
scanner and the test-baseline integrity check, extracted from the in-repo guard
(2.3.3) that consumers used to vendor under `scripts/audit/`. Version 3.0.0
ships it as one installable package with no runtime dependencies.

## Commands

    guard-core [--expect-sha SHA] scan ...
    guard-core [--expect-sha SHA] baseline-integrity ...
    guard-core [--expect-sha SHA] version [--sha]

`scan` takes the arguments of the legacy `ai_slop_scanner.py`, and
`baseline-integrity` those of the legacy `test_baseline_integrity.py`.
`--expect-sha` exits 3 unless the installed package was installed from exactly
that commit (read from the PEP 610 `direct_url.json` record).

## Consumer integration

1. Add `guard.lock` at the repository root: the full 40-character lowercase
   release SHA of guard-core, optionally followed by one newline. It must be a
   regular file, not a symlink.
2. Copy `consumer/guard` from this repository to `scripts/guard`,
   byte-identical, with git mode `100755`.
3. Call the shim from the pre-commit hook instead of the vendored scripts:

       scripts/guard scan --staged-only
       scripts/guard baseline-integrity --enforce-policy-isolation

4. In CI, run the shim from the trusted base, not from the pull request; see
   "CI: judge a pull request with the trusted base" below.

The shim reads `guard.lock` and runs
`uvx --from git+https://github.com/dpopek/guard-core@SHA guard-core --expect-sha SHA ...`.
`uv` must be on `PATH`. `scripts/guard exec -- <cmd...>` runs a command inside
an environment that has the locked guard-core installed.

The lock source is chosen as follows:

- `--lock-from REF`: the `guard.lock` blob in `REF` (mode `100644` required).
  If `REF` has no `guard.lock`, the shim prints a bootstrap notice and falls
  back to the rules below.
- Otherwise the stage-0 `guard.lock` entry of the index, i.e. the lock that the
  next commit will contain. An unstaged edit of `guard.lock` therefore never
  changes which guard judges the index. An unmerged or non-regular index entry
  exits 3.
- Only when the index has no `guard.lock` (bootstrap) is the work-tree file
  used; it must be a regular file, not a symlink.

The SHA in `guard.lock` replaces the old `guard_manifest.json` mechanism. With
an unchanged legacy manifest, the 2.3.3 findings "SHA-256 does not match
guard_manifest.json" and "version-mismatched" no longer appear, because the
manifest is superseded by `guard.lock`.

## CI: judge a pull request with the trusted base

A pull request can change `scripts/guard` and `guard.lock`, so CI must not run
the copies from the pull request to judge it: a pull request must not judge
itself. Run the shim taken from the default branch, with the lock taken from
the default branch, against a full-history checkout (`fetch-depth: 0`). The
example uses GitHub Actions' `$RUNNER_TEMP`; any path outside the checkout
works:

    git show origin/main:scripts/guard > "$RUNNER_TEMP/guard"
    sh "$RUNNER_TEMP/guard" --lock-from origin/main scan --commit-range origin/main..HEAD
    sh "$RUNNER_TEMP/guard" --lock-from origin/main baseline-integrity \
        --require-base-ref --enforce-policy-isolation --commit-range origin/main..HEAD

Replace `main` with the repository's default branch. The guard pinned by the
base then decides whether the lock bump in the pull request is allowed (an
annotated `v3.*` tag that descends from the previous pin).

When the pull request changes `guard.lock` or `scripts/guard`, add a second,
smoke step that runs the pull request's own shim and lock, so the new pin is
proven to install and run before it lands:

    if ! git diff --quiet origin/main...HEAD -- guard.lock scripts/guard; then
        scripts/guard version --sha
        scripts/guard scan --commit-range origin/main..HEAD
    fi

Make both steps required checks. Only the adoption pull request, whose base has
no `scripts/guard` yet, has to run its own shim; review it by hand.

## Changing the lock: `ALLOW_GUARD_LOCK_UPDATE`

A change to `guard.lock` is a change to the code that every hook and CI job
executes, so it is gated.

- Locally, `ALLOW_GUARD_LOCK_UPDATE=1` permits one thing: a lock change between
  HEAD and the index. It is for the repository operator only. Agents and
  automation never set it, and it is never set in CI.
- In CI, a lock change is accepted only when the new SHA is peeled from an
  annotated `v3.*` release tag of guard-core and is a descendant of the
  previous locked SHA.

## Release procedure

1. Merge the change into `main` of guard-core and wait for green CI.
2. Create an annotated tag `v3.x.y` on `main` (`git tag -a v3.x.y -m ...`) and
   push it. Record the SHA the tag peels to (`git rev-parse v3.x.y^{commit}`).
3. In each consumer, open a lock-bump pull request that sets `guard.lock` to
   that SHA (and refreshes `scripts/guard` if `consumer/guard` changed).
4. Before bumping, run the differential tool below against the consumer.

## Differential acceptance tool

`tools/differential_findings.py` proves that the packaged guard reports the
same findings as the vendored legacy copy. It is stdlib-only and is not part of
the installed package.

    python tools/differential_findings.py \
        --consumer <consumer checkout> --legacy-ref <sha> --guard-sha <sha> \
        --commits 30 --out <report dir>

- The consumer is cloned locally (`--no-hardlinks`) into a temporary directory
  and checked out detached at `--legacy-ref`; the consumer itself is never
  modified. The temporary clone is always deleted. `--legacy-ref` may be a SHA or
  any ref name; it is resolved in the consumer itself (read-only) to a SHA, which
  is recorded in `summary.txt`.
- Cases: `scan --staged-only`, `scan --commit-range HEAD~N..HEAD`,
  `baseline-integrity --enforce-policy-isolation`, and
  `baseline-integrity --require-base-ref --enforce-policy-isolation --commit-range HEAD~N..HEAD`.
  Add path-scan cases with a repeatable `--extra-scan-args "<args>"`.
- Legacy runs `python3 scripts/audit/<script>.py`; guard-core runs via
  `uvx --from <new-from> guard-core --expect-sha <guard-sha>`. Override
  `--new-from` with any uvx spec, for example `git+file:///path/to/guard-core@<sha>`
  for a pre-release run.
- `(rc, stdout, stderr)` are compared after only three normalisations: the
  clone path becomes `<ROOT>`, other temporary paths `<TMP>`, and program names
  `<PROG>`. A case that errors or times out counts as a difference.
- Exit 0 means every case is identical, 1 means at least one differs, 2 means
  a usage error, including a `HEAD~N` that does not exist at `--legacy-ref`
  and a `--legacy-ref` that starts with `-`. `--out` must be outside any git
  repository; one `<case>.diff`
  is written per differing case, plus `summary.txt`.
- `--timeout SECONDS` bounds each command; `--legacy-cmd` and `--new-cmd`
  replace the commands with a prefix (used by the tests).

### Expected differences vs 2.3.3

Two classes of difference follow from the removal of `guard_manifest.json` and
are accepted. In both, `rc` is equal on both sides and only the finding lines
named below differ:

- **Manifest sync commits in a range.** When `scan --commit-range` covers
  historical commits that synchronised `scripts/audit/guard_manifest.json`,
  2.3.3 reports one finding and 3.0 reports one finding per such commit,
  `scripts/audit/guard_manifest.json changed; Guard Core 3 is pinned by guard.lock`.
- **Baseline version bumps.** A baseline version change that relied on a
  manifest-based migration is now reported as
  `Baseline version changed without authorized migration`, because those
  migrations were removed.

Both disappear once a consumer has adopted `guard.lock` and its ranges no
longer contain 2.x manifest commits. Any other differing line is a regression.

## License

MIT, see `LICENSE`.
