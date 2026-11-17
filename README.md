# agent-ratchet

Shared quality and refactoring guards for Python repositories: the AI-slop
scanner and the test-baseline integrity check, extracted from the in-repo guard
(2.3.3) that consumers used to vendor under `scripts/audit/`. agent-ratchet ships
it as one installable package with no runtime dependencies.

Renamed from `guard-core` in 3.1.0 (the PyPI name belongs to an unrelated
project). Until 4.0 the old names keep working: `import guard_core.X` gives the
`agent_ratchet.X` module, `python -m guard_core` and the `guard-core` command run
the same CLI, and the old GitHub URL redirects. See the 3.1.0 upgrade notes in
`CHANGELOG.md`.

## Commands

    agent-ratchet [--expect-sha SHA] scan ...
    agent-ratchet [--expect-sha SHA] baseline-integrity ...
    agent-ratchet [--expect-sha SHA] version [--sha]

`scan` takes the arguments of the legacy `ai_slop_scanner.py`, and
`baseline-integrity` those of the legacy `test_baseline_integrity.py`.
`--expect-sha` exits 3 unless the installed package was installed from exactly
that commit (read from the PEP 610 `direct_url.json` record).

## Consumer integration

1. Add `guard.lock` at the repository root: the full 40-character lowercase
   release SHA of agent-ratchet, optionally followed by one newline. It must be a
   regular file, not a symlink.
2. Copy `consumer/guard` from this repository to `scripts/guard`,
   byte-identical, with git mode `100755`.
3. Call the shim from the pre-commit hook instead of the vendored scripts:

       scripts/guard scan --staged-only
       scripts/guard baseline-integrity --enforce-policy-isolation

4. In CI, run the shim from the trusted base, not from the pull request; see
   "CI: judge a pull request with the trusted base" below.

The shim reads `guard.lock` and runs
`uvx --no-config --from git+https://github.com/dpopek/agent-ratchet@SHA agent-ratchet --expect-sha SHA ...`.
`uv` must be on `PATH`. `scripts/guard exec -- <cmd...>` runs a command inside
an environment that has the locked agent-ratchet installed
(`uv run --no-config --no-project --with ...`). `--no-config` keeps a
repository `uv.toml` or `[tool.uv]` table from redirecting the index or
sources. It also ignores the user-level and system `uv.toml`, so a package
mirror must come from `UV_INDEX_URL` or another `UV_*` environment variable.
`--no-config` is not a hermetic environment; CI must control trusted
environment variables separately.

Run the shim from the repository root. It finds `guard.lock` from the root
wherever it is called, but the agent-ratchet arguments, including relative paths
and the default scan roots, are resolved against the current directory.

If `uv` or `uvx` itself fails, for example because the pinned SHA cannot be
fetched or the machine is offline, the shim exits with uv's own exit code. That
code can be 1 or 2, the same as a guard result; it is not mapped to 3. The run
still fails closed.

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

The change that adopts `guard.lock` may also delete the vendored guard files
listed in the manifest, including their tests, without a Test Tamper Guard
finding. A deleted file is exempt only when the base has the manifest and no
`guard.lock`, the target has a valid `guard.lock` and no manifest, and the
file's base blob matches its SHA-256 in the manifest. Any other deletion,
including one in a malformed manifest, is judged as before. Do not add
look-alike files in the adoption change: git's rename detection (`-M`) can pair
a deleted guard test with a similar new file, and a renamed test is not exempt.

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

Make both steps required checks.

On the adoption pull request the base has neither `scripts/guard` nor
`guard.lock`. Detect this explicitly; never key the bootstrap on a failing
`git show`, which also fails on a network or ref error:

    git rev-parse --verify origin/main >/dev/null || exit 1
    present=$(git ls-tree origin/main -- guard.lock scripts/guard) || exit 1
    if [ -z "$present" ]; then
        shim=scripts/guard                                   # bootstrap
    elif [ "$(printf '%s\n' "$present" | wc -l)" -eq 2 ]; then
        git show origin/main:scripts/guard > "$RUNNER_TEMP/guard"
        shim="$RUNNER_TEMP/guard"                            # normal path
    else
        echo "broken install: base has only one of guard.lock, scripts/guard" >&2
        exit 1
    fi
    sh "$shim" --lock-from origin/main scan --commit-range origin/main..HEAD

Only an empty listing, both files absent, bootstraps: the pull request runs
its own `scripts/guard` with `--lock-from origin/main`, and the shim prints the
bootstrap notice and uses the pull request's lock. Exactly one of the two files
present is a broken install and fails. Review the adoption pull request by
hand.

## Changing the lock: `ALLOW_GUARD_LOCK_UPDATE`

A change to `guard.lock` is a change to the code that every hook and CI job
executes, so it is gated.

- Locally, `ALLOW_GUARD_LOCK_UPDATE=1` permits a change of `guard.lock` or
  `scripts/guard` in an uncommitted target: HEAD to the index, or the work
  tree. It is for the repository operator only. Agents and automation never set
  it, and it is never set in CI.
- The variable never skips the remote checks. A changed lock must still be
  peeled from an annotated `v3.x.y`/`v4.x.y` release tag of agent-ratchet and descend from
  the previous locked SHA. On every change of `guard.lock` or `scripts/guard`,
  `scripts/guard` must equal `consumer/guard` at the locked SHA, so copy
  `consumer/guard` to `scripts/guard` whenever you bump the lock.
- A committed bump that is not yet on the trusted base is verified against
  agent-ratchet again on every pre-commit run.
- In CI, a lock change is accepted only when the new SHA is peeled from an
  annotated `v3.x.y`/`v4.x.y` release tag of agent-ratchet and is a descendant of the
  previous locked SHA.

### Break-glass: an invalid lock on the base

If the default branch itself carries an invalid `guard.lock` or
`scripts/guard`, every pull request is judged by that broken pin, and the gate
cannot repair it by design. Recover as follows:

1. The operator opens a single-purpose pull request that touches only
   `guard.lock` and `scripts/guard`.
2. A second person reviews it by hand, or the operator records the review in
   the pull request.
3. It is merged with a merge commit. The next pull request must pass the normal
   gate.

## Release procedure

1. Merge the change into `main` of agent-ratchet and wait for green CI.
2. Create an annotated tag `v3.x.y` on `main` (`git tag -a v3.x.y -m ...`) and
   push it. Record the SHA the tag peels to (`git rev-parse v3.x.y^{commit}`).
3. In each consumer, open a lock-bump pull request that sets `guard.lock` to
   that SHA (and refreshes `scripts/guard` if `consumer/guard` changed).
4. Before bumping, run the differential tool below against the consumer. Once
   a consumer has adopted `guard.lock` it no longer has `scripts/audit/*`, so
   compare the old pin with the new one:
   `--legacy-cmd "uvx --quiet --from git+https://github.com/dpopek/agent-ratchet@OLD guard-core --expect-sha OLD"`,
   where `OLD` is the SHA currently in the consumer's `guard.lock`. Use the
   `guard-core` command here: a 3.0.x pin has no `agent-ratchet` command.

Never move or delete a `v3.*` tag and never rewrite `main`: every pinned SHA
must stay fetchable.

## Upgrading to 4.x

Agent-ratchet 3.2.0 and earlier reject any `EXTRAS` line in `guard.lock` and
know only `v3.*` release tags. A base that old cannot verify a lock that uses
either, so move in separate pull requests, in this order:

1. Bump `guard.lock` to 3.3.0, SHA only (one line, no `EXTRAS`).
2. Bump to 3.4.0.
3. Pin `v4.0.0`, still without `EXTRAS`.
4. In a separate pull request, add `EXTRAS=none|php|magento` and the matching
   profile. Values other than `none` require a `v4.x.y` release.

Never add `EXTRAS` in the same PR that moves the base off ≤ 3.2.0.

## Versions

The package version (`agent-ratchet version`, `agent_ratchet.__version__`,
`agent_ratchet.version.VERSION`) and `RULES_VERSION` (still
`2.3.3`) are separate. `RULES_VERSION` names the rule identifiers, thresholds
and detection algorithms, not byte-identical findings: the scope of an
exemption can change without a rules bump. For example, 3.2.0 skips files named
like guard modules only under `scripts/audit/`, and files named like guard
tests only under `tests/`; elsewhere they are scanned.

`agent_ratchet.version.GUARD_VERSION` is a deprecated alias of `VERSION` and is
removed in 4.0. (The `GUARD_VERSION` exported by `git_guard_io` and
`refactoring_guard` is a separate alias of `RULES_VERSION`, also removed in 4.0.)

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
- The clone's `origin/*` refs mirror the consumer's remote-tracking refs as
  last fetched, and the `--require-base-ref` case judges against them. Fetch
  the consumer first.
- Cases: `scan --staged-only`, `scan --commit-range HEAD~N..HEAD`,
  `baseline-integrity --enforce-policy-isolation`, and
  `baseline-integrity --require-base-ref --enforce-policy-isolation --commit-range HEAD~N..HEAD`.
  Add path-scan cases with a repeatable `--extra-scan-args "<args>"`.
- Legacy runs `python3 scripts/audit/<script>.py`; agent-ratchet runs via
  `uvx --from <new-from> agent-ratchet --expect-sha <guard-sha>`. Override
  `--new-from` with any uvx spec, for example `git+file:///path/to/agent-ratchet@<sha>`
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
  `scripts/audit/guard_manifest.json changed; agent-ratchet 3 is pinned by guard.lock`.
- **Baseline version bumps.** A baseline version change that relied on a
  manifest-based migration is now reported as
  `Baseline version changed without authorized migration`, because those
  migrations were removed.

Both disappear once a consumer has adopted `guard.lock` and its ranges no
longer contain 2.x manifest commits. Any other differing line is a regression.

## License

MIT, see `LICENSE`.
