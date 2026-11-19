# agent-ratchet

Shared quality and refactoring guards for Python repositories: the AI-slop
scanner and the test-baseline integrity check, extracted from the in-repo guard
(2.3.3) that consumers used to vendor under `scripts/audit/`. agent-ratchet ships
it as one installable package with no runtime dependencies.

Renamed from `guard-core` in 3.1.0 (the PyPI name belongs to an unrelated
project). The old names were removed in 4.0: `import guard_core` raises
`ModuleNotFoundError`, and the `guard-core` command and `python -m guard_core` are
gone. The old GitHub URL redirects. See the 3.1.0 upgrade notes in `CHANGELOG.md`.

## Commands

    agent-ratchet [--expect-sha SHA] scan ...
    agent-ratchet [--expect-sha SHA] baseline-integrity ...
    agent-ratchet [--expect-sha SHA] version [--sha]
    agent-ratchet migrate-imports [--write] [PATH ...]

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

## Guard fixture exemptions

Test files that contain deliberate slop (guard fixtures) are exempt only when listed in the
protected config, `scripts/audit/audit_guard_config.json`:

```json
{"self_skip": {"fixture_paths": ["tests/ci/test_ai_slop_scanner.py"]}}
```

Rules:

- Each entry is an exact repo-relative POSIX file path starting with `tests/`. No empty, `.` or
  `..` segment, no trailing `/`, no `\`, none of `*?[`, and no duplicates. Anything else, a
  non-list value, a non-object `self_skip` or an unknown key inside it is a config error (exit 2).
- Vendored guard modules under `scripts/audit/` stay exempt by name, as before. No name-based
  exemption under `tests/` exists any more (the built-in `GUARD_TEST_NAMES` list is gone).
- The effective set in a base-to-target run is the intersection of the base and target lists, so
  a file added to the list is still scanned in the change that adds it. Without a base, the
  target list applies.
- Adding an entry is reported as `self_skip.fixture_paths entry added: '<path>' (widens the
  self-skip exemption)`. Removing entries is allowed.

Migration order: add `fixture_paths` while still pinned to any 3.x (3.x ignores unknown keys),
merge, then bump to 4.0. Under a 4.0 base the list can only shrink.

## Analysis profile

`scripts/audit/audit_guard_config.json` may request an analysis profile:

```json
{"languages": ["php"], "frameworks": ["magento"]}
```

- `languages` accepts `php`; `frameworks` accepts `magento`. Each is a list of unique values;
  anything else is a config error (exit 2). Both default to empty. `frameworks: ["magento"]`
  requires `languages: ["php"]`.
- A requested profile needs its extra installed: `php` needs `agent-ratchet[php]`, `magento` needs
  `agent-ratchet[magento]`; `magento` also requires the PHP modules. Pair it with the same `EXTRAS=php|magento` line
  in `guard.lock`, in two pull requests: first only `EXTRAS=php|magento` in `guard.lock` (merge it), then
  `languages`/`frameworks` in the config. One PR with both always exits 2 in CI, because CI runs the
  base lock (`--lock-from origin/main`) and the base has no `EXTRAS` yet. Without the extra, `scan` and `baseline-integrity` fail closed with exit 2:
  `profile 'php' requires agent-ratchet[php] (set EXTRAS=php in guard.lock)`.
- Since 4.1 the `php` profile runs PHP rules (below); `magento` adds no rules of its own yet.
  Removing an entry later is a finding, so add it only when you plan to keep it.
- Supported for extras: CPython 3.11–3.14 on Linux x86-64 and macOS arm64. On 3.15 `tree-sitter`
  builds from sdist (best-effort).
- Removing an entry from either list is reported (`languages entry removed: 'php' (narrows the
  analysis profile)`); adding one is allowed.
- Unknown top-level keys are a config error. Allowed: `extra_slop_rules`, `legacy_loc_waivers`,
  `import_roots`, `self_skip`, `languages`, `frameworks`, `php_paths`, `php_suppression_exceptions`.

### PHP rules

With `languages: ["php"]` (or `frameworks: ["magento"]`), `scan` compares base and target for each
changed `.php` / `.phtml` file in scope. PHP is parsed with tree-sitter; no PHP binary or Composer runs.
File-scan mode (no ref) is unchanged: the rules are diff-based.

What is detected (directives are read only from comments):

- Suppression directives for phpcs (`phpcs:ignore`, `phpcs:disable`/`enable`, `phpcs:ignoreFile`, legacy
  `@codingStandardsIgnore*`), phpstan (`@phpstan-ignore*`), psalm (`@psalm-suppress`) and PHPMD
  (`@SuppressWarnings(...)` on a class-like or function declaration). PHPCS keywords
  follow PHPCS's own prefix rules (`phpcs:disabled` is a `disable`); any other unrecognized `phpcs:<word>`
  counts as a suppression too.
- `php_suppression_added`: more directives of the same kind, codes and symbol than before.
- `php_suppression_rebound`: a directive now applies to different code than in base.
- `php_suppression_anchor_unknown`: a new or changed directive whose target cannot be determined.
- `php_suppression_range_expanded`: a `phpcs:disable` window now covers code that was outside it, or
  was widened or left unclosed. Editing code under an unchanged window is not an expansion.
- `php_test_removed` and `php_test_weakened`: PHPUnit tests removed, or with fewer assertions or `expects()`
  calls, lost expected exceptions or data providers, or more skips and incompletes. A pure rename passes.
- `php_parse_degraded` (exit 2): a changed symbol has a syntax error in the target.

Removing a suppression, closing a window, or adding tests always passes. Renames and moves are paired, so a
moved file or renamed method keeps its existing directives.

Scope and exceptions in `scripts/audit/audit_guard_config.json`:

```json
{
  "languages": ["php"],
  "php_paths": ["app/code/", "src/"],
  "php_suppression_exceptions": [
    {"path": "src/Legacy/Foo.php", "symbol": "App\\Legacy\\Foo::bar", "tool": "phpcs",
     "codes": ["Generic.Files.LineLength"], "reason": "generated table, reviewed"}
  ]
}
```

- `php_paths`: repo-relative directory prefixes ending in `/`; same path rules as `fixture_paths`. Default
  `["app/code/", "app/design/", "packages/", "src/"]`. A file is in scope when it ends in `.php` or `.phtml`,
  starts with one of the prefixes and has no `vendor` or `generated` path segment. Removing an entry is
  reported (`php_paths entry removed: '<p>' (narrows PHP analysis scope)`); adding one is allowed.
- `php_suppression_exceptions`: entries with exactly `path`, `symbol`, `tool`, `codes` (list) and a non-empty
  `reason`. An entry silences the matching added, rebound or range-expanded finding only if the same entry is
  already in the base config; an entry added in the same change has no effect. Malformed or duplicate entries
  are a config error (exit 2).
- Configs of PHP quality tools (phpstan, phpcs, phpunit, psalm, phpmd, php-cs-fixer, rector, captainhook)
  are protected governance files. A change touching them together with PHP code is rejected; make it in a
  separate change.

#### External config

For a local run without committing anything to the repository, `scan` and `baseline-integrity` accept
`--config-file PATH` (or `AGENT_RATCHET_CONFIG`; the option wins). That file, with the same schema as
`audit_guard_config.json`, is used for both base and target; in-repo configs are ignored and config
monotonicity is not checked. The file must exist, lie outside the repository, and not be writable by group or
others (POSIX), otherwise the run exits 2. `php_suppression_exceptions` in it apply as written. Lock checks are
skipped when the repository has no `guard.lock`. Each run prints `note: using external config <path>` to
stderr. This offers no CI protection and is only as safe as the file's permissions.

## Migrating off guard_core

The `guard_core` package was removed in 4.0; run this migration before bumping to 4.0. Through the shim:

1. `scripts/guard migrate-imports` lists what is pending (exit 0: nothing).
2. `scripts/guard migrate-imports --write` rewrites the import statements.
3. Fix the `manual-import` and `manual-runtime` items by hand, for example
   `-m guard_core` to `-m agent_ratchet`.
4. Re-run step 1 until it exits 0 (1: pending items, 2: errors).

Exact or runtime-looking `guard_core` strings (`"guard_core"`, `"guard-core"`,
`"guard_core.x"`, `-m guard_core`) are manual items (exit 1). Other strings and
comments are `mention` items: reported only, no effect on the exit code.

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
annotated `v3.x.y`/`v4.x.y` release tag that descends from the previous pin).

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
executes, so it is gated. Adding or removing `EXTRAS=none`, or a trailing
newline, on the same SHA is semantically no change and is not gated: the shim
and the engine read it identically.

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
   `--legacy-cmd` applies only when `OLD` is a 3.0.x pin; 4.x has only `agent-ratchet`.

Never move or delete a `v3.*` or `v4.*` tag and never rewrite `main`: every
pinned SHA must stay fetchable.

## Upgrading to 4.x

Agent-ratchet 3.2.0 and earlier reject any `EXTRAS` line in `guard.lock` and
know only `v3.*` release tags. A base that old cannot verify a lock that uses
either, so move in separate pull requests, in this order:

1. Bump `guard.lock` to 3.3.0, SHA only (one line, no `EXTRAS`).
2. Bump to 3.5.x and run `scripts/guard migrate-imports --write .` (see
   "Migrating off guard_core" above).
3. Under 3.5.x, add `self_skip.fixture_paths` to the config and remove any top-level keys
   outside the allowed set; merge. An invalid entry added under 3.x makes the base config fail
   to parse (exit 2) after the bump, so fix it while still on 3.x. Skipping this step is
   irreversible: under a 4.0 base, adding entries is a finding.
4. Pin `v4.0.0`, still without `EXTRAS`. A repository without PHP stops here: a missing
   `EXTRAS` line means `none`, so writing `EXTRAS=none` changes nothing.
5. PHP or Magento repositories only: in a separate pull request, add `EXTRAS=php|magento`
   to `guard.lock`; merge. These values require a `v4.x.y` release. In 4.0 the extras run
   no rules yet (see "Analysis profile").
6. In a later pull request, add the matching `languages`/`frameworks` profile. CI runs the
   base lock, so a profile added together with its `EXTRAS` always exits 2.

Never add `EXTRAS` in the same PR that moves the base off ≤ 3.2.0.

## Versions

The package version (`agent-ratchet version`, `agent_ratchet.__version__`,
`agent_ratchet.version.VERSION`) and `RULES_VERSION` (still
`2.3.3`) are separate. `RULES_VERSION` names the rule identifiers, thresholds
and detection algorithms, not byte-identical findings: the scope of an
exemption can change without a rules bump. For example, 3.2.0 skips files named
like guard modules only under `scripts/audit/`, and files named like guard
tests only under `tests/`; elsewhere they are scanned (4.0: replaced by `self_skip.fixture_paths`).

Setting `AGENT_RATCHET_SHADOW=1` makes a run print one
`agent-ratchet shadow: ...` line to stderr. Stdout and the exit code do not
change; any other value leaves it off.

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
