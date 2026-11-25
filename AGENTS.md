# AGENTS.md

Notes for coding agents working on agent-ratchet.

## Operational notes

- [verified] PHP suppression rows differ per tool. PHPCS reads a block comment row by row, so the directive's own row decides. PHPStan reads the comment as one token:
  - `@phpstan-ignore-line` covers the comment's end row.
  - An identifier ignore covers the start row when code precedes the comment, the end row when code follows it, and otherwise the next row.

  The rule lives in `php/directives._ignored_row`. It was probed on PHPCS 3.13.5 and 4.0.4 and on PHPStan 2.3.6.
- [verified] tree-sitter-php parses `new class {}` as `anonymous_class`. Its methods get the symbol `<ns>\class@anonymous#<k>::<method>`, where `k` is the class's position in file order.
- [verified] `--config-file` / `AGENT_RATCHET_CONFIG` is a deliberately unprotected, local-only mode (see README). `external_config.activate_cli` resets the override on every run.
- [verified] fleet/ never imports agent_ratchet; parity with the core lives in tests/test_fleet_parity.py.
- [verified] `transition_scan` imports `php.scan` and `magento.scan` only inside the two profile G-blocks in `_evaluate_transition`. A top-level or ungated import makes them core again, and every PHP-only release would then bump every consumer (`tests/test_fleet_refinement_layout.py`).
