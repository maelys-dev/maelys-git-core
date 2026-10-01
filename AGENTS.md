# Working with Maelys Git Core

The five programs (`maelys-git`, `maelys-git-agent`, `maelys-git-executor`,
`maelys-git-shell`, `maelys-git-hook`) are built on the shared Maelys CLI
framework, `libmaelys_cli` (sibling repository `maelys-cli`). The framework
owns argument parsing, `help`, `version`, `describe`, rendering and exit
codes; this repository only declares catalogs and writes handlers.

Before invoking or changing a public CLI command, run
`BINARY describe --summary --format json --compact --non-interactive`, then
inspect the selected command with
`BINARY describe COMMAND_ID --format json --compact --non-interactive`.
Treat `input` and `outputSchema` as one public contract.

For automated calls, use `--format json --non-interactive`. Exit code `0`
means success, `1` means execution failure, and `2` means a validation command
completed and found violations. Success data belongs only on stdout; failures
belong only on stderr. An authorization denial is a successful read with
`data.allowed: false`.

Transactional commands plan by default and write only with `--apply`. Review
the plan and its preconditions before repeating the same invocation with
`--apply`. `--dry-run` and `--plan` are invalid because omission of `--apply`
already selects the plan.

Never pass output-rendering flags to commands whose `outputMode` is
`protocol-stream`. Their stdout belongs exclusively to the declared
`protocol`: Git smart protocol, hook JSONL, or `maelys-git-agent/1`.

When adding or changing a command, update in the same change:

1. the catalog entry, declared with the `MAELYS_CLI_*` macros in
   `src/cli/admin.c` (maelys-git), `src/cli/agent.c` (agent and executor),
   `src/cli/shell.c` or `src/cli/hook.c`;
2. the handler in the same file, which reads its input only through the
   `maelys_cli_*` accessors and replies exactly once;
3. the output schema in `schemas/COMMAND.json`, embedded at build time by
   `maelys-cli-embed` and referenced through `maelys_git_schema_*`;
4. the focused tests in `tests/test_cli.c` and the relevant integration
   script under `tests/`.

Then regenerate `docs/cli.md` and `docs/cli-contract.json` with
`cmake --build build --target generate-cli-reference` (the framework's own
`maelys-cli-reference` generator) and run the full CTest suite; the
`maelys-git-cli-docs` test rejects any drift. Follow
`docs/command-conventions.md` for the normative contract.

<!-- maelys-cli:begin -->
<!-- SPDX-License-Identifier: CC-BY-4.0
Copyright 2026 David Bromberg.
Source: https://github.com/maelys-dev/maelys-cli/blob/main/share/agents/instructions-block.md
License: https://creativecommons.org/licenses/by/4.0/
When sharing adaptations, retain attribution and indicate your changes.
-->

# Maelys CLI framework (maelys-cli 0.5.30, da330c7)

This project builds its command-line interface on `libmaelys_cli`. The
complete guide is in `docs/maelys-cli-guide.md`; this block is the summary
that must hold for every change.

## Using a Maelys CLI from an agent

- Start with `PROGRAM describe --summary --format json --compact --non-interactive`,
  then `PROGRAM describe COMMAND_ID --format json` before invoking a command.
  Treat `input` and `outputSchema` as one public contract; never build a call
  from the human help text.
- Always pass `--format json --non-interactive` in automation. `--json` is an
  exact alias of `--format json`; `--compact` keeps one line.
- Exit `0` is success, `1` is an execution failure, `2` is a completed
  validation report that found violations. Success data is on stdout only;
  failures are a JSON envelope on stderr with a stable `error.code` and an
  actionable `error.hint`.
- Transactional commands plan by default and write only with `--apply`.
  Review the plan, then repeat the same invocation with `--apply`.
  `--dry-run` and `--plan` are rejected.
- Never pass rendering flags to a command whose `outputMode` is
  `protocol-stream`; its stdout belongs to the declared protocol. Set
  `MAELYS_CLI_FORMAT=json` in the environment to receive its failure
  envelope as JSON on stderr.
- `describe COMMAND_ID` is minimal; `describe --summary` lists everything;
  `describe --summary --prefix NAMESPACE` lists one namespace.
  A descriptor with `available: false` names a command this build cannot
  run (`unavailableReason`). Operands may carry `type` and `choices` like
  options; `input.constraints` states `requires`, `at-most-one`,
  `exactly-one` and `all-or-none` rules; `exactly-one` has no other site.
- `PROGRAM completion bash|zsh|fish` prints the shell completion generated
  from the catalog.
- Unknown, duplicated or foreign options are refused. Fix the invocation
  instead of retrying it.

## Adding or changing a CLI action

One command is one entry of the central catalog (`maelys_cli_command_t`),
one handler and one JSON Schema file. In the same change, update:

1. the catalog entry, written with the declaration macros
   (`MAELYS_CLI_READ`, `_RECORDS`, `_TRANSACTION`, `_EXECUTE`, `_STREAM`,
   `_PROTOCOL_STREAM`, `_EXTERNAL`; `MAELYS_CLI_OPERAND`, `_OPERAND_OPTIONAL`,
   `_OPERAND_REST`, `_OPERAND_CHOICE`, `_OPERAND_KIND`, an operand typed
   like an argument with `.hex_digits`, `.choices`, `.pattern`; `MAELYS_CLI_FLAG`,
   `_STRING`, `_PATH`, `_ABSOLUTE_PATH`, `_UNSIGNED`, `_INTEGER`, `_SIZE`,
   `_DURATION`, `_CHOICE`, `_HEX`, `_HEX_OR`, `_DIGEST`) plus `.required`,
   `.repeatable`, `.depends_on`, `.depends_on_all`, `.conflicts_with`,
   `.group` (all-or-none), on the command `MAELYS_CLI_CONSTRAINTS` of
   `MAELYS_CLI_CONSTRAINT(kind, options)` for `exactly-one`, `at-most-one`
   and `requires` over several options (spec 2.5; never validated in the
   handler), and `.default_text` (validated at startup, returned
   by the typed accessors: never repeat a default in the handler;
   `MAELYS_CLI_DEFAULT_OF(LIB_CONSTANT)` when the library owns the value); a command
   this build cannot provide declares `.unavailable = "reason"`; a product
   with build variants composes its catalog at startup with
   `maelys_cli_catalog_concat()` (a later part may only replace an
   `.unavailable` declaration of the same identifier; anything else is
   `EEXIST`);
2. the output schema: a JSON Schema file under the project's schema
   directory, embedded by `maelys-cli-embed` and referenced with
   `MAELYS_CLI_SCHEMA(symbol)`; never a hand-escaped C string;
3. the handler, which reads only through `maelys_cli_operand*()`,
   `maelys_cli_option*()` and `maelys_cli_flag()` (typed kinds replace
   hand validation of paths, digests and choices), replies exactly once
   through `maelys_cli_succeed*()`, `maelys_cli_emit_record*()` +
   `maelys_cli_finish_records()` or `maelys_cli_fail*()`, and tests
   `maelys_cli_replied()` after a helper that may have replied; optional
   helper programs are found with `maelys_cli_resolve_helper()`;
4. focused tests: accepted and refused inputs, plan without write, `--apply`
   with write, error codes and exit codes, `describe COMMAND_ID` exposing the
   exact contract;
5. the generated CLI reference when the project keeps one.

A product written in Python builds on `python/maelys_cli.py` of the same
pinned maelys-cli (one file, standard library only): the same declarations
(`cli.read`, `cli.records`, `cli.transaction`, `cli.stream`, `cli.external`;
`cli.operand`, `cli.option`, `cli.flag`, `cli.argument`), the same built-ins,
envelopes and exit codes; `docs/python.md` is its guide and the conformance
kit of agent-cli-spec runs on the product's program in its CI.

Linking: a product CLI links `libmaelys_cli.a` only (no dependency). A
dispatcher that runs external commands from manifests adds
`libmaelys_cli_extension.a` and one `libmaelys-json.a` (pkg-config
`maelys-cli-extension`, CMake `maelys::cli_extension`); never embed a
dependency archive into your own `.a`. Reading untrusted JSON is
maelys-json's job, not the framework's; the framework only writes JSON
and refuses invalid UTF-8 in what it writes.

Rules that must not be broken: no second usage string outside the catalog; no
hand-written argv parsing in `main()`; no product type inside the shared
framework; validation errors in causal order (command, options, values,
dependencies, operands, files, syntax, schema, state); configuration,
manifests and secrets read with `maelys_cli_read_trusted_file` (trust judged
on the descriptor read, bounded by the bytes read) and failures reported
with `maelys_cli_fail_file`; explicit
`MAELYS_CLI_WRITE_REPLACE` / `MAELYS_CLI_WRITE_NO_REPLACE` on every file
write; external programs started with absolute paths and `execve`, never a
shell or PATH lookup, with a trusted immediate parent held open through exec;
delegate scripts use a direct absolute interpreter never named `env`; relative
and `env` shebangs are refused.
<!-- maelys-cli:end -->

<!-- maelys-release:begin -->
<!-- SPDX-License-Identifier: CC-BY-4.0
Copyright 2026 David Bromberg.
Source: https://github.com/maelys-dev/maelys-release/blob/main/share/agents/conventions-block.md
License: https://creativecommons.org/licenses/by/4.0/
When sharing adaptations, retain attribution and indicate your changes.
-->

# Maelys repository conventions (maelys-release)

This repository follows the shared Maelys conventions without publishing
through the maelys-release workflows: its release mechanism is its own. The
rules below hold whatever that mechanism is; the complete conventions are in
`docs/conventions.md` of maelys-release.

- These conventions are installed by `bin/maelys-release adopt` of
  maelys-release and verified by `maelys-release check DIR` (exit 2 on any
  violation). The block between the `maelys-release` markers of `AGENTS.md`
  and `CLAUDE.md` is regenerated: never edit it by hand. Everything else here
  belongs to this repository. The command follows agent-cli/v2: `--format
  json` everywhere, `describe` for the catalog, and `--field NAME` to read
  one member of the result without a `jq` expression.
- `check` reports two verdicts. The conventions apply to this repository; the
  release mechanism of the socle does not, so `check` says nothing about
  `.github/workflows/release.yml`, which this repository owns entirely.
- A version is `X.Y.Z` in `VERSION`, and a release is a signed, annotated tag
  `vX.Y.Z` on `main` whose commit carries that `VERSION` and a dated
  `CHANGELOG.md` entry `## X.Y.Z — YYYY-MM-DD`. A published tag is never
  moved, recreated or force-pushed; a failed publication is replayed on the
  existing tag.
- Never push a tag before this repository's own checks pass on that exact
  commit, and never publish from a branch. `maelys-release cut DIR X.Y.Z
  --apply` holds both rules: it writes `VERSION`, commits it signed on
  `release/vX.Y.Z`, opens the pull request and waits for its checks, and
  `cut DIR X.Y.Z --tag --apply` then signs the tag on the merge commit
  those checks ran on. It never merges its own pull request.
- A branch is named after the change it carries, with the prefix that
  change would take in a commit message (`fix/`, `docs/`, `release/`…),
  never after the tool that created it: a name says what changes, not who
  typed. No list is closed; the commit prefixes this repository already
  uses are its vocabulary.
- `RELEASING.md` states how this repository publishes. The socle writes it
  once if it is missing, then it belongs to this repository: it is the place
  to describe the mechanism the socle does not provide here.
- `LICENSING.md` states what each part of this repository is licensed under,
  and names every document it engages publicly. `SECURITY.md` states how to
  report a vulnerability.
- `docs/` carries what a machine writes and what this repository engages
  publicly, and no other prose. Where the prose lives is not named from this
  repository's files, which a public reader may see: do not name a
  documentation repository here. A private repository that wants the name
  declares `[docs] named` in `maelys-release.conf`.
- Never commit a secret, a token or a signing key.
<!-- maelys-release:end -->
