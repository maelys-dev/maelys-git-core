<!-- maelys-cli:begin -->
# Maelys CLI framework (maelys-cli 0.5.1)

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
- `describe COMMAND_ID` is minimal; `describe --summary` lists everything.
  A descriptor with `available: false` names a command this build cannot
  run (`unavailableReason`). Operands may carry `type` and `choices` like
  options; `input.constraints` includes `requires`, `at-most-one` and
  `all-or-none` groups.
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
   `_OPERAND_REST`, `_OPERAND_CHOICE`, `_OPERAND_KIND`; `MAELYS_CLI_FLAG`,
   `_STRING`, `_PATH`, `_ABSOLUTE_PATH`, `_UNSIGNED`, `_INTEGER`, `_SIZE`,
   `_DURATION`, `_CHOICE`, `_HEX`, `_HEX_OR`, `_DIGEST`) plus `.required`,
   `.repeatable`, `.depends_on`, `.depends_on_all`, `.conflicts_with`,
   `.group` (all-or-none) and `.default_text` (validated at startup, returned
   by the typed accessors: never repeat a default in the handler); a command
   this build cannot provide declares `.unavailable = "reason"`;
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
dependencies, operands, files, syntax, schema, state); explicit
`MAELYS_CLI_WRITE_REPLACE` / `MAELYS_CLI_WRITE_NO_REPLACE` on every file
write; external programs started with absolute paths and `execve`, never a
shell or PATH lookup.
<!-- maelys-cli:end -->
