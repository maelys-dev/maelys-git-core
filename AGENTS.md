# Working with Maelys Git Core

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

Never pass output-rendering flags to commands whose `outputMode` is a protocol
stream. Their stdout belongs exclusively to Git, hook JSONL, or
`maelys-git-agent/1`.

When adding or changing a command, update the central catalog in
`src/cli/catalog.c`, the dispatcher, focused tests and any output schema in the
same change. Regenerate `docs/cli-reference.md` and `docs/cli-contract.json`
with `cmake --build build --target generate-cli-reference`, then run the full
CTest suite. Follow `docs/command-conventions.md` for the normative contract.
