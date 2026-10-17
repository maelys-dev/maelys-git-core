# Changelog

All notable changes to Maelys Git Core are documented in this file. The
format follows Keep a Changelog; versions follow Semantic Versioning.

## Unreleased

- The policy engine is reached through the installed SDK of maelys-datalog
  v0.22.0 (consumer API 2), `<maelys/datalog.h>` alone, and no longer
  through structures private to the engine, which 0.10.0 removed. The
  `maelys_git` domain declares predicates only; a policy's constants are
  local to it; one session per
  policy lives as long as the handle. Gone: the source scanner that collected
  atoms, its process-wide buffer and load lock, the yyjson read of the
  manifest and the test-only blocks compiled into `policy.c`. The 443
  decisions of a corpus recorded before the change and the fingerprints of
  three policy sets are identical. Load errors now carry the engine's own
  diagnostic: its code, the location in the policy and the capacity exceeded.
- `maelys_git_policy_explain` renders the engine's explanation of a decision:
  the why-true witness of a derived allow or deny, or the why-false document
  of a denial by default with its `complete` or `truncated` status and the
  filter evaluations. A decision carries the policy-set and session
  fingerprints.
- Gitolite migration converts literal ref prefixes into rules with a constant
  `starts_with` pattern: `refs/heads/release/`, a short name completed by
  `refs/heads/`, a final `$` as equality. A deny on a bare literal now covers
  the names that start with it, as Gitolite does and more than the exact fact
  it replaced; a grant on a bare literal stays exact. Regular-expression
  syntax is refused with `unsupported refex syntax`; exceeding the engine's
  128 rules is `rule budget exceeded`; the generated policy is loaded by the
  engine before it is published.
- SHA-256 comes from the public digest of the maelys-cli core instead of a
  header private to the engine repository.
- maelys-datalog pinned at v0.21.0 (from v0.4.0). 0.21.0 answers `OK` and
  zero, instead of `INVALID_STATE`, when a manifest enables no policy; the
  open path already handled both answers with the same message, and the
  engine compacts its internal fact records without changing any public
  record or fingerprint. 0.20.0 reads a policy's
  identifier from the loaded handle (`maelys_datalog_policy_id`), so the
  core includes `<maelys/datalog.h>` and nothing else of the engine; it also
  releases the handle of a manifest whose entries are all disabled, which
  LeakSanitizer reported on Linux. 0.18.0 had sorted the installed headers by
  audience and removed `datalog_advanced.h`.
- The Linux CI image builds Mbed TLS v3.6.7 from source, the release
  maelys-http pins: Ubuntu 24.04 ships 2.28, below the floor maelys-http
  enforces, so the Cloud agent no longer built there since the pin moved to
  v0.1.14. The engine boundary check declares the CMake version it needs;
  CMake 3.28 refused its `IN_LIST` without one.
- The Linux CI image builds Jansson as a static library. Its shared build in
  `/usr/local/lib` shadowed the system `libjansson.so.4` that binutils' `ld`
  loads, and on amd64 every link in the image failed.
- The nested make that builds maelys-system and maelys-http for the Cloud
  agent no longer inherits the outer make's flags. It received jobserver
  descriptors that were not open in it: GNU Make warned and fell back to
  one job, or failed where the descriptor numbers were reused.
- maelys-datalog pinned at v0.23.1 (from v0.22.0). Every capacity
  diagnostic now names the exceeded budget (`limit_kind`, with
  `maelys_datalog_limit_name`), at load and on a refused input batch; 0.23.1
  adds the last one, more than 128 direct policy facts (`MAX_RULE_FACTS`),
  which 0.22.0 refused with an empty diagnostic. The message of that refusal
  is the only policy error message that changes: it now names the line,
  the count and the limit. `maelys_datalog_limit_get` answers
  `INVALID_ARGUMENT` for an unknown identifier; this repository queries known
  ones only.
- maelys-datalog pinned at v0.22.0 (from v0.21.0), maelys-http at v0.1.16
  (from v0.1.15) and maelys-system at v0.13.0 (from v0.11.0).
  maelys-datalog 0.22.0 carries the compatibility freeze of its 0.x public
  contract; for a C consumer it only makes policy accessors answer
  `INVALID_STATE` consistently on a freed caller-owned handle, which this
  repository does not use, and it now installs `maelys-datalog.pc`.
  maelys-http 0.1.16 changes neither its codec, its client nor ABI 1, and
  pins maelys-system v0.13.0, so both move together and still agree.
  maelys-system 0.12 and 0.13 add directory watching and process launching
  and correct socket receives on Unix sockets; this repository calls only
  `maelys_sys_deadline_after`, unchanged.
- maelys-cli pinned at v0.7.0 (from v0.6.0) and maelys-json at v0.3.0 (from
  v0.2.0). **0.7.0 refuses four kinds of line that worked**, and a caller's
  script is where they would be: a size suffix in small letters
  (`--max-source-bytes 512m`; write `512M`), on `pr check`, `pr merge` and
  `pre-receive`; a word that starts with one dash before `--`, so a `REF` or
  a `PATH` of `authorize` that starts with a dash is written after `--`,
  and every option before it; `-h`, which is no longer `--help`; and a
  catalog the contract's schema refuses, which this one is not. `-` alone,
  which `authorize` reads as "no ref", is still an operand. Nothing in this
  repository passed any of the four. maelys-json 0.3.0 (ABI 3) copies a
  non-integral number by its lexeme instead of refusing it and adds
  `maelys_json_writer_number_text`; no call here writes such a number, and
  no caller that succeeded changes result. The framework's managed blocks,
  guide and skill are refreshed to 0.7.0.
- maelys-cli pinned at v0.6.0 (from v0.5.36). The help text is reorganised
  by family and `COMMAND --help --format json` answers as the `help`
  command; `--expect` is a reserved option name on a transaction, which no
  command here declares; the generated contract changes by the framework's
  own wording. Nothing else of the framework is called here; its managed
  blocks, guide and skill are refreshed to 0.6.0.
- maelys-cli pinned at v0.5.36 (from v0.5.30). The generated shell
  completion works again under macOS bash 3.2 and zsh (0.5.34); `--field`
  on a transaction or `run` is refused before execution unless the member is
  in the top-level `required` of the output schema (0.5.36), which every
  schema here declares; `MAELYS_CLI_FORMAT` is the default format. Nothing
  else of the framework is called here; its managed blocks, guide and skill
  are refreshed to 0.5.36.
- maelys-cli pinned at v0.5.30 (from v0.5.29) and maelys-system at v0.11.0
  (from v0.9.1). For this repository the framework differs by its version
  header alone; its managed blocks, guide and skill are refreshed to 0.5.30.
  maelys-system 0.10.0 to 0.11.0 add descriptor passing and fix byte-only
  AF_UNIX receives, none of which is called here: this repository and
  maelys-http use its deadlines only. maelys-http v0.1.14 itself pinned
  maelys-system v0.9.1 and was built here against v0.11.0 until the pin
  below moved.
- maelys-http pinned at v0.1.15 (from v0.1.14). No change to the codec, the
  client or ABI 1: the release moves maelys-http's own pins, and it now pins
  maelys-system v0.11.0, the version this repository builds it against, so
  the two no longer disagree.

- The five Maelys dependencies are pinned to the commits of published tags,
  never to a branch commit that a history rewrite can erase: maelys-cli
  v0.5.29 (from 0.5.11), maelys-json v0.2.0 (from v0.1.3, ABI 2; nothing
  here called the two removed functions), maelys-datalog v0.4.0 (from
  0.1.0-alpha.1, whose pinned commit no longer exists anywhere),
  maelys-http v0.1.14 (from 0.1.4) and maelys-system v0.9.1 (from 0.9.0).
  maelys-datalog stopped exporting its tree root in 0.3.0; until the
  migration to `<maelys/datalog.h>`, the core library and the policy
  sessions test see the pinned root privately for the alpha headers they
  still read. The maelys-cli managed blocks, guide and skill are refreshed
  to 0.5.29 and the CLI reference regenerated with its generator.
- The Cloud transport test server no longer sends `Content-Length` on its
  204 replies: RFC 9110 forbids the field there and maelys-http refuses it
  as ambiguous framing since 0.1.5. A fixture defect, not a product one.
- Adopt the shared Maelys conventions (maelys-release v0.60.0) in
  conventions-only mode: `VERSION`, this changelog, the managed blocks of
  `AGENTS.md` and `CLAUDE.md`, `RELEASING.md` and `LICENSING.md`. The
  release mechanism stays this repository's own.
- The generated CLI reference is `docs/cli.md`, the name every Maelys
  product uses; `docs/cli-contract.json` is unchanged.
- `ci.yml` runs once per pull request: `push` names `main`.

## 0.1.0 — 2026-09-18

First versioned state of the repository, as built on 2026-09-05 (`d192d0f`).

- Fail-closed authorization through versioned Maelys Datalog manifests,
  with policy-aware Git transactions, pull request core, recoverable
  repository lifecycle and selected Gitolite parity.
- Five programs (`maelys-git`, `maelys-git-agent`, `maelys-git-executor`,
  `maelys-git-shell`, `maelys-git-hook`) built on `libmaelys_cli`, following
  the `agent-cli/v2` contract.
- Agent configuration and protocol commands read through bounded
  maelys-json documents; Cloud polls and executor results validated.
- Tested dependency revisions recorded in `cmake/dependencies.cmake`.
