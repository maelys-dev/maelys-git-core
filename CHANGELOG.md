# Changelog

All notable changes to Maelys Git Core are documented in this file. The
format follows Keep a Changelog; versions follow Semantic Versioning.

## Unreleased

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
