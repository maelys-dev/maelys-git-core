# Licensing

Copyright 2026 David Bromberg.

The socle wrote this file once because it was missing. It belongs to this
repository now: state below what each part is licensed under, and name every
document this repository engages publicly. `bin/maelys-platform docs` reads
this file to tell a public engagement from prose that migrates elsewhere.

## Source code: MPL-2.0

The source code of maelys-git-core is available under the Mozilla Public License
2.0. The complete terms are in [`LICENSE`](LICENSE).

The MPL applies file by file. A program that links this code, statically or
otherwise, keeps its own license (section 3.3 of the MPL); only a modified
covered file must remain available in Source Code Form under MPL-2.0.

## Installed agent texts: CC-BY-4.0

The managed blocks of `AGENTS.md` and `CLAUDE.md` are installed from the
Maelys distributions' `share/agents/` texts under CC-BY-4.0, with attribution
to David Bromberg. Their notices identify the source and link to the license:
https://creativecommons.org/licenses/by/4.0/. Retain attribution and indicate
changes when sharing adaptations. This applies to the installed blocks,
not unrelated product-specific content outside them. When adopting another
distribution, check the actual notices of the texts it installs.

## Redistributed material

The built programs link, statically, the pinned sources recorded in
`cmake/dependencies.cmake`: maelys-cli, maelys-json, maelys-datalog,
maelys-http and maelys-system, all under MPL-2.0. maelys-datalog carries
yyjson (MIT, copyright 2020 YaoYuan) in its `vendor/` tree. SQLite
(public domain) is taken from the build host and never redistributed. No release artifact is published yet: the release mechanism
of this repository is not defined (see `RELEASING.md`).

## Documents engaged publicly

`README.md` links `docs/cli.md` (generated), `docs/cli-contract.json`
(generated), `docs/command-conventions.md`, `docs/agent-cli.md`,
`docs/cli-migration.md`, `docs/gitolite-forgejo-gap.md`,
`docs/repository-lifecycle.md`, `docs/json-boundaries.md`,
`docs/prepared-auth-receipts.md` and `protocol/README.md`. They stay in
this repository. The other documents under `docs/` are engineering prose
that is not engaged publicly.
