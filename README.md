# Maelys Git Core

Maelys Git Core is a small C11 authorization and repository layer built around
Git and [Maelys Datalog](../maelys-datalog). It deliberately delegates Git
object storage, locking, transport and reference transactions to the Git
executable. No user-controlled command is passed to a shell.

The project is a security-oriented foundation. Its current capabilities are:

- strict parsing of `SSH_ORIGINAL_COMMAND` for `git-upload-pack` and
  `git-receive-pack`;
- canonical repository-root confinement, including symlink escape checks;
- fail-closed authorization through versioned Maelys Datalog manifests;
- streamed multi-ref `pre-receive` authorization by update kind, commit, path
  operation and transaction summary;
- bare repository creation and compare-and-swap `git update-ref` operations;
- idempotent local bare mirroring with reviewed identity/ref preconditions;
- a same- or cross-repository PR core with isolated object quarantine, bounded
  source imports, deterministic FF/merge/squash plans, Datalog reauthorization
  and compare-and-swap;
- deterministic, atomic compilation of forced-command `authorized_keys`;
- a strict, versioned JSON protocol read with bounded maelys-json documents;
- a durable SQLite command journal, idempotency table, audit log and outbox;
- a persistent HTTPS/1.1 Cloud agent built on Maelys HTTP and Maelys System;
- a separate, time-bounded Git executor process;
- an administrative CLI for validation, authorization and repository work;
- an executable CLI catalog on the shared `maelys-cli` framework, for agent
  discovery and generated documentation.

## Build

The default Cloud-enabled layout expects these repositories to be siblings:

```text
GitHubDocuments/
├── maelys-cli/
├── maelys-datalog/
├── maelys-json/
├── maelys-http/
├── maelys-system/
└── maelys-git-core/
```

Build and test with:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build
ctest --test-dir build --output-on-failure
```

For a different Datalog checkout, pass
`-DMAELYS_DATALOG_SOURCE_DIR=/absolute/path/to/maelys-datalog`. The CLI
framework is taken from an installed `maelys-cli` (found through
`find_package(maelys-cli)`) or, by default, built from the sibling source
tree named by `MAELYS_CLI_SOURCE_DIR` through its own CMake project. SQLite 3 is required. The
default Cloud agent also requires Maelys HTTP, Maelys System and mbedTLS; it
can be excluded with `-DMAELYS_GIT_ENABLE_CLOUD_AGENT=OFF`.
Both configurations run the CLI reference check. The generated reference
describes the complete product; `describe` reports actual build availability.
`-DMAELYS_GIT_WERROR=ON` turns the warning set into errors, as CI does.
The tested dependency commits and versions live in `cmake/dependencies.cmake`.
CMake exports those commits from the sibling repositories into the build
directory; local edits and later commits in those siblings do not silently
change this build. Versioned source distributions are also accepted. For
intentional dependency development, `-DMAELYS_GIT_ALLOW_UNPINNED_DEPS=ON`
uses the working trees instead. An installed CLI package must match the
recorded version exactly. HTTP/System objects are also private to each build,
and inherit its compiler and sanitizer flags. Project headers take precedence
over older installed headers in `CPPFLAGS`.
Only the dependency-free core of `maelys-cli` is linked; its extension
archive and `maelys` dispatcher are not built here. maelys-json is the one
JSON library: it reads every external document and writes the CLI data, the
agent messages, the journal's deduplication form and the generated
configuration. It is pinned to the published release recorded in
`cmake/dependencies.cmake` (`v0.3.0`); its source checkout can be selected
with `-DMAELYS_JSON_SOURCE_DIR=/absolute/path/to/maelys-json`.

## Policy model

Every request injects these runtime facts when the associated value exists:

```text
request/1 user/1 repository/1 operation/1 ref/1 path/1 old_path/1
ref_prefix/1 ref_prefix_count/1
repository_segment/2 repository_depth/1 repository_leaf/1
repository_owner_namespace/2
ssh_key/1 remote_address/1 ref_kind/1 update_kind/1 change_kind/1
commit_email/1 commit_signed/1 commit_signature_status/1
commit_signer_fingerprint/1 commit_signer_identity/1 commit_signature_trusted/1
changed_count/1 added_count/1
modified_count/1 deleted_count/1 renamed_count/1 max_new_blob_size/1
has_binary/1
```

For a valid ref, `ref_prefix/1` holds each of its first sixteen prefixes
that end with `/`, shortest first and never the ref itself, and
`ref_prefix_count/1` the number of such prefixes, untruncated:
`refs/heads/a/b` gives `refs/`, `refs/heads/`, `refs/heads/a/` and 3. A
prefix is then matched as a fact, `ref_prefix("refs/heads/release/")`, with no
filter rule. A policy that tests a deeper prefix never sees it and can close
on the count, `deny(R) :- request(R), ref_prefix_count(N), N > 16.` Each of
the two is given only when a policy of the manifest reads it, in a rule body,
negated or as the source of an aggregate, as the engine's view of the
compiled program says at open time; a policy that reads neither pays nothing
for them.

The domain also declares policy facts for direct and group grants, admins,
protected refs and protected paths, and those the Gitolite migration writes:
`gitolite_access/3`, `gitolite_ref_access/4`, their `group_` forms and
`owner_namespace_access/2`. Policies derive `allow(Request)` and/or
`deny(Request)`. An explicit deny wins across the complete policy set. With no
matching allow, the decision is denied by default. Evaluation errors also deny
the operation.

See `policies/example.dl` and `policies/manifest.json` for an executable
example.

```sh
build/maelys-git validate policies/manifest.json
build/maelys-git authorize policies/manifest.json alice example.git read
build/maelys-git authorize policies/manifest.json bob example.git push refs/heads/main
```

For automation, add `--format json --compact --non-interactive`. Authorization
is a successful read even when denied: inspect `data.allowed`. Every decision
also carries `data.receipt`, a bounded record of it in Maelys Canonical JSON
v1, and `data.receiptSha256`; `--explain`, written before `--`, adds the
engine's explanation as `data.explanationText`. The receipt contract is in
[docs/prepared-auth-receipts.md](docs/prepared-auth-receipts.md). Policy
validation exits `2` when it completes and finds violations.

## Normalized CLI contract

All five binaries are applications of `libmaelys_cli`: each declares one
catalog (`src/cli/*.c`) whose output schemas live in `schemas/`, and the
framework provides parsing, `help`, `describe`, rendering and exit codes.
They expose the same `agent-cli/v2` envelope and an executable command
catalog:

```sh
build/maelys-git describe --summary --format json --compact --non-interactive
build/maelys-git describe repo.init --format json --compact --non-interactive
build/maelys-git-agent describe --summary --format json --compact --non-interactive
```

Success data is written only to stdout; structured failures are written only
to stderr. Transactional commands plan without writing and require `--apply`:

```sh
build/maelys-git repo init /srv/git example.git --format json
build/maelys-git repo init /srv/git example.git --apply --format json
```

See `docs/command-conventions.md`, `docs/agent-cli.md`,
`docs/cli-migration.md` and the generated `docs/cli.md`. Regenerate
the Markdown and aggregate JSON catalog
with `cmake --build build --target generate-cli-reference`.

The current Gitolite parity, Forgejo gap and ordered hardening roadmap are
tracked in `docs/gitolite-forgejo-gap.md`.

Local lifecycle administration is available through `repo list`,
`repo inspect`, `repo rename`, `repo archive`, `repo delete`, and
`repo restore`. `repo mirror` plans and synchronizes a complete local bare
mirror with identity and ref/HEAD fingerprints. Destructive-looking delete is
recoverable and never erases Git objects. See `docs/repository-lifecycle.md`.

## SSH forced command

An `authorized_keys` entry can bind an identity to the shell. The user value is
an administrator-controlled argument and is not read from the incoming Git
command:

```text
command="/usr/local/bin/maelys-git-shell serve --user alice --root /srv/git --manifest /etc/maelys-git/manifest.json",restrict ssh-ed25519 AAAA...
```

The shell accepts exactly one quoted repository argument. Repository names are
relative, must end in `.git`, may contain nested components, and cannot contain
traversal segments or shell metacharacters. After authorization it replaces
itself with `/usr/bin/git upload-pack` or `/usr/bin/git receive-pack` using
`execve(2)` and a restricted environment.

## Receive hooks

Install `maelys-git-hook` as the bare repository's `hooks/pre-receive`, normally
through a tiny administrator-generated wrapper that supplies immutable values:

```sh
#!/bin/sh
exec /usr/local/bin/maelys-git-hook \
  pre-receive \
  --manifest /etc/maelys-git/manifest.json \
  --repository example.git \
  --git-dir /srv/git/example.git
```

The forced SSH shell passes the authenticated identity to `git-receive-pack` as
`MAELYS_GIT_PRINCIPAL`; the hook inherits it. The wrapper itself is trusted
configuration. The core hook never builds a shell command. Git change records
are NUL-delimited and spooled through a temporary file, so authorization is not
limited to 64 changed paths. Each path is evaluated in a bounded Datalog
request, followed by a summary request. New commits are likewise streamed and
expose author email, detailed Git signature status, signer
fingerprint/identity and trust facts. Rename records expose both paths, and
binary content plus blob-size summaries are calculated locally before
authorization.

Commit inspection is relative to the destination reference. Creating a ref
checks its entire reachable history, including commits already present on
other refs, under the existing commit quota. Transaction quotas are inclusive:
reaching a limit exactly still permits later refs that consume none of that
remaining resource.

The policy engine is reached through its installed SDK only,
`<maelys/datalog.h>` alone: the engine reads the
manifest and its sources, and nothing here scans or escapes the policy
language. The `maelys_git` domain declares predicates and no constant; the
constants a policy writes stay local to that policy, a filter pattern
(`starts_with`, `ends_with`, `contains`) is policy code and counts against no
vocabulary, and request values live in the session of one evaluation. The
engine's capacities are read from the loaded library: 256 constants of at
most 63 bytes and 128 rules per policy, 64 changed paths per request in the
default size profile. `maelys_git_policy_explain` returns the engine's
witness of a derived allow or deny and, for a denial by default, its
why-false document, which refutes the request when complete and is only a
partial diagnostic when truncated. A test fails if a source file includes
another engine header or if the core library references an engine symbol the
SDK does not declare.

The same binary can be installed as `post-receive` to append versioned JSONL
events for an audit collector or the forge agent:

```sh
exec /usr/local/bin/maelys-git-hook \
  post-receive \
  --repository example.git \
  --events /var/lib/maelys-git/events.jsonl
```

## Agent architecture

The Cloud agent uses two independent, persistent HTTPS/1.1 connections: one
for command long-polling and one for the event/result outbox. WebSocket is not
required by the protocol and can be added later as a transport without changing
command semantics. Redirects are denied, TLS peer and hostname verification are
mandatory, the bearer token is reloaded from a mode-`0600` file for rotation,
and every result POST carries an idempotency key.

```text
Cloudflare Worker / forge
        | HTTPS long-poll + POST
        v
maelys-git-agent        network, token, retry, SQLite journal
        | one bounded JSON command over pipes
        v
maelys-git-executor     Datalog authorization, repository confinement
        | absolute argv, minimal environment, isolated process group; never a shell
        v
Git
```

The SQLite database uses WAL and full synchronization. It records a command
before execution, rejects reuse of an identifier with different content,
recovers interrupted `running` commands as `pending`, commits terminal results
and outbox entries in one transaction, and preserves an append-only audit
table. Delivery is therefore at least once, while command IDs and Git
compare-and-swap make mutation replay safe and observable.

### JSON protocol

Every command is at most 64 KiB and has this envelope:

```json
{
  "protocol": "maelys-git-agent/1",
  "message_id": "command-123",
  "agent_id": "host-paris-1",
  "type": "command",
  "command": "authorize",
  "repository": "example.git",
  "principal": "alice",
  "issued_at_ms": 1760000000000,
  "expires_at_ms": 1760000060000,
  "payload": {"operation": "read", "paths": []}
}
```

The machine-readable schema and transport contract live in `protocol/`.

maelys-json reads command envelopes and the executor validates their typed
payloads. Unknown envelope and command fields fail closed. The reader explicitly
bounds JSON to 65,536 bytes, 32 nesting levels and 32,768 tokens, and rejects
decoded duplicates, U+0000 and invalid Unicode. Integer fields retain their
signed 64-bit ranges and reject fractions and exponents. The message owns its
document throughout execution. maelys-json writes the results, each within
the 65,536-byte line, and the durable deduplication form v2 of each command.
Cloud validates bounded polls before processing their commands. The
supervisor validates and correlates result envelopes before persistence. The
SSH shell and receive hook write only their receipts with maelys-json. See the [protocol contract](protocol/README.md) for framing and limits.

Supported executor commands are:

- `health`;
- `authorize` with `operation`, optional `ref`, a bounded `paths` array and
  optional `explain`, a boolean that adds `explanation_text`; every decision
  result carries `matched_policy`, `receipt` and `receipt_sha256`, which the
  Cloud agent verifies and records in its audit;
- `repository_info`;
- `diff` with `old_oid` and `new_oid`;
- `update_ref` with `ref`, `old_oid` and `new_oid`;
- `create_repository`;
- `pr_check` for read-only merge analysis;
- `pr_merge` for explicit plan/apply, forge-supplied gates, local Datalog
  reauthorization, reviewed prepared-OID/policy-fingerprint preconditions and
  atomic target-ref CAS; optional `pr_id` also records the head and merged
  result under forge-neutral internal Git refs in the same transaction. Both
  commands accept an optional source repository and branch for fork PRs.

`update_ref` uses the same streamed `push` authorization as the receive hook:
ref/update kind, every new commit and signature, per-path details, ref summary
and transaction summary, with the default receive quotas. Only then does it
invoke Git's compare-and-swap update. `pr_merge` uses the
same invariant and repeats authorization immediately before its state change.
Its plan returns a deterministic prepared OID, the Maelys Datalog policy-set
fingerprint and the target repository device/inode identity; apply requires all
three values and recomputes them locally. Normalized
PR events can be persisted by the forge without coupling the C core to its
database. A cross-repository plan also returns the source repository identity;
apply requires it, verifies that the source ref still names the reviewed head,
then promotes only the quarantined source/prepared objects before the atomic
reference transaction. Source traversal defaults to 100,000 reachable objects
and 512 MiB of reachable on-disk object data and can be tightened per command.
PR repositories must have direct `config` and `objects` entries. Object
alternates and repository-local Git settings capable of launching commands or
loading external configuration are rejected before Git reads PR objects.
There is no arbitrary command execution field. Discussion threads, review
history and status-check production remain responsibilities of the forge.

For local protocol testing, run the executor-compatible mode:

```sh
build/maelys-git-agent stdio --manifest policies/manifest.json --root /srv/git
```

### Provision and run

Create the token file first and restrict it to the agent account:

```sh
install -m 600 /dev/null /etc/maelys-git/agent.token
build/maelys-git-agent provision \
  --config /etc/maelys-git/agent.json \
  --agent-id host-paris-1 \
  --authority forge.example.com \
  --ca /etc/ssl/cert.pem \
  --token /etc/maelys-git/agent.token \
  --database /var/lib/maelys-git/agent.sqlite3 \
  --manifest /etc/maelys-git/manifest.json \
  --root /srv/git \
  --executor /usr/local/bin/maelys-git-executor \
  --format json
# Relire le plan, puis reprendre le même appel avec --apply.
build/maelys-git-agent provision \
  --config /etc/maelys-git/agent.json \
  --agent-id host-paris-1 \
  --authority forge.example.com \
  --ca /etc/ssl/cert.pem \
  --token /etc/maelys-git/agent.token \
  --database /var/lib/maelys-git/agent.sqlite3 \
  --manifest /etc/maelys-git/manifest.json \
  --root /srv/git \
  --executor /usr/local/bin/maelys-git-executor \
  --apply --format json
build/maelys-git-agent run --config /etc/maelys-git/agent.json
```

The v1 agent configuration is a flat JSON object with exactly 14 required
scalar fields. maelys-json parses at most 65,536 bytes, including whitespace,
with depth 1 and 29 tokens (root, keys and values). Duplicate decoded keys,
unknown or missing fields, invalid UTF-8, U+0000, BOM and trailing data are
rejected. `version` must be the integer 1; both timeout fields must be integers
from 1,000 through 120,000 milliseconds, without fractions or exponents.
Paths and strings retain their field-specific validation and size limits.

The configuration must be a regular file owned by the agent or root, without
group/world write permission or a final symlink. The loader opens it once,
checks that descriptor with `fstat`, and reads a bounded byte buffer from the
same descriptor. FIFOs and other non-regular files are rejected without waiting
for input. Provisioning writes the configuration with maelys-json, within the
same limits the loader applies.

The Cloud command endpoint returns an exact object shaped as
`{"cursor":"...","commands":[...]}` or HTTP 204. The event endpoint accepts
one result object per POST and should return any 2xx response only after it has
durably accepted the idempotency key.

## Security boundary

The JSON architecture decision in [docs/json-boundaries.md](docs/json-boundaries.md)
maps each reader and writer. Configuration, command envelopes and executor
payload reads, Cloud polls and supervisor result validation now use
maelys-json, and maelys-json alone writes and reads authorization receipts,
command-line data, agent messages and the journal's deduplication form.
Coordinated manifest loading remains planned migration work.

The SSH shell and hook should run under a dedicated Unix account that owns only
the intended repositories. The agent should use a separate service account when
possible. Filesystem permissions remain a second line of defence behind Datalog
authorization.

All core Git subprocesses and each supervised executor receive a minimal
allowlisted environment: only the absolute service-account `HOME` is retained
for signature trust stores; global/system Git configuration, credential prompts
and askpass helpers are disabled. The receive hook validates Git's quarantine
as a direct child of this repository's object directory, and reconstructs its
object-directory environment for the duration of inspection only.
Standalone Git commands run in new process groups. An executor started by the
agent retains its Git children in the group owned by the supervisor; that
group is cleaned up before any terminal result. The deadline covers waiting
for exit even after stdout closes. Executable paths at this
boundary must be absolute.
Internal Git helpers have private stdout/stderr pipes. Diagnostics are drained
concurrently, retained as a bounded printable prefix and included in structured
failures, so child output cannot corrupt a CLI JSON envelope.

CTest includes real pushes, parity between receive-hook and `update_ref`
authorization, process-group/EOF regressions and a loopback HTTPS server that
tests command execution, durable outbox delivery, token rotation, CA/hostname
verification and rejection of redirects. Tests require Python 3 and, with
Cloud enabled, the OpenSSL command-line tool. The policy-session test compares
the prepared path with a test-only fresh-EDB oracle, including A/B/A sequences,
recovery after errors and independent worker threads. CI is configured to run the complete
suite on Linux and macOS, with Cloud enabled and disabled, both normally and
with ASan/UBSan.

This code has not received an external security audit. Before production use,
run the network agent and executor under distinct least-privilege service
accounts (or add a narrow Unix socket handoff), and fuzz the
SSH parser and all external JSON readers and command schemas.
