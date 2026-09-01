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
- a same-repository PR core for conflict checks, deterministic FF/merge/squash
  plans, policy-set preconditions, Datalog reauthorization and compare-and-swap;
- deterministic, atomic compilation of forced-command `authorized_keys`;
- a strict, versioned JSON protocol implemented with Jansson;
- a durable SQLite command journal, idempotency table, audit log and outbox;
- a persistent HTTPS/1.1 Cloud agent built on Maelys HTTP and Maelys System;
- a separate, time-bounded Git executor process;
- an administrative CLI for validation, authorization and repository work;
- a Hermes-inspired executable CLI catalog for agent discovery and generated
  documentation.

## Build

The default Cloud-enabled layout expects these repositories to be siblings:

```text
GitHubDocuments/
├── maelys-datalog/
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
`-DMAELYS_DATALOG_SOURCE_DIR=/absolute/path/to/maelys-datalog`.
Jansson >= 2.14.1 and SQLite 3 are required. The default Cloud agent also
requires Maelys HTTP, Maelys System and mbedTLS; it can be excluded with
`-DMAELYS_GIT_ENABLE_CLOUD_AGENT=OFF`.

## Policy model

Every request injects these runtime facts when the associated value exists:

```text
request/1 user/1 repository/1 operation/1 ref/1 path/1 old_path/1
ssh_key/1 remote_address/1 ref_kind/1 update_kind/1 change_kind/1
commit_email/1 commit_signed/1 commit_signature_status/1
commit_signer_fingerprint/1 commit_signer_identity/1 commit_signature_trusted/1
changed_count/1 added_count/1
modified_count/1 deleted_count/1 renamed_count/1 max_new_blob_size/1
has_binary/1
```

The domain also declares policy facts for direct and group grants, admins,
protected refs and protected paths. Policies derive `allow(Request)` and/or
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
is a successful read even when denied: inspect `data.allowed`. Policy
validation exits `2` when it completes and finds violations.

## Normalized CLI contract

All five binaries expose the same Hermes-inspired `agent-cli/v2` envelope and
an executable command catalog:

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
`docs/cli-migration.md` and the generated `docs/cli-reference.md`. Regenerate
the Markdown and aggregate JSON catalog
with `cmake --build build --target generate-cli-reference`.

The current Gitolite parity, Forgejo gap and ordered hardening roadmap are
tracked in `docs/gitolite-forgejo-gap.md`.

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
        | argv through posix_spawn/execve; never a shell
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

Jansson parses exact schemas with duplicate-key rejection. Unknown envelope and
command fields fail closed. Jansson is a good fit here because it is a small C
library already used by the surrounding Maelys projects, supports bounded
buffer parsing and preserves 64-bit JSON integers. It is deliberately kept out
of the SSH shell and receive-hook hot paths.

Supported executor commands are:

- `health`;
- `authorize` with `operation`, optional `ref`, and a bounded `paths` array;
- `repository_info`;
- `diff` with `old_oid` and `new_oid`;
- `update_ref` with `ref`, `old_oid` and `new_oid`;
- `create_repository`;
- `pr_check` for read-only merge analysis;
- `pr_merge` for explicit plan/apply, forge-supplied gates, local Datalog
  reauthorization, reviewed prepared-OID/policy-fingerprint preconditions and
  atomic target-ref CAS.

`update_ref` calculates changed paths first, authorizes the operation as a
`push`, and only then invokes Git's compare-and-swap update. `pr_merge` uses the
same invariant and repeats authorization immediately before its state change.
Its plan returns a deterministic prepared OID and the Maelys Datalog policy-set
fingerprint; apply requires both values and recomputes them locally.
There is no arbitrary command execution field. Durable PR metadata, reviews and
status-check production remain responsibilities of the forge.

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

The Cloud command endpoint returns an exact object shaped as
`{"cursor":"...","commands":[...]}` or HTTP 204. The event endpoint accepts
one result object per POST and should return any 2xx response only after it has
durably accepted the idempotency key.

## Security boundary

The SSH shell and hook should run under a dedicated Unix account that owns only
the intended repositories. The agent should use a separate service account when
possible. Filesystem permissions remain a second line of defence behind Datalog
authorization.

This code has not received an external security audit. Before production use,
run the network agent and executor under distinct least-privilege service
accounts (or add a narrow Unix socket handoff), add platform CI and fuzz the
SSH parser plus all Jansson schemas.
