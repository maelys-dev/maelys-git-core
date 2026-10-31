# Git transaction and pull-request core

The receive hook and pull-request executor share the same authorization model.
Neither the Cloud service nor a caller may bypass the local Maelys Datalog
policy.

## Receive transactions

`maelys_git_pre_receive()` reads the complete multi-ref transaction before it
authorizes any update. Each update is classified as `create`, `fast_forward`,
`force`, or `delete`, and each reference as `branch`, `tag`, or `other`.

Changed files are streamed from Git through bounded temporary files. They are
not stored in a fixed 64-item array. Blob metadata and prefixes are obtained
with one `git cat-file --batch` process per ref update instead of one process
per path. Datalog is evaluated for:

1. the reference update;
2. every new commit, with its author email and signature-verification result;
3. every changed path, with `added`, `modified`, `deleted`, `renamed`, or
   `type_changed`; a rename exposes both its old and new path;
4. a final summary containing path and commit counters, the largest new blob,
   and the total size of new blobs.

The policy domain exposes `ref_kind`, `update_kind`, `change_kind`,
`commit_email`, `commit_signed`, `commit_signature_status`,
`commit_signer_fingerprint`, `commit_signer_identity`,
`commit_signature_trusted`, `old_path`, `changed_count`, `added_count`,
`modified_count`, `deleted_count`, `renamed_count`, `max_new_blob_size`,
`total_new_blob_size`, `commit_count`, `merge_commit_count`, `has_binary`,
`change_blob_size`, `old_mode`, `new_mode`, `change_binary`,
`change_symlink`, `change_submodule`, and `change_lfs_pointer`. Binary and Git
LFS classifications use only a bounded blob prefix.

`maelys_git_pre_receive_with_limits()` and the hook options
`--max-commits`, `--max-changes`, `--max-total-blob-bytes`, and
`--max-inspected-blob-bytes` bound CPU, memory-independent iteration, and blob
I/O. The default limits are 10,000 commits, 100,000 paths, 10 GiB of new blob
metadata, and 512 MiB of inspected blob content for the complete receive
transaction.

Custom C inspectors can be composed with `maelys_git_run_inspectors()`. An
inspector returns an error to reject or abort the transaction.

## Pull requests

`maelys_git_pr_check()` works in a temporary shared bare clone. Its
`maelys_git_pr_check_with_source()` variant accepts a distinct source
repository and full branch ref for fork PRs. A check does not write objects,
refs, or `FETCH_HEAD` in the target repository. It computes:

- the merge base;
- changed-file counters of the PR's own diff, merge base -> head
  (`changeSummary`, `changed_count`... through the agent): a diagnostic,
  always present, that no decision reads;
- changed-file counters of the change the merge applies to its base, base ->
  prepared commit (`appliedChangeSummary`, `applied_changes` through the
  agent), present only with a prepared commit that applies a change, `null`
  for a conflict, a fast-forward that cannot be, or an empty PR, an empty
  fast-forward included;
- whether the PR is empty;
- fast-forward eligibility or a three-way merge tree;
- conflict paths;
- a prepared fast-forward, merge-commit, or squash-commit object ID. Commit
  creation is canonical and deterministic, so the same inputs produce the same
  prepared object ID across separate plan and apply processes.

For a fork PR, the source directory is required to differ from the target. The
core resolves the requested source branch to the reviewed head OID, records
the source directory's device/inode identity, bounds its reachable object count
and reachable on-disk object bytes, fetches only that branch into the temporary
clone, then runs strict connectivity checking. The defaults are 100,000 objects
and 512 MiB; callers may tighten both. Plan/check deletion of the temporary
clone discards the fetched objects, so the target remains unchanged.

Before reading either repository, the core requires direct, non-symlink
`config` files and `objects` directories. It rejects filesystem/HTTP object
alternates and repository-local configuration families that can execute a
program, load external configuration, redirect transport or weaken object
verification. Every Git child receives a minimal allowlisted environment. The
absolute service-account `HOME` remains available for signature trust stores;
global and system Git configuration, prompts, askpass and credential-manager
interaction are disabled.

`maelys_git_pr_merge()` and its `with_source` variant additionally validate
approvals, status checks, and blocking reviews supplied by the forge. They
authorize the reference, every path, and the summary through Datalog, of the
change the merge applies, base -> prepared commit, and never of the PR's own
diff: a merge that follows a rename of the base writes a path that diff does
not name. Paths, their attributes (`change_binary`, `change_blob_size`) and
the summary's counts all come from that change, as Gitolite's update hook
reads the files the push changes. A PR refused for a conflict or as empty
keeps its error, without summaries. On
`apply`, the core repeats that complete authorization immediately before
promoting the quarantined source and prepared objects, then updates the target
through Git compare-and-swap: a concurrent update cannot be overwritten.

When `--pr-id ID` is present, plan returns the internal references
`refs/maelys/pulls/ID/head` and `refs/maelys/pulls/ID/merged`. Apply updates
those two references and the target branch in one `git update-ref --stdin`
transaction. It also returns a versioned `pr_planned` or `pr_merged` event
object for storage or publication by a future forge. Omitting `--pr-id`
preserves the lightweight single-target-ref mode.

The plan returns `targetIdentity`, `preparedOid` and `policyFingerprint`. An
apply must echo all three through `--expected-target-identity`,
`--expected-prepared-oid` and `--expected-policy-fingerprint`. A fork
plan additionally returns `sourceIdentity`, which apply must echo through
`--expected-source-identity`. The local core recomputes all preconditions before
any target-repository mutation and refuses a replaced target or source
repository, moved source branch, stale content, or changed policy bundle. It
then evaluates the current
forge gates and reauthorizes. Gate state is intentionally live rather than
hashed into the plan: approvals and checks may advance between plan and apply,
but they must be satisfied at apply time.

Object promotion necessarily precedes the reference transaction. A failed
compare-and-swap can therefore leave unreachable imported objects, but never a
visible target or internal PR ref; normal Git garbage collection can reclaim
them. Discussion threads, review history, status-check production, and their
database indexes remain responsibilities of the forge layer.

## Normalized interfaces

The process CLI follows `agent-cli/v2`:

- `maelys-git pr check ...` is read-only;
- `maelys-git pr merge ...` returns a plan unless `--apply` is explicit;
- `maelys-git keys compile ...` returns a plan unless `--apply` is explicit;
- `describe` is the source used to generate `cli-contract.json` and the CLI
  reference.

The agent protocol exposes equivalent `pr_check` and `pr_merge` commands,
including source repository/ref and quarantine budgets. A `pr_merge` payload
must include the boolean `apply` field so the remote caller cannot accidentally
turn a check into a mutation. When it is true, the three reviewed-plan
preconditions are mandatory; `expected_source_identity` is additionally
mandatory for a cross-repository apply in the versioned JSON schema.

## SSH key and repository administration

`maelys_git_compile_authorized_keys()` reads flat `PRINCIPAL.pub` files,
base64-decodes supported OpenSSH public keys, validates their binary wire
structure and declared type (including a 2,048-bit RSA minimum and exact
Ed25519/ECDSA point sizes), sorts the result, emits
restricted forced commands, writes mode `0600`, calls `fsync()`, and replaces
the target atomically. Dynamic bare repository creation remains provided by
`repo init` / `create_repository` and is policy-gated by the `create`
operation.

Repository-scoped deploy keys live below `keys/deploy/ID/` with `key.pub`,
`repository`, and `access` (`read` or `write`), plus optional `expires-at` and
`revoked` metadata. Compilation omits inactive keys and emits a forced shell
command that enforces both the repository restriction and read-only access
before Datalog or Git execution.

`maelys-git migrate gitolite INPUT OUTPUT` analyzes Gitolite configuration
without writing by default. The safe subset covers nested groups and `@all`,
exact repositories, `C`, `R`, `RW`, `RW+`, and refexes as Gitolite reads
them: exact full refs, literal prefixes, short names completed by
`refs/heads/`, a final `$` as equality, a bare-literal deny as a prefix, and
regular expressions within the subset of `maelys/cli/regex.h`, which migrate
as `regex` patterns of the grants snapshot (`maelys-git-grants/2`) and never
into the compiled policy. It also covers the common `NAMESPACE/CREATOR/..*`
wild-repo shape and the deny VREFs `NAME`, `COUNT`, `COUNT/NEWFILES`, and
`MAX_NEWBIN_SIZE`. `RW+` remains distinct for force and delete operations.
`--apply` atomically writes a valid Datalog manifest only when every source
line has a mapping, with two assumed departures from Gitolite, both stricter
and neither a refusal: a ref deny that applies wins over every grant of its
repository whatever their order, where Gitolite decides by the first rule
that applies (the result reports it as a remark on every repository that
holds both write grants and ref denies), and a bare-literal grant matches
the exact ref only, where Gitolite reads a prefix (a bare-literal deny keeps
its prefix reading). Includes, `subconf`, other repository patterns,
positive VREFs, unknown VREFs, a refex that names `/USER/`, a top-level `|`,
a `^` outside a character class, and any syntax outside the subset remain
explicit violations. Every incompatible source line is reported rather than
silently weakened.

The output holds three files: `gitolite-migrated.dl`, the audited Gitolite
program `maelys-git-gitolite-program/2`, whose text is the same for every
configuration and which, as Gitolite, lets a ref grant read the repository
(a set migrated earlier as `/1` is still opened and decided as it was, and a
manifest never holds both); `manifest.json`; and `grants.json`, the configuration's grants
as data, `maelys-git-grants/1` (or `/2` when it holds regex ref patterns).
Every command that opens the manifest takes
the snapshot with `--grants FILE`: `authorize`, `validate`, `pr merge`, the
hook, the shell, `executor serve` and `agent stdio`, and the agent's
configuration names it as `grants_path`. A snapshot is published by renaming
a complete new file over the published one, never by writing the published
file: a stream reads it again before each command, decides on what it read,
and refuses every command while it cannot read it. A plan of `pr merge`
returns `grantsFingerprint`, which its apply requires back as
`--expected-grants-fingerprint`.

The Cloud agent never starts an executor on the configured path. Before each
command it reads the snapshot, keeps its bytes in its store beside the
journal, `grants-store/<sha256>.json` (a directory private to its account, a
file written once, read-only, synced with its directory; an existing file is
read back and must hold the bytes its name says), and starts the executor on
that file with `--expected-grants-fingerprint <sha256>`: every reading with
other bytes refuses. The reading verified at startup serves the first
command of the executor's stream, whatever it is, which does not read the
file again; every later command of the stream reads it again, after a
`health` too. A snapshot that cannot be kept starts no
executor. The
journal audits the digest with the completion, and a receipt that names other
grants fails the command. `agent provision --grants FILE` writes
`grants_path`.

The store keeps every snapshot until the operator purges it:
`maelys-git-agent grants-store prune --config FILE` plans, and `--apply`
removes. It keeps the snapshot `grants_path` holds now, the `--keep` most
recently used (16 by default) and those used within `--older-than` (90 days
by default), a snapshot's last use being its last `grants_snapshot` event or
its writing. A command holds the store's lock, shared, from its archive to
its executor's exit, and a purge takes it exclusive, waiting at most ten
seconds for running commands: it never removes a file an executor reads. A
purge syncs the directory and audits the digests it removed as a
`grants_store_pruned` event.

All Git subprocess capture paths have a 120-second execution deadline and
bounded output. Large tree, diff, commit, and blob-batch streams are spooled to
temporary files with explicit quotas rather than accumulated in RAM.
Subprocesses receive only a minimal allowlisted environment, start with no
signal blocked and every signal at its default action, whatever the service
that started Git Core blocks or ignores, and start in their own process group
(the Git children of a supervised executor join the executor's group); a
deadline terminates the whole group, SIGTERM then SIGKILL after a 100 ms
grace, so a helper cannot leave a descendant running. Exits are waited for on
the exit itself, kqueue `EVFILT_PROC` on macOS and a pidfd on Linux, with a
bounded backoff where neither exists. The network agent applies the same
boundary to each one-request executor process and uses one monotonic deadline
across partial response reads: one escalation per request, when the exchange
fails. When the exchange succeeds, the executor's end is observed without
reaping it, and the group, whose number is still the executor's own, gets
SIGTERM, then SIGKILL as soon as the life descriptor every member inherited
reports EOF, nobody holding it any more, or after the grace while something
still does; the executor is reaped last. A wait that fails otherwise than by
`ECHILD` fails the request with its error, `executor wait failed: …`, after
the group was stopped once.

Git Core reaps the processes it starts, and nothing else may. The host must
not set `SIGCHLD` explicitly to `SIG_IGN` (its default disposition is fine),
set `SA_NOCLDWAIT` on it, or reap children it did not start itself, as a
`SIGCHLD` handler that calls `waitpid(-1)` would. Until the leader of a process
group is reaped, its number, which is also the group's, stays its own, so the
signals of a deadline or a cleanup can reach no process outside the group; the
Git processes an executor starts join its group and receive them. A Git
subprocess reaped by something else makes its wait fail with `ECHILD`, reported
as a process error, `waitpid failed: …`. The network agent checks its `SIGCHLD`
disposition before each executor starts, and fails the request when it is
`SIG_IGN` or carries `SA_NOCLDWAIT`: `the supervisor cannot keep its executor:
SIGCHLD is ignored`. An executor reaped elsewhere all the same fails its
request, and once the agent sees `ECHILD` it sends its group no further
signal; a failed exchange may already have stopped the group before. The
request reports `executor was reaped outside the supervisor` unless the same
exchange already failed on its deadline, its size or a read, which is reported
instead.
