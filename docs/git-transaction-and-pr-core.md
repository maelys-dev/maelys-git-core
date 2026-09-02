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
- changed-file counters;
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
authorize the reference, every path, and the summary through Datalog. On
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
without writing by default. The safe subset covers nested groups, exact
repositories, `C`, `R`, `RW`, `RW+`, exact full-ref `RW`/`RW+` rules and exact
full-ref denies. It also covers the common `NAMESPACE/CREATOR/..*` wild-repo
shape and the deny VREFs `NAME`, `COUNT`, `COUNT/NEWFILES`, and
`MAX_NEWBIN_SIZE`. `RW+` remains distinct for force and delete operations.
`--apply` atomically writes a valid Datalog manifest only when every source
line has a semantics-preserving mapping. Includes, `subconf`, regex ref rules,
other repository patterns, positive VREFs and unknown VREFs remain explicit
violations. Every incompatible source line is reported rather than silently
weakened.

All Git subprocess capture paths have a 120-second execution deadline and
bounded output. Large tree, diff, commit, and blob-batch streams are spooled to
temporary files with explicit quotas rather than accumulated in RAM.
Subprocesses receive only a minimal allowlisted environment and start in their
own process group; a deadline terminates the whole group so a helper cannot
leave a descendant running. The network agent applies the same boundary to
each one-request executor process and uses one monotonic deadline across
partial response reads.
