# Git transaction and pull-request core

The receive hook and pull-request executor share the same authorization model.
Neither the Cloud service nor a caller may bypass the local Maelys Datalog
policy.

## Receive transactions

`maelys_git_pre_receive()` reads the complete multi-ref transaction before it
authorizes any update. Each update is classified as `create`, `fast_forward`,
`force`, or `delete`, and each reference as `branch`, `tag`, or `other`.

Changed files are streamed from Git through a temporary file. They are not
stored in a fixed 64-item array. Datalog is evaluated for:

1. the reference update;
2. every new commit, with its author email and signature-verification result;
3. every changed path, with `added`, `modified`, `deleted`, `renamed`, or
   `type_changed`; a rename exposes both its old and new path;
4. a final summary containing counters and the largest new blob size.

The policy domain exposes `ref_kind`, `update_kind`, `change_kind`,
`commit_email`, `commit_signed`, `commit_signature_status`,
`commit_signer_fingerprint`, `commit_signer_identity`,
`commit_signature_trusted`, `old_path`, `changed_count`, `added_count`,
`modified_count`, `deleted_count`, `renamed_count`, `max_new_blob_size`, and
`has_binary`. Git's binary diff classification is evaluated for modifications;
added and deleted blobs are classified from their first 8,000 bytes.

Custom C inspectors can be composed with `maelys_git_run_inspectors()`. An
inspector returns an error to reject or abort the transaction.

## Pull requests

`maelys_git_pr_check()` works in a temporary shared bare clone. A check does not
write objects, refs, or `FETCH_HEAD` in the target repository. It computes:

- the merge base;
- changed-file counters;
- whether the PR is empty;
- fast-forward eligibility or a three-way merge tree;
- conflict paths;
- a prepared fast-forward, merge-commit, or squash-commit object ID. Commit
  creation is canonical and deterministic, so the same inputs produce the same
  prepared object ID across separate plan and apply processes.

`maelys_git_pr_merge()` additionally validates approvals, status checks, and
blocking reviews supplied by the forge. It authorizes the reference, every
path, and the summary through Datalog. On `apply`, it repeats that complete
authorization immediately before importing the prepared object and calls
`git update-ref <ref> <new> <expected-old>`. That last argument is the atomic
compare-and-swap guard: a concurrent update cannot be overwritten.

The plan returns `preparedOid` and `policyFingerprint`. An apply must echo both
through `--expected-prepared-oid` and `--expected-policy-fingerprint`. The local
core recomputes them before any target-repository mutation, refuses stale
content or a changed policy bundle, then evaluates the current forge gates and
reauthorizes. Gate state is intentionally live rather than hashed into the
plan: approvals and checks may advance between plan and apply, but they must be
satisfied at apply time.

The first implementation operates on two commits already present in the same
repository. Cross-fork object transfer and durable PR metadata belong to the
forge layer.

## Normalized interfaces

The process CLI follows `agent-cli/v2`:

- `maelys-git pr check ...` is read-only;
- `maelys-git pr merge ...` returns a plan unless `--apply` is explicit;
- `maelys-git keys compile ...` returns a plan unless `--apply` is explicit;
- `describe` is the source used to generate `cli-contract.json` and the CLI
  reference.

The agent protocol exposes equivalent `pr_check` and `pr_merge` commands. A
`pr_merge` payload must include the boolean `apply` field so the remote caller
cannot accidentally turn a check into a mutation. When it is true, the two
reviewed-plan preconditions are mandatory in the versioned JSON schema.

## SSH key and repository administration

`maelys_git_compile_authorized_keys()` reads flat `PRINCIPAL.pub` files,
base64-decodes supported OpenSSH public keys, validates their binary wire
structure and declared type (including a 2,048-bit RSA minimum and exact
Ed25519/ECDSA point sizes), sorts the result, emits
restricted forced commands, writes mode `0600`, calls `fsync()`, and replaces
the target atomically. Dynamic bare repository creation remains provided by
`repo init` / `create_repository` and is policy-gated by the `create`
operation.

All Git subprocess capture paths have a 120-second execution deadline and
bounded output. Large tree, diff, and commit streams are spooled to temporary
files with explicit 64 MiB or 256 MiB quotas rather than accumulated in RAM.
