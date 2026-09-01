# Functional position: Gitolite, Forgejo, and Maelys Git Core

This document tracks the local Git enforcement core. It does not count a
future Cloudflare forge UI as part of the core.

## Compared with Gitolite

| Capability | Maelys Git Core | Position |
|---|---|---|
| SSH forced-command confinement | Strict parser and `execve`/`posix_spawn`; no shell | Covered |
| Repository read/write/create authorization | Datalog operations and dynamic bare creation | Covered |
| Branch and tag protection | Ref kind, update kind and protected-ref facts | Covered |
| Path-sensitive authorization | Every change is streamed and authorized | Covered |
| Rename-sensitive authorization | Both old and new path are facts | Beyond basic path checks |
| Transaction-wide limits | Commit/path/blob/inspection quotas across all refs in one receive | Beyond Gitolite's basic ACL model |
| Object-aware policy | Size, mode, symlink, submodule, binary and LFS-pointer facts | Beyond Gitolite's basic ACL model |
| Commit identity policy | Email plus detailed signature/trust facts | Beyond the basic ACL model |
| Multi-ref receive transaction | Fully read and fail-closed before acceptance | Covered |
| Key administration | Atomic compiler, structural validation, scoped read/write deploy keys, expiry and revocation | Beyond flat principal keys |
| Flat groups and exact repository ACL migration | Plan/apply compiler for `R`, `RW`, and `RW+` with no silent fallback | Covered common subset |
| Repository lifecycle | Inventory, inspection, CAS rename, archive, recoverable delete and restore | Beyond basic Gitolite administration |
| Repository patterns, ref rules and rule precedence | Reported source line by source line by the migration compiler | Missing compatibility |
| VREF ecosystem and custom triggers | Native facts and C inspectors exist; no compatibility layer | Partial |
| Delegated administration, mirroring and legacy extensions | Not implemented | Missing |

Maelys does not pursue source compatibility with Gitolite. The migration
compiler translates the useful ACL subset into versioned Datalog policies and
refuses apply if any source rule would be weakened or lost. Special VREFs
should become named, typed facts or inspectors with tests.

## Compared with Forgejo

The core now provides repository confinement, push authorization, repository
creation, deterministic PR merge preparation, conflict detection, FF/merge/
squash, approval/check gates supplied by a forge, local reauthorization,
reviewed-plan preconditions, normalized PR events, and atomic target/head/
merged reference transactions.

It is not a forge product. Durable users and organizations, PR metadata,
reviews and comments, issues, wiki, releases, LFS object storage, webhooks, notifications,
search, OAuth/SSO, billing, Actions runners and the Web UI remain outside this
repository. They belong in the proprietary forge/Worker layer or in separate
services communicating through the versioned agent protocol.

## Current hardening boundary

- Git remains the only object/ref implementation.
- Every spawned Git command has a 120-second deadline.
- Captured streams have explicit memory or spool quotas.
- PR commits are canonical and deterministic.
- Apply recomputes the prepared OID and complete Datalog policy-set fingerprint.
- Current forge gates are re-evaluated at apply; they are deliberately live.
- SSH public keys are decoded and structurally validated before publication.
- Blob inspection is batched, bounded, and shared by push and PR authorization.
- A PR apply can commit its target, head, and merged refs as one Git transaction.

## Next work

1. Define cross-fork PR object quarantine, reachability validation, object-size
   quotas, and promotion before enabling fork imports.
2. Add a durable forge-side PR record and map its state transitions to the
   normalized local events without coupling the C core to a database.
3. Extend Gitolite migration with an explicit library of selected ref/VREF
   mappings; continue refusing unknown behavior.
4. Add cancellation propagation from the Cloud agent into long Git processes.
5. Add hardware-key attestation metadata and rotation workflows for deploy
   keys.
6. When Datalog work resumes, return bounded proof/receipt data with decisions
   and reuse a compiled request session across changed paths.

## Maelys Datalog opportunities

The engine already supports bounded fact stores, deterministic solving,
integer comparisons and proof explanations. The policy-set fingerprint added
for PR preconditions is generic and belongs in the Datalog library.

The highest-value engine improvements would be:

- a reusable request session that resets an EDB without rebuilding/copying the
  compiled ruleset for every changed path;
- a batch authorization API for many independent request fact sets;
- a compact, versioned decision receipt containing policy fingerprint, matched
  query, proof root and solver budget statistics;
- explicit cancellation/deadline hooks for hosts processing large batches.

The receive hook streams Git records, but the Datalog solver itself still
evaluates one bounded request at a time. A streaming solver is not required for
correctness; reusable sessions and batch evaluation would improve throughput
without weakening the engine's deterministic bounds.
