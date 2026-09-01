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
| Transaction-wide limits | Counts, maximum blob size and binary-content fact | Beyond Gitolite's basic ACL model |
| Commit identity policy | Email plus detailed signature/trust facts | Beyond the basic ACL model |
| Multi-ref receive transaction | Fully read and fail-closed before acceptance | Covered |
| Key administration | Deterministic atomic compiler with structural key validation | Covered for flat principal keys |
| Groups, repository patterns and rule precedence | Expressible in Datalog, but no Gitolite-compatible config compiler | Partial |
| VREF ecosystem and custom triggers | Native facts and C inspectors exist; no compatibility layer | Partial |
| Delegated administration, mirroring and legacy extensions | Not implemented | Missing |

Maelys should not pursue source compatibility with Gitolite. A small migration
compiler can translate the useful ACL subset into versioned Datalog policies;
special VREFs should become named, typed facts or inspectors with tests.

## Compared with Forgejo

The core now provides repository confinement, push authorization, repository
creation, deterministic PR merge preparation, conflict detection, FF/merge/
squash, approval/check gates supplied by a forge, local reauthorization,
reviewed-plan preconditions and atomic ref updates.

It is not a forge product. Durable users and organizations, PR metadata,
reviews and comments, issues, wiki, releases, LFS, webhooks, notifications,
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

## Next work

1. Add a migration compiler for the common Gitolite `repo`, group and `RW+`
   syntax, with an explicit unsupported-VREF report.
2. Add batch Git object inspection (`cat-file --batch`) to remove the remaining
   per-blob subprocesses on very large pushes.
3. Return bounded Datalog proof/receipt data with authorization decisions so an
   operator can identify the exact matching rule, not only the policy ID.
4. Add configurable repository quotas, maximum commits/changes per transaction,
   and cancellation propagated from the agent.
5. Add first-class deploy keys, expiry/revocation metadata and hardware-key
   attestation policy.
6. Add cross-fork PR object import only after defining an object quarantine and
   reachability contract.

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
