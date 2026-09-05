# Maelys Git agent protocol 1

`maelys-git-agent/1` is transport independent. The reference transport is
HTTPS long-polling for commands and HTTPS POST for results. A future WebSocket
transport must carry the same JSON objects and preserve message IDs,
expiration, ordering cursors and at-least-once delivery.

The normative command shape is described by `agent-v1.schema.json`. The C
implementation additionally requires `expires_at_ms >= issued_at_ms`, rejects
duplicate object keys, limits a complete message to 64 KiB and accepts a clock
skew of at most five minutes into the future.

The poll response is exactly:

```json
{"cursor":"opaque-server-cursor","commands":[]}
```

It contains at most 32 commands. The cursor is committed only after every
command in the response has been durably processed. HTTP 204 means no command
and does not alter the cursor.

Results reuse the command's `message_id`, set `type` to `result`, and carry a
terminal `status` (`ok`, `denied`, or `failed`) plus an object `payload`.
Clients POST results with `Idempotency-Key: <message_id>`. The server must not
return 2xx until the key and result are durable.

This agent JSONL protocol is distinct from the process CLI envelope. Human and
agent invocations use `agent-cli/v2`, described by `cli-envelope-v2.schema.json`.
Commands declared as streams reject CLI rendering flags so the two protocols
cannot be accidentally nested or mixed on stdout.

`update_ref` applies the receive hook's full policy to the proposed transaction:
ref and update kind, commits/signatures, each changed path, per-ref summary and
transaction summary. Default receive quotas apply. A policy denial returns
`status: "denied"` and leaves the ref unchanged; a successful authorization is
followed by compare-and-swap against `old_oid`.

Pull-request orchestration uses `pr_check` for read-only merge analysis and
`pr_merge` for gated execution. The latter requires an explicit `apply`
boolean, validates the target OID, re-evaluates local Datalog policy, and uses
Git compare-and-swap before changing the target reference. An optional
`pr_id` creates forge-neutral `refs/maelys/pulls/<id>/head` and `merged`
references in the same atomic Git reference transaction as the target branch.
For a fork PR, `source_repository` and `source_ref` are supplied together.
Checks fetch the exact branch into a disposable quarantine, verify its head and
connectivity, and leave the target object database untouched. Plans return
`target_identity`; applies must echo it as `expected_target_identity`. Fork
plans also return `source_identity`, which applies must echo as
`expected_source_identity`. Apply fails if either repository identity or the
reviewed source OID changed. Optional
`max_source_objects` and `max_source_bytes` tighten the default traversal
budgets of 100,000 reachable objects and 512 MiB of reachable on-disk data.

Local repository administration returns lifecycle events conforming to
`repository-events-v1.schema.json`. Plan and apply have distinct event types;
the forge should persist apply events only after it has durably accepted the
successful CLI result. The stable source identity makes retries and audit
correlation explicit.
