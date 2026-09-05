# Maelys Git agent protocol 1

`maelys-git-agent/1` is transport independent. The reference transport is
HTTPS long-polling for commands and HTTPS POST for results. A future WebSocket
transport must carry the same JSON objects and preserve message IDs,
expiration, ordering cursors and at-least-once delivery.

The normative command shape is described by `agent-v1.schema.json`. The C
implementation additionally requires `expires_at_ms >= issued_at_ms` and accepts
a clock skew of at most five minutes into the future. Timestamps, approval counts
and source quotas are signed 64-bit integer lexemes: fractions and exponents
(including `1.0` and `1e0`) are refused. Counts stored as `size_t` must also fit
that platform's range; field-specific positive or nonnegative bounds still apply.

The command reader uses maelys-json `v0.1.3`, profile `RFC8259`, with explicit
limits of 65,536 JSON bytes (including whitespace), 32 levels of container
nesting, and 32,768 tokens including keys and containers. The token budget is
derived from the byte ceiling, not the library's default of 8,192. The reader
rejects duplicate decoded keys, U+0000, BOM, invalid UTF-8, lone surrogates and
data after the document. Each message owns its immutable document and a borrowed
payload handle; the executor validates typed payload fields while that document
remains alive. Handles and string views must never outlive the message.

The `stdio` and `serve` streams frame each command with one LF or CRLF delimiter,
excluded from the 65,536-byte JSON budget. Exactly 65,536 bytes plus either
delimiter are accepted. Embedded NULs are passed to the parser with their exact
length and rejected. A malformed complete line produces a protocol error and
reading continues; an oversized or unterminated line produces an error and
terminates the stream with failure.

The poll response is exactly:

```json
{"cursor":"opaque-server-cursor","commands":[]}
```

It contains at most 32 commands. The cursor is committed only after every
command in the response has been durably processed. HTTP 204 means no command
and does not alter the cursor.

The outer Cloud poll response and supervisor result readers still use Jansson;
their migration is a separate lot. Individual Cloud commands pass through the
maelys-json command reader after the existing Jansson normalization.

The durable idempotency key is `message_id`. Its stored comparison value is the
**deduplication form v1, produced by Jansson** with
`JSON_COMPACT | JSON_ENSURE_ASCII | JSON_SORT_KEYS`, without a final LF. This
contract preserves Jansson's ASCII escapes and UTF-8 `strcmp` key order across
journal reopen/replay. It is distinct from canonical receipt bytes: never
compare a maelys-json serialization against the journal's `raw_json`.

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
