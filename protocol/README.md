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

The Cloud poll reader uses maelys-json on the exact HTTP body: at most 65,536
bytes, depth 34 (two containers around a command), 32,768 tokens and a cursor
shorter than 1,024 UTF-8 bytes. Before processing any command, it validates the
poll shape and refuses every fractional/exponent lexeme and every integer
outside `[INT64_MIN, INT64_MAX]`, including nested payload values. Each command still passes envelope, payload and authorization checks; validating
the poll alone does not authorize its commands. A rejected poll leaves its
cursor unchanged.

The durable idempotency key is `message_id`. Its stored comparison value is the
**deduplication form v2**: the command written again by maelys-json, compact,
in printable ASCII (`\u` escapes in lower case), keys in RFC 8785 order (UTF-16
code units), without a final LF, at most 65,536 bytes. The journal records the
form in `metadata('dedup_form')`. A journal of form v1 (the form of earlier
builds: keys by UTF-8 bytes, escapes in upper case) is converted when the agent
opens it, in the same transaction that returns interrupted commands to
`pending`; a row that does not convert refuses the opening and changes
nothing, and an unknown form is refused. An older build cannot read a
converted journal. The form is distinct from canonical receipt bytes, which are
not ASCII-escaped: never compare a receipt serialization against the journal's
`raw_json`.

Results reuse the command's `message_id`, set `type` to `result`, and carry a
terminal `status` (`ok`, `denied`, or `failed`) plus an object `payload`.
The envelope is specified in `agent-result-v1.schema.json`. The supervisor
requires exactly one LF- or CRLF-terminated result, with at most 65,536 JSON
bytes excluding that delimiter, depth 32 and 32,768 tokens. Its maelys-json
reader checks the exact envelope fields, protocol and type, and requires
`message_id`, `agent_id` and `command` to match the submitted command. Extra or
missing fields, invalid status, non-object payload, malformed Unicode, NUL,
trailing data and multiple frames are rejected. The payload remains an opaque
bounded object here; its command-specific semantics belong to its consumers.

Only the validated status determines journal success; Cloud does not reparse
it. The executor writes each result within the 65,536-byte line. A result that
would exceed it is answered by a correlated `failed` result with code
`limit_exceeded`; a decision whose explanation text makes it too long is first
written again without `explanation_text`, its receipt unchanged. Invalid executor output is replaced by a locally constructed,
correlated `failed` result with code `executor_failed`. The rejected output is
never persisted or posted as a command result. Cached results are revalidated
against the command and journal state before re-enqueue; a corrupt cached result
blocks replay and cursor advancement. Clients POST results with `Idempotency-Key: <message_id>`. The server must not
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
Git compare-and-swap before changing the target reference. A decision result,
whether `authorize` or the denial of another command, carries
`matched_policy`, `receipt` and `receipt_sha256`, a `pr_merge` refused by that
policy included. A `pr_merge` refused by its gates, or because the pull request
is empty or not mergeable, is not a decision: its `status: "denied"` payload
keeps `code` and `message`. An optional
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

An `authorize` payload may set `explain: true` to receive the explanation text
of the decision in the result.

An executor started with a snapshot of grants (`--grants`) reads it again
before each command but `health`, and decides on the bytes it has just read.
Its `pr_check` and `pr_merge` results carry `grants_fingerprint`, the SHA-256
of those bytes, empty without a snapshot. A `pr_merge` apply under a snapshot
must echo the plan's value as `expected_grants_fingerprint`: it fails with
code `invalid_argument` when the member is missing, and with code
`process_error` and the message "grants changed; run a new pull request plan"
when the grants are no longer those of the plan. The schema
cannot state that requirement, since it depends on how the executor was
started. When the snapshot cannot be read again, the command is answered by a
`failed` result whose `code` is that of the failed read and whose `message`
starts with `grants snapshot unavailable: `; every following command is
refused the same way until a reading succeeds. That prefix is part of this
protocol and identifies the condition.

Local repository administration returns lifecycle events conforming to
`repository-events-v1.schema.json`. Plan and apply have distinct event types;
the forge should persist apply events only after it has durably accepted the
successful CLI result. The stable source identity makes retries and audit
correlation explicit.
