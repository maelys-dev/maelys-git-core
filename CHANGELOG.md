# Changelog

All notable changes to Maelys Git Core are documented in this file. The
format follows Keep a Changelog; versions follow Semantic Versioning.

## Unreleased

- **Access widened, on a new migration only.** The Gitolite migration
  writes the audited program `maelys-git-gitolite-program/2`, which lets a
  ref grant read its repository, as Gitolite 3.6.15 does: for `R any`, the
  read gitolite-shell asks for upload-pack, Gitolite applies every rule
  whose permission holds `R`, whatever its refex. With only `RW+
  refs/heads/feature/ = alice`, alice now reads the whole repository:
  `clone` and `fetch` through `maelys-git shell`, and `repository_info`,
  `diff` and `pr_check` through the executor. The grant may be the user's,
  a group's or `@all`'s, literal or regex; a deny alone, or `C` alone,
  reads nothing. Every other decision is unchanged. A set migrated earlier
  holds `maelys-git-gitolite-program/1`: it is still opened and decided as
  it was, byte for byte, its read stricter than Gitolite's, until it is
  migrated again. A manifest that holds both versions is refused when it
  is opened (`policy X is maelys-git-gitolite-program/2 but policy Y is
  maelys-git-gitolite-program/1: a set holds one version of the audited
  Gitolite program`). A receipt names the version its set holds,
  whichever policy decides; the verifier accepts both;
  `maelys_git_receipt_grants_t` gains the member `program`. A set migrated
  again has a new policy-set fingerprint: a `pr merge` plan made before is
  refused at `--apply`.
- The transaction and PR core documentation states what the host leaves to
  Git Core: it must not set `SIGCHLD` explicitly to `SIG_IGN`, set
  `SA_NOCLDWAIT` or reap the children Git Core starts. A Git subprocess
  reaped elsewhere fails with `ECHILD` as a process error; the network agent
  refuses a request under `SIG_IGN` or `SA_NOCLDWAIT` before its executor
  starts.
- The Cloud agent waits for its executor's end as Git children are waited
  for: on the exit itself, kqueue `EVFILT_PROC` on macOS and a pidfd on
  Linux, bounded by the request's deadline, instead of looking every 10 ms.
  One helper serves both waits: it reaps a Git child, and only observes
  the executor (`waitid` with `WNOWAIT`), whose group the supervisor still
  signals before it reaps the executor last. The deadline, the single
  escalation, the result categories and the messages are unchanged. An
  executor that closes its output and keeps running is seen to end when it
  exits rather than on the next 10 ms tick. A supervised `health` command,
  which pays the group's 100 ms grace, costs about 110 ms under Linux
  before and after; on a macOS host with an Endpoint Security client its
  fastest series drop from 149-153 ms to 140-148 ms.
  `bench-maelys-git-supervisor`, built on demand, measures it.
- The Cloud agent signals the executor's process group before it reaps
  the executor, never after. It observes the executor's end without
  reaping it (`waitid` with `WNOWAIT`), sends the group SIGTERM, then
  SIGKILL after the same 100 ms, and reaps the executor last: until then
  the group's number is the executor's own and can name no stranger. The
  final SIGTERM and SIGKILL were sent after the reap, to a number nothing
  reserved any more. What is signaled and when the executor is stopped are
  unchanged, and the group is escalated once per request: an exchange that
  failed before the executor ended paid the grace twice. A successful
  request that leaves no descendant now waits the 100 ms grace, which the
  empty group did not. The supervisor alone reaps its executor: under a
  SIGCHLD disposition the kernel reaps by, ignored or `SA_NOCLDWAIT`,
  inherited from whatever started the agent, no executor starts and the
  request fails, "SIGCHLD is ignored"; an executor reaped by something
  else all the same fails the request without a signal to its number. A
  wait that fails otherwise, as a seccomp filter may answer, keeps its
  error: the group is stopped once, the executor reaped last, and the
  request fails with that error even when the reap succeeds. The
  supervisor test adds an executor that exits on its own with a descendant
  that handles SIGTERM: it records that the leader was not reaped when the
  group's SIGTERM reached it, and the SIGKILL still ends it; a supervisor
  that ignores SIGCHLD starts no executor; and, in a build whose first
  observation fails, `maelys-git-supervisor-wait-fault`, the executor does
  not outlive the terminal result.
- A Git process starts with no signal blocked and every signal at its
  default action, whatever the launcher of Git Core blocks or ignores. It
  inherited both: a SIGPIPE an sshd ignores reached Git, and a SIGTERM a
  service blocks would have kept the SIGTERM that stops a process group
  from reaching it, so that only the SIGKILL that follows did. The
  isolated spawn now sets `POSIX_SPAWN_SETSIGMASK` with an empty mask and
  `POSIX_SPAWN_SETSIGDEF` on every signal, as maelys-system 0.13.1 does.
  The process test blocks SIGTERM and ignores SIGPIPE before starting a
  child that reports both.
- maelys-system is pinned to 0.14.4 (was 0.13.0), the version maelys-http
  0.1.18 was tested with: the two pins describe a pair that was tested
  together again. Nothing this repository calls changes: it reads the
  monotonic clock, and maelys-http 0.1.18 neither starts a process nor
  touches a signal. 0.13.1 gives a program started by
  `maelys_sys_process_spawn` no blocked or ignored signal of its caller's;
  0.14.0 adds owned process groups and the keeper that holds them, a
  program `make all` now builds and installs. The Cloud agent builds the
  archive alone: the keeper is neither linked nor installed here.
- A child process is reaped as soon as it exits. Once its output closed,
  the wait polled `waitpid` and slept 10 ms whenever the child had not
  exited yet, which cost almost every Git command 10 ms: about 100 s on a
  push of a new ref with 10,000 commits, which spawns one `git show` per
  commit. The wait now blocks on the exit itself, kqueue `EVFILT_PROC` on
  macOS and a pidfd on Linux, bounded by the remaining budget, and falls
  back to a short backoff where neither is available; no signal handler
  is installed. That push drops from 320 s to 216 s on an M2 Max, the cost
  of its Git commands run alone. The budget, the termination of the
  process group and the messages are unchanged, except that a timeout
  reached while waiting for the exit names the configured limit, as the
  others do, rather than what remained of it.
- A snapshot of grants may be `maelys-git-grants/2`: the format of a
  snapshot that holds ref patterns of form `regex`, a Gitolite refex
  completed by `refs/heads/` and anchored at its start, as Gitolite matches
  it. A snapshot without one stays `/1`, byte for byte, and `/1` refuses the
  form. A pattern begins with `refs/`, holds at most 256 bytes, has no
  top-level `|` and no `^` outside a class, does not name `/USER/`, and
  compiles in the subset of `maelys/cli/regex.h` (maelys-cli 0.13.0) within
  4,096 states; each distinct pattern is compiled once, when the snapshot
  is read, the patterns of one repository within 4,096 states and those of
  the snapshot within 1,048,576. A pattern is searched without allocating,
  in a scratch the snapshot holds, and each one once per ref: the requests
  of a push that carry one ref (the update, each commit, each change, the
  summary) do not search it again, until another ref or a new generation
  of the snapshot. A search that fails refuses the request (`regex search
  failed`, kind `engine`). A receipt names the format read, `/1` or `/2`,
  and the verifier accepts both; `maelys_git_receipt_grants_t` gains the
  member `format`.
- The Gitolite migration writes a refex that is not a literal name as a
  ref pattern of form `regex`, completed by `refs/heads/` as Gitolite
  completes it, kept as written and anchored at its start: `RW
  refs/heads/feature/.*`, `RW v[0-9]+`, `- refs/tags/v1.0` and `RW
  refs/tags/v1.0$` are migrated where they were refused. A refex is read in
  this order: one that names `/USER/` once completed is refused; one made
  of `[A-Za-z0-9_/-]` and of the escapes `\.`, `\/` and `\-` is a literal,
  migrated as before (exact or prefix); any other is a regex, checked by
  the rules of the reader of a snapshot, and refused with the column of the
  refex as written where reading stopped (`refex refused at column 5: a
  '|' at the top level`): its last column for a limit only its end
  reveals, the first byte past the bound for one that exceeds 256 bytes
  once completed. The snapshot is `maelys-git-grants/2` only when
  it holds a regex pattern, `/1` otherwise; the plan states it in
  `grantsFormat`. The plan also gives `remarks`, which never block a
  migration: a repository with write grants and ref denies, where any deny
  that applies wins whatever its order in Gitolite (stricter), and a group
  with rights and no member. A regex is migrated as grants as data only:
  the compiled policy refuses it. On three configurations of regex refexes
  (10,164 write decisions: updates, forced updates and writes without a
  ref), the oracle of the tests decides as Gitolite 3.6.15 itself on every
  one, and Git Core as the oracle read deny-wins; the 11 decisions where
  Gitolite's first match differs are all stricter in Git Core. Reads are
  not compared: a ref grant alone gives read access in Gitolite and not in
  Git Core, a known difference, stricter, to be corrected apart.
- maelys-http is pinned to 0.1.18 (was 0.1.16), which includes 0.1.17. The
  Cloud agent no longer loses an outbox POST to a TLS 1.3 session ticket.
  With Mbed TLS 4, a ticket the server sent just before the read between a
  request's head and its body made the body write fail: the agent reported
  `HTTPS request failed: I/O failure` and closed the connection with the
  head sent and the body missing. The result was kept and posted again on
  a later cycle under the same `Idempotency-Key`, so nothing was lost, but
  the cycle failed. This is the intermittent failure of the Cloud
  transport test on macOS. Neither the codec, the client nor ABI 1
  changes. maelys-http 0.1.17 and 0.1.18 pin maelys-system 0.14; this
  repository kept 0.13.0 until the entry above, and maelys-http calls
  nothing those versions change.
- A policy set holding the audited Gitolite program decides only the refs
  Gitolite 3.6.15 admits with its default patterns (`REF_OR_FILENAME_PATT`
  of `Rc.pm`): a ref that is not a valid ref, does not begin with a
  letter or a digit, holds anything but `[-0-9A-Za-z._@/+,]`, or exceeds
  511 bytes is an `invalid_argument`, refused before any policy of the set is evaluated,
  a hand-written one included, and no decision receipt is produced.
  Gitolite refuses such a ref before any rule; Git Core let a migrated
  prefix grant allow it (`RW refs/heads/ = @all` allowed `refs/heads/é`).
  A request without a ref and file paths are not concerned; a set written
  by hand alone is unchanged. The set is recognized by the fingerprint of
  the audited program, never by a name: a compiled Gitolite policy written
  before grants as data is not recognized and is to be generated again. A
  configuration that redefines Gitolite's patterns in `.gitolite.rc` is
  outside the fidelity this guarantees.
- The Gitolite migration reads `@all` as Gitolite does: the group of every
  user, known to the configuration or not (`Conf/Load.pm` of Gitolite
  3.6.15). It was migrated as an ordinary group named `all` with no member:
  a grant to `@all` granted no one (Gitolite's own default configuration,
  `RW+ = @all`, gave nothing), and a deny of `@all` placed before a grant
  denied no one where Gitolite denies everyone. Every slice now holds
  `slice_member(U, "all")`, and the compiled encoding derives
  `effective_group_member(U, "all")` for every user. The group `all` is
  reserved: `@g = @all` and `@all = ...`, which change nothing in Gitolite,
  are unsupported entries, and a snapshot that gives `all` a member or nests
  it is refused. It counts among a user's groups: at most 63 direct groups,
  64 with it, and 4,096 groups in a snapshot with it. The audited program is
  unchanged; a receipt counts one fact more. A snapshot takes this meaning
  when it is loaded; a compiled policy already generated keeps the old one
  until it is generated and deployed again. Everyone is every
  authenticated principal: there is no anonymous `daemon` or `gitweb`
  access.
- The Gitolite migration refuses a refex that names `/USER/` once
  completed by `refs/heads/`, and a `VREF/NAME/` path that names it:
  Gitolite replaces it with the name of each user it decides for. It was
  migrated as a literal, so that `RW+ personal/USER/ = @all` granted
  everyone the namespace `refs/heads/personal/USER/` and no one their own,
  and `- USER/` denied fewer refs than Gitolite did. The entry is reported
  as `'/USER/' is the user's own name in Gitolite; not supported` and blocks
  `--apply`, for a grant as for a deny, before any other reason.
  `refs/heads/USER$`, which Gitolite does not replace, is still a literal.
  The refex is completed as written, before its escapes are read, as
  Gitolite does. A configuration migrated before keeps its literal grant
  until it is migrated again.
- maelys-cli is pinned to 0.13.0 (was 0.7.0), which includes 0.8.0 to
  0.12.4. No source change was needed and no command of Git Core changes:
  the envelopes, error codes and exit codes are the same. What the
  framework generates moves with it: the built-in commands (`help`,
  `version`, `describe`) have new summaries, the catalog `describe`
  returns carries each program's summary as `x-maelys-summary`,
  `--lang TAG` is a global option of every command and `version` also
  returns the language it answers in (`lang`); the CLI reference is
  regenerated.
  The agent instructions (`AGENTS.md` and `CLAUDE.md` blocks,
  `docs/maelys-cli-guide.md`, the `maelys-cli-command` skill) are
  regenerated with `maelys agents install`. The release brings `maelys/cli/regex.h`, with a search in a
  scratch the caller provides, which never allocates, for the refexes of
  the Gitolite migration.
- The Gitolite migration refuses a refex holding a bare `.`, which Gitolite
  reads as any character: it was converted as a literal dot, so that
  `- refs/tags/v1.0` denied after migration fewer refs than Gitolite did
  (`refs/tags/v1x0` was allowed), and `RW refs/tags/v1.0$` granted fewer.
  The entry is reported as `'.' is any character in Gitolite; write '\.'
  for a literal dot` and blocks `--apply`; `\.`, a literal dot in Gitolite
  too, is now accepted. Other regular-expression syntax is still reported
  first as `unsupported refex syntax`. A snapshot of grants still reads `.`
  in a pattern as a literal dot.
- `maelys-git-agent grants-store prune --config FILE` purges the agent's
  store of grants snapshots: a plan by default, `--apply` to remove. It keeps
  the current snapshot, the `--keep` most recently used (16 by default) and
  those used within `--older-than` (90 days by default). A command holds the
  store's lock, shared, until its executor exits, so that a purge never
  removes a file an executor reads; a purge waits at most ten seconds for
  running commands, then refuses. It audits the removed digests as a
  `grants_store_pruned` event.
- The slice of a request finds the groups its user reaches through an index
  on their names instead of a scan of those already reached: the closure of
  G groups costs about G lookups instead of G squared comparisons. For a
  snapshot at its bounds of 4,096 groups, extracting a slice goes from about
  35 ms to under 2 ms; slices and decisions are unchanged.
- An executor started with `--expected-grants-fingerprint` decides the first
  command of its stream, whatever it is, on the snapshot it verified at
  startup, without reading the file again; every later command reads it
  again, as before, a `health` coming first included. A Cloud command thus
  reads the agent's kept snapshot twice instead of three times. Streams
  without an expected fingerprint still read the snapshot before each
  command.
- maelys-datalog is pinned to 0.26.0 (was 0.23.1), which includes 0.24.0 and
  0.25.0.
  - The engine identifies a named variable by its complete name within its
    rule; it used to identify it by its first letter, so that `Ab` and `Ac`,
    or `G1` and `G2`, were one variable. No policy of this repository, and no
    policy Git Core generates, uses a variable of more than one letter: their
    decisions and receipts do not change. **A deployed policy that uses
    longer names can change its decisions**, with the same policy source
    fingerprint; its program fingerprint can change. A rule of more than 26
    distinct names is refused, and `validate` reports the capacity budget
    `MAX_RULE_VARIABLES`.
  - `validate` reports a policy that needs more than the engine's four
    strata as a capacity failure with the budget `MAX_STRATA`, five strata
    requested and four allowed. A negation cycle stays a semantic failure,
    without a budget. The bound itself does not change.
  - A request refused because its input symbols exceed the engine's count
    of symbols (`MAX_SYMBOLS`) or its pool of text (`STRING_POOL_BYTES`) is a
    capacity denial that names that budget, with the attempted count and the
    bound; it was a failure of the engine without a budget. The decision, a
    denial, does not change.
  - A policy of more rules than the engine holds is refused with the message
    "rule capacity exceeded"; the engine used to attribute it to the
    expansion of OR. Its code, its location and its capacity do not change.
- `migrate gitolite` writes the audited Gitolite program,
  `maelys-git-gitolite-program/1`, whose text no longer depends on the
  configuration, and the configuration's grants as `grants.json`,
  `maelys-git-grants/1`. Granting or revoking a right no longer changes the
  policy or its fingerprint; publishing rights is publishing that file, by a
  rename. The program reads, for each request, the slice of the snapshot the
  request needs; a configuration beyond the 128 facts a compiled policy held
  is decided, and a request whose slice exceeds the engine's bounds is a
  capacity denial, never a truncated slice.
- `--grants FILE` on `authorize`, `validate`, `pr merge`, `maelys-git-hook
  pre-receive`, `maelys-git-shell serve`, `maelys-git-executor serve` and
  `maelys-git-agent stdio`, and `grants_path`, optional, in the agent's
  configuration. The program refuses to open without it. A stream reads the
  snapshot again before each command, and refuses commands while it cannot
  read it; a file changed while it is read is refused. The public API adds
  `maelys_git_policy_open_grants` and `maelys_git_policy_grants_fingerprint`.
- `pr merge` returns `grantsFingerprint` and applies with
  `--expected-grants-fingerprint`; grants changed since the plan are refused.
  `maelys_git_pr_merge_grants` carries that precondition; the former entry
  points still plan, and refuse to apply on a policy with a snapshot.
- `migrate gitolite --apply` syncs the directory of its output before
  renaming it into place, and the parent directory after: the published
  output is durable, not only atomic.
- The Cloud agent keeps, before each command, the snapshot of grants it
  gives the executor in a content-addressed store beside its journal,
  `grants-store/<sha256>.json`: a directory private to its account, each file
  written once, read-only, synced with its directory, and read back when it
  already exists. Every use syncs the store, an existing file and their
  directories again, so that an attempt whose sync failed is made durable by
  the next one. The executor runs on that file with
  `--expected-grants-fingerprint` (new on `maelys-git-executor serve` and
  `maelys-git-agent stdio`), which refuses a reading with other bytes, at its
  opening and before each command. A snapshot that cannot be kept starts no
  executor; the command fails with a message starting with `grants store
  unavailable: `. The journal audits the digest as a `grants_snapshot` event,
  and a receipt naming other grants fails the command.
- `agent provision --grants FILE` writes `grants_path`; the public API adds
  `maelys_git_agent_provision_grants` and
  `maelys_git_agent_validate_provision_grants`. The configuration writer
  admits the 31 values such a configuration holds.
- The agent protocol schema declares `expected_grants_fingerprint` on
  `pr_merge` and `explain` on `authorize`, which the executor already
  accepted; a client validating against the schema could not send them. A
  test holds the members of every command's payload in the schema equal to
  those the executor accepts. The protocol states that a command refused
  because the snapshot cannot be read again is a `failed` result whose message
  starts with `grants snapshot unavailable: `.
- Authorization receipts gain version 2: a decision that used a snapshot of
  grants carries `grants`, the digest of the snapshot, the number of facts of
  its slice and the formats of the snapshot, the slice and the audited
  Gitolite program. Without a snapshot a receipt stays version 1, byte for
  byte; `maelys_git_receipt_verify` accepts both. The output schema of
  `authorize` admits both.
- A stream command (`maelys-git-executor serve`, `maelys-git-agent stdio`,
  `maelys-git-shell serve`, `maelys-git-hook pre-receive` and
  `post-receive`) run with `MAELYS_CLI_FORMAT=json` reports its failure as
  the JSON failure envelope on stderr, with the `error.code` an envelope
  command gives the same result, as the maelys-cli contract states. It
  wrote the text line `PROGRAM OPERATION error [result]: message` whatever
  the variable said; that line is unchanged without it. stdout is untouched
  either way.
- maelys-json is pinned to 0.3.1 (was 0.3.0). Its canonical check answers
  without copying the document: the grants snapshot reader runs it on every
  load, and on macOS forty reloads of a 4 MiB snapshot no longer raise the
  resident peak from 120 MiB to 1.9 GiB. The answers are unchanged.
- Jansson is no longer a dependency: maelys-json, already pinned, writes
  every JSON document the programs produce, and the build, the CI and the
  Linux image no longer install Jansson. The bytes written are those of the
  previous version but for three differences: `\u` escapes in lower case
  (`\u001f`, was `\u001F`); keys in RFC 8785 order (UTF-16 code units, was
  UTF-8 bytes), which only changes received payloads copied into the
  deduplication form, since the product writes ASCII keys; and two lines that
  were written in insertion order now have sorted keys, the agent's protocol
  error and the line of the public `maelys_git_protocol_write_decision`.
  Receipts do not change. No new limit applies to command-line data.
- The agent journal compares commands in deduplication form v2, the form
  maelys-json writes, and records it in `metadata('dedup_form')`. A journal
  of form v1 is converted when the agent opens it, in one transaction that
  also returns interrupted commands to `pending`; a row that does not convert
  refuses the opening, names its command and changes nothing, and an unknown
  form is refused. Completed commands keep their results. Going back to an
  earlier build after the conversion is not supported: it would refuse the
  replayed commands as reused `message_id`s.
- The executor writes each result within the protocol's 65,536-byte line. A
  result that would exceed it, such as the diff of a thousand long paths, is
  answered by a correlated `failed` result with code `limit_exceeded`, and the
  next command of the stream is executed. The previous version wrote the whole
  line on its stream (133,152 bytes for that diff), which a reader holding to
  the protocol refuses; under the Cloud agent, the supervisor stopped the
  executor and posted `executor_failed`, "executor response exceeded 64 KiB".
  A decision whose explanation text alone makes it too long is first written
  without `explanation_text`, its receipt unchanged.
- The Gitolite migration writes one policy fact per elementary grant (a
  subject, a repository or namespace, a ref or a prefix, a level):
  `gitolite_access/3`, `gitolite_ref_access/4`, their `group_` forms and
  `owner_namespace_access/2`, read by fixed rules. Every fixed rule binds the
  request's subject, repository and ref before it reads a policy fact, so a
  derived predicate holds a number of facts that depends on the request, not
  on the configuration. A group of more than 64 members, more than 64 exact
  ref grants or VREF names, which migrated but failed every request on the
  SMALL profile, now decide. One repository holds 128 `RW` lines instead of
  42, 120 namespace prefixes for distinct subjects instead of 14, and 61
  bare-literal denies instead of 56. A bare-literal deny, and a prefix of
  more than 63 bytes or 16 `/`, stays a `starts_with` rule; when the fact or
  atom budget refuses the policy, every prefix takes that rule form, so a
  configuration the rule form admitted stays admitted. A differential test
  against the encoding of 62778f0 shows the same decisions wherever it
  decided, and decisions where it failed for capacity.
- `migrate gitolite` has the engine compile the generated policy at plan
  time, and computes the worst case of its execution: the groups of one user.
  The plan adds `budget`: the engine's rule, fact and predicate counts with
  their bounds, the derived facts per predicate and in all with theirs, and
  `failure`, a validate diagnostic or `null`. A budget that does not hold is
  an unsupported entry, `policy budget exceeded: BUDGET N requested, limit
  L`, and the apply refuses with that detail in `maelys_git_error_t`.
  `maelys_git_gitolite_migration_result_t` gains `budget`, a
  `maelys_git_policy_budget_t`: a program linked against the library must be
  rebuilt.
- A request with a valid ref carries `ref_prefix/1`, its first sixteen
  prefixes ending with `/`, and `ref_prefix_count/1`, their untruncated count,
  each only when a policy of the manifest reads it, as the engine's read-only
  view of the compiled program says when the manifest is opened. A policy
  that reads neither gets the same facts, and the same receipts, as before.
- Authorization receipts. `maelys_git_policy_authorize_receipt` decides
  exactly as `maelys_git_policy_authorize` and fills a
  `maelys_git_receipt_t`: the decision (`allow`, `deny_explicit`,
  `deny_default`, `deny_error` with the failure's code, kind and budget), the
  deciding policy and its session fingerprint, the policy-set fingerprint,
  the request without its paths, and, when an explanation is asked for
  (`MAELYS_GIT_EXPLAIN_ON_DENIAL` or `_ALWAYS`), a bounded summary of it read
  from the engine's structured views: kind, status, deciding rule, counters,
  limits reached, and the size and SHA-256 of the document. The document
  itself is never in the receipt. `maelys_git_receipt_serialize` writes it as
  Maelys Canonical JSON v1 through maelys-json, at most 8 KiB, with its
  SHA-256; `maelys_git_receipt_verify` accepts only that form and the closed
  shape of version 1 (`maelys_git_receipt.h`, library `maelys_git_receipt`).
- `maelys-git authorize` adds `receipt`, the receipt of its decision, and
  `receiptSha256`, the SHA-256 of its canonical bytes; with `--explain`,
  written before `--`, it also renders the engine's explanation and adds it
  as `explanationText`, up to 32 KiB. The four members it had are unchanged.
- The agent's decision results add `matched_policy`, `receipt` and
  `receipt_sha256`; an `authorize` command may ask for `explain: true` and
  gets `explanation_text`. A `pr_merge` refused by the policy, in plan or in
  apply, returns that decision too; refused by its gates or its
  mergeability, it keeps its `{code, message}` payload. When the executor
  refuses `create_repository`, `update_ref` or, by its policy, `pr_merge`,
  its result carries the explanation of that denial; the Cloud
  agent verifies the receipt (rewritten by maelys-json, then checked for
  canonical form and shape, then against `receipt_sha256`) and the text
  (size and SHA-256 named by the receipt), records them as
  `authorization_receipt` and `authorization_explanation` audit events in
  the transaction that completes the command, and publishes the result
  without the text, rewritten in canonical form. A receipt or text that does
  not verify fails the command and records no event. `maelys-git-agent
  stdio`, which keeps no audit, sends no denial text.
- `maelys-git-hook pre-receive --receipts FILE` appends one JSONL line per
  push, written by maelys-json: the receipt of the first denial with its
  explanation, or of the final authorization of an accepted push without
  one, and the receipt's SHA-256. A failure outside the policy writes no
  line; a line that cannot be written refuses the push. Without the option
  the hook is unchanged, and what the Git client receives is the same
  either way. Neither the hook nor the shell links Jansson.
- `maelys_git_policy_explain` now renders through the same single
  preparation as the receipt, and reads its status from the engine's
  structured views instead of searching the document's text. The policy
  handle keeps the preparation storage from its first explanation until it
  is closed: about 113 KiB in SMALL and 145 KiB in LARGE.
- A policy failure says by machine what it is. `maelys_git_error_t` gains a
  `detail`: its kind (`capacity`, `syntax`, `semantics`, `manifest`, `value`
  or `engine`, named by `maelys_git_failure_kind_name`), the engine's
  diagnostic code, and for a capacity the budget by the engine's own name
  (`MAX_RULES`, `MAX_POLICY_ATOM_BYTES`, `MAX_FACTS_PER_PRED`…), the
  attempted count and the bound in effect; the policy line and column when
  the engine located it. It is filled when a manifest does not load, when a
  solve is refused and when a request's facts exceed a bound, from the
  engine's diagnostic or from Git Core's own bounds, never from a message.
  Every result code and every message stays as it was, byte for byte. The
  structure grows by about 400 bytes: a program linked against the library
  must be rebuilt. `MAELYS_GIT_VERSION` does not change here.
- `maelys-git validate` reports that detail: each element of `diagnostics`
  keeps `code`, `path` and `message` and gains, when known, `kind`,
  `diagnostic`, `budget`, `requested`, `limit`, `file`, `line` and
  `column`; an unknown member is left out. Its output schema now declares
  the shape of an element instead of any object, and still admits the
  reports it produced before. Exit codes are unchanged. The agent's failure
  payload gains the same members under `detail` for a policy failure; its
  `code` and `message` and the protocol `maelys-git-agent/1` are unchanged.
  The failure envelopes of the other commands are unchanged.
- The policy engine is reached through the installed SDK of maelys-datalog
  v0.22.0 (consumer API 2), `<maelys/datalog.h>` alone, and no longer
  through structures private to the engine, which 0.10.0 removed. The
  `maelys_git` domain declares predicates only; a policy's constants are
  local to it; one session per
  policy lives as long as the handle. Gone: the source scanner that collected
  atoms, its process-wide buffer and load lock, the yyjson read of the
  manifest and the test-only blocks compiled into `policy.c`. The 443
  decisions of a corpus recorded before the change and the fingerprints of
  three policy sets are identical. Load errors now carry the engine's own
  diagnostic: its code, the location in the policy and the capacity exceeded.
- `maelys_git_policy_explain` renders the engine's explanation of a decision:
  the why-true witness of a derived allow or deny, or the why-false document
  of a denial by default with its `complete` or `truncated` status and the
  filter evaluations. A decision carries the policy-set and session
  fingerprints.
- Gitolite migration converts literal ref prefixes: `refs/heads/release/`, a
  short name completed by `refs/heads/`, a final `$` as equality. A deny on a
  bare literal now covers the names that start with it, as Gitolite does and
  more than the exact fact it replaced; a grant on a bare literal stays exact.
  Regular-expression syntax is refused with `unsupported refex syntax`; the
  generated policy is loaded by the engine before it is published.
- SHA-256 comes from the public digest of the maelys-cli core instead of a
  header private to the engine repository.
- maelys-datalog pinned at v0.21.0 (from v0.4.0). 0.21.0 answers `OK` and
  zero, instead of `INVALID_STATE`, when a manifest enables no policy; the
  open path already handled both answers with the same message, and the
  engine compacts its internal fact records without changing any public
  record or fingerprint. 0.20.0 reads a policy's
  identifier from the loaded handle (`maelys_datalog_policy_id`), so the
  core includes `<maelys/datalog.h>` and nothing else of the engine; it also
  releases the handle of a manifest whose entries are all disabled, which
  LeakSanitizer reported on Linux. 0.18.0 had sorted the installed headers by
  audience and removed `datalog_advanced.h`.
- The Linux CI image builds Mbed TLS v3.6.7 from source, the release
  maelys-http pins: Ubuntu 24.04 ships 2.28, below the floor maelys-http
  enforces, so the Cloud agent no longer built there since the pin moved to
  v0.1.14. The engine boundary check declares the CMake version it needs;
  CMake 3.28 refused its `IN_LIST` without one.
- The Linux CI image builds Jansson as a static library. Its shared build in
  `/usr/local/lib` shadowed the system `libjansson.so.4` that binutils' `ld`
  loads, and on amd64 every link in the image failed.
- The nested make that builds maelys-system and maelys-http for the Cloud
  agent no longer inherits the outer make's flags. It received jobserver
  descriptors that were not open in it: GNU Make warned and fell back to
  one job, or failed where the descriptor numbers were reused.
- maelys-datalog pinned at v0.23.1 (from v0.22.0). Every capacity
  diagnostic now names the exceeded budget (`limit_kind`, with
  `maelys_datalog_limit_name`), at load and on a refused input batch; 0.23.1
  adds the last one, more than 128 direct policy facts (`MAX_RULE_FACTS`),
  which 0.22.0 refused with an empty diagnostic. The message of that refusal
  is the only policy error message that changes: it now names the line,
  the count and the limit. `maelys_datalog_limit_get` answers
  `INVALID_ARGUMENT` for an unknown identifier; this repository queries known
  ones only.
- maelys-datalog pinned at v0.22.0 (from v0.21.0), maelys-http at v0.1.16
  (from v0.1.15) and maelys-system at v0.13.0 (from v0.11.0).
  maelys-datalog 0.22.0 carries the compatibility freeze of its 0.x public
  contract; for a C consumer it only makes policy accessors answer
  `INVALID_STATE` consistently on a freed caller-owned handle, which this
  repository does not use, and it now installs `maelys-datalog.pc`.
  maelys-http 0.1.16 changes neither its codec, its client nor ABI 1, and
  pins maelys-system v0.13.0, so both move together and still agree.
  maelys-system 0.12 and 0.13 add directory watching and process launching
  and correct socket receives on Unix sockets; this repository calls only
  `maelys_sys_deadline_after`, unchanged.
- maelys-cli pinned at v0.7.0 (from v0.6.0) and maelys-json at v0.3.0 (from
  v0.2.0). **0.7.0 refuses four kinds of line that worked**, and a caller's
  script is where they would be: a size suffix in small letters
  (`--max-source-bytes 512m`; write `512M`), on `pr check`, `pr merge` and
  `pre-receive`; a word that starts with one dash before `--`, so a `REF` or
  a `PATH` of `authorize` that starts with a dash is written after `--`,
  and every option before it; `-h`, which is no longer `--help`; and a
  catalog the contract's schema refuses, which this one is not. `-` alone,
  which `authorize` reads as "no ref", is still an operand. Nothing in this
  repository passed any of the four. maelys-json 0.3.0 (ABI 3) copies a
  non-integral number by its lexeme instead of refusing it and adds
  `maelys_json_writer_number_text`; no call here writes such a number, and
  no caller that succeeded changes result. The framework's managed blocks,
  guide and skill are refreshed to 0.7.0.
- maelys-cli pinned at v0.6.0 (from v0.5.36). The help text is reorganised
  by family and `COMMAND --help --format json` answers as the `help`
  command; `--expect` is a reserved option name on a transaction, which no
  command here declares; the generated contract changes by the framework's
  own wording. Nothing else of the framework is called here; its managed
  blocks, guide and skill are refreshed to 0.6.0.
- maelys-cli pinned at v0.5.36 (from v0.5.30). The generated shell
  completion works again under macOS bash 3.2 and zsh (0.5.34); `--field`
  on a transaction or `run` is refused before execution unless the member is
  in the top-level `required` of the output schema (0.5.36), which every
  schema here declares; `MAELYS_CLI_FORMAT` is the default format. Nothing
  else of the framework is called here; its managed blocks, guide and skill
  are refreshed to 0.5.36.
- maelys-cli pinned at v0.5.30 (from v0.5.29) and maelys-system at v0.11.0
  (from v0.9.1). For this repository the framework differs by its version
  header alone; its managed blocks, guide and skill are refreshed to 0.5.30.
  maelys-system 0.10.0 to 0.11.0 add descriptor passing and fix byte-only
  AF_UNIX receives, none of which is called here: this repository and
  maelys-http use its deadlines only. maelys-http v0.1.14 itself pinned
  maelys-system v0.9.1 and was built here against v0.11.0 until the pin
  below moved.
- maelys-http pinned at v0.1.15 (from v0.1.14). No change to the codec, the
  client or ABI 1: the release moves maelys-http's own pins, and it now pins
  maelys-system v0.11.0, the version this repository builds it against, so
  the two no longer disagree.

- The five Maelys dependencies are pinned to the commits of published tags,
  never to a branch commit that a history rewrite can erase: maelys-cli
  v0.5.29 (from 0.5.11), maelys-json v0.2.0 (from v0.1.3, ABI 2; nothing
  here called the two removed functions), maelys-datalog v0.4.0 (from
  0.1.0-alpha.1, whose pinned commit no longer exists anywhere),
  maelys-http v0.1.14 (from 0.1.4) and maelys-system v0.9.1 (from 0.9.0).
  maelys-datalog stopped exporting its tree root in 0.3.0; until the
  migration to `<maelys/datalog.h>`, the core library and the policy
  sessions test see the pinned root privately for the alpha headers they
  still read. The maelys-cli managed blocks, guide and skill are refreshed
  to 0.5.29 and the CLI reference regenerated with its generator.
- The Cloud transport test server no longer sends `Content-Length` on its
  204 replies: RFC 9110 forbids the field there and maelys-http refuses it
  as ambiguous framing since 0.1.5. A fixture defect, not a product one.
- Adopt the shared Maelys conventions (maelys-release v0.60.0) in
  conventions-only mode: `VERSION`, this changelog, the managed blocks of
  `AGENTS.md` and `CLAUDE.md`, `RELEASING.md` and `LICENSING.md`. The
  release mechanism stays this repository's own.
- The generated CLI reference is `docs/cli.md`, the name every Maelys
  product uses; `docs/cli-contract.json` is unchanged.
- `ci.yml` runs once per pull request: `push` names `main`.

## 0.1.0 — 2026-09-18

First versioned state of the repository, as built on 2026-09-05 (`d192d0f`).

- Fail-closed authorization through versioned Maelys Datalog manifests,
  with policy-aware Git transactions, pull request core, recoverable
  repository lifecycle and selected Gitolite parity.
- Five programs (`maelys-git`, `maelys-git-agent`, `maelys-git-executor`,
  `maelys-git-shell`, `maelys-git-hook`) built on `libmaelys_cli`, following
  the `agent-cli/v2` contract.
- Agent configuration and protocol commands read through bounded
  maelys-json documents; Cloud polls and executor results validated.
- Tested dependency revisions recorded in `cmake/dependencies.cmake`.
