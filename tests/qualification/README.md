# Qualification harness (GIT-C10, steps 2b and 2c)

Reusable laboratory components for the deployment qualification of the
agent. They drive the product from outside, through its public contracts
only. Step 2b changed nothing in `src/`; step 2c added the fault points of
the laboratory to `src/agent/`, under `MG_LAB_FAULTS`, compiled into the
`-lab` targets only (below). Standard library Python 3; registered in CTest as `maelys-git-qualification-nominal`
and `maelys-git-qualification-components` when the Cloud agent is built, and
as `maelys-git-qualification-faults` with the laboratory.

| File | Role |
| --- | --- |
| `lab_cloud_server.py` | the Cloud consumer the agent polls and posts to: TLS, scripted command queue, failure modes per channel (`normal`, `mute`, `slow`, `dedup`, `reject`, `drop_ack` = accepted then reply lost, `drop_before` = cut before acceptance, `denied`, `redirect`, `raw`), token rotation, event protocol 1/2, request journal, loopback control endpoint |
| `lab_state.py` | read-only state assertions: journal (states, attempt columns when present, audit kinds, outbox, metadata, logical inventory), Git (ref, reflog chain with marker position, lock files, validity, ref format), grants store, process topology as a diagnostic, never a proof (`/proc` on Linux; one `KERN_PROC_ALL` sysctl on macOS, its record layout checked on our own record, sessions by `getsid(2)` there since `ps -o sess` prints 0; no listing is a snapshot); a reader that fails, a malformed line or record or an empty table raise, a row that cannot be read says so (`gone`, `zombie`, `denied`, `malformed`): an empty table never proves an absence; one deadline bounds the reading), envelopes, secret search by value; a JSON-lines recorder |
| `lab_process.py` | the scope of a launch, its cleanup, and the authority a proof rests on: `Launch` starts the agent in its own session, whose id is the pid, and reads its outputs and exit status without reaping it (`waitid` `WNOWAIT`), so that its session id is not reused while the sweep runs; `claim_authority()` makes the harness the subreaper of its descendants (Linux, `PR_SET_CHILD_SUBREAPER`): every orphaned descendant of a launch is re-parented to it, pinned until reaped, and `waitid(P_ALL)` proves when none is left (`no_children`, `scope_closed`); `stop_scope()` works under one monotonic deadline, signals the agent and the adopted orphans by `kill(2)` (pinned), any other descendant through a pidfd only (Linux) and otherwise waits for it, reaps what it adopted, and separates `observed_empty`, a diagnostic from tables that are no snapshots, from `swept`, the end of the sweep under the authority (agent exited, no member observed, no adopted zombie still to reap, no unattributed child, agent reaped in time), itself not the proof: the proof is `scope_closed()`, read from the kernel immediately before the decision; on Linux the authority is required (`EXPECTED_AUTHORITY`), a refused claim fails the qualification with its errno; on macOS there is no authority: the sweep ends after two consecutive empty observations following the agent's exit and nothing is removed; `preserve_fixture()` removes the fixture only on a proven closed scope and a successful scenario, keeps it otherwise with the reason |
| `lab_hook.py` | the lab `reference-transaction` hook as generated text: at `prepared` it writes the updates and waits for a resume file, an expired wait refuses the transaction (exit 1, trace `prepared.expired`); testable with a short bound |
| `test_lab_components.py` | sensitivity tests of the components alone, no product binary: `drop_ack` accepts then loses the reply and the resend is deduplicated, exact correlation of audit and outbox ids, inventory sensitive to any stored value, `attempt()` on both schemas, secret search over an explicit output set, the hook's expiry branch, the reader on malformed tables, the cleanup's scope on fake agents (child in another group of the same session with an acknowledged start; parent exited but unreaped with its child re-parented, where the search by parent pid is blind and the session finds it; parent reaped before the sweep, where the authority is lost and nothing is signalled; the race table-then-fork-then-exit with real processes, never swept with the child alive; the two-generation race, a descendant listed then forking and vanishing before its session is read; the zombie-at-read race with real processes, the test a subreaper on Linux, the zombie reaped by the stop; every sweep ended under the authority and only observed without it; a living child omitted by the diagnostic, where the sweep ends but the kernel guard refuses the closure and the fixture is kept; the authority required on Linux; a descendant signalled only through a pidfd, refused otherwise; reader failure, malformed table and unreadable row give an unswept stop and no signal; one deadline over several slow readings on a virtual clock, a late non-empty table triggering no signal, a late reap not a success; several launches; a bystander in another session intact; the late markers of exactly the children never signalled) |
| `lab_fixture.py` | the fixture the scenarios share: the lab certificate, a migrated Gitolite policy (alice writes `refs/heads/` of `example`), the synthetic bare repository with its seed commit, the agent's configuration |
| `scenario_faults.py` | every point of B of the laboratory reached by the real `-lab` agent and executor, each fault applied once (kill, pause, synthetic, VFS, each alteration of the executor's result), its markers read and the state it leaves asserted; the http trace and the VFS survey of the operations of each phase (`vfs-survey.json`, `http-trace.json`) |
| `scenario_nominal.py` | end to end on one cell: `health`, then an `update_ref` by `alice` on a synthetic bare repository under a migrated Gitolite policy, with the real topology agent → executor (group leader, same session) → git → hook surveyed while a repository `reference-transaction` hook holds Git at `prepared`; every assertion recorded; every launch kept until its stop; the fixture lives in the evidence directory and is removed only when the scope is proven closed under the subreaper authority and the scenario succeeded, kept otherwise with the reason in `fixture-kept.json` |

The `reference-transaction` hook the scenario installs in the synthetic
repository is the synchronisation mechanism of the harness plan (§2.2): it
is a child of Git, in the executor's process group, and it never changes the
product's supervision. Fault injection is the laboratory below (step 2c),
under separate targets.

The cleanup's scope is the session of each launch, which the executor keeps
when it becomes the leader of its own group. Observation and proof are kept
apart. A process table is a diagnostic: no listing is a snapshot, a
descendant may fork and vanish between the listing and its reading, so an
empty observation never authorizes a removal. The proof rests on a kernel
authority: the agent held unreaped until the sweep is over, so that its
session id cannot be reused; and, on Linux, the harness as subreaper of
its descendants, to which every orphan is re-parented the moment its
parent dies, so that a living descendant always has a living ancestor that
is a child of the harness, pinned until reaped, and `waitid(P_ALL)` with no
child left proves the whole scope closed. That guard, `scope_closed()`, is
consulted immediately before the decision; the end of a sweep (`swept`)
rests on tables and is not it. On Linux the authority is required: a
refused claim fails the qualification with its errno rather than falling
back to observation. On macOS there is no such authority: the cleanup signals the agent, waits for the descendants it may
not signal, reports what it observed, and the fixture is kept. A
descendant that creates its own session is still adopted and counted
(`unattributed`), never dropped; the Linux laboratory of step 2c will add
confinement by cgroup.

## Existing tests and the qualification scenarios they serve

| Scenario | Existing tests reused as they are |
| --- | --- |
| Q01 installation, permissions | `test_agent_config.c` (configuration refused when unsafe), `test_cli_integration.cmake` (provision) |
| Q02 authorization on every path | `test_receive_authorization.py`, `test_hook_cli.sh`, `test_gitolite_*.py`, `test_gitolite_oracle.py`, `test_namespace_policy.sh`, `test_pr_cli.sh`, `test_authorize_update_kind.py`, `test_audit_regressions.py` |
| Q03 executor end, error, deadline, group | `test_supervisor.c`, `test_supervisor.c` (wait-fault build), `test_process.c` (isolation, backoff) |
| Q05 crash around durable transitions | `test_store_migration.c` (recovery of `running` at B), `test_agent.c` |
| Q06 network cuts and duplicates | `test_cloud_transport.py` (token rotation, replays, uncorrelated results), `test_agent_protocol.c` |
| Q08 grants publication and revocation | `test_grants.c`, `test_grants_streams.c`, `test_cloud_transport.py` (snapshot kept, unwritable store) |
| Q11 untrusted inputs and bounds | `test_json_corpus.py`, `test_protocol_limits.py`, `test_protocol_reader.py`, `test_receipt.c`, `test_policy_*` |

Q04 (service stop and restart), Q07 (concurrency on the journal), Q09
(storage failures) and Q10 (backup and restore) have no existing test: they
are the object of the qualification campaign, on a real systemd machine.

Running the nominal scenario by hand, with any build directory:

```bash
python3 tests/qualification/scenario_nominal.py build/maelys-git-agent build/maelys-git-executor build/maelys-git "$(brew --prefix openssl)/bin/openssl" /tmp/evidence   # a fresh timestamped directory under /tmp/evidence
```

## The laboratory: `-lab` targets and fault points (step 2c)

`-DMAELYS_GIT_BUILD_LAB=ON` declares `maelys-git-agent-lab` and
`maelys-git-executor-lab`: the agent sources compiled once more with the
private definition `MG_LAB_FAULTS` into one library the two programs link,
`EXCLUDE_FROM_ALL`, built by `cmake --build DIR --target maelys-git-lab`,
never installed nor packaged. The deliverables carry nothing of it: no
point name, no definition name, no file or variable name of the
laboratory, which `tests/check_no_lab_strings.py` holds on the five
programs and the five archives in every configuration
(`maelys-git-no-lab-strings`), with the `-lab` programs as its positive
control (`maelys-git-lab-strings`). `maelys-git-hook-lab` is not built yet:
its only point, `hook.open_outputs`, belongs to step 3 and joins with its
scenario. The code under `MG_LAB_FAULTS` never changes the nominal path
outside the definition: outside it the macros of `src/agent/lab.h` expand
to nothing.

Command channel, per owner (the product's environment is isolated and its
allowlist is not widened):

| Owner | Channel | Read |
| --- | --- | --- |
| `maelys-git-agent-lab` | `MG_QUAL_FAULT=<spec>[;<spec>]` in its environment | once, at `run` |
| `maelys-git-executor-lab` | the fault file fixed at configuration, `-DMG_LAB_FAULT_FILE=/var/lib/maelys-git-lab/fault` (default), one spec per line, `#` comments, mode 0600 of the account | once, at `serve` |

`<spec>` = `<point>[:<action>[:<n>]]`, action = `kill` (SIGKILL to self),
`pause` (a marker, then a wait of at most five minutes for
`resume.<point>` beside the fault file), `log`, `synthetic=<code>` (the
layer of the point fails with that code: an errno name for `grants.sync`,
a SQLite result name for `store.*`, or a number), `vfs=<file>:<op>:<code>[:<occurrence>]`
(armed by the point for the phase it opens: the n-th `<op>` on `<file>`
of that phase returns `<code>`), and a point alone is its own effect (the
executor's alterations); `n` is the passage of the point that triggers
(1 by default). A fault that cannot be read or parsed ends the process
with status 70 after a line on stderr. Every passage of a point, every
injection and every VFS fault writes one JSON line to `markers.jsonl`
beside the fault file (`ts_ms`, `pid`, `role`, `event`, `point`,
`passage`, `phase`, `message_id` when known), appended by one write.

A VFS fault lives in the instance of the phase that armed it: the next
point, whichever it is, ends that phase, and so does the exit of the
process. A fault still armed then has missed its occurrence: it is
reported by a `vfs_unreached` marker (the occurrence expected, the count
`seen`, and the `message_id` and `passage` of the arming, not of the
moment of the report: the next command may already be named when its
first point ends the phase) and disarmed; it is never carried to the next
phase, nor to the next passage of the same point on another command.

Points of B (plan §2.3), their owner and what the scenario asserts:

| Point | Owner | Actions | State the fault leaves at B |
| --- | --- | --- | --- |
| `store.pending_insert` | agent | kill, pause, log | row `pending`, executed again when served again |
| `store.open_after_barrier` | agent | kill, pause, log | journal intact, the next opening recovers |
| `supervisor.after_spawn` | agent | kill, pause, log | `running`, an executor started without a command; served again: `pending` then executed |
| `supervisor.before_validate` | agent | kill, pause, log | `running` with the Git effect applied; served again, B runs it again (recorded, the reproduction is 2d's object) |
| `store.complete_commit` | agent | kill, pause, log, synthetic, vfs | `running`, no result, no outbox row; served again: `complete`. A synthetic code is named in the agent's error; a `wal:xSync` fault reaches `IO_FAILED` |
| `grants.sync` | agent | synthetic (errno), kill, pause, log | `failed`, "grants store unavailable: …", no executor |
| `http.after_poll` | agent | kill, pause, log | no row, cursor unchanged |
| `http.before_ack` | agent | kill, pause, log | outbox row not acknowledged, the same event posted again |
| `http.trace` | agent | log | one marker per return of `advance`, with its duration |
| `vfs.trace` | agent | log | one marker per VFS operation, with its phase |
| `executor.record_launch` | executor | log (always marked) | one marker per command the executor reads, with its `message_id` |
| `executor.alter_receipt`, `.wrong_grants`, `.drop_receipt_keep_text`, `.invalid_envelope`, `.hang`, `.exit_after_effect` | executor | the point alone | `failed` at B with the message the agent gives (digest not the receipt's, other grants, text without receipt, `executor_failed`, timed out, executor failed) |
| `executor.receipt_without_grants`, `.drop_receipt_and_text` | executor | the point alone | `complete` at B: the deferred options of the dossier (§5.6) stay off |

The SQLite VFS `maelys-lab` is registered by `maelys-git-agent-lab` at
`run` as the default, wrapping the default VFS without any change to
`mg_store_open`. It names each file by the flags of its opening (`main`,
`wal`, `journal`, `temp`), writes a marker at each `xOpen`, counts
`xWrite`, `xSync`, `xTruncate` and `xFileSize` per phase (a phase runs
from a point to the next), and returns the armed code at the armed
occurrence; the index WAL `-shm` goes through the `xShm*` methods, which are
forwarded, never failed. The wrapper keeps the contract of `xOpen` in
failure: when the underlying VFS exposed its methods and failed, the
wrapper exposes its own (the `vfs_open` marker says `methods`), so the
close SQLite then performs reaches the underlying file, exactly once (a
second close through the wrapper reaches nothing). `tests/test_lab_vfs.c`
holds the fidelity of the VFS, one process per case (CTest
`maelys-git-lab-vfs-*`, built with the `-lab` programs): the armed
occurrence fires in its phase and nowhere else, the unreached fault is
reported and disarmed at the next point and at exit and its report names
the command and passage of the arming (the context changed before the
next point, the same point reached again directly, the context changed
before exit), a fault targeted at the second passage fires there only,
and the three outcomes of `xOpen` (failure with methods, failure without,
success) close once or not at all. The survey of the nominal `health` (`vfs-survey.json`)
shows the commit of the completion syncing the WAL (`wal:xSync` in the
phase `store.complete_commit`), as `journal_mode=WAL` with
`synchronous=FULL` prescribes; the same phase also holds the checkpoint of
the store's closing, which ends the run. Observed on B and recorded, not
asserted: when the commit fails on the VFS fault, the message the agent
reports is that of its explicit `ROLLBACK` ("cannot rollback - no
transaction is active", SQLite having rolled the transaction back itself),
so the fsync code does not reach the envelope.

Running the fault scenario by hand, with a laboratory build directory
whose fault file is under it:

```bash
cmake -S . -B build-lab -DCMAKE_BUILD_TYPE=Debug -DMAELYS_GIT_BUILD_LAB=ON "-DMG_LAB_FAULT_FILE=$PWD/build-lab/lab/fault" && cmake --build build-lab --target all maelys-git-lab
```

```bash
python3 tests/qualification/scenario_faults.py build-lab/maelys-git-agent-lab build-lab/maelys-git-executor-lab build-lab/maelys-git "$(brew --prefix openssl)/bin/openssl" build-lab/lab/fault /tmp/evidence
```
