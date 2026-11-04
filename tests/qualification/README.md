# Qualification harness (GIT-C10, step 2b)

Reusable laboratory components for the deployment qualification of the
agent. They drive the product from outside, through its public contracts
only, and change nothing in `src/`. Standard library Python 3; registered in CTest as `maelys-git-qualification-nominal`
and `maelys-git-qualification-components` when the Cloud agent is built.

| File | Role |
| --- | --- |
| `lab_cloud_server.py` | the Cloud consumer the agent polls and posts to: TLS, scripted command queue, failure modes per channel (`normal`, `mute`, `slow`, `dedup`, `reject`, `drop_ack` = accepted then reply lost, `drop_before` = cut before acceptance, `denied`, `redirect`, `raw`), token rotation, event protocol 1/2, request journal, loopback control endpoint |
| `lab_state.py` | read-only state assertions: journal (states, attempt columns when present, audit kinds, outbox, metadata, logical inventory), Git (ref, reflog chain with marker position, lock files, validity, ref format), grants store, process topology as a diagnostic, never a proof (`/proc` on Linux; one `KERN_PROC_ALL` sysctl on macOS, its record layout checked on our own record, sessions by `getsid(2)` there since `ps -o sess` prints 0; no listing is a snapshot); a reader that fails, a malformed line or record or an empty table raise, a row that cannot be read says so (`gone`, `zombie`, `denied`, `malformed`): an empty table never proves an absence; one deadline bounds the reading), envelopes, secret search by value; a JSON-lines recorder |
| `lab_process.py` | the scope of a launch, its cleanup, and the authority a confirmation rests on: `Launch` starts the agent in its own session, whose id is the pid, and reads its outputs and exit status without reaping it (`waitid` `WNOWAIT`), so that its session id is not reused while the sweep runs; `claim_authority()` makes the harness the subreaper of its descendants (Linux, `PR_SET_CHILD_SUBREAPER`): every orphaned descendant of a launch is re-parented to it, pinned until reaped, and `waitid(P_ALL)` proves when none is left (`no_children`, `scope_closed`); `stop_scope()` works under one monotonic deadline, signals the agent and the adopted orphans by `kill(2)` (pinned), any other descendant through a pidfd only (Linux) and otherwise waits for it, reaps what it adopted, and separates `observed_empty`, a diagnostic from tables that are no snapshots, from `confirmed`, the proof under the authority only (agent exited, no member, no adopted zombie still to reap, no unattributed child); on macOS there is no authority: the sweep ends after two consecutive empty observations following the agent's exit and nothing is removed; `preserve_fixture()` removes the fixture only on a proven closed scope and a successful scenario, keeps it otherwise with the reason |
| `lab_hook.py` | the lab `reference-transaction` hook as generated text: at `prepared` it writes the updates and waits for a resume file, an expired wait refuses the transaction (exit 1, trace `prepared.expired`); testable with a short bound |
| `test_lab_components.py` | sensitivity tests of the components alone, no product binary: `drop_ack` accepts then loses the reply and the resend is deduplicated, exact correlation of audit and outbox ids, inventory sensitive to any stored value, `attempt()` on both schemas, secret search over an explicit output set, the hook's expiry branch, the reader on malformed tables, the cleanup's scope on fake agents (child in another group of the same session with an acknowledged start; parent exited but unreaped with its child re-parented, where the search by parent pid is blind and the session finds it; parent reaped before the sweep, where the authority is lost and nothing is signalled; the race table-then-fork-then-exit with real processes, never confirmed with the child alive; the two-generation race, a descendant listed then forking and vanishing before its session is read; the zombie-at-read race with real processes, the test a subreaper on Linux, the zombie reaped by the stop; every stop confirmed under the authority and only observed without it; a descendant signalled only through a pidfd, refused otherwise; reader failure, malformed table and unreadable row give an unconfirmed stop and no signal; one deadline over several slow readings, a late non-empty table triggering no signal, a late reap not a success; several launches; a bystander in another session intact; the late markers of exactly the children never signalled) |
| `scenario_nominal.py` | end to end on one cell: `health`, then an `update_ref` by `alice` on a synthetic bare repository under a migrated Gitolite policy, with the real topology agent → executor (group leader, same session) → git → hook surveyed while a repository `reference-transaction` hook holds Git at `prepared`; every assertion recorded; every launch kept until its stop; the fixture lives in the evidence directory and is removed only when the scope is proven closed under the subreaper authority and the scenario succeeded, kept otherwise with the reason in `fixture-kept.json` |

The `reference-transaction` hook the scenario installs in the synthetic
repository is the synchronisation mechanism of the harness plan (§2.2): it
is a child of Git, in the executor's process group, and it never changes the
product's supervision. Fault injection (lab build targets, SQLite test VFS)
is not here: it is step 2c, under separate targets.

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
child left proves the whole scope closed. On macOS there is no such
authority: the cleanup signals the agent, waits for the descendants it may
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
