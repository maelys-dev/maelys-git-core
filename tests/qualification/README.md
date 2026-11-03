# Qualification harness (GIT-C10, step 2b)

Reusable laboratory components for the deployment qualification of the
agent. They drive the product from outside, through its public contracts
only, and change nothing in `src/`. Standard library Python 3; registered in CTest as `maelys-git-qualification-nominal`
and `maelys-git-qualification-components` when the Cloud agent is built.

| File | Role |
| --- | --- |
| `lab_cloud_server.py` | the Cloud consumer the agent polls and posts to: TLS, scripted command queue, failure modes per channel (`normal`, `mute`, `slow`, `dedup`, `reject`, `drop_ack` = accepted then reply lost, `drop_before` = cut before acceptance, `denied`, `redirect`, `raw`), token rotation, event protocol 1/2, request journal, loopback control endpoint |
| `lab_state.py` | read-only state assertions: journal (states, attempt columns when present, audit kinds, outbox, metadata, logical inventory), Git (ref, reflog chain with marker position, lock files, validity, ref format), grants store, process topology (`/proc` or `ps`), envelopes, secret search by value; a JSON-lines recorder |
| `lab_hook.py` | the lab `reference-transaction` hook as generated text: at `prepared` it writes the updates and waits for a resume file, an expired wait refuses the transaction (exit 1, trace `prepared.expired`); testable with a short bound |
| `test_lab_components.py` | sensitivity tests of the components alone, no product binary: `drop_ack` accepts then loses the reply and the resend is deduplicated, exact correlation of audit and outbox ids, inventory sensitive to any stored value, `attempt()` on both schemas, secret search over an explicit output set, the hook's expiry branch |
| `scenario_nominal.py` | end to end on one cell: `health`, then an `update_ref` by `alice` on a synthetic bare repository under a migrated Gitolite policy, with the real topology agent → executor (group leader) → git → hook surveyed while a repository `reference-transaction` hook holds Git at `prepared`; every assertion recorded |

The `reference-transaction` hook the scenario installs in the synthetic
repository is the synchronisation mechanism of the harness plan (§2.2): it
is a child of Git, in the executor's process group, and it never changes the
product's supervision. Fault injection (lab build targets, SQLite test VFS)
is not here: it is step 2c, under separate targets.

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
