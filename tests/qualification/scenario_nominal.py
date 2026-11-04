"""GIT-C10 qualification harness, nominal scenario (plan §4, 2b).

End to end on one cell: the lab Cloud server serves `health` then an
`update_ref` on a synthetic bare repository under a migrated Gitolite policy;
the agent runs `run --once` (command, then event); the state is read with
lab_state and every assertion is recorded. During the `update_ref`, the lab
`reference-transaction` hook (lab_hook.py) holds Git at `prepared` (locks
taken, nothing published) so that the real process topology agent ->
executor (group leader) -> git -> hook can be surveyed (plan §2.2), then
resumes it.

    scenario_nominal.py AGENT EXECUTOR MAELYS_GIT OPENSSL [EVIDENCE_ROOT]

Each run writes into a fresh directory EVIDENCE_ROOT/<utc timestamp>-<pid>/
(default root: a temporary directory): provenance.json (product revision,
working-tree patch digest when dirty, binary digests), assertions.jsonl,
topology.json, the agent's captured outputs, the server's request journal,
summary.json; on failure the synthetic repository and the journal are
copied there too, after the stop of every launch has been confirmed
(lab_process). When a stop is not confirmed, no copy is presented as
coherent: the original fixture directory is kept in place and its path is
recorded in fixture-kept.json. The lab secret is searched, at the end, in
that closed set of outputs. Exit 0 when every assertion holds, 1 otherwise.
"""
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lab_hook  # noqa: E402
import lab_process  # noqa: E402
import lab_state as S  # noqa: E402
from lab_cloud_server import LabCloudServer, command  # noqa: E402

AGENT, EXECUTOR, MAELYS_GIT, OPENSSL = map(lambda arg: str(Path(arg).resolve()), sys.argv[1:5])
ROOT_DIR = Path(sys.argv[5]).resolve() if len(sys.argv) > 5 else Path(tempfile.mkdtemp(prefix="gitc10-nominal-"))
EVIDENCE = ROOT_DIR / (time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + f"-{os.getpid()}")
EVIDENCE.mkdir(parents=True, exist_ok=False)
GIT = "/usr/bin/git"
ENV = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
ENV.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null")
PRODUCT = Path(__file__).resolve().parents[2]


def run(*args, ok=True, input=None, timeout=60):
    result = subprocess.run(list(map(str, args)), input=input, capture_output=True, text=True, env=ENV,
                            timeout=timeout)
    if ok and result.returncode:
        raise AssertionError(f"{args}: {result.stdout}\n{result.stderr}")
    return result


def git(*args, **kwargs):
    return run(GIT, *args, **kwargs)


def sha256_file(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def provenance():
    """What this run ran on: the product revision and, when the tree is
    dirty, the digest of the patch; the digests of the binaries used."""
    head = subprocess.run([GIT, "-C", str(PRODUCT), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    status = subprocess.run([GIT, "-C", str(PRODUCT), "status", "--porcelain", "--untracked-files=all", "--", "tests", "CMakeLists.txt", "src", "include"],
                            capture_output=True, text=True).stdout
    patch = subprocess.run([GIT, "-C", str(PRODUCT), "diff", "HEAD", "--", "tests", "CMakeLists.txt", "src", "include"],
                           capture_output=True, text=True).stdout
    return dict(product_head=head, tree_dirty=bool(status.strip()), status=status.strip().splitlines(),
                patch_sha256=hashlib.sha256(patch.encode()).hexdigest() if patch else None,
                binaries={Path(p).name: sha256_file(p) for p in (AGENT, EXECUTOR, MAELYS_GIT)},
                platform=sys.platform, python=sys.version.split()[0],
                git_version=git("--version").stdout.strip())


A = S.Assertions(EVIDENCE / "assertions.jsonl")
(EVIDENCE / "provenance.json").write_text(json.dumps(provenance(), indent=2))
outputs = []          # the closed set of files the secret is searched in, at the end
agent_runs = 0
failed_exception = None
server = None
launches = []         # every launch of the agent, kept until its stop is confirmed
cleanups = []         # one stop record per launch (and per stop on timeout)


def start_agent(config_path):
    """Every launch of the agent goes through here (review 843-02): its own
    session, whose id is the scope stop_scope() will clean, kept in
    `launches` before any wait that could reap the agent."""
    launch = lab_process.Launch([AGENT, "run", "--config", str(config_path), "--once", "--format", "json",
                                 "--non-interactive"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                env=ENV)
    launches.append(launch)
    return launch


def launch_agent(config_path, timeout_s=120):
    """Start the agent and wait, bounded, without reaping it (the reap ends
    the cleanup's authority: stop_scope() does it after its sweep); on
    timeout the whole scope (agent, executor in its own group, Git, hook)
    is stopped by stop_scope()."""
    launch = start_agent(config_path)
    try:
        out, err = launch.finish(timeout_s)
        timed_out = False
    except subprocess.TimeoutExpired:
        cleanups.append(lab_process.stop_scope(launch, timeout_s=10))
        out, err = launch.output.get("stdout"), launch.output.get("stderr")
        timed_out = True
    return launch.returncode, out, err, timed_out


FIXTURE_NAMES = ("example.git", "markers", "agent.sqlite3", "agent.sqlite3-wal", "agent.sqlite3-shm")


class Fixture:
    """The fixture directory: unlike TemporaryDirectory, removed on exit only
    once the finalization has confirmed the stop of every launch; kept in
    place otherwise, including when the finalization itself does not run."""

    def __init__(self):
        self.path = Path(tempfile.mkdtemp(prefix="gitc10-lab-")).resolve()
        self.keep = True

    def __enter__(self):
        return self

    def __exit__(self, *_):
        if not self.keep:
            shutil.rmtree(self.path, ignore_errors=True)


with Fixture() as fixture:
    root = fixture.path
    try:
        cert, key = root / "cert.pem", root / "key.pem"
        run(OPENSSL, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=localhost",
            "-addext", "subjectAltName=DNS:localhost", "-keyout", key, "-out", cert)
        server = LabCloudServer(str(cert), str(key)).start()

        # Policy: a migrated Gitolite configuration, alice writes refs/heads/.
        conf, migrated = root / "gitolite.conf", root / "migrated"
        conf.write_text("repo example\n    RW+ refs/heads/ = alice\n")
        run(MAELYS_GIT, "migrate", "gitolite", conf, migrated, "--apply", "--format", "json", "--non-interactive")
        manifest, grants = migrated / "manifest.json", migrated / "grants.json"

        # Synthetic repository: bare, a seed commit on refs/heads/seed, reflog
        # on every ref as the profile configures it, the lab hook.
        work, bare = root / "work", root / "example.git"
        git("init", "-q", work)
        for k, v in (("user.name", "Lab"), ("user.email", "lab@example.invalid"), ("commit.gpgSign", "false")):
            git("-C", work, "config", k, v)
        (work / "a.txt").write_text("a\n")
        git("-C", work, "add", ".")
        git("-C", work, "commit", "-qm", "seed")
        head = git("-C", work, "rev-parse", "HEAD").stdout.strip()
        git("init", "-q", "--bare", bare)
        git("--git-dir", bare, "config", "core.logAllRefUpdates", "always")
        git("-C", work, "push", "-q", bare, "HEAD:refs/heads/seed")
        markers = root / "markers"
        markers.mkdir()
        lab_hook.install(bare, markers)

        # The agent's configuration (as test_cloud_transport.py does it). The
        # token file legitimately holds the secret: it is not an output.
        token, config_path, database = root / "token", root / "config.json", root / "agent.sqlite3"
        token.write_text(server.token)
        token.chmod(0o600)
        config = dict(version=1, agent_id="lab-agent", authority=f"localhost:{server.port}", ca_file=str(cert),
                      token_file=str(token), database_path=str(database), manifest_path=str(manifest),
                      grants_path=str(grants), repository_root=str(root), git_executable=GIT, executor_path=EXECUTOR,
                      command_target="/commands", event_target="/events", poll_timeout_ms=1000,
                      request_timeout_ms=30000)
        config_path.write_text(json.dumps(config))
        config_path.chmod(0o600)

        def keep_output(name, text):
            path = EVIDENCE / name
            path.write_text(text or "")
            outputs.append(path)

        class Launched:
            def __init__(self, returncode, timed_out):
                self.returncode, self.timed_out = returncode, timed_out

        def cycle():
            global agent_runs
            agent_runs += 1
            returncode, out, err, timed_out = launch_agent(config_path)
            keep_output(f"agent-{agent_runs}.stdout", out)
            keep_output(f"agent-{agent_runs}.stderr", err)
            if timed_out:
                A.record(f"agent.run_{agent_runs}_timed_out", False, True, ok=False)
            return Launched(returncode, timed_out)

        # 1. health: queued, served, executed, recorded, then posted and acked.
        server.enqueue(command("lab-health", "health"))
        result = cycle()
        A.check("health.agent_exit", 0, result.returncode)
        A.check("health.state", "complete", S.command_state(database, "lab-health"))
        A.check("health.result_status", "ok", (S.command_result(database, "lab-health") or {}).get("status"))
        A.check("health.outbox_unacked", 1, sum(1 for row in S.outbox(database, "lab-health") if row["acked_at_ms"] is None))
        # With grants_path configured the snapshot is archived and audited for
        # every command, health included (dossier §5.1 steps 5 and 7).
        A.check("health.audit_kinds", ["command_complete", "grants_snapshot"], S.audit_kinds(database, "lab-health"))
        result = cycle()
        A.check("health.event_posted", True, server.wait_for_request(
            lambda r: r["method"] == "POST" and r["idempotency_key"] == "lab-health", 10) is not None)
        A.check("health.outbox_acked", 0, sum(1 for row in S.outbox(database, "lab-health") if row["acked_at_ms"] is None))
        A.check("health.cursor_advanced", True, (S.cursor(database) or "").startswith("cursor-"))

        # 2. update_ref refs/heads/main from nothing to the seed commit, by
        # alice, with the topology surveyed while Git is held at 'prepared'.
        server.enqueue(command("lab-update", "update_ref", repository="example.git", principal="alice",
                               payload=dict(ref="refs/heads/main", old_oid=S.ZERO_OID, new_oid=head)))
        survey = {}

        def observe():
            if not S.wait_until(lambda: (markers / "prepared").exists(), 30):
                survey["error"] = "prepared marker never appeared"
                return
            rows = S.topology(comm=True)
            survey.update(agent=rows.get(launch.pid), tree=S.descendants(launch.pid, rows),
                          session=[row for row in rows.values() if row.get("sid") == launch.sid],
                          prepared_updates=(markers / "prepared.updates").read_text(),
                          refs_during=dict(main=S.ref(bare, "refs/heads/main")),
                          locks_during=S.lock_files(bare))
            (markers / "resume").write_text("go\n")

        agent_runs += 1
        # The watcher needs the agent's pid: start the process first, then
        # the observer, then wait as every launch does.
        launch = start_agent(config_path)
        watcher = threading.Thread(target=observe, daemon=True)
        watcher.start()
        try:
            out, err = launch.finish(120)
        except subprocess.TimeoutExpired:
            cleanups.append(lab_process.stop_scope(launch, timeout_s=10))
            out, err = launch.output.get("stdout"), launch.output.get("stderr")
            survey["error"] = survey.get("error") or "agent did not finish within 120 s; its scope was stopped"
        watcher.join(timeout=5)
        keep_output(f"agent-{agent_runs}.stdout", out)
        keep_output(f"agent-{agent_runs}.stderr", err)
        (EVIDENCE / "topology.json").write_text(json.dumps(survey, indent=2, default=str))
        A.check("update.agent_exit", 0, launch.returncode)
        A.check("update.prepared_marker_seen", True, "tree" in survey)
        A.check("update.hook_wait_not_expired", False, (markers / "prepared.expired").exists())
        if "tree" in survey:
            tree = survey["tree"]
            executor = next((r for r in tree if r["ppid"] == survey["agent"]["pid"]), None)
            A.check("topology.executor_is_direct_child_of_agent", True, executor is not None)
            if executor:
                A.check("topology.executor_is_group_leader", executor["pid"], executor["pgid"])
                gits = [r for r in tree if r["ppid"] == executor["pid"]]
                A.check("topology.git_is_child_of_executor", True, len(gits) >= 1)
                A.check("topology.git_in_executor_group", [executor["pgid"]] * len(gits), [r["pgid"] for r in gits])
                hooks = [r for r in tree if any(r["ppid"] == g["pid"] for g in gits)]
                A.check("topology.hook_under_git_in_same_group", True,
                        len(hooks) >= 1 and all(r["pgid"] == executor["pgid"] for r in hooks))
            A.check("update.nothing_published_at_prepared", None, survey["refs_during"]["main"])
            A.check("update.lock_held_at_prepared", True, any(l.endswith("refs/heads/main.lock") for l in survey["locks_during"]))
            A.check("update.prepared_updates_line", f"{S.ZERO_OID} {head} refs/heads/main",
                    survey["prepared_updates"].strip())
        A.check("update.state", "complete", S.command_state(database, "lab-update"))
        A.check("update.ref_published", head, S.ref(bare, "refs/heads/main"))
        chain = S.reflog_chain(bare, "refs/heads/main")
        A.check("update.reflog_present", True, chain["present"])
        A.check("update.reflog_last_line", (S.ZERO_OID, head),
                (chain["lines"][-1]["old"], chain["lines"][-1]["new"]) if chain["lines"] else None)
        A.check("update.no_lock_left", [], S.lock_files(bare))
        A.check("update.committed_marker", True, (markers / "committed").exists())
        # An ok result of update_ref carries the ref and the changed paths; the
        # receipt belongs to decision results, and the command-to-snapshot link
        # is the grants_snapshot audit (protocol/README.md, dossier §5.1 step 7).
        payload = (S.command_result(database, "lab-update") or {}).get("payload") or {}
        A.check("update.result_ref", "refs/heads/main", payload.get("ref"))
        A.check("update.result_changed_paths_is_int", True, isinstance(payload.get("changed_paths"), int))
        A.check("update.audit_kinds", ["command_complete", "grants_snapshot"], S.audit_kinds(database, "lab-update"))
        A.check("update.attempt_reader_on_B", dict(attempt=None, grants_sha256=None, started_at_ms=None),
                S.attempt(database, "lab-update"))
        cycle()
        A.check("update.event_posted", True, server.wait_for_request(
            lambda r: r["method"] == "POST" and r["idempotency_key"] == "lab-update", 10) is not None)
        inventory = S.journal_inventory(database)
        A.check("inventory.tables", ["audit", "commands", "metadata", "outbox"], sorted(inventory))
    except BaseException as error:  # noqa: BLE001 — recorded, evidence preserved, re-raised below
        failed_exception = error
        A.record("scenario.exception", None, repr(error), ok=False)
    finally:
        # Before any copy or removal of the fixture: the scope of every
        # launch stopped, confirmed, then the agent reaped (review 843-02,
        # B8-01: the agents are held unreaped until here so that their
        # session ids cannot have been reused). On the nominal path each
        # agent has exited and reaped its executor; the stop then observes
        # an empty scope and confirms at once.
        stop_confirmed = True
        for outcome in lab_process.stop_all(launches, timeout_s=10):
            cleanups.append(outcome)
            if not outcome["confirmed"]:
                stop_confirmed = False
                A.record("cleanup.fixture_stop_confirmed", True, outcome, ok=False)
        (EVIDENCE / "cleanups.json").write_text(json.dumps(cleanups, indent=2, default=str))
        outputs.append(EVIDENCE / "cleanups.json")
        # Outputs are produced and closed before the secret is searched.
        if server is not None:
            with server.lock:
                (EVIDENCE / "server-requests.json").write_text(
                    json.dumps(dict(requests=server.requests, posts=server.posts), indent=2))
            outputs.append(EVIDENCE / "server-requests.json")
            secret = server.token
            server.stop()
        else:
            secret = None
        # A coherent copy on failure only after every stop is confirmed;
        # otherwise writers may remain and the original stays in place (it
        # holds the lab token, a lab secret), the scenario failing on the
        # record above.
        outcome = lab_process.preserve_fixture(root, EVIDENCE, stop_confirmed,
                                               failed_exception is not None or A.failed, FIXTURE_NAMES, cleanups)
        if outcome["kept"] is not None:
            A.record("cleanup.fixture_kept_in_place", None, str(root), ok=False)
            outputs.append(EVIDENCE / "fixture-kept.json")
        fixture.keep = outcome["kept"] is not None
        if secret:
            hits = S.secret_absent(secret, outputs + [EVIDENCE / "topology.json", EVIDENCE / "assertions.jsonl"]
                                   if (EVIDENCE / "topology.json").exists() else outputs)
            A.check("secret.absent_from_outputs", [], hits)

summary = A.summary()
(EVIDENCE / "summary.json").write_text(json.dumps(dict(
    scenario="nominal", platform=sys.platform, fixture_kept=None if stop_confirmed else str(root), **summary), indent=2))
print(json.dumps(dict(evidence=str(EVIDENCE), **summary)))
sys.exit(1 if summary["failed"] or failed_exception is not None else 0)
