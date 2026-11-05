"""Sensitivity tests of the qualification harness components, with no product
binary: the counter-examples of the 2b reviews (2B-01 to 2B-04, the hook's expiry,
843-01, 843-02 and the reviews of 570154a to f84cddb) must be detected.

    test_lab_components.py OPENSSL
"""
import http.client
import json
import os
import sqlite3
import ssl
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lab_hook  # noqa: E402
import lab_state as S  # noqa: E402
from lab_cloud_server import LabCloudServer  # noqa: E402

OPENSSL = str(Path(sys.argv[1]).resolve())
failures = []


def check(name, expected, observed):
    ok = expected == observed
    print(("ok    " if ok else "FAIL  ") + name + ("" if ok else f": expected {expected!r}, observed {observed!r}"))
    if not ok:
        failures.append(name)


with tempfile.TemporaryDirectory(prefix="gitc10-components-") as temporary:
    root = Path(temporary)

    # ---- 2B-01: drop_ack accepts and records the event, then loses the reply.
    cert, key = root / "cert.pem", root / "key.pem"
    subprocess.run([OPENSSL, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=localhost",
                    "-addext", "subjectAltName=DNS:localhost", "-keyout", key, "-out", cert], check=True, capture_output=True)
    server = LabCloudServer(str(cert), str(key)).start()
    try:
        tls = ssl.create_default_context(cafile=str(cert))

        def post(key_value, body, expect_reply=True):
            connection = http.client.HTTPSConnection("localhost", server.port, context=tls, timeout=10)
            connection.request("POST", "/events", body=json.dumps(body),
                               headers={"Authorization": "Bearer " + server.token, "Idempotency-Key": key_value,
                                        "Content-Type": "application/json"})
            try:
                response = connection.getresponse()
                return response.status, json.loads(response.read() or b"{}")
            except (http.client.RemoteDisconnected, ConnectionResetError, ssl.SSLError) as error:
                return None, repr(error)
            finally:
                connection.close()

        event = dict(protocol="maelys-git-agent/1", message_id="e1", type="result", status="ok", payload={})
        server.set_mode("event", "drop_ack")
        status, body = post("e1", event)
        check("drop_ack.reply_lost", None, status)
        check("drop_ack.event_accepted_and_recorded", 1, len([p for p in server.posts if p["idempotency_key"] == "e1"]))
        check("drop_ack.recorded_as_not_acknowledged", False, server.posts[-1]["acknowledged"])
        server.set_mode("event", "dedup")
        status, body = post("e1", event)
        check("drop_ack.resend_is_deduplicated", (200, {"deduplicated": True}), (status, body))
        check("drop_ack.resend_same_as_first", True, server.posts[-1]["same_as_first"])
        server.set_mode("event", "drop_before")
        status, body = post("e2", dict(event, message_id="e2"))
        check("drop_before.nothing_accepted", 0, len([p for p in server.posts if p["idempotency_key"] == "e2"]))
    finally:
        server.stop()

    # ---- 2B-02 and 2B-04: a synthetic journal with the B schema plus the
    # attempt columns of C.
    db = root / "journal.sqlite3"
    with sqlite3.connect(db) as c:
        c.executescript("""
            CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE commands(id TEXT PRIMARY KEY, raw_json TEXT NOT NULL, command TEXT NOT NULL,
              state TEXT NOT NULL, result_json TEXT, created_at_ms INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL,
              attempt INTEGER NOT NULL DEFAULT 0, grants_sha256 TEXT, started_at_ms INTEGER);
            CREATE TABLE outbox(id TEXT PRIMARY KEY, kind TEXT NOT NULL, payload TEXT NOT NULL,
              attempts INTEGER NOT NULL DEFAULT 0, next_attempt_ms INTEGER NOT NULL, created_at_ms INTEGER NOT NULL,
              acked_at_ms INTEGER);
            CREATE TABLE audit(sequence INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT UNIQUE NOT NULL,
              kind TEXT NOT NULL, payload TEXT NOT NULL, created_at_ms INTEGER NOT NULL);
            INSERT INTO metadata VALUES('dedup_form','v2');
            INSERT INTO commands VALUES('cmd','{"a":1}','health','complete','{"status":"ok"}',1,2,1,'abc',3);
            INSERT INTO commands VALUES('cmd-extra','{"a":2}','health','complete','{"status":"ok"}',1,2,0,NULL,NULL);
            INSERT INTO outbox VALUES('cmd-extra','command_result','{"x":1}',0,0,1,NULL);
            INSERT INTO audit(event_id,kind,payload,created_at_ms) VALUES('grants:cmd-extra','grants_snapshot','{"sha256":"x"}',1);
            INSERT INTO audit(event_id,kind,payload,created_at_ms) VALUES('command:cmd-extra','command_complete','{}',1);
            INSERT INTO audit(event_id,kind,payload,created_at_ms) VALUES('poll:cmd:1','command_rejected','{}',1);
        """)
    check("correlation.audit_kinds_exact_no_match_for_prefix", [], S.audit_kinds(db, "cmd"))
    # 843-01: a command id may contain ":" (protocol.c); the event id is
    # compared whole against family:message_id, never split on ":".
    with sqlite3.connect(db) as c:
        c.execute("INSERT INTO audit(event_id,kind,payload,created_at_ms) VALUES('command:cmd:part','command_complete','{}',1)")
        c.execute("INSERT INTO audit(event_id,kind,payload,created_at_ms) VALUES('grants:cmd:part','grants_snapshot','{}',1)")
        c.execute("INSERT INTO audit(event_id,kind,payload,created_at_ms) VALUES('attempt:cmd:part:2','command_attempt','{}',1)")
    check("correlation.colon_id_not_attributed_to_prefix", [], S.audit_kinds(db, "cmd"))
    check("correlation.colon_id_found_whole", ["command_complete", "grants_snapshot"], S.audit_kinds(db, "cmd:part"))
    check("correlation.suffixed_family_only_when_declared", ["command_complete", "grants_snapshot", "command_attempt"],
          S.audit_kinds(db, "cmd:part") if False else [r["kind"] for r in S.audit_entries(db, "cmd:part", suffixed=("attempt",))])
    check("correlation.suffixed_family_not_truncating_id", [], [r["kind"] for r in S.audit_entries(db, "cmd", suffixed=("attempt",))])
    check("correlation.audit_kinds_exact_for_extra", ["grants_snapshot", "command_complete"], S.audit_kinds(db, "cmd-extra"))
    check("correlation.outbox_exact", [], S.outbox(db, "cmd"))
    check("correlation.outbox_extra", ["cmd-extra"], [row["id"] for row in S.outbox(db, "cmd-extra")])
    check("correlation.outbox_with_declared_suffix", ["cmd-extra"], [row["id"] for row in S.outbox(db, "cmd", suffixes=("-extra",))])
    check("attempt.columns_present", dict(attempt=1, grants_sha256="abc", started_at_ms=3), S.attempt(db, "cmd"))
    check("attempt.row_absent", dict(attempt=None, grants_sha256=None, started_at_ms=None), S.attempt(db, "nope"))
    before = S.journal_inventory(db)
    with sqlite3.connect(db) as c:
        c.execute("UPDATE commands SET raw_json='{\"a\":99}' WHERE id='cmd'")
    after_raw = S.journal_inventory(db)
    check("inventory.detects_raw_json_mutation", True, before != after_raw)
    with sqlite3.connect(db) as c:
        c.execute("UPDATE audit SET payload='{\"sha256\":\"y\"}' WHERE event_id='grants:cmd-extra'")
    after_audit = S.journal_inventory(db)
    check("inventory.detects_audit_payload_mutation", True, after_raw != after_audit)
    check("inventory.stable_without_mutation", True, S.journal_inventory(db) == after_audit)
    # The B schema without the attempt columns.
    db_b = root / "journal-b.sqlite3"
    with sqlite3.connect(db_b) as c:
        c.executescript("""
            CREATE TABLE commands(id TEXT PRIMARY KEY, raw_json TEXT NOT NULL, command TEXT NOT NULL,
              state TEXT NOT NULL, result_json TEXT, created_at_ms INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL);
            INSERT INTO commands VALUES('cmd','{}','health','complete',NULL,1,2);
        """)
    check("attempt.schema_B", dict(attempt=None, grants_sha256=None, started_at_ms=None), S.attempt(db_b, "cmd"))

    # ---- 2B-03: the secret search over an explicit output set is sensitive
    # to a leak in a captured stderr and in an event body, in every
    # representation, and a missing output fails the inspection.
    secret = "lab-token-SECRET-xyz"
    out = root / "outputs"
    out.mkdir()
    (out / "agent-1.stderr").write_text("warning: token " + secret + "\n")
    (out / "server-requests.json").write_text(json.dumps(dict(posts=[dict(body=S.secret_representations(secret)["base64"])])))
    (out / "clean.txt").write_text("nothing here\n")
    hits = S.secret_absent(secret, [out])
    check("secret.leak_in_stderr_found", True, any(h["file"].endswith("agent-1.stderr") and h["representation"] == "raw" for h in hits))
    check("secret.leak_in_event_body_base64_found", True, any(h["file"].endswith("server-requests.json") and h["representation"] == "base64" for h in hits))
    check("secret.clean_file_not_reported", False, any(h["file"].endswith("clean.txt") for h in hits))
    try:
        S.secret_absent(secret, [out / "missing"])
        check("secret.missing_output_fails", True, False)
    except OSError:
        check("secret.missing_output_fails", True, True)

    # ---- the hook's expiry branch refuses: exit 1 and a trace, no silent go.
    markers = root / "markers"
    markers.mkdir()
    hook = root / "hook.sh"
    hook.write_text(lab_hook.hook_script(markers, max_steps=3, step_s=0.05))
    hook.chmod(0o700)
    result = subprocess.run(["sh", str(hook), "prepared"], input="0 1 refs/heads/x\n", capture_output=True, text=True)
    check("hook.expired_refuses", 1, result.returncode)
    check("hook.expired_trace", True, (markers / "prepared.expired").exists())
    check("hook.expired_updates_kept", "0 1 refs/heads/x\n", (markers / "prepared.updates").read_text())
    (markers / "resume").write_text("go\n")
    result = subprocess.run(["sh", str(hook), "prepared"], input="0 1 refs/heads/x\n", capture_output=True, text=True)
    check("hook.resumed_allows", 0, result.returncode)
    result = subprocess.run(["sh", str(hook), "committed"], input="0 1 refs/heads/x\n", capture_output=True, text=True)
    check("hook.committed_marker", True, result.returncode == 0 and (markers / "committed").exists())

    # ---- 843-02 and the reviews of 570154a, b8bdb60, 03b12b6, c0e5e1f,
    # d310295, 49b7115, f84cddb: cleanup covers the real scope of a launch,
    # signals only identities it can hold, separates observation from
    # proof, and proves a closed scope only under the subreaper authority
    # (Linux), read from the kernel, never from a table.
    # A fake agent in its own session starts a child that, like the
    # executor, leads another process group in the same session (setpgrp,
    # no setsid) and would write a marker late; the agent acknowledges the
    # child's start by a file holding its pid, published complete by
    # atomic replacement. Each child has a bounded lifetime and a safety
    # net closes the block. The expectations say, per host, whether a
    # descendant is signalled (our adopted child or a pidfd) or waited for,
    # and whether a sweep ends under an authority or is only observed.
    import lab_process
    import time as _time

    try:  # the test is the subreaper of its fakes, as the scenario is; required on Linux (F84-02)
        AUTH, auth_error = lab_process.claim_authority(), None
    except OSError as error:
        AUTH, auth_error = None, error
    check("authority.claimed", lab_process.EXPECTED_AUTHORITY, AUTH if auth_error is None else repr(auth_error))
    PIN = lab_process.PINNABLE_DESCENDANTS
    print(f"      authority: {AUTH}, pidfd: {PIN}")

    def ended(pid):
        """Exited, whether reaped or a zombie of ours: the opposite of
        `alive and runnable`, which kill(pid, 0) does not tell."""
        try:
            return os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None
        except ChildProcessError:
            return not lab_process._alive(pid)

    fake_child = root / "fake-child.py"
    PLAIN_CHILD = "import sys, time\ntime.sleep(float(sys.argv[2]))\nopen(sys.argv[1], 'w').write('late')\n"
    LEAF_CHILD = ("import os, sys, time\nopen(sys.argv[1] + '.leaf.tmp', 'w').write(str(os.getpid()))\n"
                  "os.replace(sys.argv[1] + '.leaf.tmp', sys.argv[1] + '.leaf')\n"
                  "time.sleep(float(sys.argv[2]))\nopen(sys.argv[1], 'w').write('late')\n")
    fake_child.write_text(PLAIN_CHILD)
    fake_agent = root / "fake-agent.py"
    fake_agent.write_text(
        "import os, subprocess, sys, time\n"
        "marker, ack, mode, delay, go = sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6]\n"
        "def publish(text):\n    open(ack + '.tmp', 'w').write(text)\n    os.replace(ack + '.tmp', ack)\n"
        "if mode == 'wait':\n"
        "    publish('ready')\n"
        "    end = time.monotonic() + 5\n"
        "    while not os.path.exists(go) and time.monotonic() < end:\n        time.sleep(0.002)\n"
        "child = subprocess.Popen([sys.executable, sys.argv[1], marker, delay], preexec_fn=os.setpgrp)\n"
        "publish(str(child.pid))\n"
        "if mode == 'alive':\n    time.sleep(30)\n")
    # A worker in the executor's place (two generations): it publishes its
    # pid, waits for `<marker>.go`, starts the leaf and exits at once.
    fake_worker = root / "fake-worker.py"
    fake_worker.write_text(
        "import os, subprocess, sys, time\n"
        "marker, delay = sys.argv[1], sys.argv[2]\n"
        "open(marker + '.worker.tmp', 'w').write(str(os.getpid()))\n"
        "os.replace(marker + '.worker.tmp', marker + '.worker')\n"
        "end = time.monotonic() + 5\n"
        "while not os.path.exists(marker + '.go') and time.monotonic() < end:\n    time.sleep(0.002)\n"
        f"subprocess.Popen([sys.executable, {str(fake_child)!r}, marker, delay])\n")
    fake_launches, all_outcomes = [], []

    def published(path, expected):
        """The complete content of an acknowledgement, or None: `expected`
        is a literal, or `int` for a pid."""
        if not path.exists():
            return None
        text = path.read_text()
        if expected is int:
            return int(text) if text.isdigit() else None
        return text if text == expected else None

    def fake(name, mode, delay=1.0, child_script=None):
        """A fake agent and its child, which writes `<name>.late` after
        `delay` seconds unless stopped. Mode `wait` acknowledges `ready`,
        then forks the child and exits once `<name>.go` exists."""
        ack = root / f"{name}.ack"
        launch = lab_process.Launch([sys.executable, str(fake_agent), str(child_script or fake_child),
                                     str(root / f"{name}.late"), str(ack), mode, str(delay), str(root / f"{name}.go")])
        fake_launches.append(launch)
        expected = "ready" if mode == "wait" else int
        if S.wait_until(lambda: published(ack, expected) is not None, 15) is None:
            raise AssertionError(f"fake agent {name} ({mode}) gave no complete acknowledgement within 15 s: "
                                 f"content={ack.read_text() if ack.exists() else None!r} host overloaded? "
                                 f"exited={launch.exited()} returncode={launch.returncode}")
        return launch, (None if mode == "wait" else published(ack, int))

    def child_of(name):
        return published(root / f"{name}.ack", int)

    def held_except(launch):
        return [other.sid for other in fake_launches if other is not launch]

    def stop(launch, **options):
        outcome = lab_process.stop_scope(launch, held=held_except(launch), **options)
        all_outcomes.append(outcome)
        return outcome

    def check_stopped(name, outcome, launch, descendants):
        """What every nominal stop must show on this host: the agent
        signalled when it was alive and reaped after; every descendant
        ended; the sweep ended under an authority (`swept`, not the
        proof), observed empty otherwise, and each descendant signalled
        (pinned: our adopted child, or a pidfd) or refused and waited
        for."""
        check(f"{name}.agent_reaped", True, launch.reaped)
        check(f"{name}.descendants_ended", [True] * len(descendants), [ended(pid) for pid in descendants])
        check(f"{name}.observed_empty", True, outcome["observed_empty"])
        check(f"{name}.swept", AUTH is not None, outcome["swept"])
        check(f"{name}.authority", AUTH, outcome["authority"])
        check(f"{name}.descendants_signalled_or_refused", sorted(descendants),
              sorted(pid for pid in descendants if pid in outcome["signalled"] or pid in outcome["refused"]))
        check(f"{name}.only_scope_signalled", True,
              set(outcome["signalled"]) <= {launch.pid, *descendants})

    bystander = None  # started later, in our own session, once the kernel guard has been exercised
    real_topology, real_signal = S.topology, lab_process.signal_member
    LISTING = "list_proc" if lab_process.LINUX else "kern_proc_all"
    real_listing = getattr(S, LISTING)

    def listed_pids(listing_result):
        if lab_process.LINUX:
            return {int(p.name) for p in listing_result if p.name.isdigit()}
        return set(S.parse_kinfo_procs(listing_result))

    try:
        # The reader: our own session id as getsid(2) gives it, never 0; a
        # malformed stat line, a stat line without a start field, a
        # truncated or empty kinfo buffer and a layout that does not
        # describe our own record are refused, never guessed; a table
        # keeps the rows it could not read, with the reason.
        rows = S.topology()
        check("topology.own_sid_by_getsid", os.getsid(0), rows[os.getpid()]["sid"])
        check("topology.own_sid_not_zero", True, rows[os.getpid()]["sid"] > 0)
        check("topology.unread_rows_say_why", True, all("sid_error" in r for r in rows.values() if r.get("sid") is None))
        check("reader.proc_parsed", dict(pid=7, ppid=1, pgid=7, sid=7, state="S", comm="a b", start=12345),
              S.parse_proc_stat("7 (a b) S 1 7 7 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 12345 0 0\n"))
        for name, text in (("short", "7 (comm) S 1\n"), ("without_start", "7 (a b) S 1 7 7 0 -1 4194560 0\n")):
            try:
                S.parse_proc_stat(text)
                check(f"reader.proc_{name}_refused", "TopologyError", "accepted")
            except S.TopologyError:
                check(f"reader.proc_{name}_refused", "TopologyError", "TopologyError")
        if not lab_process.LINUX:
            for name, raw in (("truncated", b"x" * (S.KINFO_PROC_SIZE + 1)), ("empty", b"")):
                try:
                    S.parse_kinfo_procs(raw, os.getpid())
                    check(f"reader.kinfo_{name}_refused", "TopologyError", "accepted")
                except S.TopologyError:
                    check(f"reader.kinfo_{name}_refused", "TopologyError", "TopologyError")
            try:
                S.parse_kinfo_procs(S.kern_proc_all(), 1)
                check("reader.kinfo_wrong_self_refused", "TopologyError", "accepted")
            except S.TopologyError:
                check("reader.kinfo_wrong_self_refused", "TopologyError", "TopologyError")
            check("reader.kinfo_self_comm", True,
                  S.parse_kinfo_procs(S.kern_proc_all(), os.getpid())[os.getpid()]["comm"].lower().startswith("python"))

        # (a) parent alive, child in another group of the same session.
        launch, child = fake("alive", "alive")
        rows = S.topology()
        check("scope.child_acknowledged", True, child is not None and child in rows)
        check("scope.child_same_session", launch.sid, rows[child]["sid"] if child in rows else None)
        check("scope.agent_session_is_pid", launch.sid, rows[launch.pid]["sid"] if launch.pid in rows else None)
        check("scope.child_other_group", True, child in rows and rows[child]["pgid"] == child != rows[launch.pid]["pgid"])
        outcome = stop(launch, timeout_s=5)
        check("stop.alive_agent_signalled", True, launch.pid in outcome["signalled"] and launch.returncode == -9)
        check_stopped("stop.alive", outcome, launch, [child])

        # (b) parent exited but not reaped, child re-parented and alive in
        # that session: the search by parent pid is blind (the
        # counter-example of 570154a), the session finds it, the authority
        # holds because the agent's pid is still reserved. Under the
        # subreaper the orphan is our child now: pinned, signalled by kill.
        launch, child = fake("dead", "exit")
        check("orphan.parent_exited_unreaped", True, S.wait_until(launch.exited, 5) and not launch.reaped)
        check("orphan.parent_status_without_reap", 0, launch.returncode)
        check("orphan.child_alive", True, not ended(child))
        check("orphan.descendants_blind", [], S.descendants(launch.pid))
        rows = S.topology()
        check("orphan.child_reparented", True, child in rows and rows[child]["ppid"] != launch.pid)
        check("orphan.child_adopted_by_us", AUTH == "subreaper", child in rows and rows[child]["ppid"] == os.getpid())
        check("orphan.child_in_session", launch.sid, rows[child]["sid"] if child in rows else None)
        outcome = stop(launch, timeout_s=5)
        check("stop.orphan_child_signalled", AUTH == "subreaper" or PIN, child in outcome["signalled"])
        check_stopped("stop.orphan", outcome, launch, [child])
        check("stop.orphan_parent_status", 0, launch.returncode)

        # (b') authority lost: the parent reaped before the sweep. The
        # number may be reused: nothing is signalled, the stop is not
        # swept, the child is left alone and ends by itself (its late
        # marker is the proof that no signal reached it).
        launch, child = fake("lost", "exit")
        S.wait_until(launch.exited, 5)
        check("lost.reaped_before_sweep", 0, launch.reap(timeout=5))
        outcome = stop(launch, timeout_s=5)
        check("lost.not_swept", False, outcome["swept"])
        check("lost.no_signal", [], outcome["signalled"])
        check("lost.reason", True, any("authority lost" in e for e in outcome["errors"]))
        check("lost.no_sweep", 0, outcome["sweeps"])
        check("lost.child_left_alone", False, ended(child))
        check("lost.child_ends_by_itself", True, S.wait_until(lambda: ended(child), 5))
        check("lost.child_wrote_late", True, (root / "lost.late").exists())
        if AUTH == "subreaper":
            os.waitpid(child, 0)  # adopted, ended by itself: reaped here, the stop having refused to act

        # (r) the race of review 03-01, with real processes: the table is
        # read while the agent is alive, then the agent forks its child and
        # exits before the classification. The status is read before the
        # table, so that table cannot conclude; the next one sees the
        # child. Never a swept stop with the child alive.
        launch, _ = fake("race", "wait")
        calls = []

        def table_then_fork(pids=None, timeout=30.0):
            rows = real_topology(timeout=timeout)
            calls.append(sorted(r["pid"] for r in rows.values() if r.get("sid") == launch.sid))
            if len(calls) == 1:
                (root / "race.go").write_text("fork after the reading\n")
                S.wait_until(lambda: launch.exited() and child_of("race") is not None, 5)
            return rows

        S.topology = table_then_fork
        outcome = stop(launch, timeout_s=5)
        S.topology = real_topology
        child = child_of("race")
        check("race.first_table_agent_only", [launch.pid], calls[0] if calls else None)
        check("race.child_seen_by_a_later_table", True, child is not None and any(child in c for c in calls[1:]))
        check("race.never_swept_with_child_alive", False, outcome["swept"] and not ended(child))
        check_stopped("race", outcome, launch, [child])

        # (g) the two-generation race of review C0-01: the worker is listed,
        # then forks the leaf and exits before its session is read. The
        # leaf is seen by a later table; never a swept stop with the
        # leaf alive.
        launch, worker = fake("gen2", "exit", child_script=fake_worker)
        marker = root / "gen2.late"
        leaf_ack = Path(str(marker) + ".leaf")
        check("gen2.agent_exited_unreaped", True, S.wait_until(launch.exited, 5) and not launch.reaped)
        check("gen2.worker_published", worker, S.wait_until(lambda: published(Path(str(marker) + ".worker"), int), 5))
        fake_child.write_text(LEAF_CHILD)
        phases = []

        def listing_then_worker_forks(*args, **kwargs):
            result = real_listing(*args, **kwargs)
            phases.append(worker in listed_pids(result))
            if len(phases) == 1:
                (root / "gen2.late.go").write_text("fork after the listing\n")
                S.wait_until(lambda: ended(worker) and published(leaf_ack, int) is not None, 5)
            return result

        setattr(S, LISTING, listing_then_worker_forks)
        outcome = stop(launch, timeout_s=5)
        setattr(S, LISTING, real_listing)
        leaf = published(leaf_ack, int)
        check("gen2.worker_listed_first", True, bool(phases) and phases[0])
        check("gen2.leaf_started", True, leaf is not None)
        check("gen2.never_swept_with_leaf_alive", False, outcome["swept"] and not ended(leaf))
        check("gen2.sweeps_more_than_one", True, outcome["sweeps"] >= 2)
        check_stopped("gen2", outcome, launch, [leaf])
        check("gen2.worker_reaped_by_the_stop", AUTH == "subreaper", worker in outcome["reaped_adopted"])
        fake_child.write_text(PLAIN_CHILD)

        # (z) the zombie-at-read race of review D310-01: the worker is listed
        # alive, forks the leaf and exits before its own row is read. Under
        # the subreaper the worker is our zombie, reaped by the stop, which
        # reads again; the leaf, adopted, is ours. Never a swept stop
        # with the leaf alive.
        launch, worker = fake("zomb", "exit", child_script=fake_worker)
        marker = root / "zomb.late"
        leaf_ack = Path(str(marker) + ".leaf")
        check("zombie.agent_exited_unreaped", True, S.wait_until(launch.exited, 5) and not launch.reaped)
        check("zombie.worker_published", worker, S.wait_until(lambda: published(Path(str(marker) + ".worker"), int), 5))
        fake_child.write_text(LEAF_CHILD)
        listings = []

        def listing_then_fork(*args, **kwargs):
            result = real_listing(*args, **kwargs)
            listings.append(worker in listed_pids(result))
            if len(listings) == 1:
                (root / "zomb.late.go").write_text("fork after the listing\n")
                S.wait_until(lambda: ended(worker) and published(leaf_ack, int) is not None, 5)
            return result

        setattr(S, LISTING, listing_then_fork)
        outcome = stop(launch, timeout_s=5)
        setattr(S, LISTING, real_listing)
        leaf = published(leaf_ack, int)
        check("zombie.worker_listed_first", True, bool(listings) and listings[0])
        check("zombie.leaf_started", True, leaf is not None)
        check("zombie.never_swept_with_leaf_alive", False, outcome["swept"] and not ended(leaf))
        check_stopped("zombie", outcome, launch, [leaf])
        check("zombie.worker_reaped_by_the_stop", AUTH == "subreaper", worker in outcome["reaped_adopted"])
        fake_child.write_text(PLAIN_CHILD)

        # (o) F84-01: a living descendant omitted by the diagnostic. The
        # agent exits, its child is adopted (Linux) and alive, and the only
        # table returned shows nothing of it. The sweep ends on that
        # diagnostic (`swept` under the authority: not the proof) and the
        # child is never signalled; the proof, scope_closed(), reads the
        # kernel and refuses while the child lives, so the fixture is kept;
        # once the child has ended and been reaped, the scope is closed.
        # Every previous launch is reaped here: nothing of ours is left.
        check("omit.nothing_of_ours_before", True, lab_process.no_children())
        launch, child = fake("omit", "exit")
        S.wait_until(launch.exited, 5)
        S.topology = lambda pids=None, timeout=30.0: {pid: row for pid, row in real_topology(timeout=timeout).items()
                                                      if pid != child}
        outcome = stop(launch, timeout_s=5)
        S.topology = real_topology
        check("omit.child_alive_after_sweep", False, ended(child))
        check("omit.child_never_signalled", False, child in outcome["signalled"])
        check("omit.swept_on_the_diagnostic", AUTH is not None, outcome["swept"])
        check("omit.agent_reaped", True, launch.reaped)
        check("omit.not_closed_with_child_alive", False, lab_process.scope_closed([outcome]))
        omit_fixture, omit_evidence = root / "omit-fixture", root / "omit-evidence"
        omit_fixture.mkdir()
        omit_evidence.mkdir()
        (omit_fixture / "agent.sqlite3").write_text("journal")
        kept = lab_process.preserve_fixture(omit_fixture, omit_evidence, lab_process.scope_closed([outcome]), False,
                                            [outcome])
        check("omit.fixture_kept", (omit_fixture, "no authority on this host" if AUTH is None else "scope not proven closed"),
              (kept["kept"], kept["reason"]))
        check("omit.original_intact", "journal", (omit_fixture / "agent.sqlite3").read_text())
        check("omit.child_ends_by_itself", True, S.wait_until(lambda: ended(child), 5))
        if AUTH == "subreaper":
            os.waitpid(child, 0)  # adopted, ended by itself: reaped here, the sweep never saw it
        check("omit.closed_once_reaped", AUTH is not None, lab_process.scope_closed([outcome]))
        bystander = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])  # in our own session

        # (p) identity held until the signal (03-02): a child of a living
        # fake agent is signalled through a pidfd only; without one the
        # request is refused (None) and the child is untouched. The agent,
        # our unreaped child, is always signallable; a stranger is refused.
        launch, child = fake("pin", "alive", delay=3.0)
        sent = lab_process.signal_member(child, launch.sid, 0, launch)
        check("pin.descendant_signal", True if PIN else None, sent)
        check("pin.descendant_untouched", False, ended(child))
        check("pin.not_a_member_refused", False, lab_process.signal_member(bystander.pid, launch.sid, 0, launch))
        check("pin.agent_signal_zero", True, lab_process.signal_member(launch.pid, launch.sid, 0, launch))

        # (c) observation impossible (reader error, malformed table, an
        # unreadable row): no signal, stop not swept, the child
        # untouched; then the real stop (the launch `pin` is reused).
        S.topology = lambda pids=None, timeout=30.0: (_ for _ in ()).throw(S.TopologyError("lab: reader failed"))
        outcome = lab_process.stop_scope(launch, held=held_except(launch), timeout_s=1)
        S.topology = real_topology
        check("unsure.reader_failed_not_swept", False, outcome["swept"] or outcome["observed_empty"])
        check("unsure.reader_failed_no_signal", [], outcome["signalled"])
        check("unsure.reader_failed_reason", True, any("topology unreadable" in e for e in outcome["errors"]))
        S.topology = lambda pids=None, timeout=30.0: S.parse_proc_stat("100002 (x) S 1\n")
        outcome = lab_process.stop_scope(launch, held=held_except(launch), timeout_s=1)
        S.topology = real_topology
        check("unsure.malformed_not_swept", False, outcome["swept"] or outcome["observed_empty"])
        check("unsure.malformed_no_signal", [], outcome["signalled"])
        unreadable_rows = dict(real_topology())
        unreadable_rows[child] = dict(pid=child, ppid=None, pgid=None, sid=None, comm=None, sid_error="denied")
        S.topology = lambda pids=None, timeout=30.0: unreadable_rows
        outcome = lab_process.stop_scope(launch, held=held_except(launch), timeout_s=1)
        S.topology = real_topology
        check("unsure.unreadable_row_not_swept", False, outcome["swept"] or outcome["observed_empty"])
        check("unsure.unreadable_row_listed", [child], [r["pid"] for r in outcome["unreadable"]])
        check("unsure.agent_never_signalled", True, launch.pid not in outcome["signalled"] and not launch.exited())
        check("unsure.child_alive", False, ended(child))

        # (d) one deadline for the whole cleanup (B8-03, 03-03): a slow
        # reader gets the remaining budget; an empty table after the
        # deadline is not a success; a non-empty table after the deadline
        # triggers no signal; several slow readings do not add up; a reap
        # returning late is not a success either.
        budgets, requests = [], []

        def recording_signal(pid, sid, sig, launch_):
            requests.append(pid)
            return False

        def slow_empty(pids=None, timeout=30.0):
            budgets.append(timeout)
            _time.sleep(0.06)
            return {os.getpid(): real_topology()[os.getpid()]}

        lab_process.signal_member = recording_signal
        S.topology = slow_empty
        outcome = lab_process.stop_scope(launch, held=held_except(launch), timeout_s=0.01)
        S.topology = real_topology
        check("deadline.empty_after_deadline_not_swept", False, outcome["swept"] or outcome["observed_empty"])
        check("deadline.reason_recorded", True, any("deadline" in e for e in outcome["errors"]))
        check("deadline.budget_handed_to_reader", True, bool(budgets) and all(b <= 0.01 for b in budgets))
        live_table = real_topology()

        def slow_live(pids=None, timeout=30.0):
            budgets.append(timeout)
            _time.sleep(min(0.06, max(timeout, 0.06)))
            return live_table

        budgets.clear()
        S.topology = slow_live
        outcome = lab_process.stop_scope(launch, held=held_except(launch), timeout_s=0.01)
        S.topology = real_topology
        check("deadline.late_table_no_signal", [], requests)
        check("deadline.late_table_not_swept", False, outcome["swept"])

        # Several slow readings on a virtual clock, so that the readings
        # cost what the test says whatever the host's timers do (the CI
        # macOS runner stretched a 30 ms sleep to 90 ms): readings of 30,
        # 30 and 20 ms (the last cut to its budget) and two intervals of
        # 10 ms exhaust a 100 ms deadline, with decreasing budgets, and
        # the sweep ends on the deadline with the members unsignalled.
        class Clock:
            now = 1000.0

            def monotonic(self):
                return self.now

            def sleep(self, seconds):
                self.now += max(seconds, 1e-6)

        clock = Clock()

        def slow_live_short(pids=None, timeout=30.0):
            budgets.append(timeout)
            clock.sleep(min(0.03, timeout))
            return live_table

        budgets.clear()
        S.topology = slow_live_short
        lab_process.time = clock
        try:
            outcome = lab_process.stop_scope(launch, held=held_except(launch), timeout_s=0.1, interval_s=0.01)
        finally:
            lab_process.time = _time
        S.topology = real_topology
        print("      deadline probe:", dict(readings=len(budgets), budgets=[round(b, 3) for b in budgets],
                                          elapsed_ms=outcome["elapsed_ms"], errors=outcome["errors"]))
        check("deadline.several_readings_bounded", True, [round(b, 3) for b in budgets] == [0.1, 0.06, 0.02]
              and 99 <= outcome["elapsed_ms"] <= 100 and not outcome["swept"]
              and any("deadline expired" in e for e in outcome["errors"]))
        check("deadline.budgets_decrease", True, all(b2 < b1 for b1, b2 in zip(budgets, budgets[1:])))
        lab_process.signal_member = real_signal
        check("deadline.child_untouched", False, ended(child))
        outcome = stop(launch, timeout_s=5)
        check_stopped("stop.unsure_then", outcome, launch, [child])

        # A late reap: the table shows nothing of the scope, in time; the
        # reap returns after the deadline. Not a success. The table is
        # built so that only the reap is under test.
        launch, child = fake("latereap", "exit", delay=0.0)
        S.wait_until(lambda: launch.exited() and ended(child), 5)
        if AUTH == "subreaper":
            os.waitpid(child, 0)  # adopted and ended: reaped, so that nothing of ours is left to reap
        quiet_table = {pid: row for pid, row in real_topology().items()
                       if row.get("sid") not in (None, launch.sid) and row.get("ppid") != os.getpid()}
        real_reap = launch.reap
        launch.reap = lambda timeout=None: (_time.sleep(0.06), real_reap(timeout))[1]
        S.topology = lambda pids=None, timeout=30.0: quiet_table
        outcome = lab_process.stop_scope(launch, held=held_except(launch), timeout_s=0.05, interval_s=0.001)
        S.topology = real_topology
        check("deadline.late_reap_observed", True, outcome["observed_empty"])
        check("deadline.late_reap_not_swept", False, outcome["swept"])
        check("deadline.late_reap_reason", AUTH is not None, any("after the reap" in e for e in outcome["errors"]))
        check("deadline.late_reap_done", True, launch.reaped)

        # (e) several launches: no previous scope is forgotten, a swept
        # launch keeps its record (its agent is reaped: no later sweep
        # holds the authority), the others' adopted orphans are attributed
        # to them.
        first, child1 = fake("first", "alive", delay=1.5)   # alive during its own sweep
        second, child2 = fake("second", "alive", delay=4.0)  # still alive when its turn comes, after the first's drain
        outcomes = lab_process.stop_all([first, second], timeout_s=5)
        all_outcomes.extend(outcomes)
        check_stopped("stop.first", outcomes[0], first, [child1])
        check_stopped("stop.second", outcomes[1], second, [child2])
        check("stop.no_unattributed", [[], []], [o["unattributed"] for o in outcomes])
        if AUTH is not None:
            check("stop.swept_record_stands", outcomes[0], lab_process.stop_scope(first, timeout_s=5))

        # Late markers: exactly the children never signalled wrote theirs
        # (left alone on lost authority; waited for where a descendant can
        # be neither adopted nor pinned); the bystander, in our own session,
        # is intact, was never signalled, and never counted as unattributed.
        _time.sleep(1.3)
        waited = {"alive", "pin", "first", "second"} if not (AUTH == "subreaper" or PIN) else set()
        waited |= {"dead", "race", "gen2", "zomb"} if not (AUTH == "subreaper" or PIN) else set()
        expected = sorted({"latereap", "lost", "omit"} | waited)
        check("stop.late_markers", [n + ".late" for n in expected], sorted(p.name for p in root.glob("*.late")))
        check("bystander.intact", None, bystander.poll())
        check("bystander.never_signalled", False, any(bystander.pid in o["signalled"] for o in all_outcomes))
        check("bystander.never_unattributed", False, any(bystander.pid in [r["pid"] for r in o["unattributed"]]
                                                          for o in all_outcomes))
    finally:
        S.topology, lab_process.signal_member = real_topology, real_signal
        setattr(S, LISTING, real_listing)
        for launch in fake_launches:  # safety net: nothing of the test survives it
            if not launch.reaped:
                lab_process.stop_scope(launch, held=held_except(launch), timeout_s=5)
        if bystander is not None:
            bystander.kill()
            bystander.wait(timeout=5)
        if AUTH == "subreaper":  # whatever was adopted and has ended
            while True:
                try:
                    if os.waitpid(-1, os.WNOHANG) == (0, 0):
                        break
                except ChildProcessError:
                    break
    if AUTH == "subreaper":
        check("authority.no_child_left", True, lab_process.no_children())

    # ---- the fixture after the stops: removed only on a proven closed
    # scope and a successful scenario; kept otherwise with the reason.
    fixture, evidence = root / "fixture", root / "evidence"
    fixture.mkdir()
    evidence.mkdir()
    (fixture / "agent.sqlite3").write_text("journal")
    outcome = lab_process.preserve_fixture(fixture, evidence, False, False, [dict(swept=False)])
    check("preserve.unproven_kept", fixture, outcome["kept"])
    check("preserve.unproven_reason", "no authority on this host" if AUTH is None else "scope not proven closed",
          outcome["reason"])
    check("preserve.unproven_recorded", str(fixture), json.loads((evidence / "fixture-kept.json").read_text())["path"])
    check("preserve.unproven_original_intact", "journal", (fixture / "agent.sqlite3").read_text())
    outcome = lab_process.preserve_fixture(fixture, evidence, True, True)
    check("preserve.failed_kept", (fixture, "scenario failed"), (outcome["kept"], outcome["reason"]))
    outcome = lab_process.preserve_fixture(fixture, evidence, True, False)
    check("preserve.closed_success_removed", (None, False), (outcome["kept"], fixture.exists()))

if failures:
    print(f"{len(failures)} component check(s) failed: {failures}")
    sys.exit(1)
print("lab components: ok")
