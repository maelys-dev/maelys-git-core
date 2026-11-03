"""Sensitivity tests of the qualification harness components, with no product
binary: the counter-examples of the 2b reviews (2B-01 to 2B-04, the hook's expiry,
843-01, 843-02, its follow-up on 570154a, reviews B8 and 03) must be detected.

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

    # ---- 843-02, its follow-up on 570154a, reviews B8 and 03: cleanup
    # covers the real scope of a launch, under an authority it can prove,
    # and signals only identities it can hold. A fake agent in its own
    # session starts a child that, like the executor, leads another process
    # group in the same session (setpgrp, no setsid) and would write a
    # marker late; the agent acknowledges the child's start by a file
    # holding its pid. Each child has a bounded lifetime (it exits by itself
    # after its delay) and a safety net closes the block. Where descendants
    # cannot be pinned (no pidfd: macOS), they are never signalled and the
    # cleanup waits for them: the expectations say so explicitly.
    import lab_process
    import time as _time

    PIN = lab_process.PINNABLE_DESCENDANTS
    print(f"      descendants pinnable on this host: {PIN}")
    fake_child = root / "fake-child.py"
    fake_child.write_text("import sys, time\ntime.sleep(float(sys.argv[2]))\nopen(sys.argv[1], 'w').write('late')\n")
    fake_agent = root / "fake-agent.py"
    fake_agent.write_text(
        "import os, subprocess, sys, time\n"
        "marker, ack, mode, delay, go = sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6]\n"
        "if mode == 'wait':\n"
        "    open(ack, 'w').write('ready')\n"
        "    end = time.monotonic() + 5\n"
        "    while not os.path.exists(go) and time.monotonic() < end:\n        time.sleep(0.002)\n"
        "child = subprocess.Popen([sys.executable, sys.argv[1], marker, delay], preexec_fn=os.setpgrp)\n"
        "open(ack, 'w').write(str(child.pid))\n"
        "if mode == 'alive':\n    time.sleep(30)\n")
    fake_launches, all_outcomes = [], []

    def fake(name, mode, delay=1.0):
        """A fake agent and its child, which writes `<name>.late` after
        `delay` seconds unless stopped. Mode `wait` acknowledges `ready`,
        then forks the child and exits once `<name>.go` exists."""
        ack = root / f"{name}.ack"
        launch = lab_process.Launch([sys.executable, str(fake_agent), str(fake_child), str(root / f"{name}.late"),
                                     str(ack), mode, str(delay), str(root / f"{name}.go")])
        fake_launches.append(launch)
        # The bound covers a loaded host, not a stalled one: without the
        # acknowledgement the case cannot be exercised and the test fails
        # here, explicitly, with the launch still under the safety net.
        if not S.wait_until(ack.exists, 15):
            raise AssertionError(f"fake agent {name} ({mode}) gave no acknowledgement within 15 s: "
                                 f"host overloaded? exited={launch.exited()} returncode={launch.returncode}")
        text = ack.read_text()
        return launch, (int(text) if text.isdigit() else None)

    def child_of(name):
        text = (root / f"{name}.ack").read_text()
        return int(text) if text.isdigit() else None

    bystander = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"], start_new_session=True)
    real_topology, real_signal = S.topology, lab_process.signal_member
    try:
        # The reader (B8-02): our own session id as getsid(2) gives it, never
        # 0; a non-empty malformed line, a short /proc line and an empty
        # table are errors or explicitly unreadable rows, never an absence.
        rows = S.topology()
        check("topology.own_sid_by_getsid", os.getsid(0), rows[os.getpid()]["sid"])
        check("topology.own_sid_not_zero", True, rows[os.getpid()]["sid"] > 0)
        for name, text in (("short_line", "100002 1 100002\n"), ("not_a_number", "x 1 1 comm\n"), ("empty", "\n\n")):
            try:
                S.parse_ps_table(text)
                check(f"reader.ps_{name}_refused", "TopologyError", "accepted")
            except S.TopologyError:
                check(f"reader.ps_{name}_refused", "TopologyError", "TopologyError")
        check("reader.ps_blank_lines_skipped", [7], list(S.parse_ps_table("\n7 1 7 comm\n\n")))
        try:
            S.parse_proc_stat("7 (comm) S 1\n")
            check("reader.proc_short_refused", "TopologyError", "accepted")
        except S.TopologyError:
            check("reader.proc_short_refused", "TopologyError", "TopologyError")
        check("reader.proc_parsed", dict(pid=7, ppid=1, pgid=7, sid=7, comm="a b"),
              S.parse_proc_stat("7 (a b) S 1 7 7 0 -1 4194560 0\n"))

        # (a) parent alive, child in another group of the same session. The
        # agent is signalled on every host; the child only where pinnable,
        # otherwise it is waited for and ends by itself (its marker says so).
        launch, child = fake("alive", "alive")
        rows = S.topology()
        check("scope.child_acknowledged", True, child is not None and child in rows)
        check("scope.child_same_session", launch.sid, rows[child]["sid"] if child in rows else None)
        check("scope.agent_session_is_pid", launch.sid, rows[launch.pid]["sid"] if launch.pid in rows else None)
        check("scope.child_other_group", True, child in rows and rows[child]["pgid"] == child != rows[launch.pid]["pgid"])
        outcome = lab_process.stop_scope(launch, timeout_s=5)
        all_outcomes.append(outcome)
        check("stop.alive_confirmed", True, outcome["confirmed"])
        check("stop.alive_signalled", sorted([launch.pid, child]) if PIN else [launch.pid], outcome["signalled"])
        check("stop.alive_refused", [] if PIN else [child], outcome["refused"])
        check("stop.alive_root_reaped", True, launch.reaped and launch.returncode == -9)
        check("stop.alive_child_gone", False, lab_process._alive(child))
        check("stop.alive_child_marker", not PIN, (root / "alive.late").exists())

        # (b) parent exited but not reaped, child re-parented and alive in
        # that session: the search by parent pid is blind (the
        # counter-example of 570154a), the session finds it, the authority
        # holds because the agent's pid is still reserved.
        launch, child = fake("dead", "exit")
        check("orphan.parent_exited_unreaped", True, S.wait_until(launch.exited, 5) and not launch.reaped)
        check("orphan.parent_status_without_reap", 0, launch.returncode)
        check("orphan.child_alive", True, lab_process._alive(child))
        check("orphan.descendants_blind", [], S.descendants(launch.pid))
        rows = S.topology()
        check("orphan.child_reparented", True, child in rows and rows[child]["ppid"] != launch.pid)
        check("orphan.child_in_session", launch.sid, rows[child]["sid"] if child in rows else None)
        outcome = lab_process.stop_scope(launch, timeout_s=5)
        all_outcomes.append(outcome)
        check("stop.orphan_confirmed", True, outcome["confirmed"])
        check("stop.orphan_child_signalled", [child] if PIN else [], outcome["signalled"])
        check("stop.orphan_child_refused", [] if PIN else [child], outcome["refused"])
        check("stop.orphan_child_gone", False, lab_process._alive(child))
        check("stop.orphan_parent_reaped_after", True, launch.reaped and launch.returncode == 0)

        # (b') authority lost (B8-01): the parent reaped before the sweep. The
        # number may be reused: nothing is signalled, the stop is not
        # confirmed, the child is left alone and ends by itself (its late
        # marker is the proof that no signal reached it).
        launch, child = fake("lost", "exit")
        S.wait_until(launch.exited, 5)
        check("lost.reaped_before_sweep", 0, launch.reap(timeout=5))
        outcome = lab_process.stop_scope(launch, timeout_s=5)
        all_outcomes.append(outcome)
        check("lost.not_confirmed", False, outcome["confirmed"])
        check("lost.no_signal", [], outcome["signalled"])
        check("lost.reason", True, any("authority lost" in e for e in outcome["errors"]))
        check("lost.no_sweep", 0, outcome["sweeps"])
        check("lost.child_left_alone", True, lab_process._alive(child))
        check("lost.child_ends_by_itself", True, S.wait_until(lambda: not lab_process._alive(child), 5))
        check("lost.child_wrote_late", True, (root / "lost.late").exists())

        # (r) the race of review 03-01, with real processes: the table is
        # read while the agent is alive, then the agent forks its child and
        # exits before the classification. The status is now read before
        # the table, so that table cannot conclude; the next one sees the
        # child. Never a confirmed stop with the child alive.
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
        outcome = lab_process.stop_scope(launch, timeout_s=5)
        S.topology = real_topology
        all_outcomes.append(outcome)
        child = child_of("race")
        check("race.first_table_agent_only", [launch.pid], calls[0] if calls else None)
        check("race.child_seen_by_a_later_table", True, child is not None and any(child in c for c in calls[1:]))
        check("race.never_confirmed_with_child_alive", False, outcome["confirmed"] and lab_process._alive(child))
        check("race.confirmed_once_drained", True, outcome["confirmed"])
        check("race.child_signalled_or_refused", [child], outcome["signalled"] if PIN else outcome["refused"])
        check("race.agent_reaped_after", True, launch.reaped)

        # (p) identity held until the signal (03-02): on this host a
        # descendant is signalled only through a pidfd; without one the
        # request is refused (None) and the child is untouched. The agent,
        # our unreaped child, is always signallable.
        launch, child = fake("pin", "alive", delay=3.0)
        sent = lab_process.signal_member(child, launch.sid, 0, launch)
        check("pin.descendant_signal", True if PIN else None, sent)
        check("pin.descendant_untouched_without_pidfd", True, lab_process._alive(child))
        check("pin.not_a_member_refused", False, lab_process.signal_member(bystander.pid, launch.sid, 0, launch)
              if PIN else False)
        check("pin.agent_signal_zero", True, lab_process.signal_member(launch.pid, launch.sid, 0, launch))

        # (c) observation impossible (reader error, malformed table, an
        # unreadable row): no signal, stop not confirmed, the child
        # untouched; then the real stop (the same launch `pin` is reused).
        S.topology = lambda pids=None, timeout=30.0: (_ for _ in ()).throw(S.TopologyError("lab: reader failed"))
        outcome = lab_process.stop_scope(launch, timeout_s=1)
        S.topology = real_topology
        check("unsure.reader_failed_not_confirmed", False, outcome["confirmed"])
        check("unsure.reader_failed_no_signal", [], outcome["signalled"])
        check("unsure.reader_failed_reason", True, any("topology unreadable" in e for e in outcome["errors"]))
        S.topology = lambda pids=None, timeout=30.0: S.parse_ps_table("100002 1 100002\n")
        outcome = lab_process.stop_scope(launch, timeout_s=1)
        S.topology = real_topology
        check("unsure.malformed_not_confirmed", False, outcome["confirmed"])
        check("unsure.malformed_no_signal", [], outcome["signalled"])
        unreadable_rows = dict(real_topology())
        unreadable_rows[child] = dict(pid=child, ppid=None, pgid=None, sid=None, comm=None, sid_error="denied")
        S.topology = lambda pids=None, timeout=30.0: unreadable_rows
        outcome = lab_process.stop_scope(launch, timeout_s=1)
        S.topology = real_topology
        check("unsure.unreadable_row_not_confirmed", False, outcome["confirmed"])
        check("unsure.unreadable_row_listed", [child], [r["pid"] for r in outcome["unreadable"]])
        check("unsure.unreadable_row_reason", True, any("unreadable" in e for e in outcome["errors"]))
        check("unsure.agent_never_signalled", True, launch.pid not in outcome["signalled"] and not launch.exited())
        check("unsure.child_alive", True, lab_process._alive(child))

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
            return {}

        lab_process.signal_member = recording_signal
        S.topology = slow_empty
        outcome = lab_process.stop_scope(launch, timeout_s=0.01)
        S.topology = real_topology
        check("deadline.empty_after_deadline_not_confirmed", False, outcome["confirmed"])
        check("deadline.reason_recorded", True, any("deadline" in e for e in outcome["errors"]))
        check("deadline.budget_handed_to_reader", True, bool(budgets) and all(b <= 0.01 for b in budgets))

        live_table = real_topology()

        def slow_live(pids=None, timeout=30.0):
            budgets.append(timeout)
            _time.sleep(min(0.06, max(timeout, 0.06)))
            return live_table

        budgets.clear()
        S.topology = slow_live
        outcome = lab_process.stop_scope(launch, timeout_s=0.01)
        S.topology = real_topology
        check("deadline.late_table_no_signal", [], requests)
        check("deadline.late_table_not_confirmed", False, outcome["confirmed"])

        def slow_live_short(pids=None, timeout=30.0):
            budgets.append(timeout)
            _time.sleep(min(0.03, timeout))
            return live_table

        budgets.clear()
        S.topology = slow_live_short
        outcome = lab_process.stop_scope(launch, timeout_s=0.1, interval_s=0.01)
        S.topology = real_topology
        print("      deadline probe:", dict(readings=len(budgets), budgets=[round(b, 3) for b in budgets],
                                          elapsed_ms=outcome["elapsed_ms"], errors=outcome["errors"]))
        check("deadline.several_readings_bounded", True, len(budgets) >= 2 and outcome["elapsed_ms"] <= 200
              and not outcome["confirmed"])
        check("deadline.budgets_decrease", True, all(b2 < b1 for b1, b2 in zip(budgets, budgets[1:])))
        lab_process.signal_member = real_signal
        check("deadline.child_untouched", True, lab_process._alive(child))
        outcome = lab_process.stop_scope(launch, timeout_s=5)
        all_outcomes.append(outcome)
        check("stop.unsure_then_confirmed", True, outcome["confirmed"] and not lab_process._alive(child))

        # A late reap: the scope observed empty in time, the reap returning
        # after the deadline. Not a success.
        launch, child = fake("latereap", "exit", delay=0.0)
        S.wait_until(lambda: launch.exited() and not lab_process._alive(child), 5)
        empty_table = real_topology()  # read in time: the reading itself is not under test here
        real_reap = launch.reap
        launch.reap = lambda timeout=None: (_time.sleep(0.06), real_reap(timeout))[1]
        S.topology = lambda pids=None, timeout=30.0: empty_table
        outcome = lab_process.stop_scope(launch, timeout_s=0.03)
        S.topology = real_topology
        check("deadline.late_reap_not_confirmed", False, outcome["confirmed"])
        check("deadline.late_reap_reason", True, any("after the reap" in e for e in outcome["errors"]))
        check("deadline.late_reap_done", True, launch.reaped)

        # (e) several launches: no previous scope is forgotten, a confirmed
        # stop is final.
        first, child1 = fake("first", "alive")
        second, child2 = fake("second", "alive")
        outcomes = lab_process.stop_all([first, second], timeout_s=5)
        all_outcomes.extend(outcomes)
        check("stop.all_confirmed", [True, True], [o["confirmed"] for o in outcomes])
        check("stop.all_children_gone", [False, False], [lab_process._alive(child1), lab_process._alive(child2)])
        check("stop.confirmed_is_final", outcomes[0], lab_process.stop_scope(first, timeout_s=5))

        # Late markers: only the children that were never signalled wrote
        # theirs (left alone on lost authority; waited for where descendants
        # cannot be pinned); the bystander, in another session, is intact
        # and was never signalled.
        _time.sleep(1.3)
        expected = ["latereap.late", "lost.late"] if PIN else sorted(
            ["alive.late", "dead.late", "first.late", "latereap.late", "lost.late", "pin.late", "race.late", "second.late"])
        check("stop.late_markers", expected, sorted(p.name for p in root.glob("*.late")))
        check("bystander.intact", None, bystander.poll())
        check("bystander.never_signalled", False, any(bystander.pid in o["signalled"] for o in all_outcomes))
    finally:
        S.topology, lab_process.signal_member = real_topology, real_signal
        for launch in fake_launches:  # safety net: nothing of the test survives it
            if not launch.reaped:
                lab_process.stop_scope(launch, timeout_s=5)
        bystander.kill()
        bystander.wait(timeout=5)

    # ---- the fixture after the stops: kept in place, never copied, when a
    # stop is not confirmed; copied as a coherent state on a confirmed stop
    # of a failed scenario; nothing on success.
    fixture, evidence = root / "fixture", root / "evidence"
    fixture.mkdir()
    evidence.mkdir()
    (fixture / "agent.sqlite3").write_text("journal")
    outcome = lab_process.preserve_fixture(fixture, evidence, False, True, ("agent.sqlite3",), [dict(confirmed=False)])
    check("preserve.unconfirmed_kept", fixture, outcome["kept"])
    check("preserve.unconfirmed_not_copied", False, (evidence / "failure").exists())
    check("preserve.unconfirmed_recorded", str(fixture), json.loads((evidence / "fixture-kept.json").read_text())["path"])
    check("preserve.unconfirmed_original_intact", "journal", (fixture / "agent.sqlite3").read_text())
    outcome = lab_process.preserve_fixture(fixture, evidence, True, True, ("agent.sqlite3", "absent"))
    check("preserve.failed_copied", "journal", (evidence / "failure" / "agent.sqlite3").read_text())
    check("preserve.failed_not_kept", None, outcome["kept"])
    outcome = lab_process.preserve_fixture(fixture, evidence / "clean", True, False, ("agent.sqlite3",))
    check("preserve.success_nothing", dict(kept=None, copied=None), outcome)

if failures:
    print(f"{len(failures)} component check(s) failed: {failures}")
    sys.exit(1)
print("lab components: ok")
