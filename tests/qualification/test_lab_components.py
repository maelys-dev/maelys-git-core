"""Sensitivity tests of the qualification harness components, with no product
binary: the counter-examples of the 2b reviews (2B-01 to 2B-04, the hook's expiry,
843-01, 843-02 and its follow-up on 570154a) must be detected.

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

    # ---- 843-02 (and its follow-up on 570154a): cleanup covers the real
    # scope of a launch. A fake agent in its own session starts a child that,
    # like the executor, leads another process group in the same session
    # (setpgrp, no setsid) and would write a marker late; the agent
    # acknowledges the child's start by a file holding its pid. The proofs
    # expected by the review follow, each with a bounded child (it exits by
    # itself after a second) and a safety net at the end.
    import lab_process
    import time as _time

    fake_child = root / "fake-child.py"
    fake_child.write_text("import sys, time\ntime.sleep(float(sys.argv[2]))\nopen(sys.argv[1], 'w').write('late')\n")
    fake_agent = root / "fake-agent.py"
    fake_agent.write_text("import os, subprocess, sys, time\n"
                          "child = subprocess.Popen([sys.executable, sys.argv[1], sys.argv[2], sys.argv[5]], preexec_fn=os.setpgrp)\n"
                          "open(sys.argv[3], 'w').write(str(child.pid))\n"
                          "if sys.argv[4] == 'alive':\n    time.sleep(30)\n")
    fake_launches, all_outcomes = [], []

    def fake(name, mode, delay=1.0):
        """A fake agent and its child, which writes `<name>.late` after
        `delay` seconds unless stopped."""
        marker, ack = root / f"{name}.late", root / f"{name}.ack"
        launch = lab_process.Launch([sys.executable, str(fake_agent), str(fake_child), str(marker), str(ack), mode,
                                     str(delay)])
        fake_launches.append(launch)
        S.wait_until(ack.exists, 5)
        child = int(ack.read_text()) if ack.exists() else None
        return launch, child, marker

    bystander = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"], start_new_session=True)
    try:
        # The reader: our own session id read as getsid(2) gives it, never 0.
        rows = S.topology()
        check("topology.own_sid_by_getsid", os.getsid(0), rows[os.getpid()]["sid"])
        check("topology.own_sid_not_zero", True, rows[os.getpid()]["sid"] > 0)

        # (a) parent alive, child in another group of the same session.
        launch, child, marker = fake("alive", "alive")
        rows = S.topology()
        check("scope.child_acknowledged", True, child is not None and child in rows)
        check("scope.child_same_session", launch.sid, rows[child]["sid"] if child in rows else None)
        check("scope.agent_session_is_pid", launch.sid, rows[launch.pid]["sid"] if launch.pid in rows else None)
        check("scope.child_other_group", True, child in rows and rows[child]["pgid"] == child != rows[launch.pid]["pgid"])
        outcome = lab_process.stop_scope(launch, timeout_s=5)
        all_outcomes.append(outcome)
        check("stop.alive_confirmed", True, outcome["confirmed"])
        check("stop.alive_two_groups", sorted({launch.pid, child}), outcome["signalled_groups"])
        check("stop.alive_root_reaped", True, launch.returncode is not None)
        check("stop.alive_child_gone", False, lab_process._alive(child))

        # (b) parent already exited and reaped, child re-parented, still
        # alive in that session: the search by parent pid is blind (the
        # counter-example of 570154a), the search by session finds it.
        launch, child, marker_dead = fake("dead", "exit")
        check("orphan.parent_reaped", 0, launch.wait(timeout=5))
        check("orphan.child_alive", True, lab_process._alive(child))
        check("orphan.descendants_blind", [], S.descendants(launch.pid))
        rows = S.topology()
        check("orphan.child_reparented", True, child in rows and rows[child]["ppid"] != launch.pid)
        check("orphan.child_in_session", launch.sid, rows[child]["sid"] if child in rows else None)
        outcome = lab_process.stop_scope(launch, timeout_s=5)
        all_outcomes.append(outcome)
        check("stop.orphan_confirmed", True, outcome["confirmed"])
        check("stop.orphan_group_signalled", [child], outcome["signalled_groups"])
        check("stop.orphan_child_gone", False, lab_process._alive(child))

        # (c) observation impossible, then identity uncertain: no signal,
        # stop not confirmed, the child untouched (it lives long enough to
        # outlast both bounded attempts); then the real stop.
        launch, child, marker_unsure = fake("unsure", "alive", delay=2.0)
        real_topology, real_started_at = S.topology, lab_process.started_at
        S.topology = lambda pids=None: (_ for _ in ()).throw(S.TopologyError("lab: reader failed"))
        try:
            outcome = lab_process.stop_scope(launch, timeout_s=1)
        finally:
            S.topology = real_topology
        check("unsure.reader_failed_not_confirmed", False, outcome["confirmed"])
        check("unsure.reader_failed_no_signal", [], outcome["signalled_groups"])
        check("unsure.reader_failed_reason", True, any("topology unreadable" in e for e in outcome["errors"]))
        check("unsure.reader_failed_child_alive", True, lab_process._alive(child) and launch.returncode is None)
        lab_process.started_at = lambda pid: None
        try:
            outcome = lab_process.stop_scope(launch, timeout_s=0.3)
        finally:
            lab_process.started_at = real_started_at
        check("unsure.identity_not_confirmed", False, outcome["confirmed"])
        check("unsure.identity_no_signal", [], outcome["signalled_groups"])
        check("unsure.identity_listed", sorted([launch.pid, child]), sorted(r["pid"] for r in outcome["uncertain"]))
        check("unsure.identity_child_alive", True, lab_process._alive(child) and launch.returncode is None)
        outcome = lab_process.stop_scope(launch, timeout_s=5)
        all_outcomes.append(outcome)
        check("stop.unsure_then_confirmed", True, outcome["confirmed"] and not lab_process._alive(child))

        # (d) several launches: no previous scope is forgotten.
        first, child1, marker1 = fake("first", "alive")
        second, child2, marker2 = fake("second", "alive")
        outcomes = lab_process.stop_all([first, second], timeout_s=5)
        all_outcomes.extend(outcomes)
        check("stop.all_confirmed", [True, True], [o["confirmed"] for o in outcomes])
        check("stop.all_children_gone", [False, False], [lab_process._alive(child1), lab_process._alive(child2)])

        # No late marker from any stopped child once every delay has passed;
        # the bystander, in another session, is intact and was never signalled.
        _time.sleep(2.3)
        check("stop.no_late_marker", [], sorted(p.name for p in root.glob("*.late")))
        check("bystander.intact", None, bystander.poll())
        check("bystander.never_signalled", False, any(bystander.pid in o["signalled_groups"] for o in all_outcomes))
    finally:
        for launch in fake_launches:  # safety net: nothing of the test survives it
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
