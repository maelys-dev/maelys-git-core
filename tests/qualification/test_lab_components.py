"""Sensitivity tests of the qualification harness components, with no product
binary: the counter-examples of the 2b review (2B-01 to 2B-04 and the hook's
expiry) must be detected.

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

    # ---- 843-02: cleanup covers the real fixture scope. A fake agent in its
    # own session starts a child that, like the executor, leads another
    # process group and would write a marker late; stop_tree() must stop
    # both, confirm it, and no late marker may appear.
    import lab_process
    marker = root / "late-marker"
    fake_child = root / "fake-child.py"
    fake_child.write_text("import sys, time\ntime.sleep(1.0)\nopen(sys.argv[1], 'w').write('late')\n")
    fake_agent = root / "fake-agent.py"
    fake_agent.write_text("import subprocess, sys, time\n"
                          "subprocess.Popen([sys.executable, sys.argv[1], sys.argv[2]], start_new_session=True)\n"
                          "time.sleep(30)\n")
    agent = subprocess.Popen([sys.executable, str(fake_agent), str(fake_child), str(marker)], start_new_session=True)
    import time as _time
    _time.sleep(0.4)
    tree_before = S.descendants(agent.pid)
    check("cleanup.child_in_another_group_before", True, bool(tree_before) and all(r["pgid"] != os.getpgid(agent.pid) for r in tree_before))
    outcome = lab_process.stop_tree(agent, timeout_s=5)
    check("cleanup.confirmed", True, outcome["confirmed"])
    check("cleanup.two_groups_signalled", True, len(outcome["signalled_groups"]) >= 2)
    check("cleanup.root_reaped", True, agent.returncode is not None)
    _time.sleep(1.5)
    check("cleanup.no_late_marker", False, marker.exists())

if failures:
    print(f"{len(failures)} component check(s) failed: {failures}")
    sys.exit(1)
print("lab components: ok")
