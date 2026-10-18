"""Local HTTPS end-to-end test: agent, executor, durable outbox and TLS boundary."""
import http.server
import json
from pathlib import Path
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import threading
import time

AGENT, EXECUTOR, MANIFEST, OPENSSL = map(lambda arg: str(Path(arg).resolve()), sys.argv[1:])


def run(*args, ok=True):
    result = subprocess.run(args, capture_output=True, text=True, timeout=20)
    if ok and result.returncode:
        raise AssertionError(f"{args}: {result.stdout}\n{result.stderr}")
    return result


run(AGENT, "describe", "--summary", "--format", "json", "--non-interactive")
run(AGENT, "describe", "run", "--format", "json", "--non-interactive")
run(EXECUTOR, "describe", "--summary", "--format", "json", "--non-interactive")
run(EXECUTOR, "describe", "serve", "--format", "json", "--non-interactive")

with tempfile.TemporaryDirectory(prefix="maelys-cloud-test-") as temporary:
    root = Path(temporary).resolve()
    cert, key = root / "cert.pem", root / "key.pem"
    for stem in ["cert", "wrong-ca"]:
        run(OPENSSL, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
            "-keyout", str(key if stem == "cert" else root / "wrong-key.pem"),
            "-out", str(root / (stem + ".pem")))
    now = int(time.time() * 1000)
    command = dict(protocol="maelys-git-agent/1", message_id="cloud-health", agent_id="local-test",
                   type="command", command="health", issued_at_ms=now,
                   expires_at_ms=now + 120000, payload={})
    state = dict(token="first-token", command=command, posts=[], requests=[], mode="normal")

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def respond(self, code, data=None, location=None):
            body = data if isinstance(data, bytes) else json.dumps(data).encode() if data is not None else b""
            self.send_response(code)
            # RFC 9110 section 6.4.1: a 1xx or 204 response carries no
            # framing field; maelys-http refuses one as ambiguous framing.
            if not (100 <= code < 200 or code == 204):
                self.send_header("Content-Length", str(len(body)))
            if location:
                self.send_header("Location", location)
            self.end_headers()
            self.wfile.write(body)

        def authenticated(self):
            state["requests"].append(self.path)
            if self.headers.get("Authorization") != "Bearer " + state["token"]:
                self.respond(401)
                return False
            return True

        def do_GET(self):
            if not self.authenticated():
                return
            if state["mode"] == "redirect":
                self.respond(302, location=f"https://localhost:{self.server.server_port}/redirect-target")
            elif state["mode"] == "denied":
                self.respond(403)
            elif state["mode"] == "raw":
                self.respond(200, state["body"])
            elif state["command"]:
                self.respond(200, dict(cursor="cursor-1", commands=[state["command"]]))
                state["command"] = None
            else:
                self.respond(204)

        def do_POST(self):
            if not self.authenticated():
                return
            body = self.rfile.read(int(self.headers["Content-Length"]))
            state["posts"].append((self.headers.get("Idempotency-Key"), json.loads(body)))
            self.respond(200, {})

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(cert, key)
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    token, config_path, database = root / "token", root / "config.json", root / "agent.sqlite3"
    token.write_text(state["token"])
    token.chmod(0o600)
    config = dict(version=1, agent_id="local-test", authority=f"localhost:{server.server_port}",
                  ca_file=str(cert), token_file=str(token), database_path=str(database),
                  manifest_path=MANIFEST, repository_root=str(root), git_executable="/usr/bin/git",
                  executor_path=EXECUTOR, command_target="/commands", event_target="/events",
                  # Keep startup headroom for instrumented CI binaries. The
                  # supervisor unit tests exercise the sub-second deadlines.
                  poll_timeout_ms=1000, request_timeout_ms=10000)

    def cycle(ok=True):
        config_path.write_text(json.dumps(config))
        config_path.chmod(0o600)
        result = run(AGENT, "run", "--config", str(config_path), "--once", "--format", "json",
                     "--non-interactive", ok=ok)
        if not ok:
            assert result.returncode and not result.stdout, result
            assert not json.loads(result.stderr)["ok"], result.stderr
        return result

    try:
        cycle()
        with sqlite3.connect(database) as connection:
            rows = connection.execute("SELECT state,result_json FROM commands").fetchall()
            assert len(rows) == 1 and rows[0][0] == "complete", rows
            assert connection.execute("SELECT count(*) FROM outbox WHERE acked_at_ms IS NULL").fetchone() == (1,)
        state["token"] = "rotated-token"
        token.write_text(state["token"])
        cycle()
        assert len(state["posts"]) == 1, state
        message_id, result = state["posts"][0]
        assert message_id == "cloud-health" and result["status"] == "ok", result
        assert result["payload"]["healthy"], result
        with sqlite3.connect(database) as connection:
            assert connection.execute("SELECT count(*) FROM outbox WHERE acked_at_ms IS NULL").fetchone() == (0,)

        def poll_bytes(commands, cursor="next"):
            return json.dumps(dict(cursor=cursor, commands=commands), separators=(",", ":")).encode()

        def fresh_database(name):
            path = root / (name + ".sqlite3")
            config["database_path"] = str(path)
            return path

        def assert_empty_journal(path):
            with sqlite3.connect(path) as connection:
                assert connection.execute("SELECT count(*) FROM commands").fetchone() == (0,)
                assert connection.execute("SELECT count(*) FROM outbox").fetchone() == (0,)
                assert connection.execute("SELECT value FROM metadata WHERE key='cursor'").fetchone() in [None, ("",)]

        state["mode"] = "raw"
        valid_poll = poll_bytes([command])
        malformed = [b"{}", b"[]", b"\xef\xbb\xbf" + valid_poll, valid_poll + b"\0",
                     valid_poll + b"{}", valid_poll.replace(b'"next"', b'"\\ud800"'),
                     valid_poll.replace(b'"next"', b'"a\\u0000b"'),
                     valid_poll.replace(b'"next"', b'"\xff"'),
                     valid_poll.replace(b'"next"', b'"next","cur\\u0073or":"other"'),
                     poll_bytes([command] * 33), poll_bytes([], "x" * 1024)]
        for number in ["1.0", "1e0", "9223372036854775808", "18446744073709551615",
                       "18446744073709551616", "-9223372036854775809"]:
            # Validate the entire numeric domain before processing the first command.
            second = dict(command, message_id="numeric", payload={"value": "NUMBER"})
            malformed.append(poll_bytes([command, second]).replace(b'"NUMBER"', number.encode()))
        for i, body in enumerate(malformed):
            path = fresh_database("bad-poll-" + str(i))
            state["body"] = body
            cycle(ok=False)
            assert_empty_journal(path)

        for size in [65536, 65537]:
            path = fresh_database("poll-size-" + str(size))
            state["body"] = poll_bytes([]).ljust(size, b" ")
            cycle(ok=size == 65536)
            with sqlite3.connect(path) as connection:
                cursor = connection.execute("SELECT value FROM metadata WHERE key='cursor'").fetchone()
                assert cursor == (("next",) if size == 65536 else None), cursor
        path = fresh_database("cursor-max")
        state["body"] = poll_bytes([], "x" * 1023)
        cycle()
        with sqlite3.connect(path) as connection:
            assert connection.execute("SELECT value FROM metadata WHERE key='cursor'").fetchone() == ("x" * 1023,)
        path = fresh_database("wrong-agent")
        state["body"] = poll_bytes([dict(command, agent_id="someone-else")])
        cycle(ok=False)
        assert_empty_journal(path)

        # A whole batch above 8192 tokens still reaches each command executor.
        path = fresh_database("many-values")
        batch = [dict(command, message_id="batch-" + str(i), payload={"values": [0] * 300})
                 for i in range(32)]
        state["body"] = poll_bytes(batch)
        assert len(state["body"]) < 65536
        cycle()
        with sqlite3.connect(path) as connection:
            rows = connection.execute("SELECT state,result_json FROM commands").fetchall()
            assert len(rows) == 32 and all(row[0] == "failed" for row in rows), rows
            assert all(json.loads(row[1])["payload"]["code"] == "protocol_error" for row in rows), rows
            assert connection.execute("SELECT value FROM metadata WHERE key='cursor'").fetchone() == ("next",)

        path = fresh_database("unicode-replay")
        unicode_command = dict(command, message_id="unicode", payload={"\ue000": 1, "\U00010000": 2, "text": "café"})
        state["body"] = poll_bytes([unicode_command])
        cycle()
        # Deduplication form v2: keys sorted by UTF-16 code units, printable
        # ASCII with lower-case escapes, compact.
        def form_v2(value):
            if isinstance(value, dict):
                return "{" + ",".join(json.dumps(key) + ":" + form_v2(value[key]) for key in
                                      sorted(value, key=lambda key: key.encode("utf-16-be"))) + "}"
            return json.dumps(value, ensure_ascii=True, separators=(",", ":"))
        expected_v2 = form_v2(unicode_command)
        assert expected_v2.index("\\ud800\\udc00") < expected_v2.index("\\ue000"), expected_v2
        with sqlite3.connect(path) as connection:
            first = connection.execute("SELECT raw_json,result_json FROM commands WHERE id='unicode'").fetchone()
            assert first[0] == expected_v2, first
            assert connection.execute("SELECT value FROM metadata WHERE key='dedup_form'").fetchone() == ("v2",)
        state["body"] = json.dumps(dict(commands=[unicode_command], cursor="replayed"), ensure_ascii=False, indent=2).encode()
        cycle()
        with sqlite3.connect(path) as connection:
            assert connection.execute("SELECT raw_json,result_json FROM commands WHERE id='unicode'").fetchone() == first
            assert connection.execute("SELECT count(*) FROM commands").fetchone() == (1,)
        # Reinterpretation of an older journal also requires a correlated result.
        for corrupted in ["{}", json.dumps(dict(json.loads(first[1]), status="ok"))]:
            with sqlite3.connect(path) as connection:
                connection.execute("UPDATE commands SET result_json=? WHERE id='unicode'", (corrupted,))
                connection.execute("UPDATE outbox SET acked_at_ms=1")
            state["body"] = poll_bytes([unicode_command], "must-not-advance")
            cycle(ok=False)
            with sqlite3.connect(path) as connection:
                assert connection.execute("SELECT value FROM metadata WHERE key='cursor'").fetchone() == ("replayed",)
                assert connection.execute("SELECT count(*) FROM outbox WHERE acked_at_ms IS NULL").fetchone() == (0,)

        # A substitute executor cannot persist or post an uncorrelated success.
        reply_file, fake_executor = root / "reply.bin", root / "fake-executor"
        fake_executor.write_text(f"#!{sys.executable}\nimport sys\nfrom pathlib import Path\n"
                                 f"sys.stdin.buffer.read()\nsys.stdout.buffer.write(Path({str(reply_file)!r}).read_bytes())\n")
        fake_executor.chmod(0o755)
        config["executor_path"] = str(fake_executor)
        response = dict(protocol="maelys-git-agent/1", message_id=command["message_id"],
                        agent_id=command["agent_id"], type="result", command="health", status="ok", payload={})
        bad_results = [b"{}\n", json.dumps(response).encode(),
                       json.dumps(response).encode() + b"\0\n",
                       json.dumps(response).encode() + b"\n{}\n"]
        for field, value in [("protocol", "wrong"), ("message_id", "someone-else"),
                             ("agent_id", "someone-else"), ("command", "pr_merge"),
                             ("type", "event"), ("status", "pending"), ("status", True),
                             ("payload", [])]:
            bad_results.append(json.dumps(dict(response, **{field: value})).encode() + b"\n")
        bad_results.append(json.dumps(response).encode().replace(b'"ok"', b'"ok","st\\u0061tus":"failed"') + b"\n")
        for i, body in enumerate(bad_results):
            path = fresh_database("bad-result-" + str(i))
            state["body"] = valid_poll
            reply_file.write_bytes(body)
            cycle()
            with sqlite3.connect(path) as connection:
                terminal, encoded = connection.execute("SELECT state,result_json FROM commands").fetchone()
                safe = json.loads(encoded)
                assert terminal == "failed" and safe["status"] == "failed", safe
                assert safe["message_id"] == command["message_id"] and safe["command"] == "health", safe
                assert safe["payload"]["code"] == "executor_failed", safe
                assert connection.execute("SELECT payload FROM outbox").fetchone() == (encoded,)
            state["body"] = poll_bytes([])
            cycle()
            assert state["posts"][-1] == (command["message_id"], safe), state["posts"][-1]
        for status in ["ok", "denied", "failed"]:
            path = fresh_database("valid-result-" + status)
            state["body"] = valid_poll
            reply_file.write_bytes(json.dumps(dict(response, status=status)).encode() + b"\r\n")
            cycle()
            with sqlite3.connect(path) as connection:
                assert connection.execute("SELECT state FROM commands").fetchone() == (
                    "complete" if status == "ok" else "failed",)
        config["executor_path"] = EXECUTOR
        config["database_path"] = str(database)
        state["mode"] = "normal"
        count = len(state["requests"])
        config["ca_file"] = str(root / "wrong-ca.pem")
        cycle(ok=False)
        assert len(state["requests"]) == count
        config["ca_file"] = str(cert)
        config["authority"] = f"127.0.0.1:{server.server_port}"
        cycle(ok=False)
        assert len(state["requests"]) == count
        config["authority"] = f"localhost:{server.server_port}"
        state["mode"] = "redirect"
        cycle(ok=False)
        assert "/redirect-target" not in state["requests"]
        state["mode"] = "denied"
        cycle(ok=False)
    finally:
        server.shutdown()
        server.server_close()
        thread.join()

print("HTTPS command/executor/outbox, token rotation, CA/hostname verification and redirects: ok")
