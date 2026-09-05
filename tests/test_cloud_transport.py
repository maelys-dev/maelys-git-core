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
            body = json.dumps(data).encode() if data is not None else b""
            self.send_response(code)
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
