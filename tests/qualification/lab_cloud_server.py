"""Lab Cloud server for the GIT-C10 qualification harness.

A TLS HTTPS server that plays the Cloud consumer the agent polls (`GET
command_target`) and posts events to (`POST event_target`), with a scripted
command queue, failure modes switched at run time, and a request journal.
It extends the server of tests/test_cloud_transport.py; it is a standard
library only module, usable in-process (LabCloudServer) or as a program
(`python3 lab_cloud_server.py --cert CERT --key KEY [--control PORT]`), whose
stdout first line is a JSON object naming the listening ports.

Modes (one at a time, per channel: `poll` or `event`):
  normal     answer from the queue (poll) or accept and record (event)
  mute       accept the TCP connection and never answer (Q04 silent peer)
  slow       one byte every SLOW_INTERVAL_S of a valid answer (Q04 slow peer)
  dedup      remember Idempotency-Key; a repeated key is answered 2xx and
             recorded as a repeat, with the form received (Q06)
  reject     answer REJECT_STATUS with a JSON body (Q06, Q09)
  drop_ack   accept and record the event exactly as `normal` does, then
             close without answering: the lost acknowledgement of Q06
  drop_before close before reading or accepting anything (the cut before
             acceptance, distinguished from the lost acknowledgement)
  denied     403
  redirect   302 to /redirect-target
  raw        answer RAW_BODY as is (Q11)
Token rotation: set_token(). event_protocol 1 refuses an event whose `type`
is not `result` with 400 (what an old consumer would do), 2 accepts every
declared type. The control endpoint is plain HTTP on 127.0.0.1 only, for the
orchestrator: GET /state, GET /requests, POST /mode {"channel","mode"},
POST /enqueue {command}, POST /token {"token"}, POST /event_protocol {"v"}.
"""
import argparse
import http.server
import json
import socket
import ssl
import sys
import threading
import time

SLOW_INTERVAL_S = 0.24
REJECT_STATUS = 503
MODES = {"normal", "mute", "slow", "dedup", "reject", "drop_ack", "drop_before", "denied", "redirect", "raw"}


class LabCloudServer:
    def __init__(self, cert, key, host="127.0.0.1", port=0, control_port=None):
        self.lock = threading.Lock()
        self.queue = []            # commands to serve, oldest first
        self.cursor = 0
        self.requests = []         # journal: dicts with t_ms, method, path, headers of interest, body
        self.posts = []            # (idempotency_key, body) of accepted events
        self.seen_keys = {}        # Idempotency-Key -> first body (dedup mode)
        self.token = "lab-token-5b2f1e9c-SECRET-LAB-VALUE-000"
        self.mode = {"poll": "normal", "event": "normal"}
        self.event_protocol = 2
        self.raw_body = b""
        server = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                pass

            def journal(self, body):
                with server.lock:
                    server.requests.append(dict(
                        t_ms=int(time.time() * 1000), method=self.command, path=self.path,
                        idempotency_key=self.headers.get("Idempotency-Key"),
                        authorization_ok=self.headers.get("Authorization") == "Bearer " + server.token,
                        content_length=self.headers.get("Content-Length"),
                        body=body.decode("utf-8", "replace") if body else None))

            def respond(self, code, data=None, location=None, slow=False):
                body = data if isinstance(data, bytes) else json.dumps(data).encode() if data is not None else b""
                if slow:
                    # One byte at a time, header then body, just before each
                    # wait slice of the client would expire (plan §2.1).
                    head = (f"HTTP/1.1 {code} OK\r\nContent-Type: application/json\r\n"
                            f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode()
                    for byte in head + body:
                        self.wfile.write(bytes([byte]))
                        self.wfile.flush()
                        time.sleep(SLOW_INTERVAL_S)
                    self.close_connection = True
                    return
                self.send_response(code)
                if not (100 <= code < 200 or code == 204):
                    self.send_header("Content-Length", str(len(body)))
                if location:
                    self.send_header("Location", location)
                self.end_headers()
                self.wfile.write(body)

            def authenticated(self):
                if self.headers.get("Authorization") != "Bearer " + server.token:
                    self.respond(401)
                    return False
                return True

            def common(self, channel, body):
                mode = server.mode[channel]
                if mode == "mute":
                    # Hold the connection open until the client gives up.
                    try:
                        self.connection.settimeout(None)
                        self.rfile.read(1)
                    except OSError:
                        pass
                    self.close_connection = True
                    return True
                if mode == "denied":
                    self.respond(403)
                    return True
                if mode == "redirect":
                    self.respond(302, location=f"https://localhost:{self.server.server_port}/redirect-target")
                    return True
                if mode == "reject":
                    self.respond(REJECT_STATUS, {"error": "lab reject"})
                    return True
                if mode == "raw":
                    self.respond(200, server.raw_body)
                    return True
                if mode == "drop_before":
                    self.close_connection = True
                    return True
                return False

            def do_GET(self):
                self.journal(b"")
                if not self.authenticated():
                    return
                if self.common("poll", b""):
                    return
                with server.lock:
                    commands = list(server.queue)
                    server.queue.clear()
                    server.cursor += 1
                    cursor = f"cursor-{server.cursor}"
                if commands:
                    self.respond(200, dict(cursor=cursor, commands=commands), slow=server.mode["poll"] == "slow")
                else:
                    self.respond(204)

            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                self.journal(body)
                if not self.authenticated():
                    return
                if self.common("event", body):
                    return
                key = self.headers.get("Idempotency-Key")
                try:
                    event = json.loads(body)
                except ValueError:
                    self.respond(400, {"error": "not JSON"})
                    return
                if server.event_protocol == 1 and event.get("type") not in (None, "result"):
                    self.respond(400, {"error": "unknown event type for protocol 1"})
                    return
                with server.lock:
                    repeated = key in server.seen_keys
                    if server.mode["event"] in ("dedup", "drop_ack") and key is not None:
                        server.seen_keys.setdefault(key, body)
                    server.posts.append(dict(idempotency_key=key, body=event, repeated=repeated,
                                             same_as_first=(server.seen_keys.get(key) == body) if repeated else None,
                                             acknowledged=server.mode["event"] != "drop_ack"))
                if server.mode["event"] == "drop_ack":
                    # Accepted and recorded above; the acknowledgement is what is lost.
                    self.close_connection = True
                    return
                self.respond(200, {"deduplicated": repeated} if repeated else {})

        self.server = http.server.ThreadingHTTPServer((host, port), Handler)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(cert, key)
        self.server.socket = tls.wrap_socket(self.server.socket, server_side=True)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.control = None
        if control_port is not None:
            self.control = self._control_server(host, control_port)
            self.control_port = self.control.server_address[1]

    def _control_server(self, host, port):
        server = self

        class Control(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                pass

            def reply(self, code, data):
                body = json.dumps(data).encode()
                self.send_response(code)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                if self.path == "/state":
                    self.reply(200, server.state())
                elif self.path == "/requests":
                    with server.lock:
                        self.reply(200, dict(requests=server.requests, posts=server.posts))
                else:
                    self.reply(404, {"error": "unknown"})

            def do_POST(self):
                data = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))) or b"{}")
                try:
                    if self.path == "/mode":
                        server.set_mode(data["channel"], data["mode"])
                    elif self.path == "/enqueue":
                        server.enqueue(data)
                    elif self.path == "/token":
                        server.set_token(data["token"])
                    elif self.path == "/event_protocol":
                        server.event_protocol = int(data["v"])
                    elif self.path == "/raw":
                        server.raw_body = data["body"].encode()
                    else:
                        self.reply(404, {"error": "unknown"})
                        return
                except (KeyError, ValueError) as error:
                    self.reply(400, {"error": str(error)})
                    return
                self.reply(200, server.state())

        control = http.server.ThreadingHTTPServer((host, port), Control)
        threading.Thread(target=control.serve_forever, daemon=True).start()
        return control

    # ---- orchestrator API ------------------------------------------------
    def start(self):
        self.thread.start()
        return self

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
        if self.control:
            self.control.shutdown()
            self.control.server_close()

    def enqueue(self, command):
        with self.lock:
            self.queue.append(command)

    def set_mode(self, channel, mode):
        if channel not in self.mode or mode not in MODES:
            raise ValueError(f"unknown channel or mode: {channel} {mode}")
        with self.lock:
            self.mode[channel] = mode

    def set_token(self, token):
        with self.lock:
            self.token = token

    def state(self):
        with self.lock:
            return dict(port=self.port, mode=dict(self.mode), event_protocol=self.event_protocol,
                        queued=len(self.queue), requests=len(self.requests), posts=len(self.posts),
                        cursor=self.cursor)

    def wait_for_request(self, predicate, timeout_s=10.0, interval_s=0.05):
        """Synchronisation point s5: the first journal entry matching
        predicate, or None after timeout_s (the caller fails the test)."""
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            with self.lock:
                for entry in self.requests:
                    if predicate(entry):
                        return entry
            time.sleep(interval_s)
        return None


def command(message_id, name, agent_id="lab-agent", repository=None, principal=None, payload=None,
            lifetime_ms=120000):
    """A command message in the agent protocol, as the Cloud would send it."""
    now = int(time.time() * 1000)
    message = dict(protocol="maelys-git-agent/1", message_id=message_id, agent_id=agent_id,
                   type="command", command=name, issued_at_ms=now, expires_at_ms=now + lifetime_ms,
                   payload=payload or {})
    if repository is not None:
        message["repository"] = repository
    if principal is not None:
        message["principal"] = principal
    return message


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--control", type=int, default=0, help="control port on the loopback (0 = ephemeral)")
    args = parser.parse_args(argv)
    server = LabCloudServer(args.cert, args.key, args.host, args.port, control_port=args.control).start()
    print(json.dumps(dict(port=server.port, control_port=server.control_port)), flush=True)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        server.stop()


if __name__ == "__main__":
    main(sys.argv[1:])
