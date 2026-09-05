"""Exercise byte framing and typed input through both public JSONL streams."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

AGENT, EXECUTOR, MANIFEST = [str(Path(arg).resolve()) for arg in sys.argv[1:]]
ENV = {key: value for key, value in os.environ.items()
       if not key.startswith(("GIT_", "MAELYS_"))}
ENV.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null",
           MAELYS_CLI_FORMAT="json")
JSON_FLAGS = ["--format", "json", "--compact", "--non-interactive"]
MAX_BYTES = 65536
I64_MAX = 9223372036854775807


def run(*args, data=None):
    return subprocess.run(list(map(str, args)), input=data, capture_output=True,
                          env=ENV, timeout=15)


def command(name="health", payload=None, **fields):
    now = int(time.time() * 1000)
    return dict(protocol="maelys-git-agent/1", message_id="reader-1", agent_id="agent-1",
                type="command", command=name, repository="example.git", principal="alice",
                issued_at_ms=now, expires_at_ms=now + 300000,
                payload={} if payload is None else payload, **fields)


def encode(value):
    return json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode()


def with_number(value, field, lexeme, payload=False):
    value = json.loads(encode(value))
    (value["payload"] if payload else value)[field] = "NUMBER_MARKER"
    return encode(value).replace(b'"NUMBER_MARKER"', lexeme.encode())


def expect_error(reply, code="protocol_error", execution=False):
    if execution:
        assert reply["type"] == "result" and reply["status"] == "failed", reply
        reply = reply["payload"]
    else:
        assert reply["type"] == "error", reply
    assert reply["code"] == code, reply


with tempfile.TemporaryDirectory(prefix="maelys-protocol-reader-") as temporary:
    root = Path(temporary).resolve()
    for name in ["example.git", "source.git"]:
        result = run("/usr/bin/git", "init", "--bare", "-q", root / name)
        assert result.returncode == 0, result.stderr

    for binary, stream in [(AGENT, "stdio"), (EXECUTOR, "serve")]:
        for selected in ["--summary", stream]:
            result = run(binary, "describe", selected, *JSON_FLAGS)
            assert result.returncode == 0, result.stderr

        def exchange(data, exit_code=0):
            result = run(binary, stream, "--manifest", MANIFEST, "--root", root, data=data)
            assert result.returncode == exit_code, (result.returncode, result.stdout, result.stderr)
            if exit_code == 0:
                assert not result.stderr, result.stderr
            else:
                assert b"stream error [" in result.stderr, result.stderr
            return [json.loads(line) for line in result.stdout.splitlines()]

        valid = encode(command())
        for ending in [b"\n", b"\r\n"]:
            for size in [len(valid), MAX_BYTES - 1, MAX_BYTES]:
                replies = exchange(valid.ljust(size, b" ") + ending)
                assert len(replies) == 1 and replies[0]["status"] == "ok", replies
            replies = exchange(valid.ljust(MAX_BYTES + 1, b" ") + ending, exit_code=1)
            assert len(replies) == 1, replies
            expect_error(replies[0], "limit_exceeded")
        replies = exchange(valid, exit_code=1)
        assert len(replies) == 1, replies
        expect_error(replies[0])

        malformed = [
            b"\xef\xbb\xbf" + valid, valid + b" trailing", valid + b"{}",
            valid + b"\0", valid + b"\0{}", b"[]", b"null", b"",
            valid.replace(b'"alice"', b'"a\\u0000b"'),
            valid.replace(b'"alice"', b'"a\0b"'),
            valid.replace(b'"alice"', b'"\xff"'),
            valid.replace(b'"alice"', b'"\\ud800"'),
            valid.replace(b'"alice"', b'"\\udc00"'),
            valid.replace(b'"alice"', b'"alice","princ\\u0069pal":"bob"'),
            valid.replace(b'"payload":{}', b'"payload":{"x":1,"\\u0078":2}'),
            valid.replace(b'"payload":{}', b'"payload":[]'),
            valid[:-1] + b',"unknown":true}',
        ]
        for field in ["issued_at_ms", "expires_at_ms"]:
            for lexeme in ["0", "-1", "-9223372036854775808", "9223372036854775808",
                           "18446744073709551615", "18446744073709551616",
                           "1.0", "1e0", "true", "null", '"1"']:
                malformed.append(with_number(command(), field, lexeme))
        malformed.append(with_number(command(), "expires_at_ms", "1"))
        # A rejected line must not consume or truncate the following command.
        replies = exchange(b"\n".join(malformed + [valid]) + b"\n")
        assert len(replies) == len(malformed) + 1, replies
        for reply in replies[:-1]:
            expect_error(reply)
        assert replies[-1]["status"] == "ok", replies[-1]
        replies = exchange(with_number(command(), "expires_at_ms", str(I64_MAX)) + b"\n")
        assert replies[0]["status"] == "ok", replies

        # More than the library's default 8192 tokens reaches schema validation.
        many = encode(command(payload={"values": [0] * 9000}))
        reply = exchange(many + b"\n")[0]
        expect_error(reply, execution=True)
        assert reply["payload"]["message"] == "health payload must be empty", reply
        for depth in [32, 33]:
            nested = 0
            for _ in range(depth - 2):
                nested = [nested]
            reply = exchange(encode(command(payload={"nested": nested})) + b"\n")[0]
            expect_error(reply, "protocol_error" if depth == 32 else "limit_exceeded",
                         execution=depth == 32)

        rejected = []
        for field, values in [("ref", ["", None, 1, False]),
                              ("paths", [None, {}, [""], [1], ["x"] * 65])]:
            for value in values:
                rejected.append(encode(command("authorize", {"operation": "read", field: value})))
        for payload in [{}, {"operation": 1}, {"operation": "read", "unknown": True}]:
            rejected.append(encode(command("authorize", payload)))
        check = dict(base_oid="0" * 40, head_oid="0" * 40, style="ff")
        merge = dict(check, base_ref="refs/heads/main", approvals=0, required_approvals=0,
                     status_checks_passed=True, blocking_review=False, apply=False)
        for name, payload in [("pr_check", check), ("pr_merge", merge)]:
            for field in ["message", "source_repository", "source_ref"]:
                for value in [None, "", 1, True]:
                    rejected.append(encode(command(name, dict(payload, **{field: value}))))
            for field in ["max_source_objects", "max_source_bytes"]:
                for lexeme in ["0", "-1", "9223372036854775808", "18446744073709551615",
                               "1.0", "1e0", "true", "null"]:
                    source = dict(payload, source_repository="source.git", source_ref="refs/heads/main")
                    rejected.append(with_number(command(name, source), field, lexeme, payload=True))
        for field in ["approvals", "required_approvals"]:
            for lexeme in ["-1", "9223372036854775808", "18446744073709551615",
                           "1.0", "1e0", "true", "null", '"1"']:
                rejected.append(with_number(command("pr_merge", merge), field, lexeme, payload=True))
        for field in ["status_checks_passed", "blocking_review", "apply"]:
            for value in [0, 1, None, "false"]:
                rejected.append(encode(command("pr_merge", dict(merge, **{field: value}))))
        for field in ["pr_id", "expected_prepared_oid", "expected_policy_fingerprint",
                      "expected_target_identity", "expected_source_identity"]:
            for value in ["", None, 1]:
                rejected.append(encode(command("pr_merge", dict(merge, **{field: value}))))
        rejected.append(encode(command("pr_merge", dict(merge, apply=True))))
        replies = exchange(b"\n".join(rejected) + b"\n")
        assert len(replies) == len(rejected), replies
        for request, reply in zip(rejected, replies):
            try:
                expect_error(reply, execution=True)
            except AssertionError as error:
                raise AssertionError((request, reply)) from error

        # Decoded Unicode views remain valid during synchronous policy evaluation.
        replies = exchange(encode(command("authorize", {"operation": "read", "paths": ["café.txt"]})) + b"\n")
        assert replies[0]["status"] == "ok" and replies[0]["payload"]["allowed"], replies
        assert not (root / "example.git" / "refs" / "heads" / "main").exists()

print("ok: both JSONL streams enforce framing, structure and typed payloads")
