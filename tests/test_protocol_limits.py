"""Results that do not fit a protocol line, through the executor's stream.

A diff whose path list exceeds the 65 536 bytes of JSON of a line is
answered by a short failure correlated with its command, written whole on
one line, and the next command of the stream is still executed. A denial
whose explanation fits the line raw but not once its non-ASCII text is
escaped is answered without explanation_text, its receipt unchanged.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

EXECUTOR, MANIFEST = sys.argv[1:3]
LINE = 65536
ENV = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
ENV.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null",
           GIT_AUTHOR_NAME="Limits", GIT_AUTHOR_EMAIL="limits@example.invalid",
           GIT_COMMITTER_NAME="Limits", GIT_COMMITTER_EMAIL="limits@example.invalid",
           # No automatic maintenance: run in the background after the commit
           # of a thousand files, it repacks the repository the clone reads.
           GIT_CONFIG_COUNT="2", GIT_CONFIG_KEY_0="gc.auto", GIT_CONFIG_VALUE_0="0",
           GIT_CONFIG_KEY_1="maintenance.auto", GIT_CONFIG_VALUE_1="false")


def git(*args):
    result = subprocess.run(["git", *map(str, args)], capture_output=True, env=ENV, timeout=120)
    assert result.returncode == 0, (args, result.returncode, result.stderr.decode())
    return result.stdout.decode().strip()


def command(identifier, name, principal, payload):
    now = int(time.time() * 1000)
    return json.dumps(dict(protocol="maelys-git-agent/1", message_id=identifier,
                           agent_id="limits-agent", type="command", command=name,
                           repository="example.git", principal=principal,
                           issued_at_ms=now, expires_at_ms=now + 120000, payload=payload),
                      ensure_ascii=False)


def serve(manifest, root, lines):
    output = subprocess.run([EXECUTOR, "serve", "--manifest", manifest, "--root", root,
                             "--git", "/usr/bin/git"],
                            input=("\n".join(lines) + "\n").encode(), capture_output=True,
                            timeout=120)
    assert output.stdout.endswith(b"\n"), (output.stdout[-200:], output.stderr[-2000:])
    output = output.stdout
    return output[:-1].split(b"\n")


def write_manifest(directory, source):
    policy = directory / "policy.dl"
    policy.write_text(source)
    manifest = directory / "manifest.json"
    manifest.write_text(json.dumps({
        "policy_set_id": "limits", "policy_set_version": "1", "manifest_version": "1",
        "default_profile": "enforce", "created_for": "maelys-git-core-tests",
        "strict_loading": True, "fail_closed": True, "capabilities": [],
        "policies": [{"policy_id": "limits.policy", "domain": "maelys_git", "file": "policy.dl",
                      "sha256": hashlib.sha256(policy.read_bytes()).hexdigest(),
                      "mode": "enforce", "enabled": True, "description": "limits",
                      "queries": [{"name": "allow", "arity": 1}, {"name": "deny", "arity": 1}]}]}))
    return manifest


def large_diff(root):
    work = root / "work"
    git("init", "-q", "-b", "main", work)
    (work / "base.txt").write_text("base\n")
    git("-C", work, "add", ".")
    git("-C", work, "commit", "-qm", "base")
    base = git("-C", work, "rev-parse", "HEAD")
    directory = work / ("d" * 60)
    directory.mkdir()
    for index in range(1000):
        (directory / f"{'n' * 60}-{index:04d}.txt").write_text(f"{index}\n")
    git("-C", work, "add", ".")
    git("-C", work, "commit", "-qm", "many paths")
    head = git("-C", work, "rev-parse", "HEAD")
    git("clone", "-q", "--bare", work, root / "example.git")
    lines = serve(MANIFEST, root, [
        command("diff-big", "diff", "alice", {"old_oid": base, "new_oid": head}),
        command("health-after", "health", "alice", {}),
    ])
    assert len(lines) == 2, [line[:120] for line in lines]
    first, second = lines
    # Integrity: one whole line within the limit, which parses.
    assert len(first) <= LINE, len(first)
    result = json.loads(first)
    # Correlation: the failure names its command.
    assert (result["message_id"], result["agent_id"], result["command"], result["type"]) == \
        ("diff-big", "limits-agent", "diff", "result"), result
    assert result["status"] == "failed", result
    assert result["payload"]["code"] == "limit_exceeded", result
    assert "65536-byte protocol line" in result["payload"]["message"], result
    # Continuity: the next command is read, executed and answered.
    health = json.loads(second)
    assert health["message_id"] == "health-after" and health["status"] == "ok", health


def explanation_fallback(root):
    # Twelve paths, each read by a rule through a filter: the explanation
    # carries each one twice, as a fact and as the filtered value. Their e
    # with acute accent is two bytes raw and six once escaped as é.
    # The domain is closed: four of its derived predicates of arity 2 carry
    # the intermediate steps.
    helpers = ["has_ref_write", "has_push_access", "vref_count_exceeded", "vref_new_count_exceeded"]
    body = []
    for rule, helper in enumerate(helpers):
        # A variable is identified by its first uppercase letter: A, B and C.
        literals = ", ".join(f'path({v}), starts_with({v}, "p{rule * 3 + n:02d}")'
                             for n, v in enumerate("ABC"))
        body.append(f"{helper}(R, R) :- request(R), {literals}.")
    source = "\n".join(body) + "\n" + "deny(R) :- request(R), " + \
        ", ".join(f"{helper}(R, R)" for helper in helpers) + ".\nallow(R) :- request(R).\n"
    manifest = write_manifest(root, source)
    accent = "é" * 480

    def paths(count):
        return [f"p{index:02d}{accent}" for index in range(count)]
    full, short = paths(12), paths(12)
    short = [path[:12] for path in short]  # the same rules, short values
    lines = serve(manifest, root, [
        command("explain-long", "authorize", "u", {"operation": "push", "paths": full, "explain": True}),
        command("explain-short", "authorize", "u", {"operation": "push", "paths": short, "explain": True}),
    ])
    assert len(lines) == 2
    long, small = (json.loads(line) for line in lines)
    assert len(lines[0]) <= LINE and len(lines[1]) <= LINE
    for result in (long, small):
        assert result["status"] == "denied" and result["payload"]["explicit_deny"] is True, result
        explanation = result["payload"]["receipt"]["explanation"]
        assert explanation["textBytes"] > 0 and len(explanation["textSha256"]) == 64, explanation
    # The long text fits raw, not escaped: it goes, the receipt stays.
    raw_text_bytes = long["payload"]["receipt"]["explanation"]["textBytes"]
    # Each of the 12 paths appears twice, 480 accents each: escaping adds 4
    # bytes per accent.
    escaped_growth = 4 * 480 * 12 * 2
    assert raw_text_bytes + 4096 < LINE < raw_text_bytes + escaped_growth, raw_text_bytes
    assert "explanation_text" not in long["payload"], sorted(long["payload"])
    canonical = json.dumps(long["payload"]["receipt"], sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False)
    assert hashlib.sha256(canonical.encode()).hexdigest() == long["payload"]["receipt_sha256"]
    # Under the limit, the same rules keep their text, vouched for by the receipt.
    text = small["payload"]["explanation_text"].encode()
    explanation = small["payload"]["receipt"]["explanation"]
    assert len(text) == explanation["textBytes"]
    assert hashlib.sha256(text).hexdigest() == explanation["textSha256"]


with tempfile.TemporaryDirectory(prefix="maelys-protocol-limits-") as temporary:
    root = Path(temporary).resolve()
    large_diff(root)
    explanation_fallback(root)
print("protocol line limits: bounded failure, stream continuity, explanation fallback: ok")
