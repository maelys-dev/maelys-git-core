"""Regression coverage for ref authorization, exact quotas and CLI boundaries."""
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import time

ADMIN, HOOK, EXECUTOR, AGENT = [str(Path(arg).resolve()) for arg in sys.argv[1:5]]
CLOUD = sys.argv[5] == "1"
ZERO = "0" * 40
ENV = {key: value for key, value in os.environ.items()
       if not key.startswith(("GIT_", "MAELYS_"))}
ENV.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null",
           GIT_AUTHOR_NAME="Test", GIT_AUTHOR_EMAIL="test@example.invalid",
           GIT_COMMITTER_NAME="Test", GIT_COMMITTER_EMAIL="test@example.invalid")
JSON = ["--format", "json", "--compact", "--non-interactive"]


def run(*args, input=None, ok=True):
    result = subprocess.run(list(map(str, args)), input=input, text=True,
                            capture_output=True, env=ENV, timeout=30)
    if ok:
        assert result.returncode == 0, (args, result.stdout, result.stderr)
    return result


def git(repository, *args, **kwargs):
    return run("/usr/bin/git", "--git-dir", repository, *args, **kwargs)


def failure(result, code):
    assert result.returncode == 1 and not result.stdout, result
    envelope = json.loads(result.stderr)
    assert envelope["ok"] is False and envelope["error"]["code"] == code, envelope
    return envelope["error"]["message"]


for binary, commands in [(ADMIN, ["repo.diff", "repo.init", "authorize"]),
                         (HOOK, ["pre-receive"]), (EXECUTOR, ["serve"]),
                         (AGENT, ["run"])]:
    run(binary, "describe", "--summary", *JSON)
    for command in commands:
        descriptor = json.loads(run(binary, "describe", command, *JSON).stdout)["data"]["commands"][0]
        if binary == AGENT:
            assert descriptor["available"] == CLOUD, descriptor
            assert ("unavailableReason" in descriptor) != CLOUD, descriptor

with tempfile.TemporaryDirectory(prefix="maelys-audit-regressions-") as temporary:
    root = Path(temporary).resolve()
    bare, source = root / "example.git", root / "source.git"
    for repository in [bare, source]:
        run("/usr/bin/git", "init", "-q", "--bare", repository)
    policy, manifest = root / "policy.dl", root / "manifest.json"

    def set_policy(deny=""):
        policy.write_text('allow(R) :- request(R), operation("push").\n' + deny + "\n")
        document = dict(policy_set_id="regressions", policy_set_version="1", manifest_version="1",
                        default_profile="enforce", created_for="tests", strict_loading=True,
                        fail_closed=True, capabilities=[], policies=[dict(
                            policy_id="regression.policy", domain="maelys_git", file=policy.name,
                            sha256=hashlib.sha256(policy.read_bytes()).hexdigest(), mode="enforce",
                            enabled=True, description="Regression policy",
                            queries=[dict(name="allow", arity=1), dict(name="deny", arity=1)])])
        manifest.write_text(json.dumps(document))
        return document

    def commit(repository, contents):
        records = []
        for name, content in sorted(contents.items()):
            blob = git(repository, "hash-object", "-w", "--stdin", input=content).stdout.strip()
            records.append(f"100644 blob {blob}\t{name}\n")
        tree = git(repository, "mktree", input="".join(records)).stdout.strip()
        return git(repository, "commit-tree", tree, "-m", "fixture").stdout.strip()

    hook_args = [HOOK, "pre-receive", "--repository", "example.git", "--manifest", str(manifest),
                 "--user", "alice", "--git-dir", str(bare)]
    hook = bare / "hooks/pre-receive"
    hook.write_text("#!/bin/sh\nexec " + shlex.join(hook_args) + "\n")
    hook.chmod(0o700)

    def update(new, ref):
        now = int(time.time() * 1000)
        request = dict(protocol="maelys-git-agent/1", message_id="regression", agent_id="test",
                       type="command", command="update_ref", repository="example.git", principal="alice",
                       issued_at_ms=now, expires_at_ms=now + 60000,
                       payload=dict(ref=ref, old_oid=ZERO, new_oid=new))
        result = run(EXECUTOR, "serve", "--manifest", manifest, "--root", root,
                     input=json.dumps(request) + "\n")
        assert not result.stderr, result.stderr
        return json.loads(result.stdout)

    # An object already authorized under staging must be checked for main.
    set_policy('deny(R) :- request(R), ref("refs/heads/main"), commit_signature_status("unsigned").')
    one = commit(source, {"file.txt": "x"})
    git(source, "push", bare, f"{one}:refs/heads/staging")
    refused = git(source, "push", bare, f"{one}:refs/heads/main", ok=False)
    assert refused.returncode and "denied" in refused.stderr, refused
    assert update(one, "refs/heads/main")["status"] == "denied"
    assert git(bare, "show-ref", "--verify", "refs/heads/main", ok=False).returncode != 0
    assert update(one, "refs/heads/review")["status"] == "ok"
    assert git(bare, "rev-parse", "refs/heads/staging").stdout.strip() == one

    # Exact quotas permit later zero consumption, in either ref order.
    set_policy()
    empty = commit(bare, {})
    zero_size = commit(bare, {"empty.txt": ""})
    for option in ["--max-changes", "--max-total-blob-bytes", "--max-inspected-blob-bytes"]:
        zero_consumers = [empty] if option == "--max-changes" else [empty, zero_size]
        for other in zero_consumers:
            lines = [f"{ZERO} {one} refs/heads/one\n", f"{ZERO} {other} refs/heads/zero\n"]
            for order in [lines, lines[::-1]]:
                run(*hook_args, option, "1", input="".join(order))
        # Two nonzero consumers must still be refused.
        excess = run(*hook_args, option, "1", ok=False,
                     input=f"{ZERO} {one} refs/heads/one\n{ZERO} {one} refs/heads/two\n")
        assert excess.returncode and "limit" in excess.stderr, excess

    # Disabled entries do not contribute file reads or policy vocabulary.
    document = set_policy()
    def authorize(ok=True):
        return run(ADMIN, "authorize", manifest, "alice", "example.git", "push", *JSON, ok=ok)

    baseline = json.loads(authorize().stdout)["data"]
    disabled = dict(document["policies"][0], policy_id="disabled.policy", enabled=False, file="absent.dl")
    for entries in [[disabled, document["policies"][0]], [document["policies"][0], disabled]]:
        manifest.write_text(json.dumps(dict(document, policies=entries)))
        assert json.loads(authorize().stdout)["data"] == baseline
    # Parsing must agree with Datalog even when JSON keys are escaped.
    manifest.write_text(json.dumps(dict(document, policies=[disabled, document["policies"][0]]))
                        .replace('"file"', '"fi\\u006ce"'))
    assert json.loads(authorize().stdout)["data"] == baseline
    manifest.write_text(json.dumps(dict(document, policies=[dict(disabled, enabled=True)])))
    failure(authorize(ok=False), "POLICY_FAILED")
    manifest.write_text(json.dumps(dict(document, policies=[disabled])))
    failure(authorize(ok=False), "POLICY_FAILED")
    manifest.write_text('{"policies": [')
    failure(authorize(ok=False), "POLICY_FAILED")

    # Ordinary Git errors must stay inside one parseable CLI envelope.
    result = run(ADMIN, "repo", "diff", root, "example.git", "1" * 40, "2" * 40, *JSON, ok=False)
    assert "bad object" in failure(result, "PROCESS_FAILED")
    # Run-only helpers also drain stdout and large stderr without leaking it.
    helper = root / "noisy-git"
    helper.write_text("#!/bin/sh\nprintf 'diagnostic marker\\n' >&2\n"
                      "i=0\nwhile [ $i -lt 8192 ]; do printf 'noise noise noise\\n' >&2; i=$((i+1)); done\n"
                      "printf 'stdout noise\\n'\nexit 1\n")
    helper.chmod(0o700)
    args = [ADMIN, "repo", "init", str(root), "noisy.git", "--git", str(helper), *JSON]
    plan = json.loads(run(*args).stdout)
    assert plan["data"]["mode"] == "plan" and not (root / "noisy.git").exists()
    message = failure(run(*args, "--apply", ok=False), "PROCESS_FAILED")
    assert "diagnostic marker" in message and len(message) < 512

print("per-ref commit policy, exact quotas, disabled policies, JSON diagnostics and build availability: ok")
