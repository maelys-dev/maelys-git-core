"""Exercise real receive-pack quarantine and the agent against identical policies."""
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import time


HOOK, EXECUTOR = map(lambda arg: str(Path(arg).resolve()), sys.argv[1:])
ENV = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
ENV.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null")


def run(*args, input=None, ok=True, env=None):
    result = subprocess.run(list(map(str, args)), input=input, text=True,
                            capture_output=True, env=env or ENV, timeout=30)
    if ok and result.returncode:
        raise AssertionError(f"{args}: {result.stdout}\n{result.stderr}")
    return result


def git(*args, **kwargs):
    return run("/usr/bin/git", *args, **kwargs)


for binary, command in [(HOOK, "pre-receive"), (EXECUTOR, "serve")]:
    run(binary, "describe", "--summary", "--format", "json", "--non-interactive")
    descriptor = json.loads(run(binary, "describe", command, "--format", "json",
                                "--non-interactive").stdout)
    assert descriptor["data"]["commands"][0]["outputMode"] == "protocol-stream"

with tempfile.TemporaryDirectory(prefix="maelys-receive-quote'-colon:") as temporary:
    root = Path(temporary).resolve()
    work, bare = root / "work", root / "example.git"
    git("init", "-q", work)
    git("-C", work, "config", "user.name", "Test")
    git("-C", work, "config", "user.email", "test@example.invalid")
    git("-C", work, "config", "commit.gpgSign", "false")
    git("init", "-q", "--bare", bare)
    policy, manifest = root / "policy.dl", root / "manifest.json"

    def set_policy(deny=""):
        policy.write_text('allow(R) :- request(R), operation("push").\n' + deny + "\n")
        manifest.write_text(json.dumps({
            "policy_set_id": "receive-test", "policy_set_version": "1",
            "manifest_version": "1", "default_profile": "enforce",
            "created_for": "maelys-git-core-tests", "strict_loading": True,
            "fail_closed": True, "capabilities": [], "policies": [{
                "policy_id": "receive-test.policy", "domain": "maelys_git",
                "file": policy.name, "sha256": hashlib.sha256(policy.read_bytes()).hexdigest(),
                "mode": "enforce", "enabled": True, "description": "Receive regression",
                "queries": [{"name": "allow", "arity": 1}, {"name": "deny", "arity": 1}],
            }],
        }))

    hook_args = [HOOK, "pre-receive", "--repository", "example.git", "--manifest",
                 str(manifest), "--user", "alice", "--git-dir", str(bare)]
    hook = bare / "hooks/pre-receive"
    hook.write_text("#!/bin/sh\nexec " + shlex.join(hook_args) + "\n")
    hook.chmod(0o700)
    set_policy()
    (work / "base.txt").write_text("base\n")
    git("-C", work, "add", ".")
    git("-C", work, "commit", "-qm", "base")
    base = git("-C", work, "rev-parse", "HEAD").stdout.strip()
    git("-C", work, "push", bare, "HEAD:refs/heads/main")
    # A second push must see both quarantined objects and the existing base.
    (work / "new.txt").write_text("unsigned\n")
    (work / "link").symlink_to("new.txt")
    git("-C", work, "add", ".")
    git("-C", work, "commit", "-qm", "unsigned")
    head = git("-C", work, "rev-parse", "HEAD").stdout.strip()
    git("-C", work, "push", bare, "HEAD:refs/heads/staging")
    git("--git-dir", bare, "update-ref", "-d", "refs/heads/staging")

    def current():
        return git("--git-dir", bare, "rev-parse", "refs/heads/main").stdout.strip()

    def update(old, new):
        now = int(time.time() * 1000)
        request = dict(protocol="maelys-git-agent/1", message_id="update-test",
                       agent_id="test-agent", type="command", command="update_ref",
                       repository="example.git", principal="alice", issued_at_ms=now,
                       expires_at_ms=now + 60000,
                       payload=dict(ref="refs/heads/main", old_oid=old, new_oid=new))
        result = run(EXECUTOR, "serve", "--manifest", manifest, "--root", root,
                     input=json.dumps(request) + "\n")
        return json.loads(result.stdout)

    for deny in [
        'deny(R) :- request(R), commit_signature_status("unsigned").',
        'deny(R) :- request(R), update_kind("fast_forward").',
        'deny(R) :- request(R), change_symlink(true).',
        'deny(R) :- request(R), changed_count(N), N > 0.',
    ]:
        set_policy(deny)
        refused = run(*hook_args, input=f"{base} {head} refs/heads/main\n", ok=False)
        assert refused.returncode and "denied" in refused.stderr, refused.stderr
        result = update(base, head)
        assert result["status"] == "denied", result
        assert result["payload"]["explicit_deny"], result
        assert current() == base

    # Deny inside an actual receive-pack, before new objects are promoted.
    (work / "third.txt").write_text("new quarantined unsigned commit\n")
    git("-C", work, "add", ".")
    git("-C", work, "commit", "-qm", "third")
    set_policy('deny(R) :- request(R), commit_signature_status("unsigned").')
    refused = git("-C", work, "push", bare, "HEAD:refs/heads/main", ok=False)
    assert refused.returncode and "denied" in refused.stderr, refused.stderr
    assert current() == base

    set_policy()
    assert update(base, head)["status"] == "ok"
    assert current() == head
    # CAS remains enforced after full authorization.
    assert update(base, head)["status"] == "failed"
    set_policy('deny(R) :- request(R), update_kind("force").')
    assert update(head, base)["status"] == "denied"
    assert current() == head
    set_policy('deny(R) :- request(R), update_kind("delete").')
    assert update(head, "0" * 40)["status"] == "denied"
    assert current() == head

    # More paths than a single Datalog request can hold must be streamed.
    set_policy()
    for index in range(300):
        (work / f"file-{index}.txt").write_text(f"{index}\n")
    git("-C", work, "add", ".")
    git("-C", work, "commit", "-qm", "many paths")
    many = git("-C", work, "rev-parse", "HEAD").stdout.strip()
    git("-C", work, "push", bare, "HEAD:refs/heads/staging")
    git("--git-dir", bare, "update-ref", "-d", "refs/heads/staging")
    result = update(head, many)
    assert result["status"] == "ok" and result["payload"]["changed_paths"] == 301, result
    assert current() == many

    # Foreign object directories cannot be injected into the hook's Git calls.
    foreign = root / "foreign"
    foreign.mkdir()
    hostile = dict(ENV, GIT_OBJECT_DIRECTORY=str(foreign), GIT_QUARANTINE_PATH=str(foreign))
    refused = run(*hook_args, input=f"{head} {many} refs/heads/main\n", env=hostile, ok=False)
    assert refused.returncode and "quarantine" in refused.stderr, refused.stderr
    assert current() == many

print("real pushes, quarantine confinement, complete update_ref policy and CAS: ok")
