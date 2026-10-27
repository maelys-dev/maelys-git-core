"""A migrated Gitolite policy decides only the refs Gitolite admits.

D7 (b) of GIT-C08: with the audited Gitolite program, a ref outside the
alphabet Gitolite 3.6.15 admits by default, or not a valid ref, is refused
before any policy is evaluated. Through a real receive-pack, a push that
carries such a ref beside an admitted one is refused whole and writes
neither, whether Git runs the receive-pack itself or maelys-git-shell does,
as the SSH forced command; through the executor, the update is refused and
the ref is left as it was.

    test_gitolite_ref_domain.py MAELYS_GIT HOOK EXECUTOR SHELL
"""
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import time

MAELYS_GIT, HOOK, EXECUTOR, SHELL = map(lambda arg: str(Path(arg).resolve()), sys.argv[1:])
REFUSED = "Gitolite admits"
ENV = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
ENV.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null")


def run(*args, input=None, ok=True):
    result = subprocess.run(list(map(str, args)), input=input, text=True,
                            capture_output=True, env=ENV, timeout=60)
    if ok and result.returncode:
        raise AssertionError(f"{args}: {result.stdout}\n{result.stderr}")
    return result


def git(*args, **kwargs):
    return run("/usr/bin/git", *args, **kwargs)


with tempfile.TemporaryDirectory(prefix="maelys-ref-domain-") as temporary:
    root = Path(temporary).resolve()
    conf, migrated = root / "gitolite.conf", root / "migrated"
    conf.write_text("repo example\n    RW+ refs/heads/ = alice\n    RW+ refs/tags/ = alice\n")
    run(MAELYS_GIT, "migrate", "gitolite", conf, migrated, "--apply", "--format", "json",
        "--non-interactive")
    manifest, grants = migrated / "manifest.json", migrated / "grants.json"

    work, bare = root / "work", root / "example.git"
    git("init", "-q", work)
    git("-C", work, "config", "user.name", "Test")
    git("-C", work, "config", "user.email", "test@example.invalid")
    git("-C", work, "config", "commit.gpgSign", "false")
    git("init", "-q", "--bare", bare)
    hook = bare / "hooks/pre-receive"
    hook.write_text("#!/bin/sh\nexec " + shlex.join([
        HOOK, "pre-receive", "--repository", "example.git", "--manifest", str(manifest),
        "--grants", str(grants), "--user", "alice", "--git-dir", str(bare)]) + "\n")
    hook.chmod(0o700)
    (work / "a.txt").write_text("a\n")
    git("-C", work, "add", ".")
    git("-C", work, "commit", "-qm", "a")
    head = git("-C", work, "rev-parse", "HEAD").stdout.strip()

    def refs():
        return git("--git-dir", bare, "for-each-ref", "--format=%(refname)").stdout.split()

    # SSH as the forced command sees it: the shell authorizes the write, then
    # replaces itself with git-receive-pack, whose pre-receive hook decides.
    ssh = root / "ssh"
    ssh.write_text("#!/bin/sh\n"
                   "while [ $# -gt 1 ]; do shift; done\n"
                   "SSH_ORIGINAL_COMMAND=$1 exec " + shlex.join([
                       SHELL, "serve", "--user", "alice", "--root", str(root),
                       "--manifest", str(manifest), "--grants", str(grants),
                       "--git", "/usr/bin/git"]) + "\n")
    ssh.chmod(0o700)
    remotes = {"local": ([], str(bare)), "shell": (["-c", f"core.sshCommand={ssh}"], "test:example.git")}

    # One admitted ref and one outside the alphabet: the push is refused
    # whole, with Gitolite's reason, directly and through the shell.
    for via, (options, target) in remotes.items():
        for outside in ["refs/heads/é", "refs/heads/a%b", "refs/heads/a#b"]:
            refused = git("-C", work, *options, "push", target, "HEAD:refs/heads/ok",
                          f"HEAD:{outside}", ok=False)
            assert refused.returncode and REFUSED in refused.stderr, (via, refused.stderr)
            assert refs() == [], (via, refs())
    git("-C", work, "-c", f"core.sshCommand={ssh}", "push", "test:example.git", "HEAD:refs/heads/via-shell")
    assert refs() == ["refs/heads/via-shell"], refs()
    git("--git-dir", bare, "update-ref", "-d", "refs/heads/via-shell")
    git("-C", work, "push", bare, "HEAD:refs/heads/ok", "HEAD:refs/tags/v1.0", "HEAD:refs/heads/a@b+c,d")
    assert sorted(refs()) == ["refs/heads/a@b+c,d", "refs/heads/ok", "refs/tags/v1.0"], refs()

    # The executor decides on the same snapshot: the update is refused.
    now = int(time.time() * 1000)
    request = dict(protocol="maelys-git-agent/1", message_id="domain", agent_id="test-agent",
                   type="command", command="update_ref", repository="example.git",
                   principal="alice", issued_at_ms=now, expires_at_ms=now + 60000,
                   payload=dict(ref="refs/heads/é", old_oid="0" * 40, new_oid=head))
    result = run(EXECUTOR, "serve", "--manifest", manifest, "--grants", grants, "--root", root,
                 input=json.dumps(request) + "\n", ok=False)
    answer = json.loads(result.stdout.splitlines()[0])
    assert answer["status"] != "ok", answer
    assert REFUSED in json.dumps(answer), answer
    assert "refs/heads/é" not in refs(), refs()
print("ref domain: pushes and updates outside what Gitolite admits refused")
