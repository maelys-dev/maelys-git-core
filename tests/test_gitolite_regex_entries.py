"""Regex refexes decide on every entry that opens a Gitolite policy.

GIT-C08, section 6 of the directive: a configuration whose refexes are
regular expressions migrates to a maelys-git-grants/2 snapshot, and each
entry point decides with it as Gitolite reads the refexes: the authorize
command, by its grants with --update-kind and by its denies alone without; a real push through the pre-receive hook, run by Git itself or by
maelys-git-shell as the SSH forced command; the executor's update_ref and
pr_check, a read without a ref beside regex grants; and pr merge, by the command line and by the executor, on its
target ref.

    test_gitolite_regex_entries.py MAELYS_GIT HOOK EXECUTOR SHELL
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


with tempfile.TemporaryDirectory(prefix="maelys-regex-entries-") as temporary:
    root = Path(temporary).resolve()
    conf, migrated = root / "gitolite.conf", root / "migrated"
    conf.write_text("repo example\n"
                    "    R = alice\n"
                    "    - refs/tags/v[0-9]+\\.0 = alice\n"
                    "    RW+ refs/tags/ = alice\n"
                    "    RW refs/heads/(main|dev)$ = alice\n"
                    "    RW+ refs/heads/feature/.* = alice\n")
    plan = json.loads(run(MAELYS_GIT, "migrate", "gitolite", conf, migrated, "--apply", "--format", "json",
                          "--non-interactive").stdout)
    assert plan["data"]["grantsFormat"] == "maelys-git-grants/2", plan
    manifest, grants = migrated / "manifest.json", migrated / "grants.json"

    def authorize(ref, *kind):
        answer = run(MAELYS_GIT, "authorize", manifest, "alice", "example.git", "push", ref, "--grants", grants,
                     *kind, "--format", "json", "--non-interactive", ok=False)
        data = json.loads(answer.stdout)["data"] if answer.stdout else None
        assert data is not None, (ref, kind, answer.stdout, answer.stderr)
        return data["allowed"], data["explicitDeny"]

    # Without --update-kind, which a grant needs, a push is decided by its
    # denies alone, the regex one included.
    for ref, denied in [("refs/tags/v1.0", True), ("refs/tags/v12.0", True), ("refs/tags/v1x0", False),
                        ("refs/tags/va.0", False), ("refs/heads/dev", False)]:
        assert authorize(ref) == (False, denied), ref
    # With it, the regex grants decide as Gitolite reads them: RW creates and
    # fast-forwards, RW+ also forces and deletes, the regex deny comes first.
    for kind in ["create", "fast_forward", "force", "delete"]:
        rewrites = kind in ("force", "delete")
        for ref, expected in [("refs/tags/v1.0", (False, True)), ("refs/tags/v12.0", (False, True)),
                              ("refs/tags/v1x0", (True, False)), ("refs/tags/va.0", (True, False)),
                              ("refs/heads/dev", (not rewrites, False)), ("refs/heads/main", (not rewrites, False)),
                              ("refs/heads/devx", (False, False)), ("refs/heads/feature/x", (True, False))]:
            assert authorize(ref, "--update-kind", kind) == expected, (ref, kind)

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
    base = git("-C", work, "rev-parse", "HEAD").stdout.strip()
    (work / "b.txt").write_text("b\n")
    git("-C", work, "add", ".")
    git("-C", work, "commit", "-qm", "b")
    head = git("-C", work, "rev-parse", "HEAD").stdout.strip()

    def refs():
        return sorted(git("--git-dir", bare, "for-each-ref", "--format=%(refname)").stdout.split())

    # A real push, by Git and through the shell as the SSH forced command.
    ssh = root / "ssh"
    ssh.write_text("#!/bin/sh\n"
                   "while [ $# -gt 1 ]; do shift; done\n"
                   "SSH_ORIGINAL_COMMAND=$1 exec " + shlex.join([
                       SHELL, "serve", "--user", "alice", "--root", str(root),
                       "--manifest", str(manifest), "--grants", str(grants),
                       "--git", "/usr/bin/git"]) + "\n")
    ssh.chmod(0o700)
    remotes = {"local": ([], str(bare)), "shell": (["-c", f"core.sshCommand={ssh}"], "test:example.git")}
    for via, (options, target) in remotes.items():
        for refused in ["refs/heads/devel", "refs/heads/mainline", "refs/tags/v1.0", "refs/heads/xfeature/x"]:
            denied = git("-C", work, *options, "push", target, f"{base}:{refused}", ok=False)
            assert denied.returncode, (via, refused)
            assert refs() == [], (via, refs())
        git("-C", work, *options, "push", target, f"{base}:refs/heads/dev", f"{base}:refs/tags/v1x0",
            f"{base}:refs/heads/feature/{via}")
        assert refs() == sorted(["refs/heads/dev", "refs/tags/v1x0", f"refs/heads/feature/{via}"]), (via, refs())
        for ref in refs():
            git("--git-dir", bare, "update-ref", "-d", ref)
    git("-C", work, "push", str(bare), f"{base}:refs/heads/main", f"{base}:refs/heads/dev",
        f"{head}:refs/heads/feature/pr")

    def executor(command, payload, principal="alice"):
        now = int(time.time() * 1000)
        request = dict(protocol="maelys-git-agent/1", message_id=command, agent_id="test-agent",
                       type="command", command=command, repository="example.git",
                       principal=principal, issued_at_ms=now, expires_at_ms=now + 60000, payload=payload)
        result = run(EXECUTOR, "serve", "--manifest", manifest, "--grants", grants, "--root", root,
                     input=json.dumps(request) + "\n", ok=False)
        return json.loads(result.stdout.splitlines()[0])

    # The executor: update_ref on the refexes, pr_check a read without a ref
    # (alice may read, bob holds nothing).
    answer = executor("update_ref", dict(ref="refs/heads/feature/y", old_oid="0" * 40, new_oid=base))
    assert answer["status"] == "ok", answer
    answer = executor("update_ref", dict(ref="refs/heads/devel", old_oid="0" * 40, new_oid=base))
    assert answer["status"] != "ok" and "refs/heads/devel" not in refs(), answer
    answer = executor("pr_check", dict(base_oid=base, head_oid=head, style="ff"))
    assert answer["status"] == "ok", answer
    answer = executor("pr_check", dict(base_oid=base, head_oid=head, style="ff"), principal="bob")
    assert answer["status"] != "ok", answer

    # pr merge, planned, on its target ref: by the command line and by the
    # executor, (main|dev)$ allows dev and not devel.
    git("--git-dir", bare, "update-ref", "refs/heads/devel", base)
    for target, allowed in [("refs/heads/dev", True), ("refs/heads/devel", False)]:
        planned = run(MAELYS_GIT, "pr", "merge", root, "example.git", target, base, head, manifest, "alice",
                      "--style", "ff", "--approvals", "0", "--required-approvals", "0", "--status-checks-passed",
                      "--grants", grants, "--format", "json", "--non-interactive", ok=False)
        assert (planned.returncode == 0) is allowed, (target, planned.stdout, planned.stderr)
        if not allowed:
            assert "no allow rule matched" in planned.stderr + planned.stdout, (target, planned.stderr)
        answer = executor("pr_merge", dict(base_ref=target, base_oid=base, head_oid=head, style="ff",
                                           approvals=0, required_approvals=0, status_checks_passed=True,
                                           blocking_review=False, apply=False))
        assert (answer["status"] == "ok") is allowed, (target, answer)
        if not allowed:
            assert answer["status"] == "denied" and answer["payload"]["allowed"] is False, (target, answer)
print("regex refexes: authorize, hook, shell, update_ref, pr_check and pr merge decide as Gitolite reads them")
