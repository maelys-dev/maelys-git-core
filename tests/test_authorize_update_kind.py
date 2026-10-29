"""authorize decides a migrated Gitolite ref grant with --update-kind.

A Gitolite ref grant allows a push according to the kind of update: `RW`
fast-forwards and creates, `RW+` also forces and deletes. The hook, the
shell and the executor pass that kind; authorize passes it with
--update-kind. Without it no grant allows and only the denies decide.

    test_authorize_update_kind.py MAELYS_GIT
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

MAELYS_GIT = str(Path(sys.argv[1]).resolve())
ENV = {key: value for key, value in os.environ.items() if not key.startswith("MAELYS_CLI_")}


def run(*args):
    result = subprocess.run([MAELYS_GIT, *map(str, args), "--format", "json", "--compact",
                             "--non-interactive"],
                            text=True, capture_output=True, env=ENV, timeout=60)
    return result


with tempfile.TemporaryDirectory(prefix="maelys-update-kind-") as temporary:
    root = Path(temporary).resolve()
    conf, migrated = root / "gitolite.conf", root / "migrated"
    conf.write_text("repo example\n"
                    "    -   refs/heads/locked = alice\n"
                    "    RW  refs/heads/ = alice\n"
                    "    RW+ refs/heads/ = bob\n")
    migration = run("migrate", "gitolite", conf, migrated, "--apply")
    assert migration.returncode == 0, migration.stderr
    manifest, grants = migrated / "manifest.json", migrated / "grants.json"

    def authorize(user, ref, *kind):
        result = run("authorize", manifest, user, "example.git", "push", ref,
                     "--grants", grants, *kind)
        assert result.returncode == 0 and result.stderr == "", (user, ref, kind, result.stderr)
        data = json.loads(result.stdout)["data"]
        return data["allowed"], data["explicitDeny"]

    # Without the kind, no grant allows: only the deny is seen.
    assert authorize("alice", "refs/heads/x") == (False, False)
    assert authorize("bob", "refs/heads/x") == (False, False)
    assert authorize("alice", "refs/heads/locked") == (False, True)

    # With it, each grant allows what Gitolite gives it.
    for kind in ["create", "fast_forward"]:
        assert authorize("alice", "refs/heads/x", "--update-kind", kind) == (True, False), kind
        assert authorize("bob", "refs/heads/x", "--update-kind", kind) == (True, False), kind
    for kind in ["force", "delete"]:
        assert authorize("alice", "refs/heads/x", "--update-kind", kind) == (False, False), kind
        assert authorize("bob", "refs/heads/x", "--update-kind", kind) == (True, False), kind
    # The deny keeps deciding first, whatever the kind.
    assert authorize("alice", "refs/heads/locked", "--update-kind", "fast_forward") == (False, True)

    # A kind outside the four is refused before the policy is opened.
    refused = run("authorize", manifest, "alice", "example.git", "push", "refs/heads/x",
                  "--grants", grants, "--update-kind", "rewind")
    assert refused.returncode == 1 and refused.stdout == "", refused
    error = json.loads(refused.stderr)["error"]
    assert error["code"] == "VALIDATION_FAILED" and "--update-kind" in error["message"], error
print("authorize: a Gitolite ref grant decided with --update-kind")
