#!/usr/bin/env python3
"""The versions of the audited Gitolite program a migrated set may hold.

tests/fixtures/gitolite-program-1 is a set migrated from its gitolite.conf
by a Git Core that wrote maelys-git-gitolite-program/1, kept as it was
written: a set deployed before any later version. decisions.tsv records,
for each request, the decision and the SHA-256 of the receipt and of the
whole output of `maelys-git authorize --explain`, as that Git Core wrote
them. Whatever version Git Core migrates to now, it must decide this set
as it did, byte for byte.

The same gitolite.conf migrated now gives maelys-git-gitolite-program/2:
the same decisions, but a ref grant also lets its holder read the
repository, as Gitolite does; and a manifest holding both versions is
refused when it is opened. A clone through maelys-git-shell reads as each
version decides.

    test_gitolite_program_versions.py MAELYS_GIT SHELL FIXTURES [--record]

--record rewrites decisions.tsv from what is observed; only a commit that
records the set as it was first written does that.
"""
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile

USERS = ["alice", "bob", "carol", "dave", "mallory", "zed"]
# The command gives a push no kind of update: merge and update-ref are the
# requests on a ref it decides by the ref grants.
REQUESTS = [("read", "-"), ("write", "-"), ("merge", "refs/heads/main"), ("merge", "refs/heads/feature/x"),
            ("merge", "refs/heads/secret"), ("update-ref", "refs/heads/feature/x"),
            ("update-ref", "refs/heads/secret")]
HEADER = ("# The decisions of tests/fixtures/gitolite-program-1 as the Git Core that wrote it\n"
          "# made them: maelys-git authorize MANIFEST USER app.git OPERATION REF --grants\n"
          "# grants.json --explain --format json --compact --non-interactive.\n"
          "# user\toperation\tref\tallowed\treceiptSha256\toutputSha256\n")


def authorize(maelys_git, directory, user, operation, ref):
    result = subprocess.run(
        [maelys_git, "authorize", "manifest.json", user, "app.git", operation, ref, "--grants", "grants.json",
         "--explain", "--format", "json", "--compact", "--non-interactive"],
        cwd=directory, capture_output=True, timeout=60)
    if result.returncode != 0:
        raise SystemExit(f"authorize {user} {operation} {ref}: exit {result.returncode}: "
                         f"{result.stderr.decode(errors='replace')}")
    data = json.loads(result.stdout)["data"]
    return ("true" if data["allowed"] else "false", data["receiptSha256"],
            hashlib.sha256(result.stdout).hexdigest(), result.stdout)


def second_version(maelys_git, shell, one, root, first):
    """The same gitolite.conf migrated now: maelys-git-gitolite-program/2,
    which decides as /1 but also lets a ref grant read the repository, and
    which no manifest may hold beside /1."""
    failures = []
    two = root / "two"
    result = subprocess.run([maelys_git, "migrate", "gitolite", str(one / "gitolite.conf"), str(two), "--apply",
                             "--format", "json", "--non-interactive"], capture_output=True, timeout=60)
    if result.returncode != 0:
        return [f"migrate: {result.stderr.decode(errors='replace')}"]
    program = (two / "gitolite-migrated.dl").read_text()
    if not program.startswith("% maelys-git-gitolite-program/2: "):
        failures.append("the migration does not write maelys-git-gitolite-program/2")
    if "maelys-git-gitolite-program/2" not in (two / "manifest.json").read_text():
        failures.append("the manifest does not name maelys-git-gitolite-program/2")
    if (two / "grants.json").read_bytes() != (one / "grants.json").read_bytes():
        failures.append("the snapshot changed with the program")
    # Ref grants alone: alice (prefix), bob (regex, by @devs), mallory (a
    # deny, then a prefix).
    reads = {"alice", "bob", "mallory"}
    for (user, operation, ref), (allowed, _, _, _) in first.items():
        now, _, _, stdout = authorize(maelys_git, two, user, operation, ref)
        expected = "true" if (operation == "read" and user in reads) else allowed
        if now != expected:
            failures.append(f"/2 {user} {operation} {ref}: {now}, expected {expected}")
        receipt = json.loads(stdout)["data"]["receipt"]
        if receipt["grants"]["program"] != "maelys-git-gitolite-program/2":
            failures.append(f"/2 {user} {operation} {ref}: receipt names {receipt['grants']['program']}")
    # A real clone through the shell, as the SSH forced command: alice holds
    # a ref grant alone; /2 lets her read, /1 does not, nor /2 anyone else.
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null")
    git = lambda *args, **kwargs: subprocess.run(["/usr/bin/git", *map(str, args)], env=env, capture_output=True,
                                                 timeout=60, **kwargs)
    work, bare = root / "work", root / "app.git"
    for command in (["init", "-q", "--initial-branch=main", work], ["-C", work, "config", "user.name", "Test"],
                    ["-C", work, "config", "user.email", "test@example.invalid"],
                    ["-C", work, "config", "commit.gpgSign", "false"],
                    ["init", "-q", "--bare", "--initial-branch=main", bare]):
        git(*command, check=True)
    (work / "a.txt").write_text("a\n")
    git("-C", work, "add", ".", check=True)
    git("-C", work, "commit", "-qm", "a", check=True)
    git("-C", work, "push", "-q", bare, "HEAD:refs/heads/main", check=True)
    for directory, user, readable in ((two, "alice", True), (one, "alice", False), (two, "zed", False)):
        ssh = root / f"ssh-{directory.name}-{user}"
        ssh.write_text("#!/bin/sh\nwhile [ $# -gt 1 ]; do shift; done\nSSH_ORIGINAL_COMMAND=$1 exec " + shlex.join([
            shell, "serve", "--user", user, "--root", str(root), "--manifest", str(directory / "manifest.json"),
            "--grants", str(directory / "grants.json"), "--git", "/usr/bin/git"]) + "\n")
        ssh.chmod(0o700)
        clone = root / f"clone-{directory.name}-{user}"
        result = git("-c", f"core.sshCommand={ssh}", "clone", "-q", "test:app.git", clone)
        if (result.returncode == 0) != readable or (readable and not (clone / "a.txt").exists()):
            failures.append(f"clone of {user} through {directory.name}: exit {result.returncode}, "
                            f"{result.stderr.decode(errors='replace')}")
    # A manifest that holds both versions is refused at open.
    both = root / "both"
    both.mkdir()
    (both / "grants.json").write_bytes((one / "grants.json").read_bytes())
    (both / "one.dl").write_bytes((one / "gitolite-migrated.dl").read_bytes())
    (both / "two.dl").write_bytes((two / "gitolite-migrated.dl").read_bytes())
    manifest = json.loads((two / "manifest.json").read_text())
    entry = manifest["policies"][0]
    manifest["policies"] = [
        dict(entry, policy_id="one", file="one.dl", sha256=hashlib.sha256((both / "one.dl").read_bytes()).hexdigest()),
        dict(entry, policy_id="two", file="two.dl", sha256=hashlib.sha256((both / "two.dl").read_bytes()).hexdigest()),
    ]
    (both / "manifest.json").write_text(json.dumps(manifest))
    result = subprocess.run([maelys_git, "authorize", "manifest.json", "alice", "app.git", "read", "--grants",
                             "grants.json", "--format", "json", "--non-interactive"],
                            cwd=both, capture_output=True, timeout=60)
    refusal = ("policy two is maelys-git-gitolite-program/2 but policy one is maelys-git-gitolite-program/1: "
               "a set holds one version of the audited Gitolite program")
    if result.returncode != 1 or result.stdout or refusal not in result.stderr.decode(errors="replace"):
        failures.append(f"a manifest of /1 and /2: exit {result.returncode}, {result.stderr!r}")
    return failures


def main():
    record = "--record" in sys.argv
    args = [a for a in sys.argv[1:] if a != "--record"]
    if len(args) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    maelys_git, shell, fixtures = os.path.abspath(args[0]), os.path.abspath(args[1]), Path(args[2])
    one = fixtures / "gitolite-program-1"
    table = one / "decisions.tsv"
    observed = {}
    for user in USERS:
        for operation, ref in REQUESTS:
            observed[(user, operation, ref)] = authorize(maelys_git, one, user, operation, ref)
    if record:
        with open(table, "w") as out:
            out.write(HEADER)
            for key, (allowed, receipt, output, _) in observed.items():
                out.write("\t".join(key + (allowed, receipt, output)) + "\n")
        print(f"recorded {len(observed)} decisions")
        return 0
    failures = []
    expected = {}
    for line in open(table):
        if line.startswith("#") or not line.strip():
            continue
        fields = line.rstrip("\n").split("\t")
        expected[tuple(fields[:3])] = tuple(fields[3:])
    if set(expected) != set(observed):
        failures.append(f"{len(expected)} recorded requests, {len(observed)} asked")
    for key, (allowed, receipt, output, stdout) in observed.items():
        if key in expected and expected[key] != (allowed, receipt, output):
            failures.append(f"/1 {' '.join(key)}: recorded {expected[key]}, now {(allowed, receipt, output)}:\n"
                            f"{stdout.decode(errors='replace')}")
    print(f"{len(observed)} decisions of a /1 set compared with their record")
    with tempfile.TemporaryDirectory(prefix="maelys-program-versions-") as temporary:
        failures += second_version(maelys_git, shell, one, Path(temporary).resolve(), observed)
    for failure in failures:
        print("FAIL", failure)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
