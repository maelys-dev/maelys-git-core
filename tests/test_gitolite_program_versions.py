#!/usr/bin/env python3
"""The versions of the audited Gitolite program a migrated set may hold.

tests/fixtures/gitolite-program-1 is a set migrated from its gitolite.conf
by a Git Core that wrote maelys-git-gitolite-program/1, kept as it was
written: a set deployed before any later version. decisions.tsv records,
for each request, the decision and the SHA-256 of the receipt and of the
whole output of `maelys-git authorize --explain`, as that Git Core wrote
them. Whatever version Git Core migrates to now, it must decide this set
as it did, byte for byte.

    test_gitolite_program_versions.py MAELYS_GIT FIXTURES [--record]

--record rewrites decisions.tsv from what is observed; only a commit that
records the set as it was first written does that.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

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


def main():
    record = "--record" in sys.argv
    args = [a for a in sys.argv[1:] if a != "--record"]
    if len(args) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    maelys_git, fixtures = os.path.abspath(args[0]), Path(args[1])
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
    for failure in failures:
        print("FAIL", failure)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
