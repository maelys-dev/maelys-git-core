#!/usr/bin/env python3
"""Git Core's Gitolite migration against the decisions of Gitolite itself.

tests/gitolite_oracle.pl reproduces Gitolite 3.6.15, calibrated against it.
For each case of tests/fixtures/gitolite-oracle, this test migrates the
configuration with Git Core (tests/gitolite_oracle_decide.c) and:

- a case listed as refused in cases.tsv must be refused, with that reason;
- a case that migrates is asked every query (7 users, one unknown to it, W and +, the refs of
  refs.txt and their variants that Git can carry, and "any"), and its
  decision is compared with
  the oracle's in --mode deny-wins, Git Core's rule for the order of rules.
  A refusal of Gitolite at admission (ERROR) and a denial of Git Core agree.
  Every other difference must be listed in divergences.tsv with its kind,
  and every listed one must still occur: the list is the frozen account of
  where Git Core and Gitolite differ.

    test_gitolite_oracle.py PERL ORACLE DECIDE FIXTURES WORKDIR [--record]

--record rewrites divergences.tsv from what is observed, keeping known
kinds; a commit that changes it explains every changed line.
"""
import os
import subprocess
import sys
import tempfile

# zed is named by no configuration: @all holds it all the same.
USERS = ["alice", "bob", "carol", "dave", "mallory", "eve", "zed"]
GIT = "/usr/bin/git"
HEADER = (
    "# Where Git Core decides otherwise than Gitolite 3.6.15 (tests/gitolite_oracle.pl,\n"
    "# --mode deny-wins, Git Core's rule for the order of rules), each with its kind;\n"
    "# the test fails on any other difference, and on a listed one no longer observed.\n"
    "# Kinds:\n"
    "#   bare-literal-grant  a bare literal grant (RW refs/heads/main) is the exact ref\n"
    "#                       in Git Core and a prefix in Gitolite: Git Core denies\n"
    "#                       main-hotfix, main/x... Stricter, by design of the migration.\n"
    "# Against Gitolite's own first-match rule, the order of rules adds differences,\n"
    "# all stricter too; they are not this list's.\n"
    "# case\tuser\taa\tref\tgit_core\tgitolite\tkind\n")


def git_carries(ref):
    """Whether Git lets a push carry REF, by git check-ref-format itself:
    receive-pack refuses any other ref before a hook runs, so that neither
    Gitolite nor Git Core is asked about it."""
    return subprocess.run([GIT, "check-ref-format", ref], capture_output=True).returncode == 0


def refs_of(path):
    base = [line.strip() for line in open(path) if line.strip() and not line.startswith("#")]
    seen, refs = set(), []
    variants = []
    for ref in base:
        variants += [ref + "x", ref + "/x", ref[:-1]] + ([ref.replace(".", "x", 1)] if "." in ref else [])
    for ref in base + variants:
        if ref not in seen and ref.startswith("refs/") and len(ref) > len("refs/") and git_carries(ref):
            seen.add(ref)
            refs.append(ref)
    return refs


def load_table(path, columns):
    rows = {}
    for line in open(path):
        if not line.strip() or line.startswith("#"):
            continue
        fields = line.rstrip("\n").split("\t")
        if len(fields) != columns:
            raise SystemExit(f"{path}: {columns} columns expected: {line!r}")
        rows[tuple(fields[:-1])] = fields[-1]
    return rows


def main():
    record = "--record" in sys.argv
    args = [a for a in sys.argv[1:] if a != "--record"]
    if len(args) != 5:
        print(__doc__, file=sys.stderr)
        return 2
    perl, oracle, decide, fixtures, workdir = args
    os.makedirs(workdir, exist_ok=True)
    # A migration never writes over an output: each run migrates into a
    # directory of its own, removed when it ends.
    with tempfile.TemporaryDirectory(dir=workdir, prefix="run-") as run_dir:
        return compare(perl, oracle, decide, fixtures, run_dir, record)


def compare(perl, oracle, decide, fixtures, workdir, record):
    cases = load_table(os.path.join(fixtures, "cases.tsv"), 2)
    divergences_path = os.path.join(fixtures, "divergences.tsv")
    expected = load_table(divergences_path, 7)
    refs = refs_of(os.path.join(fixtures, "refs.txt"))
    observed, failures, compared, agreed = {}, [], 0, 0
    for (case,), outcome in sorted(cases.items()):
        conf = os.path.join(fixtures, "cases", case + ".conf")
        queries = [("app", user, aa, ref) for user in USERS for aa in ("W", "+") for ref in refs]
        queries += [("app", user, "W", "any") for user in USERS]
        text = "".join(" ".join(query) + "\n" for query in queries)
        result = subprocess.run([decide, conf, os.path.join(workdir, case)], input=text,
                                capture_output=True, text=True)
        if result.returncode != 0:
            failures.append(f"{case}: Git Core failed: {result.stderr.strip()}")
            continue
        lines = result.stdout.split("\n")
        if outcome != "migrates":
            reason = outcome.removeprefix("refused: ")
            if lines[0] != "UNSUPPORTED" or not any(reason in line for line in lines[1:]):
                failures.append(f"{case}: expected refused with {reason!r}, got {lines[:3]}")
            continue
        if lines[0] != "MIGRATED":
            failures.append(f"{case}: expected to migrate, got {lines[:3]}")
            continue
        mine = lines[1:1 + len(queries)]
        oracle_run = subprocess.run([perl, oracle, "--mode", "deny-wins", conf], input=text,
                                    capture_output=True, text=True)
        if oracle_run.returncode != 0:
            failures.append(f"{case}: oracle failed: {oracle_run.stderr.strip()}")
            continue
        theirs = oracle_run.stdout.split()
        if len(mine) != len(queries) or len(theirs) != len(queries):
            failures.append(f"{case}: {len(mine)} and {len(theirs)} answers for {len(queries)} queries")
            continue
        for (_, user, aa, ref), git_core, gitolite in zip(queries, mine, theirs):
            compared += 1
            if git_core == gitolite or (gitolite == "ERROR" and git_core == "DENY"):
                agreed += 1
                continue
            observed[(case, user, aa, ref, git_core, gitolite)] = None
    if not compared:
        failures.append("no decision compared: no case migrated")
    if record:
        with open(divergences_path, "w") as out:
            out.write(HEADER)
            for key in sorted(observed):
                out.write("\t".join(key) + "\t" + expected.get(key, "UNEXPLAINED") + "\n")
        print(f"recorded {len(observed)} divergences")
    else:
        for key in sorted(observed):
            if key not in expected:
                failures.append("unlisted divergence: " + " ".join(key))
        for key in sorted(expected):
            if key not in observed:
                failures.append("listed divergence no longer observed: " + " ".join(key))
        for key, kind in sorted(expected.items()):
            if kind == "UNEXPLAINED":
                failures.append("divergence without a kind: " + " ".join(key))
    kinds = {}
    for key in observed:
        kind = expected.get(key, "UNEXPLAINED")
        kinds[kind] = kinds.get(kind, 0) + 1
    print(f"{compared} decisions compared with Gitolite: {agreed} agree, {len(observed)} listed divergences {kinds}")
    for failure in failures:
        print("FAIL", failure)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
