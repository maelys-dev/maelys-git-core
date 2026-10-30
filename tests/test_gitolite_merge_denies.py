#!/usr/bin/env python3
"""A merge of a pull request against the denies of a migrated Gitolite set.

Gitolite has one way to write a ref, the push its update hook judges
(Hooks/Update.pm of 3.6.15): access(W or +) on the ref, then the VREF of
`git diff --name-only OLD NEW`. A merge of a pull request into a ref is the
push of its result: the denies of that ref and the VREF denies apply to it,
on the change it applies, base -> prepared commit. Each scene migrates a
gitolite.conf, prepares a repository, then runs `maelys-git pr merge` (plan,
then --apply) as mallory, and the executor's pr_merge, update_ref and
authorize; EXPECTED says, for each, whether the ref is written, and the
test checks the ref moved exactly then. The change applied is what pr merge
authorizes, for any policy, a written one too; pr check and pr merge show it
as appliedChangeSummary (applied_changes through the executor), beside the
pull request's own diff, changeSummary, a diagnostic always present.

    test_gitolite_merge_denies.py MAELYS_GIT EXECUTOR
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

MAELYS_GIT, EXECUTOR = map(lambda arg: str(Path(arg).resolve()), sys.argv[1:])
ENV = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
ENV.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null", GIT_AUTHOR_NAME="Test",
           GIT_AUTHOR_EMAIL="test@example.invalid", GIT_COMMITTER_NAME="Test",
           GIT_COMMITTER_EMAIL="test@example.invalid")
JSON = ["--format", "json", "--compact", "--non-interactive"]

# applied: the ref is written; refused: it is not. Where Git Core still
# differs from Gitolite, the scene says how.
EXPECTED = {
    # A deny of the ref, then a grant on its prefix, on the whole repository,
    # or a deny by a nested group: Gitolite refuses W on the ref.
    "ref-deny ff secret": "refused",
    "ref-deny ff other": "applied",
    "ref-deny-repository ff secret": "refused",
    "ref-deny-group ff secret": "refused",
    # VREF/NAME on a path the pull request adds.
    "vref-name ff main": "refused",
    # The base renames public.txt to secret.txt after the merge base, the
    # pull request edits public.txt: the merge writes secret.txt.
    "rename merge main": "refused",
    "rename squash main": "refused",
    "rename-control ff main": "applied",
    # The pull request edits a.txt and b.txt, the base has the same edit of
    # b.txt: the applied change touches a.txt alone, which COUNT/1 and
    # NAME/b.txt let through.
    "counts merge main": "applied",
    "counts squash main": "applied",
    "counts-name merge main": "applied",
    "counts-name squash main": "applied",
    # A written policy that denies secret.txt to a merge sees the rename.
    "written rename merge main": "refused",
    # The executor: its pr_merge, its update_ref (a push), its authorize.
    "executor pr_merge secret": "refused",
    "executor pr_merge other": "applied",
    "executor update_ref secret": "refused",
    "executor update_ref other": "applied",
}
# What authorize answers mallory on refs/heads/secret of the ref-deny scene,
# through the CLI and through the executor: (allowed, explicit_deny).
AUTHORIZED = {"push": (False, True), "merge": (False, True), "update-ref": (False, True)}


def run(*args, cwd=None, input=None, ok=True):
    result = subprocess.run(list(map(str, args)), cwd=cwd, input=input, text=True, capture_output=True, env=ENV,
                            timeout=120)
    if ok and result.returncode:
        raise AssertionError(f"{args}: exit {result.returncode}\n{result.stdout}\n{result.stderr}")
    return result


def git(*args, **kwargs):
    return run("/usr/bin/git", *args, **kwargs)


class Scene:
    def __init__(self, root, name, conf):
        self.dir = root / name
        self.dir.mkdir()
        (self.dir / "gitolite.conf").write_text(conf)
        run(MAELYS_GIT, "migrate", "gitolite", "gitolite.conf", "policy", "--apply", *JSON, cwd=self.dir)
        self.bare, self.work = self.dir / "app.git", self.dir / "work"
        git("init", "-q", "--bare", "--initial-branch=main", self.bare)
        git("init", "-q", "--initial-branch=main", self.work)
        git("-C", self.work, "config", "commit.gpgSign", "false")

    def commit(self, files, message, renames=(), allow_empty=False):
        for old, new in renames:
            git("-C", self.work, "mv", old, new)
        for path, text in files.items():
            (self.work / path).write_text(text)
        git("-C", self.work, "add", "-A")
        git("-C", self.work, "commit", "-qm", message, *(["--allow-empty"] if allow_empty else []))

    def push(self, *refs):
        git("-C", self.work, "push", "-q", "--force", self.bare, *refs)

    def oid(self, ref):
        return git("--git-dir", self.bare, "rev-parse", ref).stdout.strip()

    def policy(self, name):
        return str(self.dir / "policy" / name)

    def written_policy(self, source):
        """A set of one written policy in place of the migrated one."""
        written = self.dir / "policy"
        (written / "written.dl").write_text(source)
        manifest = json.loads((written / "manifest.json").read_text())
        manifest["policies"][0].update(policy_id="written", file="written.dl", description="written",
                                       sha256=hashlib.sha256(source.encode()).hexdigest())
        (written / "manifest.json").write_text(json.dumps(manifest))
        (written / "grants.json").unlink()

    def check(self, base, head, style):
        result = run(MAELYS_GIT, "pr", "check", self.dir, "app.git", base, head, "--style", style, *JSON, ok=False)
        return json.loads(result.stdout)["data"]

    def pr_merge(self, ref, style):
        """Plan then apply a pull request of feature into REF; whether the
        ref was written."""
        base, head = self.oid(ref), self.oid("refs/heads/feature")
        grants = ["--grants", self.policy("grants.json")] if os.path.exists(self.policy("grants.json")) else []
        common = ["pr", "merge", self.dir, "app.git", ref, base, head, self.policy("manifest.json"), "mallory",
                  *grants, "--style", style, "--message", "m", "--approvals", "1",
                  "--required-approvals", "1", "--status-checks-passed", *JSON]
        plan = run(MAELYS_GIT, *common, ok=False)
        written = False
        self.plan = None
        if plan.returncode == 0:
            data = self.plan = json.loads(plan.stdout)["data"]
            expected_grants = (["--expected-grants-fingerprint", data["grantsFingerprint"]]
                               if data["grantsFingerprint"] else [])
            apply = run(MAELYS_GIT, *common, "--apply", "--expected-prepared-oid", data["preparedOid"],
                        "--expected-policy-fingerprint", data["policyFingerprint"],
                        "--expected-target-identity", data["targetIdentity"], *expected_grants, ok=False)
            written = apply.returncode == 0
            if not written:
                assert json.loads(apply.stderr)["error"]["code"] == "ACCESS_DENIED", apply.stderr
        else:
            assert json.loads(plan.stderr)["error"]["code"] == "ACCESS_DENIED", plan.stderr
        assert (self.oid(ref) != base) == written, (ref, base, self.oid(ref), written)
        return "applied" if written else "refused"

    def executor(self, command, payload):
        now = int(time.time() * 1000)
        request = dict(protocol="maelys-git-agent/1", message_id=command, agent_id="test-agent", type="command",
                       command=command, repository="app.git", principal="mallory", issued_at_ms=now,
                       expires_at_ms=now + 60000, payload=payload)
        result = run(EXECUTOR, "serve", "--manifest", self.policy("manifest.json"), "--grants",
                     self.policy("grants.json"), "--root", self.dir, "--git", "/usr/bin/git",
                     input=json.dumps(request) + "\n", ok=False)
        return json.loads(result.stdout.splitlines()[0])

    def executor_pr_merge(self, ref):
        base, head = self.oid(ref), self.oid("refs/heads/feature")
        payload = dict(base_ref=ref, base_oid=base, head_oid=head, style="ff", approvals=1, required_approvals=1,
                       status_checks_passed=True, blocking_review=False, apply=False)
        plan = self.executor("pr_merge", payload)
        written = False
        if plan["status"] == "ok":
            planned = plan["payload"]
            apply = self.executor("pr_merge", dict(payload, apply=True, expected_prepared_oid=planned["prepared_oid"],
                                                   expected_policy_fingerprint=planned["policy_fingerprint"],
                                                   expected_target_identity=planned["target_identity"],
                                                   expected_grants_fingerprint=planned["grants_fingerprint"]))
            written = apply["status"] == "ok"
            assert written or apply["status"] == "denied", apply
        else:
            assert plan["status"] == "denied", plan
        assert (self.oid(ref) != base) == written, (ref, written)
        return "applied" if written else "refused"

    def executor_update_ref(self, ref):
        before = self.oid(ref)
        answer = self.executor("update_ref", dict(ref=ref, old_oid=before, new_oid=self.oid("refs/heads/feature")))
        written = answer["status"] == "ok"
        assert written or answer["status"] == "denied", answer
        assert (self.oid(ref) != before) == written, (ref, written)
        return "applied" if written else "refused"


def linear(scene, extra):
    """main, secret and other at a base commit; feature one commit ahead."""
    scene.commit({"a.txt": "a\n"}, "base")
    git("-C", scene.work, "checkout", "-q", "-b", "feature")
    scene.commit(extra, "feature")
    scene.push("main:refs/heads/main", "main:refs/heads/secret", "main:refs/heads/other",
               "feature:refs/heads/feature")


def main():
    observed = {}
    with tempfile.TemporaryDirectory(prefix="maelys-merge-denies-") as temporary:
        root = Path(temporary).resolve()
        for name, conf in (("ref-deny", "    - refs/heads/secret = mallory\n    RW+ refs/heads/ = mallory\n"),
                           ("ref-deny-repository", "    - refs/heads/secret = mallory\n    RW+ = mallory\n"),
                           ("ref-deny-group", "    - refs/heads/secret = @ops\n    RW+ = mallory\n")):
            groups = "@devs = mallory\n@ops = @devs\n" if name == "ref-deny-group" else ""
            scene = Scene(root, name, groups + "repo app\n" + conf)
            linear(scene, {"b.txt": "b\n"})
            observed[f"{name} ff secret"] = scene.pr_merge("refs/heads/secret", "ff")
            if name == "ref-deny":
                observed["ref-deny ff other"] = scene.pr_merge("refs/heads/other", "ff")
                git("--git-dir", scene.bare, "update-ref", "refs/heads/secret", scene.oid("refs/heads/main"))
                git("--git-dir", scene.bare, "update-ref", "refs/heads/other", scene.oid("refs/heads/main"))
                observed["executor pr_merge secret"] = scene.executor_pr_merge("refs/heads/secret")
                observed["executor pr_merge other"] = scene.executor_pr_merge("refs/heads/other")
                git("--git-dir", scene.bare, "update-ref", "refs/heads/secret", scene.oid("refs/heads/main"))
                git("--git-dir", scene.bare, "update-ref", "refs/heads/other", scene.oid("refs/heads/main"))
                observed["executor update_ref secret"] = scene.executor_update_ref("refs/heads/secret")
                observed["executor update_ref other"] = scene.executor_update_ref("refs/heads/other")
                for operation, expected in AUTHORIZED.items():
                    cli = json.loads(run(MAELYS_GIT, "authorize", scene.policy("manifest.json"), "mallory",
                                         "app.git", operation, "refs/heads/secret", "--grants",
                                         scene.policy("grants.json"), *JSON).stdout)["data"]
                    answer = scene.executor("authorize", dict(operation=operation, ref="refs/heads/secret"))
                    for via, decision in (("cli", cli), ("executor", answer["payload"])):
                        if (decision["allowed"], decision["explicit_deny"] if via == "executor" else
                                decision["receipt"]["decision"] == "deny_explicit") != expected:
                            raise AssertionError(f"authorize {operation} through {via}: {decision}")

        scene = Scene(root, "vref-name", "repo app\n    - VREF/NAME/secret.txt = mallory\n    RW+ = mallory\n")
        linear(scene, {"secret.txt": "s\n"})
        observed["vref-name ff main"] = scene.pr_merge("refs/heads/main", "ff")

        for style in ("merge", "squash"):
            scene = Scene(root, f"rename-{style}",
                          "repo app\n    - VREF/NAME/secret.txt = mallory\n    RW+ = mallory\n")
            scene.commit({"public.txt": "".join(f"{i}\n" for i in range(1, 21))}, "base")
            git("-C", scene.work, "checkout", "-q", "-b", "feature")
            scene.commit({"public.txt": "".join(("ten\n" if i == 10 else f"{i}\n") for i in range(1, 21))}, "edit")
            git("-C", scene.work, "checkout", "-q", "main")
            scene.commit({}, "rename", renames=(("public.txt", "secret.txt"),))
            scene.push("main:refs/heads/main", "feature:refs/heads/feature")
            check = scene.check(scene.oid("refs/heads/main"), scene.oid("refs/heads/feature"), style)
            assert check["changeSummary"]["changed"] == 1 and check["appliedChangeSummary"]["changed"] == 1, check
            observed[f"rename {style} main"] = scene.pr_merge("refs/heads/main", style)
            if observed[f"rename {style} main"] == "applied":
                assert git("--git-dir", scene.bare, "show", "main:secret.txt").stdout.split("\n")[9] == "ten"
            if style == "merge":
                scene.written_policy('deny(R) :- request(R), operation("merge"), path("secret.txt").\n'
                                     'allow(R) :- request(R), operation("merge").\n')
                observed["written rename merge main"] = scene.pr_merge("refs/heads/main", style)
        scene = Scene(root, "rename-control", "repo app\n    - VREF/NAME/secret.txt = mallory\n    RW+ = mallory\n")
        linear(scene, {"public.txt": "edited\n"})
        observed["rename-control ff main"] = scene.pr_merge("refs/heads/main", "ff")
        assert scene.plan["appliedChangeSummary"] == scene.plan["changeSummary"], scene.plan
        assert scene.plan["changeSummary"]["changed"] == 1, scene.plan

        for limit in ("counts", "counts-name"):
            deny = "- VREF/COUNT/1 = mallory" if limit == "counts" else "- VREF/NAME/b.txt = mallory"
            for style in ("merge", "squash"):
                scene = Scene(root, f"{limit}-{style}", f"repo app\n    {deny}\n    RW+ = mallory\n")
                scene.commit({"a.txt": "a\n", "b.txt": "b\n"}, "base")
                git("-C", scene.work, "checkout", "-q", "-b", "feature")
                scene.commit({"a.txt": "a2\n", "b.txt": "b2\n"}, "edit a and b")
                git("-C", scene.work, "checkout", "-q", "main")
                scene.commit({"b.txt": "b2\n"}, "edit b as the pull request does")
                scene.push("main:refs/heads/main", "feature:refs/heads/feature")
                base = scene.oid("refs/heads/main")
                head = scene.oid("refs/heads/feature")
                observed[f"{limit} {style} main"] = scene.pr_merge("refs/heads/main", style)
                if limit == "counts":
                    summaries = (scene.plan["changeSummary"], scene.plan["appliedChangeSummary"])
                    assert [summary["changed"] for summary in summaries] == [2, 1], summaries
                    answer = scene.executor("pr_check", dict(base_oid=base, head_oid=head, style=style))
                    assert answer["status"] == "ok", answer
                    payload = answer["payload"]
                    assert payload["changed_count"] == 2 and payload["applied_changes"]["changed_count"] == 1, payload
                if observed[f"{limit} {style} main"] == "applied":
                    applied = git("--git-dir", scene.bare, "diff", "--name-only", base, "main").stdout.split()
                    assert applied == ["a.txt"], applied

        scene = Scene(root, "no-prepared", "repo app\n    RW+ = mallory\n")
        scene.commit({"a.txt": "a\n"}, "base")
        git("-C", scene.work, "checkout", "-q", "-b", "feature")
        scene.commit({"a.txt": "feature\n"}, "feature")
        git("-C", scene.work, "checkout", "-q", "main")
        scene.commit({"a.txt": "main\n"}, "main")
        scene.commit({}, "nothing", allow_empty=True)
        scene.push("main~1:refs/heads/main", "feature:refs/heads/feature", "main~2:refs/heads/start",
                   "main:refs/heads/nothing")
        main, feature, start, nothing = (scene.oid(f"refs/heads/{name}")
                                         for name in ("main", "feature", "start", "nothing"))
        # The pull request's diff is there whatever is prepared: one file,
        # none for an empty one. An empty fast-forward, of the base itself or
        # of an empty commit on it, has a prepared commit but applies nothing.
        for label, base, head, style, mergeable, changed in (("conflict", main, feature, "merge", False, 1),
                                                             ("no fast-forward", main, feature, "ff", False, 1),
                                                             ("empty", main, start, "merge", True, 0),
                                                             ("empty ff of the base", main, main, "ff", True, 0),
                                                             ("empty ff of an empty commit", main, nothing, "ff",
                                                              True, 0),
                                                             ("prepared", start, feature, "merge", True, 1)):
            data = scene.check(base, head, style)
            assert data["mergeable"] == mergeable, (label, data)
            assert data["changeSummary"]["changed"] == changed, (label, data)
            assert (data["appliedChangeSummary"] is None) == (label != "prepared"), (label, data)
            answer = scene.executor("pr_check", dict(base_oid=base, head_oid=head, style=style))
            assert answer["status"] == "ok" and "changed_count" in answer["payload"], (label, answer)
            assert (answer["payload"]["applied_changes"] is None) == (label != "prepared"), (label, answer)
        # A pr merge refused for a conflict or an empty pull request keeps its
        # error envelope, without summaries.
        for base, head, style in ((main, feature, "merge"), (main, start, "merge"), (main, main, "ff"),
                                  (main, nothing, "ff")):
            refused = run(MAELYS_GIT, "pr", "merge", scene.dir, "app.git", "refs/heads/main", base, head,
                          scene.policy("manifest.json"), "mallory", "--grants", scene.policy("grants.json"),
                          "--style", style, "--approvals", "1", "--required-approvals", "1",
                          "--status-checks-passed", *JSON, ok=False)
            envelope = json.loads(refused.stderr)
            assert refused.returncode == 1 and not refused.stdout, refused
            assert envelope["error"]["code"] == "ACCESS_DENIED" and "data" not in envelope, envelope

    failures = [f"{scene}: {observed.get(scene, 'not run')}, expected {outcome}"
                for scene, outcome in EXPECTED.items() if observed.get(scene) != outcome]
    failures += [f"{scene}: not listed" for scene in observed if scene not in EXPECTED]
    for failure in failures:
        print("FAIL", failure)
    if not failures:
        print(f"merge denies: {len(observed)} scenes as expected")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
