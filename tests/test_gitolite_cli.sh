#!/bin/sh
set -eu

maelys_git_bin=$1
maelys_hook_bin=$2
test_root=$(mktemp -d "${TMPDIR:-/tmp}/maelys-gitolite-test.XXXXXX")
trap 'rm -rf -- "$test_root"' EXIT HUP INT TERM

printf '%s\n' \
  '@developers = alice bob' \
  'repo example tools' \
  '    R = guest' \
  '    RW = @developers' \
  '    RW+ = admin' > "$test_root/gitolite.conf"

plan=$(
  "$maelys_git_bin" migrate gitolite "$test_root/gitolite.conf" \
    "$test_root/generated" --format json --compact
)
printf '%s\n' "$plan" | grep -q '"mode":"plan"'
printf '%s\n' "$plan" | grep -q '"canApply":true'
test ! -e "$test_root/generated"

"$maelys_git_bin" migrate gitolite "$test_root/gitolite.conf" \
  "$test_root/generated" --apply --format json --compact >/dev/null
test -f "$test_root/generated/manifest.json"
test -f "$test_root/generated/gitolite-migrated.dl"
test -f "$test_root/generated/grants.json"
# The program is the same for every configuration; the grants are data.
grep -q 'maelys-git-gitolite-program/1' "$test_root/generated/gitolite-migrated.dl"
if grep -q 'alice' "$test_root/generated/gitolite-migrated.dl"; then
  printf 'the migrated program names a principal of the configuration\n' >&2
  exit 1
fi
grep -qF '["alice","developers"]' "$test_root/generated/grants.json"
grep -qF '["user","admin","example.git","RW+"]' "$test_root/generated/grants.json"
grants="--grants=$test_root/generated/grants.json"
"$maelys_git_bin" validate "$test_root/generated/manifest.json" "$grants" \
  --format json --compact | grep -q '"valid":true'
# Without its snapshot the program does not open, and says what it needs.
"$maelys_git_bin" validate "$test_root/generated/manifest.json" \
  --format json --compact > "$test_root/no-grants.json" || true
grep -q '"valid":false' "$test_root/no-grants.json"
grep -q 'with --grants FILE' "$test_root/no-grants.json"
"$maelys_git_bin" authorize "$test_root/generated/manifest.json" \
  guest example.git read "$grants" --format json --compact | grep -q '"allowed":true'
"$maelys_git_bin" authorize "$test_root/generated/manifest.json" \
  bob tools.git write "$grants" --format json --compact | grep -q '"allowed":true'
"$maelys_git_bin" authorize "$test_root/generated/manifest.json" \
  guest tools.git write "$grants" --format json --compact | grep -q '"allowed":false'
"$maelys_git_bin" authorize "$test_root/generated/manifest.json" \
  bob tools.git write "$grants" --format json --compact | grep -q '"version":2'

printf '%s\n' \
  'repo example' \
  '    RW+ VREF/NAME/ = alice' > "$test_root/unsupported.conf"
unsupported=$(
  "$maelys_git_bin" migrate gitolite "$test_root/unsupported.conf" \
    "$test_root/refused" --format json --compact
)
printf '%s\n' "$unsupported" | grep -q '"canApply":false'
printf '%s\n' "$unsupported" | grep -q 'full-ref'
if "$maelys_git_bin" migrate gitolite "$test_root/unsupported.conf" \
     "$test_root/refused" --apply --format json --compact >/dev/null 2>/dev/null; then
  printf 'unsupported Gitolite migration unexpectedly applied\n' >&2
  exit 1
fi
test ! -e "$test_root/refused"

printf '%s\n' \
  '@juniors = alice' \
  '@developers = @juniors bob' \
  'repo guarded' \
  '    RW+ = @developers' \
  '    - VREF/NAME/Makefile = @juniors' \
  '    - VREF/COUNT/5 = @juniors' \
  '    - VREF/COUNT/2/NEWFILES = @juniors' \
  '    - VREF/MAX_NEWBIN_SIZE/1024 = @juniors' > "$test_root/vrefs.conf"
vref_plan=$(
  "$maelys_git_bin" migrate gitolite "$test_root/vrefs.conf" \
    "$test_root/vrefs" --format json --compact
)
printf '%s\n' "$vref_plan" | grep -q '"canApply":true'
printf '%s\n' "$vref_plan" | grep -q '"vrefCount":4'
"$maelys_git_bin" migrate gitolite "$test_root/vrefs.conf" \
  "$test_root/vrefs" --apply --format json --compact >/dev/null
grants="--grants=$test_root/vrefs/grants.json"
grep -qF '["juniors","developers"]' "$test_root/vrefs/grants.json"
grep -qF '["group","juniors","guarded.git","Makefile"]' "$test_root/vrefs/grants.json"
grep -qF '["group","juniors","guarded.git","count",5]' "$test_root/vrefs/grants.json"
grep -qF '["group","juniors","guarded.git","new_count",2]' "$test_root/vrefs/grants.json"
grep -qF '["group","juniors","guarded.git","max_new_binary",1024]' "$test_root/vrefs/grants.json"
"$maelys_git_bin" validate "$test_root/vrefs/manifest.json" "$grants" \
  --format json --compact | grep -q '"valid":true'
"$maelys_git_bin" authorize "$test_root/vrefs/manifest.json" \
  alice guarded.git write "$grants" --format json --compact | grep -q '"allowed":true'
"$maelys_git_bin" authorize "$test_root/vrefs/manifest.json" \
  alice guarded.git push refs/heads/main "$grants" --format json --compact -- Makefile | \
  grep -q '"explicitDeny":true'

printf '%s\n' \
  '@creators = alice bob' \
  'repo users/CREATOR/..*' \
  '    C = @creators' \
  '    RW+ = CREATOR' > "$test_root/wild.conf"
wild_plan=$(
  "$maelys_git_bin" migrate gitolite "$test_root/wild.conf" \
    "$test_root/wild" --format json --compact
)
printf '%s\n' "$wild_plan" | grep -q '"canApply":true'
"$maelys_git_bin" migrate gitolite "$test_root/wild.conf" \
  "$test_root/wild" --apply --format json --compact >/dev/null
grants="--grants=$test_root/wild/grants.json"
grep -qF '["group","creators","users"]' "$test_root/wild/grants.json"
grep -qF '["users","RW+"]' "$test_root/wild/grants.json"
"$maelys_git_bin" validate "$test_root/wild/manifest.json" "$grants" \
  --format json --compact | grep -q '"valid":true'
"$maelys_git_bin" authorize "$test_root/wild/manifest.json" \
  alice users/alice/project.git create "$grants" --format json --compact | \
  grep -q '"allowed":true'
"$maelys_git_bin" authorize "$test_root/wild/manifest.json" \
  bob users/alice/project.git create "$grants" --format json --compact | \
  grep -q '"allowed":false'
"$maelys_git_bin" authorize "$test_root/wild/manifest.json" \
  alice users/alice/project.git write "$grants" --format json --compact | \
  grep -q '"allowed":true'

printf '%s\n' \
  'repo refs' \
  '    RW refs/heads/main = alice' \
  '    RW+ refs/heads/release = bob' \
  '    - refs/heads/main = mallory' > "$test_root/refs.conf"
"$maelys_git_bin" migrate gitolite "$test_root/refs.conf" \
  "$test_root/refs" --apply --format json --compact >/dev/null
refs_grants="$test_root/refs/grants.json"
grep -qF '["user","alice","refs.git","exact","refs/heads/main","RW"]' "$refs_grants"
grep -qF '["user","bob","refs.git","exact","refs/heads/release","RW+"]' "$refs_grants"
# A bare literal denies as a prefix, as Gitolite does; grants stay exact.
grep -qF '["user","mallory","refs.git","prefix","refs/heads/main","-"]' "$refs_grants"
"$maelys_git_bin" validate "$test_root/refs/manifest.json" --grants "$refs_grants" \
  --format json --compact | grep -q '"valid":true'
"$maelys_git_bin" authorize "$test_root/refs/manifest.json" \
  alice refs.git write --grants "$refs_grants" --format json --compact | grep -q '"allowed":true'
"$maelys_git_bin" authorize "$test_root/refs/manifest.json" \
  mallory refs.git push refs/heads/main --grants "$refs_grants" --format json --compact | \
  grep -q '"explicitDeny":true'

git init -q --bare "$test_root/refrepo.git"
git init -q "$test_root/refwork"
git -C "$test_root/refwork" config user.name tester
git -C "$test_root/refwork" config user.email tester@example.test
printf 'one\n' > "$test_root/refwork/file.txt"
git -C "$test_root/refwork" add file.txt
git -C "$test_root/refwork" commit -q -m one
git -C "$test_root/refwork" branch -M main
git -C "$test_root/refwork" remote add origin "$test_root/refrepo.git"
git -C "$test_root/refwork" push -q origin main
old_oid=$(git -C "$test_root/refwork" rev-parse HEAD)
printf 'two\n' >> "$test_root/refwork/file.txt"
git -C "$test_root/refwork" commit -q -am two
new_oid=$(git -C "$test_root/refwork" rev-parse HEAD)
git --git-dir "$test_root/refrepo.git" fetch -q "$test_root/refwork" \
  "$new_oid:refs/maelys-test/candidate"
printf '%s %s %s\n' "$old_oid" "$new_oid" refs/heads/main | \
  "$maelys_hook_bin" pre-receive --repository refs.git \
    --manifest "$test_root/refs/manifest.json" --grants "$refs_grants" --user alice \
    --git-dir "$test_root/refrepo.git" >/dev/null
if printf '%s %s %s\n' "$old_oid" "$new_oid" refs/heads/main | \
     "$maelys_hook_bin" pre-receive --repository refs.git \
       --manifest "$test_root/refs/manifest.json" --grants "$refs_grants" --user bob \
       --git-dir "$test_root/refrepo.git" >/dev/null 2>/dev/null; then
  printf 'ref-scoped Gitolite migration allowed the wrong principal\n' >&2
  exit 1
fi
zero_oid=0000000000000000000000000000000000000000
printf '%s %s %s\n' "$zero_oid" "$new_oid" refs/heads/release | \
  "$maelys_hook_bin" pre-receive --repository refs.git \
    --manifest "$test_root/refs/manifest.json" --grants "$refs_grants" --user bob \
    --git-dir "$test_root/refrepo.git" >/dev/null

# Prefixes: a real push through the hook, on the namespace and beside it.
printf '%s\n' \
  'repo refs' \
  '    RW refs/heads/release/ = alice' \
  '    RW refs/heads/main = alice' > "$test_root/prefix.conf"
plan=$("$maelys_git_bin" migrate gitolite "$test_root/prefix.conf" \
  "$test_root/prefix" --format json --compact)
printf '%s\n' "$plan" | grep -q '"canApply":true'
"$maelys_git_bin" migrate gitolite "$test_root/prefix.conf" \
  "$test_root/prefix" --apply --format json --compact >/dev/null
prefix_grants="$test_root/prefix/grants.json"
grep -qF '["user","alice","refs.git","prefix","refs/heads/release/","RW"]' "$prefix_grants"
"$maelys_git_bin" validate "$test_root/prefix/manifest.json" --grants "$prefix_grants" \
  --format json --compact | grep -q '"valid":true'
printf '%s %s %s\n' "$zero_oid" "$new_oid" refs/heads/release/1.0 | \
  "$maelys_hook_bin" pre-receive --repository refs.git \
    --manifest "$test_root/prefix/manifest.json" --grants "$prefix_grants" --user alice \
    --git-dir "$test_root/refrepo.git" >/dev/null
for neighbour in refs/heads/release-evil refs/heads/releases refs/heads/release; do
  if printf '%s %s %s\n' "$zero_oid" "$new_oid" "$neighbour" | \
       "$maelys_hook_bin" pre-receive --repository refs.git \
         --manifest "$test_root/prefix/manifest.json" --grants "$prefix_grants" --user alice \
         --git-dir "$test_root/refrepo.git" >/dev/null 2>/dev/null; then
    printf 'prefix migration allowed %s, which is outside the namespace\n' "$neighbour" >&2
    exit 1
  fi
done
if printf '%s %s %s\n' "$zero_oid" "$new_oid" refs/heads/release/1.0 | \
     "$maelys_hook_bin" pre-receive --repository refs.git \
       --manifest "$test_root/prefix/manifest.json" --grants "$prefix_grants" --user bob \
       --git-dir "$test_root/refrepo.git" >/dev/null 2>/dev/null; then
  printf 'prefix migration allowed the wrong principal\n' >&2
  exit 1
fi

# A refex read as a regular expression: grants.json of format /2 and the
# pattern kept as written, then a real push through the hook; a refex that
# Gitolite would read as "or anywhere" is reported, never applied. Remarks
# do not block: a deny with grants, a group with rights and no member.
printf '%s\n' \
  'repo refs' \
  '    RW refs/heads/(main|dev)$ = alice' \
  '    - refs/heads/main = bob' \
  '    RW refs/heads/ = bob' \
  '    R = @ghost' > "$test_root/regex.conf"
regex=$("$maelys_git_bin" migrate gitolite "$test_root/regex.conf" \
  "$test_root/regex" --format json --compact)
printf '%s\n' "$regex" | grep -q '"canApply":true'
printf '%s\n' "$regex" | grep -q '"grantsFormat":"maelys-git-grants/2"'
printf '%s\n' "$regex" | grep -q 'repository refs.git: a ref deny that applies wins'
printf '%s\n' "$regex" | grep -q 'group @ghost holds rights but has no member'
"$maelys_git_bin" migrate gitolite "$test_root/regex.conf" \
  "$test_root/regex" --apply --format json --compact >/dev/null
regex_grants="$test_root/regex/grants.json"
grep -qF '"format":"maelys-git-grants/2"' "$regex_grants"
grep -qF '["user","alice","refs.git","regex","refs/heads/(main|dev)$","RW"]' "$regex_grants"
for allowed in refs/heads/main refs/heads/dev; do
  printf '%s %s %s\n' "$zero_oid" "$new_oid" "$allowed" | \
    "$maelys_hook_bin" pre-receive --repository refs.git \
      --manifest "$test_root/regex/manifest.json" --grants "$regex_grants" --user alice \
      --git-dir "$test_root/refrepo.git" >/dev/null
done
for refused in refs/heads/mainline refs/heads/devel refs/tags/main; do
  if printf '%s %s %s\n' "$zero_oid" "$new_oid" "$refused" | \
       "$maelys_hook_bin" pre-receive --repository refs.git \
         --manifest "$test_root/regex/manifest.json" --grants "$regex_grants" --user alice \
         --git-dir "$test_root/refrepo.git" >/dev/null 2>/dev/null; then
    printf 'regex migration allowed %s\n' "$refused" >&2
    exit 1
  fi
done
printf '%s\n' \
  'repo refs' \
  '    RW main|dev = alice' > "$test_root/alternation.conf"
alternation=$("$maelys_git_bin" migrate gitolite "$test_root/alternation.conf" \
  "$test_root/alternation" --format json --compact)
printf '%s\n' "$alternation" | grep -q '"canApply":false'
printf '%s\n' "$alternation" | grep -q "refex refused at column 5: a '|' at the top level"
if "$maelys_git_bin" migrate gitolite "$test_root/alternation.conf" \
     "$test_root/alternation" --apply --format json --compact >/dev/null 2>&1; then
  printf 'a top-level alternation was applied\n' >&2
  exit 1
fi
test ! -e "$test_root/alternation"

# The plan's budget: the engine's counts and bounds, the generator's worst
# cases of execution, and the failure in the shape of a validate diagnostic.
"$maelys_git_bin" describe migrate.gitolite --format json --compact --non-interactive | \
  python3 -I -c '
import json, sys
schema = json.load(sys.stdin)["data"]["commands"][0]["outputSchema"]
assert "budget" in schema["required"], schema["required"]
budget = schema["properties"]["budget"]
assert budget["additionalProperties"] is False
assert set(budget["required"]) == {"compiled", "rules", "ruleLimit", "facts", "factLimit",
    "predicates", "predicateLimit", "derivedPerPredicate", "derivedPerPredicateLimit",
    "derived", "derivedLimit", "failure"}, budget["required"]
'
{
  printf 'repo app\n'
  i=1
  while [ "$i" -le 129 ]; do printf '    RW = u%s\n' "$i"; i=$((i + 1)); done
} > "$test_root/facts.conf"
"$maelys_git_bin" migrate gitolite "$test_root/gitolite.conf" "$test_root/budget-ok" \
  --format json --compact | python3 -I -c '
import json, sys
budget = json.load(sys.stdin)["data"]["budget"]
assert budget["compiled"] is True and budget["failure"] is None, budget
# The audited program: no fact, the same rules for every configuration.
assert budget["facts"] == 0 and 0 < budget["rules"] <= budget["ruleLimit"], budget
assert budget["derivedPerPredicate"] == 4, budget
'
# 129 grants: beyond the facts a compiled policy held, decided as grants.
"$maelys_git_bin" migrate gitolite "$test_root/facts.conf" "$test_root/facts" \
  --format json --compact | python3 -I -c '
import json, sys
data = json.load(sys.stdin)["data"]
assert data["canApply"] is True and data["unsupported"] == [], data
'
"$maelys_git_bin" migrate gitolite "$test_root/facts.conf" "$test_root/facts" \
  --apply --format json --compact >/dev/null
"$maelys_git_bin" authorize "$test_root/facts/manifest.json" u129 app.git write \
  --grants "$test_root/facts/grants.json" --format json --compact | grep -q '"allowed":true'
# A member of 65 groups: beyond the direct groups a snapshot holds.
{
  i=1
  while [ "$i" -le 65 ]; do printf '@g%s = alice\n' "$i"; i=$((i + 1)); done
  printf 'repo app\n    R = @g1\n'
} > "$test_root/groups.conf"
"$maelys_git_bin" migrate gitolite "$test_root/groups.conf" "$test_root/groups-refused" \
  --format json --compact | python3 -I -c '
import json, sys
data = json.load(sys.stdin)["data"]
assert data["canApply"] is False, data
assert any("grants snapshot refused" in entry and "more than 64 groups" in entry
           for entry in data["unsupported"]), data["unsupported"]
'
if "$maelys_git_bin" migrate gitolite "$test_root/groups.conf" "$test_root/groups-refused" \
     --apply --format json --compact >/dev/null 2>"$test_root/groups-refused.err"; then
  printf 'a migration beyond its snapshot bounds was applied\n' >&2
  exit 1
fi
test ! -e "$test_root/groups-refused"

# The options of grants, as describe exposes them.
for command in authorize validate pr.merge; do
  "$maelys_git_bin" describe "$command" --format json --compact --non-interactive | \
    grep -q '"long":"--grants"'
done
"$maelys_git_bin" describe pr.merge --format json --compact --non-interactive | \
  grep -q '"long":"--expected-grants-fingerprint"'
"$maelys_hook_bin" describe pre-receive --format json --compact --non-interactive | \
  grep -q '"long":"--grants"'
