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
grep -q 'group_member("alice", "developers")' "$test_root/generated/gitolite-migrated.dl"
grep -q 'grant_force("admin", "example.git")' "$test_root/generated/gitolite-migrated.dl"
"$maelys_git_bin" validate "$test_root/generated/manifest.json" \
  --format json --compact | grep -q '"valid":true'
"$maelys_git_bin" authorize "$test_root/generated/manifest.json" \
  guest example.git read --format json --compact | grep -q '"allowed":true'
"$maelys_git_bin" authorize "$test_root/generated/manifest.json" \
  bob tools.git write --format json --compact | grep -q '"allowed":true'
"$maelys_git_bin" authorize "$test_root/generated/manifest.json" \
  guest tools.git write --format json --compact | grep -q '"allowed":false'

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
grep -q 'group_in_group("juniors", "developers")' \
  "$test_root/vrefs/gitolite-migrated.dl"
grep -q 'group_vref_deny_name("juniors", "guarded.git", "Makefile")' \
  "$test_root/vrefs/gitolite-migrated.dl"
grep -q 'group_vref_deny_count("juniors", "guarded.git", 5)' \
  "$test_root/vrefs/gitolite-migrated.dl"
grep -q 'group_vref_deny_new_count("juniors", "guarded.git", 2)' \
  "$test_root/vrefs/gitolite-migrated.dl"
grep -q 'group_vref_deny_max_new_binary("juniors", "guarded.git", 1024)' \
  "$test_root/vrefs/gitolite-migrated.dl"
"$maelys_git_bin" validate "$test_root/vrefs/manifest.json" \
  --format json --compact | grep -q '"valid":true'
"$maelys_git_bin" authorize "$test_root/vrefs/manifest.json" \
  alice guarded.git write --format json --compact | grep -q '"allowed":true'
"$maelys_git_bin" authorize "$test_root/vrefs/manifest.json" \
  alice guarded.git push refs/heads/main Makefile --format json --compact | \
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
grep -q 'group_namespace_creator("creators", "users")' \
  "$test_root/wild/gitolite-migrated.dl"
grep -q 'owner_namespace_grant_force("users")' \
  "$test_root/wild/gitolite-migrated.dl"
"$maelys_git_bin" validate "$test_root/wild/manifest.json" \
  --format json --compact | grep -q '"valid":true'
"$maelys_git_bin" authorize "$test_root/wild/manifest.json" \
  alice users/alice/project.git create --format json --compact | \
  grep -q '"allowed":true'
"$maelys_git_bin" authorize "$test_root/wild/manifest.json" \
  bob users/alice/project.git create --format json --compact | \
  grep -q '"allowed":false'
"$maelys_git_bin" authorize "$test_root/wild/manifest.json" \
  alice users/alice/project.git write --format json --compact | \
  grep -q '"allowed":true'

printf '%s\n' \
  'repo refs' \
  '    RW refs/heads/main = alice' \
  '    RW+ refs/heads/release = bob' \
  '    - refs/heads/main = mallory' > "$test_root/refs.conf"
"$maelys_git_bin" migrate gitolite "$test_root/refs.conf" \
  "$test_root/refs" --apply --format json --compact >/dev/null
grep -q 'ref_grant_push("alice", "refs.git", "refs/heads/main")' \
  "$test_root/refs/gitolite-migrated.dl"
grep -q 'ref_grant_force("bob", "refs.git", "refs/heads/release")' \
  "$test_root/refs/gitolite-migrated.dl"
grep -q 'ref_deny("mallory", "refs.git", "refs/heads/main")' \
  "$test_root/refs/gitolite-migrated.dl"
"$maelys_git_bin" validate "$test_root/refs/manifest.json" \
  --format json --compact | grep -q '"valid":true'
"$maelys_git_bin" authorize "$test_root/refs/manifest.json" \
  alice refs.git write --format json --compact | grep -q '"allowed":true'
"$maelys_git_bin" authorize "$test_root/refs/manifest.json" \
  mallory refs.git push refs/heads/main --format json --compact | \
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
    --manifest "$test_root/refs/manifest.json" --user alice \
    --git-dir "$test_root/refrepo.git" >/dev/null
if printf '%s %s %s\n' "$old_oid" "$new_oid" refs/heads/main | \
     "$maelys_hook_bin" pre-receive --repository refs.git \
       --manifest "$test_root/refs/manifest.json" --user bob \
       --git-dir "$test_root/refrepo.git" >/dev/null 2>/dev/null; then
  printf 'ref-scoped Gitolite migration allowed the wrong principal\n' >&2
  exit 1
fi
zero_oid=0000000000000000000000000000000000000000
printf '%s %s %s\n' "$zero_oid" "$new_oid" refs/heads/release | \
  "$maelys_hook_bin" pre-receive --repository refs.git \
    --manifest "$test_root/refs/manifest.json" --user bob \
    --git-dir "$test_root/refrepo.git" >/dev/null
