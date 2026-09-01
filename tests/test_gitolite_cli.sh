#!/bin/sh
set -eu

maelys_git_bin=$1
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
printf '%s\n' "$unsupported" | grep -q 'ref/VREF'
if "$maelys_git_bin" migrate gitolite "$test_root/unsupported.conf" \
     "$test_root/refused" --apply --format json --compact >/dev/null 2>/dev/null; then
  printf 'unsupported Gitolite migration unexpectedly applied\n' >&2
  exit 1
fi
test ! -e "$test_root/refused"
