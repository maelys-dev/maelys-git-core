#!/bin/sh
set -eu

maelys_git_bin=$1
manifest=$2
test_root=$(mktemp -d "${TMPDIR:-/tmp}/maelys-pr-test.XXXXXX")
trap 'rm -rf -- "$test_root"' EXIT HUP INT TERM

git init -q "$test_root/work"
git -C "$test_root/work" config user.name Test
git -C "$test_root/work" config user.email test@example.invalid
git -C "$test_root/work" config commit.gpgSign false
printf 'base\n' > "$test_root/work/base.txt"
git -C "$test_root/work" add .
git -C "$test_root/work" commit -qm base
git -C "$test_root/work" branch feature
base_oid=$(git -C "$test_root/work" rev-parse HEAD)
git -C "$test_root/work" checkout -q feature
printf 'feature\n' > "$test_root/work/feature.txt"
git -C "$test_root/work" add .
git -C "$test_root/work" commit -qm feature
head_oid=$(git -C "$test_root/work" rev-parse HEAD)

git -C "$test_root/work" checkout -q -b conflict-base "$base_oid"
printf 'target\n' > "$test_root/work/base.txt"
git -C "$test_root/work" commit -qam conflict-base
conflict_base_oid=$(git -C "$test_root/work" rev-parse HEAD)
git -C "$test_root/work" checkout -q -b conflict-head "$base_oid"
printf 'source\n' > "$test_root/work/base.txt"
git -C "$test_root/work" commit -qam conflict-head
conflict_head_oid=$(git -C "$test_root/work" rev-parse HEAD)
git clone -q --bare "$test_root/work" "$test_root/example.git"
git --git-dir "$test_root/example.git" update-ref refs/heads/target "$base_oid"

check=$(
  "$maelys_git_bin" pr check "$test_root" example.git "$base_oid" "$head_oid" \
    --style merge --format json --compact
)
printf '%s\n' "$check" | grep -q '"mergeable":true'
printf '%s\n' "$check" | grep -q '"empty":false'

conflict=$(
  "$maelys_git_bin" pr check "$test_root" example.git \
    "$conflict_base_oid" "$conflict_head_oid" --style merge --format json --compact
)
printf '%s\n' "$conflict" | grep -q '"mergeable":false'
printf '%s\n' "$conflict" | grep -q '"conflicts":\["base.txt"\]'

plan=$(
  "$maelys_git_bin" pr merge "$test_root" example.git refs/heads/target \
    "$base_oid" "$head_oid" "$manifest" alice --style merge \
    --approvals 1 --required-approvals 1 --status-checks-passed \
    --format json --compact
)
printf '%s\n' "$plan" | grep -q '"mode":"plan"'
test "$(git --git-dir "$test_root/example.git" rev-parse refs/heads/target)" = "$base_oid"

applied=$(
  "$maelys_git_bin" pr merge "$test_root" example.git refs/heads/target \
    "$base_oid" "$head_oid" "$manifest" alice --style merge \
    --approvals 1 --required-approvals 1 --status-checks-passed --apply \
    --format json --compact
)
printf '%s\n' "$applied" | grep -q '"mode":"apply"'
test "$(git --git-dir "$test_root/example.git" rev-parse refs/heads/target)" != "$base_oid"

# The stale expected base must never overwrite the already-updated target.
if "$maelys_git_bin" pr merge "$test_root" example.git refs/heads/target \
     "$base_oid" "$head_oid" "$manifest" alice --style merge \
     --approvals 1 --required-approvals 1 --status-checks-passed --apply \
     --format json --compact >/dev/null 2>/dev/null; then
  printf 'stale PR compare-and-swap unexpectedly succeeded\n' >&2
  exit 1
fi
