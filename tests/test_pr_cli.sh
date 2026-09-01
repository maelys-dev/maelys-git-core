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
printf 'rename me\n' > "$test_root/work/old-name.txt"
printf '\000base-binary\n' > "$test_root/work/image.bin"
git -C "$test_root/work" add .
git -C "$test_root/work" commit -qm base
git -C "$test_root/work" branch feature
base_oid=$(git -C "$test_root/work" rev-parse HEAD)
git -C "$test_root/work" checkout -q feature
printf 'feature\n' > "$test_root/work/feature.txt"
git -C "$test_root/work" mv old-name.txt new-name.txt
printf '\000feature-binary\n' > "$test_root/work/image.bin"
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
printf '%s\n' "$check" | grep -q '"renamed":1'
printf '%s\n' "$check" | grep -q '"hasBinary":true'

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
planned_oid=$(printf '%s\n' "$plan" | sed -n 's/.*"preparedOid":"\([0-9a-f]*\)".*/\1/p')
policy_fingerprint=$(printf '%s\n' "$plan" | sed -n 's/.*"policyFingerprint":"\([0-9a-f]*\)".*/\1/p')
test -n "$planned_oid"
test "${#policy_fingerprint}" -eq 64
test "$(git --git-dir "$test_root/example.git" rev-parse refs/heads/target)" = "$base_oid"

# A mismatched reviewed policy must fail before changing the target ref.
if "$maelys_git_bin" pr merge "$test_root" example.git refs/heads/target \
     "$base_oid" "$head_oid" "$manifest" alice --style merge \
     --approvals 1 --required-approvals 1 --status-checks-passed --apply \
     --expected-prepared-oid "$planned_oid" \
     --expected-policy-fingerprint 0000000000000000000000000000000000000000000000000000000000000000 \
     --format json --compact >/dev/null 2>/dev/null; then
  printf 'mismatched policy fingerprint unexpectedly succeeded\n' >&2
  exit 1
fi
test "$(git --git-dir "$test_root/example.git" rev-parse refs/heads/target)" = "$base_oid"

# Ensure wall-clock time cannot change the prepared commit identity.
sleep 2
applied=$(
  "$maelys_git_bin" pr merge "$test_root" example.git refs/heads/target \
    "$base_oid" "$head_oid" "$manifest" alice --style merge \
    --approvals 1 --required-approvals 1 --status-checks-passed --apply \
    --expected-prepared-oid "$planned_oid" \
    --expected-policy-fingerprint "$policy_fingerprint" \
    --format json --compact
)
printf '%s\n' "$applied" | grep -q '"mode":"apply"'
applied_oid=$(printf '%s\n' "$applied" | sed -n 's/.*"preparedOid":"\([0-9a-f]*\)".*/\1/p')
test "$applied_oid" = "$planned_oid"
test "$(git --git-dir "$test_root/example.git" rev-parse refs/heads/target)" != "$base_oid"

# The stale expected base must never overwrite the already-updated target.
if "$maelys_git_bin" pr merge "$test_root" example.git refs/heads/target \
     "$base_oid" "$head_oid" "$manifest" alice --style merge \
     --approvals 1 --required-approvals 1 --status-checks-passed --apply \
     --expected-prepared-oid "$planned_oid" \
     --expected-policy-fingerprint "$policy_fingerprint" \
     --format json --compact >/dev/null 2>/dev/null; then
  printf 'stale PR compare-and-swap unexpectedly succeeded\n' >&2
  exit 1
fi
