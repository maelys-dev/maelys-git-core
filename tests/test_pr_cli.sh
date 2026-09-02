#!/bin/sh
set -eu

maelys_git_bin=$1
manifest=$2
maelys_executor_bin=$3
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
    --pr-id 42 \
    --format json --compact
)
printf '%s\n' "$plan" | grep -q '"mode":"plan"'
printf '%s\n' "$plan" | grep -q '"type":"pr_planned"'
printf '%s\n' "$plan" | grep -q '"prHeadRef":"refs/maelys/pulls/42/head"'
planned_oid=$(printf '%s\n' "$plan" | sed -n 's/.*"preparedOid":"\([0-9a-f]*\)".*/\1/p')
policy_fingerprint=$(printf '%s\n' "$plan" | sed -n 's/.*"policyFingerprint":"\([0-9a-f]*\)".*/\1/p')
target_identity=$(printf '%s\n' "$plan" | sed -n 's/.*"targetIdentity":"\([^"]*\)".*/\1/p')
test -n "$planned_oid"
test -n "$target_identity"
test "${#policy_fingerprint}" -eq 64
test "$(git --git-dir "$test_root/example.git" rev-parse refs/heads/target)" = "$base_oid"
if git --git-dir "$test_root/example.git" show-ref --verify --quiet refs/maelys/pulls/42/head; then
  printf 'PR plan unexpectedly wrote the internal head ref\n' >&2
  exit 1
fi

# A mismatched reviewed policy must fail before changing the target ref.
if "$maelys_git_bin" pr merge "$test_root" example.git refs/heads/target \
     "$base_oid" "$head_oid" "$manifest" alice --style merge \
     --approvals 1 --required-approvals 1 --status-checks-passed --apply \
     --pr-id 42 \
     --expected-target-identity "$target_identity" \
     --expected-prepared-oid "$planned_oid" \
     --expected-policy-fingerprint 0000000000000000000000000000000000000000000000000000000000000000 \
     --format json --compact >/dev/null 2>/dev/null; then
  printf 'mismatched policy fingerprint unexpectedly succeeded\n' >&2
  exit 1
fi

# A fork head is copied into an isolated temporary repository for checking and
# reaches the target object database only during a reviewed apply.
mkdir "$test_root/cross-root"
git init -q "$test_root/upstream-work"
git -C "$test_root/upstream-work" config user.name Test
git -C "$test_root/upstream-work" config user.email test@example.invalid
printf 'upstream\n' > "$test_root/upstream-work/base.txt"
git -C "$test_root/upstream-work" add base.txt
git -C "$test_root/upstream-work" commit -qm upstream
git -C "$test_root/upstream-work" branch -M main
cross_base_oid=$(git -C "$test_root/upstream-work" rev-parse HEAD)
git clone -q --bare "$test_root/upstream-work" "$test_root/cross-root/example.git"
git clone -q "$test_root/cross-root/example.git" "$test_root/fork-work"
git -C "$test_root/fork-work" config user.name Fork
git -C "$test_root/fork-work" config user.email fork@example.invalid
git -C "$test_root/fork-work" checkout -q -b feature
printf 'fork\n' > "$test_root/fork-work/feature.txt"
git -C "$test_root/fork-work" add feature.txt
git -C "$test_root/fork-work" commit -qm fork-feature
cross_head_oid=$(git -C "$test_root/fork-work" rev-parse HEAD)
git clone -q --bare "$test_root/fork-work" "$test_root/cross-root/fork.git"

if git --git-dir "$test_root/cross-root/example.git" cat-file -e \
     "$cross_head_oid^{commit}" 2>/dev/null; then
  printf 'target unexpectedly contains the fork head before quarantine\n' >&2
  exit 1
fi

cross_check=$(
  "$maelys_git_bin" pr check "$test_root/cross-root" example.git \
    "$cross_base_oid" "$cross_head_oid" --style merge \
    --source-repository fork.git --source-ref refs/heads/feature \
    --format json --compact
)
printf '%s\n' "$cross_check" | grep -q '"crossRepository":true'
printf '%s\n' "$cross_check" | grep -q '"sourceRepository":"fork.git"'
printf '%s\n' "$cross_check" | grep -q '"sourceRef":"refs/heads/feature"'
printf '%s\n' "$cross_check" | grep -q '"sourceObjectCount":[1-9]'
if git --git-dir "$test_root/cross-root/example.git" cat-file -e \
     "$cross_head_oid^{commit}" 2>/dev/null; then
  printf 'cross-repository check leaked fork objects into target\n' >&2
  exit 1
fi

now_ms=$(($(date +%s) * 1000))
expires_ms=$((now_ms + 60000))
printf '{"protocol":"maelys-git-agent/1","message_id":"cross-check-1","agent_id":"test-agent","type":"command","command":"pr_check","repository":"example.git","principal":"alice","issued_at_ms":%s,"expires_at_ms":%s,"payload":{"base_oid":"%s","head_oid":"%s","style":"merge","source_repository":"fork.git","source_ref":"refs/heads/feature"}}\n' \
  "$now_ms" "$expires_ms" "$cross_base_oid" "$cross_head_oid" > "$test_root/executor-input.jsonl"
printf '{"protocol":"maelys-git-agent/1","message_id":"cross-plan-1","agent_id":"test-agent","type":"command","command":"pr_merge","repository":"example.git","principal":"alice","issued_at_ms":%s,"expires_at_ms":%s,"payload":{"base_ref":"refs/heads/main","base_oid":"%s","head_oid":"%s","style":"merge","source_repository":"fork.git","source_ref":"refs/heads/feature","approvals":1,"required_approvals":1,"status_checks_passed":true,"blocking_review":false,"apply":false,"pr_id":"agent-fork-7"}}\n' \
  "$now_ms" "$expires_ms" "$cross_base_oid" "$cross_head_oid" >> "$test_root/executor-input.jsonl"
"$maelys_executor_bin" serve --manifest "$manifest" \
  --root "$test_root/cross-root" --git /usr/bin/git \
  < "$test_root/executor-input.jsonl" > "$test_root/executor-output.jsonl"
executor_check=$(cat "$test_root/executor-output.jsonl")
printf '%s\n' "$executor_check" | grep -q '"status":"ok"'
printf '%s\n' "$executor_check" | grep -q '"cross_repository":true'
printf '%s\n' "$executor_check" | grep -q '"command":"pr_merge"'
printf '%s\n' "$executor_check" | grep -q '"event_type":"pr_planned"'

# Repository-local configuration capable of executing commands, as well as
# object alternates escaping the quarantine boundary, must be rejected.
git --git-dir "$test_root/cross-root/fork.git" config core.hooksPath /tmp/forbidden-hooks
if "$maelys_git_bin" pr check "$test_root/cross-root" example.git \
     "$cross_base_oid" "$cross_head_oid" --style merge \
     --source-repository fork.git --source-ref refs/heads/feature \
     --format json --compact >/dev/null 2>/dev/null; then
  printf 'cross-repository check accepted active source Git configuration\n' >&2
  exit 1
fi
git --git-dir "$test_root/cross-root/fork.git" config --unset core.hooksPath
printf '%s\n' "$test_root/cross-root/example.git/objects" > \
  "$test_root/cross-root/fork.git/objects/info/alternates"
if "$maelys_git_bin" pr check "$test_root/cross-root" example.git \
     "$cross_base_oid" "$cross_head_oid" --style merge \
     --source-repository fork.git --source-ref refs/heads/feature \
     --format json --compact >/dev/null 2>/dev/null; then
  printf 'cross-repository check accepted source object alternates\n' >&2
  exit 1
fi
rm "$test_root/cross-root/fork.git/objects/info/alternates"

if "$maelys_git_bin" pr check "$test_root/cross-root" example.git \
     "$cross_base_oid" "$cross_head_oid" --style merge \
     --source-repository fork.git --source-ref refs/heads/feature \
     --max-source-objects 1 --format json --compact >/dev/null 2>/dev/null; then
  printf 'cross-repository check ignored the source object quota\n' >&2
  exit 1
fi

cross_plan=$(
  "$maelys_git_bin" pr merge "$test_root/cross-root" example.git refs/heads/main \
    "$cross_base_oid" "$cross_head_oid" "$manifest" alice --style merge \
    --approvals 1 --required-approvals 1 --status-checks-passed --pr-id fork-7 \
    --source-repository fork.git --source-ref refs/heads/feature \
    --format json --compact
)
cross_prepared_oid=$(printf '%s\n' "$cross_plan" | sed -n 's/.*"preparedOid":"\([0-9a-f]*\)".*/\1/p')
cross_policy_fingerprint=$(printf '%s\n' "$cross_plan" | sed -n 's/.*"policyFingerprint":"\([0-9a-f]*\)".*/\1/p')
cross_source_identity=$(printf '%s\n' "$cross_plan" | sed -n 's/.*"sourceIdentity":"\([^"]*\)".*/\1/p')
cross_target_identity=$(printf '%s\n' "$cross_plan" | sed -n 's/.*"targetIdentity":"\([^"]*\)".*/\1/p')
test -n "$cross_prepared_oid"
test -n "$cross_source_identity"
test -n "$cross_target_identity"

if "$maelys_git_bin" pr merge "$test_root/cross-root" example.git refs/heads/main \
     "$cross_base_oid" "$cross_head_oid" "$manifest" alice --style merge \
     --approvals 1 --required-approvals 1 --status-checks-passed --pr-id fork-7 \
     --source-repository fork.git --source-ref refs/heads/feature \
     --expected-source-identity "$cross_source_identity" \
     --expected-target-identity 0:0 \
     --expected-prepared-oid "$cross_prepared_oid" \
     --expected-policy-fingerprint "$cross_policy_fingerprint" --apply \
     --format json --compact >/dev/null 2>/dev/null; then
  printf 'cross-repository apply accepted a stale target identity\n' >&2
  exit 1
fi
if git --git-dir "$test_root/cross-root/example.git" cat-file -e \
     "$cross_head_oid^{commit}" 2>/dev/null; then
  printf 'stale target identity check leaked fork objects into target\n' >&2
  exit 1
fi

if "$maelys_git_bin" pr merge "$test_root/cross-root" example.git refs/heads/main \
     "$cross_base_oid" "$cross_head_oid" "$manifest" alice --style merge \
     --approvals 1 --required-approvals 1 --status-checks-passed --pr-id fork-7 \
     --source-repository fork.git --source-ref refs/heads/feature \
     --expected-source-identity 0:0 \
     --expected-target-identity "$cross_target_identity" \
     --expected-prepared-oid "$cross_prepared_oid" \
     --expected-policy-fingerprint "$cross_policy_fingerprint" --apply \
     --format json --compact >/dev/null 2>/dev/null; then
  printf 'cross-repository apply accepted a stale source identity\n' >&2
  exit 1
fi
test "$(git --git-dir "$test_root/cross-root/example.git" rev-parse refs/heads/main)" = \
     "$cross_base_oid"
if git --git-dir "$test_root/cross-root/example.git" cat-file -e \
     "$cross_head_oid^{commit}" 2>/dev/null; then
  printf 'stale source identity check leaked fork objects into target\n' >&2
  exit 1
fi

printf 'moved\n' >> "$test_root/fork-work/feature.txt"
git -C "$test_root/fork-work" commit -qam moved-source
moved_head_oid=$(git -C "$test_root/fork-work" rev-parse HEAD)
git -C "$test_root/fork-work" push -q "$test_root/cross-root/fork.git" \
  feature:refs/heads/feature
if "$maelys_git_bin" pr merge "$test_root/cross-root" example.git refs/heads/main \
     "$cross_base_oid" "$cross_head_oid" "$manifest" alice --style merge \
     --approvals 1 --required-approvals 1 --status-checks-passed --pr-id fork-7 \
     --source-repository fork.git --source-ref refs/heads/feature \
     --expected-source-identity "$cross_source_identity" \
     --expected-target-identity "$cross_target_identity" \
     --expected-prepared-oid "$cross_prepared_oid" \
     --expected-policy-fingerprint "$cross_policy_fingerprint" --apply \
     --format json --compact >/dev/null 2>/dev/null; then
  printf 'cross-repository apply accepted a moved source branch\n' >&2
  exit 1
fi
if git --git-dir "$test_root/cross-root/example.git" cat-file -e \
     "$moved_head_oid^{commit}" 2>/dev/null; then
  printf 'moved source branch check leaked fork objects into target\n' >&2
  exit 1
fi
git --git-dir "$test_root/cross-root/fork.git" update-ref refs/heads/feature \
  "$cross_head_oid" "$moved_head_oid"

cross_applied=$(
  "$maelys_git_bin" pr merge "$test_root/cross-root" example.git refs/heads/main \
    "$cross_base_oid" "$cross_head_oid" "$manifest" alice --style merge \
    --approvals 1 --required-approvals 1 --status-checks-passed --pr-id fork-7 \
    --source-repository fork.git --source-ref refs/heads/feature \
    --expected-source-identity "$cross_source_identity" \
    --expected-target-identity "$cross_target_identity" \
    --expected-prepared-oid "$cross_prepared_oid" \
    --expected-policy-fingerprint "$cross_policy_fingerprint" --apply \
    --format json --compact
)
printf '%s\n' "$cross_applied" | grep -q '"type":"pr_merged"'
test "$(git --git-dir "$test_root/cross-root/example.git" rev-parse refs/heads/main)" = \
     "$cross_prepared_oid"
test "$(git --git-dir "$test_root/cross-root/example.git" rev-parse refs/maelys/pulls/fork-7/head)" = \
     "$cross_head_oid"
if git --git-dir "$test_root/cross-root/example.git" show-ref --verify --quiet \
     refs/maelys/quarantine/source; then
  printf 'quarantine ref leaked into target repository\n' >&2
  exit 1
fi

# Fast-forward has no prepared ref to promote: the source quarantine alone must
# make the reviewed head available before the target compare-and-swap.
mkdir "$test_root/ff-root"
git clone -q --bare "$test_root/upstream-work" "$test_root/ff-root/example.git"
git clone -q --bare "$test_root/cross-root/fork.git" "$test_root/ff-root/fork.git"
ff_plan=$(
  "$maelys_git_bin" pr merge "$test_root/ff-root" example.git refs/heads/main \
    "$cross_base_oid" "$cross_head_oid" "$manifest" alice --style ff \
    --approvals 1 --required-approvals 1 --status-checks-passed \
    --source-repository fork.git --source-ref refs/heads/feature \
    --format json --compact
)
ff_policy_fingerprint=$(printf '%s\n' "$ff_plan" | sed -n 's/.*"policyFingerprint":"\([0-9a-f]*\)".*/\1/p')
ff_source_identity=$(printf '%s\n' "$ff_plan" | sed -n 's/.*"sourceIdentity":"\([^"]*\)".*/\1/p')
ff_target_identity=$(printf '%s\n' "$ff_plan" | sed -n 's/.*"targetIdentity":"\([^"]*\)".*/\1/p')
printf '%s\n' "$ff_plan" | grep -q '"preparedOid":"'"$cross_head_oid"'"'
"$maelys_git_bin" pr merge "$test_root/ff-root" example.git refs/heads/main \
  "$cross_base_oid" "$cross_head_oid" "$manifest" alice --style ff \
  --approvals 1 --required-approvals 1 --status-checks-passed \
  --source-repository fork.git --source-ref refs/heads/feature \
  --expected-source-identity "$ff_source_identity" \
  --expected-target-identity "$ff_target_identity" \
  --expected-prepared-oid "$cross_head_oid" \
  --expected-policy-fingerprint "$ff_policy_fingerprint" --apply \
  --format json --compact >/dev/null
test "$(git --git-dir "$test_root/ff-root/example.git" rev-parse refs/heads/main)" = \
     "$cross_head_oid"
if git --git-dir "$test_root/ff-root/example.git" show-ref --verify --quiet \
     refs/maelys/quarantine/source; then
  printf 'fast-forward quarantine ref leaked into target repository\n' >&2
  exit 1
fi
test "$(git --git-dir "$test_root/example.git" rev-parse refs/heads/target)" = "$base_oid"

# Ensure wall-clock time cannot change the prepared commit identity.
sleep 2
applied=$(
  "$maelys_git_bin" pr merge "$test_root" example.git refs/heads/target \
    "$base_oid" "$head_oid" "$manifest" alice --style merge \
    --approvals 1 --required-approvals 1 --status-checks-passed --apply \
    --pr-id 42 \
    --expected-target-identity "$target_identity" \
    --expected-prepared-oid "$planned_oid" \
    --expected-policy-fingerprint "$policy_fingerprint" \
    --format json --compact
)
printf '%s\n' "$applied" | grep -q '"mode":"apply"'
printf '%s\n' "$applied" | grep -q '"type":"pr_merged"'
applied_oid=$(printf '%s\n' "$applied" | sed -n 's/.*"preparedOid":"\([0-9a-f]*\)".*/\1/p')
test "$applied_oid" = "$planned_oid"
test "$(git --git-dir "$test_root/example.git" rev-parse refs/heads/target)" = "$planned_oid"
test "$(git --git-dir "$test_root/example.git" rev-parse refs/maelys/pulls/42/head)" = "$head_oid"
test "$(git --git-dir "$test_root/example.git" rev-parse refs/maelys/pulls/42/merged)" = "$planned_oid"

# The stale expected base must never overwrite the already-updated target.
if "$maelys_git_bin" pr merge "$test_root" example.git refs/heads/target \
     "$base_oid" "$head_oid" "$manifest" alice --style merge \
     --approvals 1 --required-approvals 1 --status-checks-passed --apply \
     --pr-id 42 \
     --expected-target-identity "$target_identity" \
     --expected-prepared-oid "$planned_oid" \
     --expected-policy-fingerprint "$policy_fingerprint" \
     --format json --compact >/dev/null 2>/dev/null; then
  printf 'stale PR compare-and-swap unexpectedly succeeded\n' >&2
  exit 1
fi
