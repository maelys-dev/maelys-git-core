#!/bin/sh
set -eu

maelys_git_bin=$1
test_root=$(mktemp -d "${TMPDIR:-/tmp}/maelys-mirror-test.XXXXXX")
trap 'rm -rf -- "$test_root"' EXIT HUP INT TERM

mkdir "$test_root/source" "$test_root/target"
"$maelys_git_bin" repo init "$test_root/source" project.git --apply \
  --format json --compact >/dev/null
git clone -q "$test_root/source/project.git" "$test_root/work"
git -C "$test_root/work" config user.name tester
git -C "$test_root/work" config user.email tester@example.test
printf 'first\n' > "$test_root/work/README.md"
git -C "$test_root/work" add README.md
git -C "$test_root/work" commit -q -m first
git -C "$test_root/work" branch -M main
git -C "$test_root/work" push -q -u origin main
git --git-dir "$test_root/source/project.git" symbolic-ref HEAD refs/heads/main

json_string() {
  printf '%s\n' "$1" | sed -n "s/.*\"$2\":\"\([^\"]*\)\".*/\1/p"
}

plan=$(
  "$maelys_git_bin" repo mirror "$test_root/source" project.git \
    "$test_root/target" --format json --compact
)
printf '%s\n' "$plan" | grep -q '"synchronizationRequired":true'
printf '%s\n' "$plan" | grep -q '"targetExists":false'
source_identity=$(json_string "$plan" sourceIdentity)
target_identity=$(json_string "$plan" targetIdentity)
source_fingerprint=$(json_string "$plan" sourceFingerprint)
target_fingerprint=$(json_string "$plan" targetFingerprint)
test "$target_identity" = absent

"$maelys_git_bin" repo mirror "$test_root/source" project.git \
  "$test_root/target" \
  --expected-source-identity "$source_identity" \
  --expected-target-identity "$target_identity" \
  --expected-source-fingerprint "$source_fingerprint" \
  --expected-target-fingerprint "$target_fingerprint" \
  --apply --format json --compact | grep -q '"changed":true'
test "$(git --git-dir "$test_root/source/project.git" rev-parse refs/heads/main)" = \
     "$(git --git-dir "$test_root/target/project.git" rev-parse refs/heads/main)"
test "$(git --git-dir "$test_root/target/project.git" symbolic-ref HEAD)" = refs/heads/main

git --git-dir "$test_root/target/project.git" update-ref refs/heads/stale \
  "$(git --git-dir "$test_root/target/project.git" rev-parse refs/heads/main)"
prune_plan=$(
  "$maelys_git_bin" repo mirror "$test_root/source" project.git \
    "$test_root/target" --format json --compact
)
printf '%s\n' "$prune_plan" | grep -q '"synchronizationRequired":true'
"$maelys_git_bin" repo mirror "$test_root/source" project.git \
  "$test_root/target" \
  --expected-source-identity "$(json_string "$prune_plan" sourceIdentity)" \
  --expected-target-identity "$(json_string "$prune_plan" targetIdentity)" \
  --expected-source-fingerprint "$(json_string "$prune_plan" sourceFingerprint)" \
  --expected-target-fingerprint "$(json_string "$prune_plan" targetFingerprint)" \
  --apply --format json --compact | grep -q '"type":"repository_mirrored"'
if git --git-dir "$test_root/target/project.git" show-ref --verify --quiet refs/heads/stale; then
  printf 'mirror failed to prune a target-only ref\n' >&2
  exit 1
fi

unchanged=$(
  "$maelys_git_bin" repo mirror "$test_root/source" project.git \
    "$test_root/target" --format json --compact
)
printf '%s\n' "$unchanged" | grep -q '"synchronizationRequired":false'
unchanged_source_identity=$(json_string "$unchanged" sourceIdentity)
unchanged_target_identity=$(json_string "$unchanged" targetIdentity)
unchanged_source_fingerprint=$(json_string "$unchanged" sourceFingerprint)
unchanged_target_fingerprint=$(json_string "$unchanged" targetFingerprint)
"$maelys_git_bin" repo mirror "$test_root/source" project.git \
  "$test_root/target" \
  --expected-source-identity "$unchanged_source_identity" \
  --expected-target-identity "$unchanged_target_identity" \
  --expected-source-fingerprint "$unchanged_source_fingerprint" \
  --expected-target-fingerprint "$unchanged_target_fingerprint" \
  --apply --format json --compact | grep -q '"changed":false'

printf 'second\n' >> "$test_root/work/README.md"
git -C "$test_root/work" commit -q -am second
git -C "$test_root/work" push -q
stale=$(
  "$maelys_git_bin" repo mirror "$test_root/source" project.git \
    "$test_root/target" --format json --compact
)
stale_source_identity=$(json_string "$stale" sourceIdentity)
stale_target_identity=$(json_string "$stale" targetIdentity)
stale_source_fingerprint=$(json_string "$stale" sourceFingerprint)
stale_target_fingerprint=$(json_string "$stale" targetFingerprint)
printf 'third\n' >> "$test_root/work/README.md"
git -C "$test_root/work" commit -q -am third
git -C "$test_root/work" push -q
if "$maelys_git_bin" repo mirror "$test_root/source" project.git \
     "$test_root/target" \
     --expected-source-identity "$stale_source_identity" \
     --expected-target-identity "$stale_target_identity" \
     --expected-source-fingerprint "$stale_source_fingerprint" \
     --expected-target-fingerprint "$stale_target_fingerprint" \
     --apply --format json --compact >/dev/null 2>/dev/null; then
  printf 'stale mirror plan unexpectedly applied\n' >&2
  exit 1
fi

fresh=$(
  "$maelys_git_bin" repo mirror "$test_root/source" project.git \
    "$test_root/target" --format json --compact
)
"$maelys_git_bin" repo mirror "$test_root/source" project.git \
  "$test_root/target" \
  --expected-source-identity "$(json_string "$fresh" sourceIdentity)" \
  --expected-target-identity "$(json_string "$fresh" targetIdentity)" \
  --expected-source-fingerprint "$(json_string "$fresh" sourceFingerprint)" \
  --expected-target-fingerprint "$(json_string "$fresh" targetFingerprint)" \
  --apply --format json --compact >/dev/null
test "$(git --git-dir "$test_root/source/project.git" rev-parse refs/heads/main)" = \
     "$(git --git-dir "$test_root/target/project.git" rev-parse refs/heads/main)"
