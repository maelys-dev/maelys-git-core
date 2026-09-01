#!/bin/sh
set -eu

maelys_git_bin=$1
test_root=$(mktemp -d "${TMPDIR:-/tmp}/maelys-lifecycle-test.XXXXXX")
trap 'rm -rf -- "$test_root"' EXIT HUP INT TERM

mkdir -p "$test_root/repos"
git init -q "$test_root/work"
git -C "$test_root/work" config user.name Test
git -C "$test_root/work" config user.email test@example.invalid
printf 'lifecycle\n' > "$test_root/work/file.txt"
git -C "$test_root/work" add file.txt
git -C "$test_root/work" commit -qm initial
head_oid=$(git -C "$test_root/work" rev-parse HEAD)
"$maelys_git_bin" repo init "$test_root/repos" team/alpha.git \
  --apply --format json --compact >/dev/null
git -C "$test_root/work" push -q "$test_root/repos/team/alpha.git" HEAD:refs/heads/main
git --git-dir "$test_root/repos/team/alpha.git" symbolic-ref HEAD refs/heads/main

active=$(
  "$maelys_git_bin" repo list "$test_root/repos" --format json --compact
)
printf '%s\n' "$active" | grep -q '"name":"team/alpha.git"'
printf '%s\n' "$active" | grep -q '"state":"active"'

inspection=$(
  "$maelys_git_bin" repo inspect "$test_root/repos" team/alpha.git \
    --format json --compact
)
printf '%s\n' "$inspection" | grep -q "\"headOid\":\"$head_oid\""
printf '%s\n' "$inspection" | grep -q '"refCount":1'
identity=$(printf '%s\n' "$inspection" | sed -n 's/.*"identity":"\([^"]*\)".*/\1/p')
test -n "$identity"

rename_plan=$(
  "$maelys_git_bin" repo rename "$test_root/repos" team/alpha.git team/beta.git \
    --format json --compact
)
printf '%s\n' "$rename_plan" | grep -q '"type":"repository_rename_planned"'
test -d "$test_root/repos/team/alpha.git"
test ! -e "$test_root/repos/team/beta.git"
if "$maelys_git_bin" repo rename "$test_root/repos" team/alpha.git team/beta.git \
     --apply --expected-source-identity 0:0 --format json --compact \
     >/dev/null 2>/dev/null; then
  printf 'rename accepted a stale source identity\n' >&2
  exit 1
fi
renamed=$(
  "$maelys_git_bin" repo rename "$test_root/repos" team/alpha.git team/beta.git \
    --apply --expected-source-identity "$identity" --format json --compact
)
printf '%s\n' "$renamed" | grep -q '"type":"repository_renamed"'
test ! -e "$test_root/repos/team/alpha.git"
test "$(git --git-dir "$test_root/repos/team/beta.git" rev-parse HEAD)" = "$head_oid"

archive_plan=$(
  "$maelys_git_bin" repo archive "$test_root/repos" team/beta.git arc-1 \
    --format json --compact
)
archive_identity=$(printf '%s\n' "$archive_plan" | sed -n 's/.*"sourceIdentity":"\([^"]*\)".*/\1/p')
test -n "$archive_identity"
test ! -e "$test_root/repos/.maelys-git"
archived=$(
  "$maelys_git_bin" repo archive "$test_root/repos" team/beta.git arc-1 \
    --apply --expected-source-identity "$archive_identity" --format json --compact
)
printf '%s\n' "$archived" | grep -q '"type":"repository_archived"'
printf '%s\n' "$archived" | grep -q '"sourceState":"active"'
printf '%s\n' "$archived" | grep -q '"targetState":"archive"'
test ! -e "$test_root/repos/team/beta.git"
test "$(git --git-dir "$test_root/repos/.maelys-git/archive/arc-1/repository.git" rev-parse HEAD)" = "$head_oid"

stored=$(
  "$maelys_git_bin" repo list "$test_root/repos" --include-stored \
    --format json --compact
)
printf '%s\n' "$stored" | grep -q '"name":"team/beta.git"'
printf '%s\n' "$stored" | grep -q '"state":"archive"'
printf '%s\n' "$stored" | grep -q '"storageId":"arc-1"'
if "$maelys_git_bin" parse-ssh "git-upload-pack '.maelys-git/archive/arc-1/repository.git'" \
     --format json --compact >/dev/null 2>/dev/null; then
  printf 'reserved lifecycle namespace was accepted as an SSH repository\n' >&2
  exit 1
fi

restore_plan=$(
  "$maelys_git_bin" repo restore "$test_root/repos" arc-1 --from archive \
    --as restored.git --format json --compact
)
restore_identity=$(printf '%s\n' "$restore_plan" | sed -n 's/.*"sourceIdentity":"\([^"]*\)".*/\1/p')
test -n "$restore_identity"
test ! -e "$test_root/repos/restored.git"
restored=$(
  "$maelys_git_bin" repo restore "$test_root/repos" arc-1 --from archive \
    --as restored.git --apply --expected-source-identity "$restore_identity" \
    --format json --compact
)
printf '%s\n' "$restored" | grep -q '"type":"repository_restored"'
test "$(git --git-dir "$test_root/repos/restored.git" rev-parse HEAD)" = "$head_oid"
test ! -e "$test_root/repos/.maelys-git/archive/arc-1"

delete_plan=$(
  "$maelys_git_bin" repo delete "$test_root/repos" restored.git del-1 \
    --format json --compact
)
delete_identity=$(printf '%s\n' "$delete_plan" | sed -n 's/.*"sourceIdentity":"\([^"]*\)".*/\1/p')
deleted=$(
  "$maelys_git_bin" repo delete "$test_root/repos" restored.git del-1 \
    --apply --expected-source-identity "$delete_identity" --format json --compact
)
printf '%s\n' "$deleted" | grep -q '"type":"repository_trashed"'
printf '%s\n' "$deleted" | grep -q '"targetState":"trash"'
test ! -e "$test_root/repos/restored.git"
test "$(git --git-dir "$test_root/repos/.maelys-git/trash/del-1/repository.git" rev-parse HEAD)" = "$head_oid"

trash_restore_plan=$(
  "$maelys_git_bin" repo restore "$test_root/repos" del-1 --from trash \
    --format json --compact
)
trash_identity=$(printf '%s\n' "$trash_restore_plan" | sed -n 's/.*"sourceIdentity":"\([^"]*\)".*/\1/p')
"$maelys_git_bin" repo restore "$test_root/repos" del-1 --from trash \
  --apply --expected-source-identity "$trash_identity" --format json --compact >/dev/null
test "$(git --git-dir "$test_root/repos/restored.git" rev-parse HEAD)" = "$head_oid"
test ! -e "$test_root/repos/.maelys-git/trash/del-1"
