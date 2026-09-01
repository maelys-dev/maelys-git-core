#!/bin/sh
set -eu

maelys_hook_bin=$1
test_root=$(mktemp -d "${TMPDIR:-/tmp}/maelys-hook-test.XXXXXX")
trap 'rm -rf -- "$test_root"' EXIT HUP INT TERM

git init -q "$test_root/work"
git -C "$test_root/work" config user.name Test
git -C "$test_root/work" config user.email test@example.invalid
git -C "$test_root/work" config commit.gpgSign false
printf 'unsigned commit\n' > "$test_root/work/file.txt"
git -C "$test_root/work" add file.txt
git -C "$test_root/work" commit -qm unsigned
new_oid=$(git -C "$test_root/work" rev-parse HEAD)

git init -q --bare "$test_root/example.git"
git -C "$test_root/work" push -q "$test_root/example.git" HEAD:refs/heads/staging
git --git-dir "$test_root/example.git" update-ref -d refs/heads/staging

printf '%s\n' \
  'allow(R) :- request(R), operation("push").' \
  'deny(R) :- request(R), operation("push"), commit_signature_status("unsigned").' \
  > "$test_root/signature.dl"
policy_sha=$(shasum -a 256 "$test_root/signature.dl" | awk '{print $1}')
printf '%s\n' \
  '{' \
  '  "policy_set_id": "hook-test",' \
  '  "policy_set_version": "1",' \
  '  "manifest_version": "1",' \
  '  "default_profile": "enforce",' \
  '  "created_for": "maelys-git-core-tests",' \
  '  "strict_loading": true,' \
  '  "fail_closed": true,' \
  '  "capabilities": [],' \
  '  "policies": [{' \
  '    "policy_id": "hook-test.signature",' \
  '    "domain": "maelys_git",' \
  '    "file": "signature.dl",' \
  "    \"sha256\": \"$policy_sha\"," \
  '    "mode": "enforce",' \
  '    "enabled": true,' \
  '    "description": "Reject unsigned commits",' \
  '    "queries": [{"name":"allow","arity":1},{"name":"deny","arity":1}]' \
  '  }]' \
  '}' > "$test_root/manifest.json"

zero=0000000000000000000000000000000000000000
if printf '%s %s %s\n' "$zero" "$new_oid" refs/heads/topic | \
   "$maelys_hook_bin" pre-receive --repository example.git \
     --manifest "$test_root/manifest.json" --user alice \
     --git-dir "$test_root/example.git" >/dev/null 2>"$test_root/diagnostics"; then
  printf 'unsigned commit unexpectedly passed signature policy\n' >&2
  exit 1
fi
if ! grep -q 'denied' "$test_root/diagnostics"; then
  printf 'hook diagnostics did not report the expected policy denial:\n' >&2
  sed -n '1,20p' "$test_root/diagnostics" >&2
  exit 1
fi
