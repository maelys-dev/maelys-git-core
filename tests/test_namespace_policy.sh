#!/bin/sh
set -eu

maelys_git_bin=$1
test_root=$(mktemp -d "${TMPDIR:-/tmp}/maelys-namespace-test.XXXXXX")
trap 'rm -rf -- "$test_root"' EXIT HUP INT TERM

printf '%s\n' \
  'delegate_namespace("lead", "teams").' \
  'owned_repository(U) :- repository_segment(0, "users"), repository_segment(1, U), repository_depth(D), D >= 3.' \
  'allow(R) :- request(R), user(U), operation("create"), owned_repository(U).' \
  'allow(R) :- request(R), user(U), operation("admin"), repository_segment(0, N), delegate_namespace(U, N).' \
  > "$test_root/namespaces.dl"
policy_sha=$(shasum -a 256 "$test_root/namespaces.dl" | awk '{print $1}')
printf '%s\n' \
  '{' \
  '  "policy_set_id": "namespace-test",' \
  '  "policy_set_version": "1",' \
  '  "manifest_version": "1",' \
  '  "default_profile": "enforce",' \
  '  "created_for": "maelys-git-core-tests",' \
  '  "strict_loading": true,' \
  '  "fail_closed": true,' \
  '  "capabilities": [],' \
  '  "policies": [{' \
  '    "policy_id": "namespace-test.authorization",' \
  '    "domain": "maelys_git",' \
  '    "file": "namespaces.dl",' \
  "    \"sha256\": \"$policy_sha\"," \
  '    "mode": "enforce",' \
  '    "enabled": true,' \
  '    "description": "Owned repositories and bounded delegation",' \
  '    "queries": [{"name":"allow","arity":1},{"name":"deny","arity":1}]' \
  '  }]' \
  '}' > "$test_root/manifest.json"

"$maelys_git_bin" validate "$test_root/manifest.json" \
  --format json --compact | grep -q '"valid":true'
"$maelys_git_bin" authorize "$test_root/manifest.json" \
  alice users/alice/project.git create --format json --compact | \
  grep -q '"allowed":true'
"$maelys_git_bin" authorize "$test_root/manifest.json" \
  bob users/alice/project.git create --format json --compact | \
  grep -q '"allowed":false'
"$maelys_git_bin" authorize "$test_root/manifest.json" \
  alice users/alice.git create --format json --compact | \
  grep -q '"allowed":false'
"$maelys_git_bin" authorize "$test_root/manifest.json" \
  lead teams/acme/project.git admin --format json --compact | \
  grep -q '"allowed":true'
"$maelys_git_bin" authorize "$test_root/manifest.json" \
  lead users/alice/project.git admin --format json --compact | \
  grep -q '"allowed":false'
