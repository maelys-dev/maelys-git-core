#!/bin/sh
set -eu

maelys_hook_bin=$1
maelys_shell_bin=$2
test_root=$(mktemp -d "${TMPDIR:-/tmp}/maelys-hook-test.XXXXXX")
trap 'rm -rf -- "$test_root"' EXIT HUP INT TERM

git init -q "$test_root/work"
git -C "$test_root/work" config user.name Test
git -C "$test_root/work" config user.email test@example.invalid
git -C "$test_root/work" config commit.gpgSign false
printf 'unsigned commit\n' > "$test_root/work/file.txt"
printf '%s\n' \
  'version https://git-lfs.github.com/spec/v1' \
  'oid sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' \
  'size 12345' > "$test_root/work/pointer.lfs"
git -C "$test_root/work" add file.txt pointer.lfs
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
if [ -e "$test_root/receipts.jsonl" ]; then
  printf 'the hook wrote receipts without --receipts\n' >&2
  exit 1
fi

# With --receipts, a refused push appends one line: the receipt of the first
# denial, its digest and its explanation. The Git client sees the same bytes.
if printf '%s %s %s\n' "$zero" "$new_oid" refs/heads/topic | \
   "$maelys_hook_bin" pre-receive --repository example.git \
     --manifest "$test_root/manifest.json" --user alice \
     --git-dir "$test_root/example.git" --receipts "$test_root/receipts.jsonl" \
     >/dev/null 2>"$test_root/receipt-diagnostics"; then
  printf 'unsigned commit passed the policy with --receipts\n' >&2
  exit 1
fi
cmp "$test_root/diagnostics" "$test_root/receipt-diagnostics"
check_receipts() {
  python3 -I - "$@" <<'PY'
import hashlib, json, sys
path, decision, with_text = sys.argv[1], sys.argv[2], sys.argv[3] == "text"
lines = open(path, encoding="utf-8").read().splitlines()
assert len(lines) == 1, lines
line = json.loads(lines[0])
receipt = line["receipt"]
canonical = json.dumps(receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
assert hashlib.sha256(canonical.encode()).hexdigest() == line["receiptSha256"], line
assert receipt["decision"] == decision, receipt
assert ("explanationText" in line) == with_text, sorted(line)
if with_text:
    text = line["explanationText"].encode()
    assert len(text) == receipt["explanation"]["textBytes"]
    assert hashlib.sha256(text).hexdigest() == receipt["explanation"]["textSha256"]
    assert text.startswith(b"MAELYS-DATALOG-v2\n")
assert lines[0] == json.dumps(line, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
PY
}
check_receipts "$test_root/receipts.jsonl" deny_explicit text

printf '%s\n' \
  'allow(R) :- request(R), operation("push").' \
  'deny(R) :- request(R), operation("push"), change_lfs_pointer(true).' \
  > "$test_root/lfs.dl"
lfs_sha=$(shasum -a 256 "$test_root/lfs.dl" | awk '{print $1}')
printf '%s\n' \
  '{' \
  '  "policy_set_id": "hook-lfs-test",' \
  '  "policy_set_version": "1",' \
  '  "manifest_version": "1",' \
  '  "default_profile": "enforce",' \
  '  "created_for": "maelys-git-core-tests",' \
  '  "strict_loading": true,' \
  '  "fail_closed": true,' \
  '  "capabilities": [],' \
  '  "policies": [{' \
  '    "policy_id": "hook-test.lfs",' \
  '    "domain": "maelys_git",' \
  '    "file": "lfs.dl",' \
  "    \"sha256\": \"$lfs_sha\"," \
  '    "mode": "enforce",' \
  '    "enabled": true,' \
  '    "description": "Reject Git LFS pointers",' \
  '    "queries": [{"name":"allow","arity":1},{"name":"deny","arity":1}]' \
  '  }]' \
  '}' > "$test_root/lfs-manifest.json"

if printf '%s %s %s\n' "$zero" "$new_oid" refs/heads/topic | \
   "$maelys_hook_bin" pre-receive --repository example.git \
     --manifest "$test_root/lfs-manifest.json" --user alice \
     --git-dir "$test_root/example.git" >/dev/null 2>"$test_root/lfs-diagnostics"; then
  printf 'LFS pointer unexpectedly passed the path policy\n' >&2
  exit 1
fi
grep -q 'denied' "$test_root/lfs-diagnostics"

printf '%s\n' 'allow(R) :- request(R), operation("push").' > "$test_root/quota.dl"
quota_sha=$(shasum -a 256 "$test_root/quota.dl" | awk '{print $1}')
sed \
  -e 's/hook-lfs-test/hook-quota-test/' \
  -e 's/hook-test.lfs/hook-test.quota/' \
  -e 's/lfs.dl/quota.dl/' \
  -e "s/$lfs_sha/$quota_sha/" \
  -e 's/Reject Git LFS pointers/Allow pushes for quota testing/' \
  "$test_root/lfs-manifest.json" > "$test_root/quota-manifest.json"
if printf '%s %s %s\n' "$zero" "$new_oid" refs/heads/topic | \
   "$maelys_hook_bin" pre-receive --repository example.git \
     --manifest "$test_root/quota-manifest.json" --user alice \
     --git-dir "$test_root/example.git" --max-total-blob-bytes 1 \
     >/dev/null 2>"$test_root/quota-diagnostics"; then
  printf 'oversized push unexpectedly passed the configured quota\n' >&2
  exit 1
fi
grep -q 'limit' "$test_root/quota-diagnostics"

# A receive quota applies to the complete multi-ref transaction, not once per ref.
if printf '%s %s %s\n%s %s %s\n' \
     "$zero" "$new_oid" refs/heads/topic \
     "$zero" "$new_oid" refs/heads/other | \
   "$maelys_hook_bin" pre-receive --repository example.git \
     --manifest "$test_root/quota-manifest.json" --user alice \
     --git-dir "$test_root/example.git" --max-total-blob-bytes 200 \
     >/dev/null 2>"$test_root/transaction-quota-diagnostics"; then
  printf 'multi-ref push unexpectedly received a fresh quota per ref\n' >&2
  exit 1
fi
grep -q 'limit' "$test_root/transaction-quota-diagnostics"

# An accepted push of three refs appends one line: the final authorization,
# without an explanation.
printf '%s %s %s\n%s %s %s\n%s %s %s\n' \
     "$zero" "$new_oid" refs/heads/one \
     "$zero" "$new_oid" refs/heads/two \
     "$zero" "$new_oid" refs/heads/three | \
  "$maelys_hook_bin" pre-receive --repository example.git \
    --manifest "$test_root/quota-manifest.json" --user alice \
    --git-dir "$test_root/example.git" --receipts "$test_root/accepted.jsonl" \
    >/dev/null 2>"$test_root/accepted-diagnostics"
check_receipts "$test_root/accepted.jsonl" allow none

# The hook and the shell carry no Jansson: receipts are written by maelys-json.
for program in "$maelys_hook_bin" "$maelys_shell_bin"; do
  if nm -g "$program" | grep -E ' _?json_[a-z_]+$' >/dev/null; then
    printf '%s links Jansson\n' "$program" >&2
    exit 1
  fi
done
