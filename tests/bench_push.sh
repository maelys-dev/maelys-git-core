#!/bin/sh
# Wall-clock cost of a real three-ref push through the pre-receive hook,
# next to the cost of one authorization measured by bench-maelys-git-authorize.
#
#   tests/bench_push.sh HOOK_BINARY MANIFEST [PUSHES]
#
# Not a test: timing depends on the machine and has no place in CTest.
set -eu
hook_bin=$1
manifest=$2
pushes=${3:-30}
root=$(mktemp -d "${TMPDIR:-/tmp}/maelys-git-bench.XXXXXX")
trap 'rm -rf "$root"' EXIT HUP INT TERM

git init -q --bare "$root/example.git"
git init -q "$root/work"
git -C "$root/work" config user.name bench
git -C "$root/work" config user.email bench@example.test
for name in one two three; do
  printf '%s\n' "$name" > "$root/work/$name.txt"
  git -C "$root/work" add "$name.txt"
  git -C "$root/work" commit -q -m "$name"
done
new_oid=$(git -C "$root/work" rev-parse HEAD)
git --git-dir "$root/example.git" fetch -q "$root/work" "$new_oid:refs/maelys-bench/candidate"
zero=0000000000000000000000000000000000000000
updates=$(printf '%s %s %s\n%s %s %s\n%s %s %s\n' \
  "$zero" "$new_oid" refs/heads/feature-a \
  "$zero" "$new_oid" refs/heads/feature-b \
  "$zero" "$new_oid" refs/heads/feature-c)

# One push to fail early and loudly, then the timed ones.
printf '%s\n' "$updates" | "$hook_bin" pre-receive --repository example.git \
  --manifest "$manifest" --user alice --git-dir "$root/example.git" >/dev/null

started=$(python3 -c 'import time; print(time.time())')
count=0
while [ "$count" -lt "$pushes" ]; do
  printf '%s\n' "$updates" | "$hook_bin" pre-receive --repository example.git \
    --manifest "$manifest" --user alice --git-dir "$root/example.git" >/dev/null
  count=$((count + 1))
done
python3 -c "import sys, time; n = int(sys.argv[2]); print('%.2f ms per three-ref push (%d pushes)' % ((time.time() - float(sys.argv[1])) * 1000.0 / n, n))" "$started" "$pushes"
