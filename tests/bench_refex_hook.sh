#!/bin/sh
# Wall-clock cost of the pre-receive hook deciding one ref update, its
# grants migrated from a gitolite.conf: refs/heads/ granted as a literal
# prefix, alone, then beside 50 regex refexes refs/heads/(.*a){16}xNN that
# never match and read the whole ref. The hook is fed its update line
# directly, on objects already in the repository: no git push and no
# receive-pack run, only the hook, its Git commands and its authorizations.
# The ref holds 511 bytes of 'a'; the update creates it with COMMITS commits
# whose last tree holds CHANGES files, under --max-commits COMMITS and
# --max-changes CHANGES (the hook's defaults are 10000 and 100000). The
# difference of the two times estimates the cost of the patterns in the
# hook; bench-maelys-git-refex push gives the same requests without Git and
# counts the searches. The Git commands the hook runs are also replayed
# alone, with the hook's Git (/usr/bin/git), as an estimate of their share.
#
#   tests/bench_refex_hook.sh MAELYS_GIT HOOK COMMITS CHANGES [RUNS]
#
# Not a test: timing depends on the machine and has no place in CTest.
set -eu
maelys_git_bin=$1
hook_bin=$2
commits=$3
changes=$4
runs=${5:-3}
root=$(mktemp -d "${TMPDIR:-/tmp}/maelys-git-refex-hook.XXXXXX")
trap 'rm -rf "$root"' EXIT HUP INT TERM

printf 'repo app\n    RW refs/heads/ = alice\n' > "$root/literal.conf"
cp "$root/literal.conf" "$root/regex.conf"
i=0
while [ "$i" -lt 50 ]; do
  printf '    RW refs/heads/(.*a){16}x%02d = alice\n' "$i" >> "$root/regex.conf"
  i=$((i + 1))
done
for kind in literal regex; do
  "$maelys_git_bin" migrate gitolite "$root/$kind.conf" "$root/$kind" \
    --apply --format json --compact --non-interactive > "$root/$kind.json"
done
grep -qF '"format":"maelys-git-grants/1"' "$root/literal/grants.json"
grep -qF '"format":"maelys-git-grants/2"' "$root/regex/grants.json"

# COMMITS commits on one line of history: the first adds CHANGES files of
# one blob, a thousand per directory; the others change nothing.
git init -q --bare "$root/app.git"
python3 - "$commits" "$changes" <<'EOF' | git --git-dir "$root/app.git" fast-import --quiet
import sys
commits, changes = int(sys.argv[1]), int(sys.argv[2])
out = sys.stdout
out.write("blob\nmark :1\ndata 2\nx\n")
for c in range(commits):
    message = "commit %d" % c
    out.write("commit refs/maelys-bench/candidate\n")
    out.write("committer bench <bench@example.test> %d +0000\n" % (1700000000 + c))
    out.write("data %d\n%s\n" % (len(message), message))
    if c == 0:
        for f in range(changes):
            out.write("M 100644 :1 d%03d/f%06d\n" % (f // 1000, f))
EOF
new_oid=$(git --git-dir "$root/app.git" rev-parse refs/maelys-bench/candidate)
test "$(git --git-dir "$root/app.git" rev-list --count "$new_oid")" -eq "$commits"
test "$(git --git-dir "$root/app.git" ls-tree -r "$new_oid" | wc -l)" -eq "$changes"
ref=refs/heads/$(printf '%0250d' 0 | tr 0 a)/$(printf '%0249d' 0 | tr 0 a)
test "${#ref}" -eq 511
zero=0000000000000000000000000000000000000000

decide() {
  printf '%s %s %s\n' "$zero" "$new_oid" "$ref" | "$hook_bin" pre-receive \
    --repository app.git --manifest "$root/$1/manifest.json" --grants "$root/$1/grants.json" \
    --user alice --git-dir "$root/app.git" \
    --max-commits "$commits" --max-changes "$changes" >/dev/null
}

# rev-list of the new ref, the header of each commit, the tree of the ref.
git_only() {
  /usr/bin/git --git-dir "$root/app.git" rev-list "$new_oid" > "$root/oids"
  while read -r oid; do
    /usr/bin/git --git-dir "$root/app.git" show -s \
      --format=%ae%x00%G?%x00%GF%x00%GS%x00%P "$oid" >/dev/null
  done < "$root/oids"
  /usr/bin/git --git-dir "$root/app.git" ls-tree -r -z --full-tree "$new_oid" >/dev/null
}

# One update of each to fail early and loudly, then RUNS of each, alternated.
decide literal
decide regex
: > "$root/times"
run=0
while [ "$run" -lt "$runs" ]; do
  for kind in literal regex git; do
    started=$(python3 -c 'import time; print(time.time())')
    if [ "$kind" = git ]; then git_only; else decide "$kind"; fi
    python3 -c 'import sys, time; print(sys.argv[1], time.time() - float(sys.argv[2]))' \
      "$kind" "$started" >> "$root/times"
  done
  run=$((run + 1))
done
python3 - "$root/times" "$commits" "$changes" <<'EOF'
import statistics, sys
times = {"literal": [], "regex": [], "git": []}
for line in open(sys.argv[1]):
    kind, seconds = line.split()
    times[kind].append(float(seconds))
commits, changes = int(sys.argv[2]), int(sys.argv[3])
# The update, each commit, each change and the summary of the ref carry it;
# the summary of the transaction does not.
with_ref = commits + changes + 2
for kind in ("literal", "regex", "git"):
    print("%-7s %s s (median %.3f s)" % (kind, " ".join("%.3f" % t for t in times[kind]),
                                         statistics.median(times[kind])))
difference = statistics.median(times["regex"]) - statistics.median(times["literal"])
print("the hook on one ref update of 511 bytes, %d commits, %d changes (%d requests, %d carry the ref), "
      "--max-commits %d --max-changes %d: 50 regex patterns add %.3f s to the median"
      % (commits, changes, with_ref + 1, with_ref, commits, changes, difference))
print("its Git commands replayed alone: median %.3f s; the difference of the medians: %.3f s"
      % (statistics.median(times["git"]),
         statistics.median(times["literal"]) - statistics.median(times["git"])))
EOF
