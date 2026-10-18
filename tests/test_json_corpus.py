"""The JSON the programs write, byte for byte, against a corpus recorded with
Jansson before it was removed.

Every case runs a program on fixed inputs and keeps its whole standard output
(the framework writes the data it receives verbatim in compact mode), the
configuration a provision writes, or a line the corpus emitter prints. The
temporary root is replaced by @ROOT@, the directory of the programs by
@BUILD@, the source checkout by @SOURCE@, and the values that depend on the
file system or the clock by named placeholders, in the recording and in the
replay alike.

A replayed output must equal its recording, or the v2 form recorded beside
it. A v2 form is admitted under exactly one of two named cases:
  case: the same JSON tokens in the same order; bytes differ only in the
        case of hexadecimal digits inside a \\uXXXX escape the lexer
        recognizes in a string;
  sort: the members of some objects are permuted; keys, values, types,
        number lexemes and array order are kept; escape case may differ as
        above, and only it.
MG_RECORD_JSON_CORPUS=FILE writes the corpus of this build; MG_RECORD_JSON_V2
adds the replayed output as the v2 form of every case that differs, under the
case the comparator finds, and fails if none applies.
"""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time

GIT_CLI, AGENT, EXECUTOR, EMITTER, MANIFEST, CORPUS = sys.argv[1:7]
# The checkout the test manifest belongs to: policies/manifest.json.
SOURCE = Path(MANIFEST).resolve().parent.parent
# The directory of the programs, which may lie inside the checkout.
BUILD = Path(EXECUTOR).resolve().parent
ENV = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
ENV.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null",
           GIT_AUTHOR_NAME="Corpus", GIT_AUTHOR_EMAIL="corpus@example.invalid",
           GIT_COMMITTER_NAME="Corpus", GIT_COMMITTER_EMAIL="corpus@example.invalid",
           GIT_AUTHOR_DATE="2026-01-01T00:00:00Z", GIT_COMMITTER_DATE="2026-01-01T00:00:00Z",
           TZ="UTC", LC_ALL="C")
FLAGS = ["--format", "json", "--compact", "--non-interactive"]

# Values that depend on the machine or the build: a device/inode identity, a
# storage id, a time in milliseconds, an engine bound. Replaced by name, in
# the recording and the replay.
VOLATILE = [
    (re.compile(r'("(?:identity|sourceIdentity|targetIdentity|source_identity|target_identity|'
                r'expectedSourceIdentity|repositoryIdentity)":")[^"]*(")'), r"\1@IDENTITY@\2"),
    (re.compile(r'("(?:storageId|storage_id)":")[^"]*(")'), r"\1@STORAGE@\2"),
    (re.compile(r'("(?:[a-z_]*At(?:Ms)?|[a-z_]*_at_ms|createdAt|modifiedAt)":)\d+'), r"\1@TIME@"),
    # The engine's bounds, which depend on the Datalog profile (SMALL, LARGE),
    # as a string so that the text stays JSON for the comparator.
    (re.compile(r'("(?:derived|derivedPerPredicate|fact|predicate|rule)Limit":)\d+'), r'\1"@LIMIT@"'),
]


def run(*args, stdin=None, ok=True, env=None):
    result = subprocess.run([str(a) for a in args], input=stdin, capture_output=True,
                            env=env or ENV, timeout=60)
    if ok and result.returncode not in (0, 2):
        raise AssertionError(f"{args}: {result.stdout!r}\n{result.stderr!r}")
    return result


def git(*args):
    return run("git", *args).stdout.decode().strip()


def normal(text, root):
    text = text.replace(str(root), "@ROOT@").replace(str(BUILD), "@BUILD@")
    text = text.replace(str(SOURCE), "@SOURCE@")
    for pattern, replacement in VOLATILE:
        text = pattern.sub(replacement, text)
    return text


def cases(root):
    """(label, bytes) of every output, in a fixed order."""
    work, bare = root / "work", root / "example.git"
    git("init", "-q", "-b", "main", work)
    (work / "base.txt").write_text("base\n")
    git("-C", work, "add", ".")
    git("-C", work, "commit", "-qm", "base")
    base = git("-C", work, "rev-parse", "HEAD")
    git("-C", work, "checkout", "-q", "-b", "feature")
    (work / "café.txt").write_text("café\n")
    (work / "ctl\x01.txt").write_text("control\n")
    (work / "base.txt").write_text("changed\n")
    git("-C", work, "add", ".")
    git("-C", work, "commit", "-qm", "feature")
    head = git("-C", work, "rev-parse", "HEAD")
    git("clone", "-q", "--bare", work, bare)
    out = []

    def cli(label, *args, program=GIT_CLI):
        result = run(program, *args, *FLAGS, ok=False)
        out.append((label, normal(result.stdout.decode(), root)))
        if result.stderr:
            out.append((label + "#stderr", normal(result.stderr.decode(), root)))

    broken = root / "broken.json"
    broken.write_text(Path(MANIFEST).read_text().replace('"sha256": "', '"sha256": "00'))
    cli("validate/valid", "validate", MANIFEST)
    cli("validate/broken", "validate", broken)
    cli("authorize/allow", "authorize", MANIFEST, "alice", "example.git", "read")
    cli("authorize/deny", "authorize", MANIFEST, "mallory", "example.git", "push", "refs/heads/main")
    cli("authorize/explain", "authorize", "--explain", MANIFEST, "mallory", "example.git", "push",
        "refs/heads/main", "café.txt")
    cli("authorize/paths", "authorize", MANIFEST, "alice", "example.git", "push", "refs/heads/main",
        "ctl\x01.txt", "café.txt")
    cli("parse-ssh", "parse-ssh", "git-upload-pack 'example.git'")
    cli("repo/init-plan", "repo", "init", root, "new.git")
    cli("repo/list", "repo", "list", root)
    cli("repo/list-stored", "repo", "list", root, "--include-stored")
    cli("repo/inspect", "repo", "inspect", root, "example.git")
    cli("repo/diff", "repo", "diff", root, "example.git", base, head)
    cli("repo/update-ref-plan", "repo", "update-ref", root, "example.git", "refs/heads/topic", head,
        "0" * 40)
    cli("repo/rename-plan", "repo", "rename", root, "example.git", "renamed.git")
    gitolite = root / "gitolite.conf"
    gitolite.write_bytes("@devs = alice bob\nrepo example\n    RW = @devs\n"
                         "    RW refs/heads/(main|dev) = café\n"
                         "    RW refs/heads/x\x01 = alice\n"
                         "    - VREF/NAME/ = alice\n"
                         # A literal backslash before u00AF: text, not an escape.
                         "    RW refs/heads/\\u00AF = alice\n".encode())
    cli("migrate/gitolite-plan", "migrate", "gitolite", gitolite, root / "migrated")
    keys = root / "keys"
    keys.mkdir()
    (keys / "alice.pub").write_text(
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFqswLrSefGZt4InrGnicUN4CuDKKMoZbafXI4nFavMT alice@test\n")
    cli("keys/compile-plan", "keys", "compile", keys, root / "authorized_keys", AGENT, root, MANIFEST)
    cli("pr/check", "pr", "check", root, "example.git", base, head, "--style", "merge")
    cli("pr/merge-plan", "pr", "merge", root, "example.git", "refs/heads/main", base, head, MANIFEST,
        "alice", "--style", "merge", "--approvals", "1", "--required-approvals", "1",
        "--status-checks-passed")
    cli("pr/merge-gates", "pr", "merge", root, "example.git", "refs/heads/main", base, head, MANIFEST,
        "alice", "--style", "merge", "--approvals", "0", "--required-approvals", "1")

    config = root / "agent.json"
    for name in ["ca.pem", "token"]:
        (root / name).write_text("x\n")
        os.chmod(root / name, 0o600)
    provision = ["provision", "--config", config, "--agent-id", "corpus-agent",
                 "--authority", "cloud.example.invalid:443", "--ca", root / "ca.pem",
                 "--token", root / "token", "--database", root / "agent.sqlite3",
                 "--manifest", MANIFEST, "--root", root, "--executor", EXECUTOR]
    cli("agent/provision-plan", *provision, program=AGENT)
    cli("agent/provision-apply", *provision, "--apply", program=AGENT)
    out.append(("agent/config-file", normal(config.read_text(), root)))

    now = int(time.time() * 1000)

    def command(identifier, name, principal, payload):
        return json.dumps(dict(protocol="maelys-git-agent/1", message_id=identifier,
                               agent_id="corpus-agent", type="command", command=name,
                               repository="example.git", principal=principal,
                               issued_at_ms=now, expires_at_ms=now + 120000, payload=payload),
                          ensure_ascii=False)
    lines = [
        command("health-1", "health", "alice", {}),
        command("authorize-1", "authorize", "alice", {"operation": "read"}),
        command("authorize-2", "authorize", "mallory", {"operation": "push", "ref": "refs/heads/main",
                                                         "paths": ["café.txt"], "explain": True}),
        command("info-1", "repository_info", "alice", {}),
        command("diff-1", "diff", "alice", {"old_oid": base, "new_oid": head}),
        command("update-1", "update_ref", "mallory", {"ref": "refs/heads/main", "old_oid": base,
                                                       "new_oid": head}),
        command("create-1", "create_repository", "nobody", {}),
        command("check-1", "pr_check", "alice", {"base_oid": base, "head_oid": head, "style": "merge"}),
        command("merge-1", "pr_merge", "mallory", {"base_ref": "refs/heads/main", "base_oid": base,
                                                    "head_oid": head, "style": "merge", "approvals": 1,
                                                    "required_approvals": 1,
                                                    "status_checks_passed": True,
                                                    "blocking_review": False, "apply": False}),
        command("unknown-1", "no_such_command", "alice", {}),
        "this is not json",
    ]
    stream = run(EXECUTOR, "serve", "--manifest", MANIFEST, "--root", root,
                 stdin=("\n".join(lines) + "\n").encode()).stdout.decode()
    for index, line in enumerate(stream.splitlines()):
        out.append((f"executor/{index:02d}", normal(line, root)))

    for label, line in zip(["emitter/" + name for name in run(EMITTER, "--names").stdout.decode().split()],
                           run(EMITTER).stdout.decode().splitlines()):
        out.append((label, line))
    return out


# The only outputs whose member order may change: the two lines that were
# written unsorted (the protocol error line, the decision line of the public
# maelys_git_protocol_write_decision), and deduplication forms, whose keys
# come from received payloads and sort by UTF-16 code units.
SORT_ADMITTED = re.compile(r"^(executor/10|emitter/decision/.*|emitter/dedup/.*)$")


# ---- the comparator --------------------------------------------------------

TOKEN = re.compile(r'\s*(?:(?P<string>"(?:[^"\\]|\\.)*")|(?P<punct>[{}\[\]:,])|'
                   r'(?P<literal>-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null))')


def tokens(text):
    """The JSON tokens of `text` (raw lexemes), or None when it is not one
    JSON text: an envelope line, a configuration, a stream line."""
    out, position = [], 0
    text = text.rstrip("\n")
    while position < len(text):
        match = TOKEN.match(text, position)
        if not match:
            return None
        out.append(match.group(match.lastgroup))
        position = match.end()
    return out


def same_but_escape_case(a, b):
    """True when two string lexemes differ only in the case of hex digits
    inside \\uXXXX escapes: an escape is a backslash preceded by an even
    number of backslashes, followed by u and four hex digits."""
    if len(a) != len(b) or a == b:
        return a == b
    # Scanning left to right, a backslash reached outside an escape always
    # starts one: an escaped backslash is consumed whole, two bytes at once.
    i = 0
    while i < len(a):
        if a[i] == "\\":
            if a[i:i + 2] != b[i:i + 2]:
                return False
            if a[i + 1] == "u":
                if a[i + 2:i + 6].lower() != b[i + 2:i + 6].lower():
                    return False
                i += 6
            else:
                i += 2
            continue
        if a[i] != b[i]:
            return False
        i += 1
    return True


def case_only(recorded, replayed):
    a, b = tokens(recorded), tokens(replayed)
    if a is None or b is None or len(a) != len(b):
        return False
    return all(x == y or (x.startswith('"') and same_but_escape_case(x, y)) for x, y in zip(a, b))


def parse_tree(token_list):
    """A tree of the lexemes: objects as lists of (key, value), arrays as
    lists, scalars as their lexeme with string escapes case-folded."""
    position = 0

    def fold(lexeme):
        return re.sub(r'(?<!\\)((?:\\\\)*)\\u([0-9a-fA-F]{4})',
                      lambda m: m.group(1) + "\\u" + m.group(2).lower(), lexeme)

    def value():
        nonlocal position
        token = token_list[position]
        position += 1
        if token == "{":
            members = []
            while token_list[position] != "}":
                key = fold(token_list[position])
                position += 2
                members.append((key, value()))
                if token_list[position] == ",":
                    position += 1
            position += 1
            return ("object", members)
        if token == "[":
            items = []
            while token_list[position] != "]":
                items.append(value())
                if token_list[position] == ",":
                    position += 1
            position += 1
            return ("array", items)
        return ("scalar", fold(token))
    tree = value()
    return tree if position == len(token_list) else None


def permuted(a, b):
    if a[0] != b[0]:
        return False
    if a[0] == "scalar":
        return a[1] == b[1]
    if a[0] == "array":
        return len(a[1]) == len(b[1]) and all(permuted(x, y) for x, y in zip(a[1], b[1]))
    if sorted(k for k, _ in a[1]) != sorted(k for k, _ in b[1]):
        return False
    right = dict(b[1])
    return len(right) == len(b[1]) and all(permuted(v, right[k]) for k, v in a[1])


def sort_only(recorded, replayed):
    a, b = tokens(recorded), tokens(replayed)
    if a is None or b is None:
        return False
    ta, tb = parse_tree(a), parse_tree(b)
    return ta is not None and tb is not None and permuted(ta, tb)


def verdict(recorded, replayed):
    if recorded == replayed:
        return "same"
    if case_only(recorded, replayed):
        return "case"
    if sort_only(recorded, replayed):
        return "sort"
    return None


def comparator_self_test():
    v1 = '{"\\uE000":"caf\\u00E9","\\uD800\\uDC00":2}'
    v2 = '{"\\ud800\\udc00":2,"\\ue000":"caf\\u00e9"}'
    assert verdict(v1, v2) == "sort"
    assert verdict('{"a":"caf\\u00E9"}', '{"a":"caf\\u00e9"}') == "case"
    # A literal backslash followed by u00AF is text, not an escape.
    assert verdict('{"a":"\\\\u00AF"}', '{"a":"\\\\u00af"}') is None
    assert verdict('{"a":[1,2]}', '{"a":[2,1]}') is None
    assert verdict('{"a":1}', '{"a":1.0}') is None
    assert verdict('{"a":1,"b":2}', '{"b":2,"a":1}') == "sort"


def main():
    comparator_self_test()
    with tempfile.TemporaryDirectory(prefix="maelys-json-corpus-") as temporary:
        produced = cases(Path(temporary).resolve())
    record = os.environ.get("MG_RECORD_JSON_CORPUS")
    if record:
        Path(record).write_text(json.dumps([{"label": label, "baseline": text} for label, text in produced],
                                           indent=1, ensure_ascii=True) + "\n")
        print(f"recorded {len(produced)} outputs")
        return
    corpus = json.loads(Path(CORPUS).read_text())
    assert [c["label"] for c in corpus] == [label for label, _ in produced], \
        ([c["label"] for c in corpus], [label for label, _ in produced])
    add_v2 = os.environ.get("MG_RECORD_JSON_V2")
    counts = {"same": 0, "case": 0, "sort": 0}
    for case, (label, text) in zip(corpus, produced):
        if text == case["baseline"]:
            counts["same"] += 1
            continue
        if add_v2:
            found = verdict(case["baseline"], text)
            assert found in ("case", "sort"), f"{label}: no admitted case\n{case['baseline']}\n{text}"
            case["case"], case["v2"] = found, text
        expected = case.get("v2")
        assert expected is not None, f"{label}: differs and has no v2 form\n{case['baseline']}\n{text}"
        assert text == expected, f"{label}: differs from its v2 form\n{expected}\n{text}"
        assert case["case"] != "sort" or SORT_ADMITTED.match(label), \
            f"{label}: member order may not change for this output"
        recheck = verdict(case["baseline"], expected)
        assert recheck == case["case"], f"{label}: v2 form is not of case {case['case']}"
        counts[case["case"]] += 1
    if add_v2:
        Path(CORPUS).write_text(json.dumps(corpus, indent=1, ensure_ascii=True) + "\n")
    print(f"JSON corpus: {counts['same']} identical, {counts['case']} by escape case, "
          f"{counts['sort']} by member order")


main()
