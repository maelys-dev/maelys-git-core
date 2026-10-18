"""One JSON library: no identifier of the former one in the tree or in a
binary, and explicit limits on every writer.

usage: check_json_single_library.py SOURCE_DIR NM FILE...

1. The pattern finds each line of tests/fixtures/json-guard/positive.txt
   and none of negative.txt.
2. No file of the tree matches it, except the change log and the dated
   decision records that tell the history.
3. Every maelys_json_writer_create of src/ and tests/ passes the address of
   a limits structure whose three fields are set and none to zero.
4. nm -g finds no symbol of the former library in any FILE (the programs
   and the static libraries of the product).
"""
import os
from pathlib import Path
import re
import subprocess
import sys

SOURCE, NM, FILES = Path(sys.argv[1]), sys.argv[2], sys.argv[3:]
PATTERN = re.compile(r"\bjson_[a-z0-9_]+\s*\(|\bjson_(t|int_t|error_t|type)\b|"
                     r"\bJSON_[A-Z0-9_]+\b|jansson|Jansson")
GUARD = "tests/fixtures/json-guard/"
HISTORY = {
    "CHANGELOG.md",
    "docs/json-boundaries.md",          # decision record, dated sections
    "docs/prepared-auth-receipts.md",   # decision record of GIT-C02
    "tests/check_json_single_library.py",
}
FIELDS = ("maximum_bytes", "maximum_depth", "maximum_tokens")
failures = []


def self_test():
    for name, expected in (("positive.txt", True), ("negative.txt", False)):
        lines = (SOURCE / GUARD / name).read_text().splitlines()
        assert len(lines) == (6 if expected else 5), (name, len(lines))
        for line in lines:
            if bool(PATTERN.search(line)) != expected:
                failures.append(f"pattern {'misses' if expected else 'matches'} {name}: {line}")


def tree():
    try:
        listed = subprocess.run(["git", "-C", str(SOURCE), "ls-files", "-co", "--exclude-standard", "-z"],
                                check=True, capture_output=True).stdout.decode()
        return [name for name in listed.split("\0") if name]
    except (OSError, subprocess.CalledProcessError):
        names = []
        for directory, subdirectories, files in os.walk(SOURCE):
            subdirectories[:] = [d for d in subdirectories if d != ".git" and
                                 not (Path(directory) / d / "CMakeCache.txt").exists()]
            names += [str((Path(directory) / f).relative_to(SOURCE)) for f in files]
        return names


def scan(names):
    for name in names:
        if name in HISTORY or name.startswith(GUARD):
            continue
        try:
            text = (SOURCE / name).read_bytes().decode("utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for number, line in enumerate(text.splitlines(), 1):
            if PATTERN.search(line):
                failures.append(f"{name}:{number}: {line.strip()}")


def initializer_ok(body):
    entries = [entry.strip() for entry in body.split(",") if entry.strip()]
    if len(entries) != 3:
        return False
    if all(entry.startswith(".") for entry in entries):
        named = dict(entry[1:].split("=", 1) for entry in entries if "=" in entry)
        named = {key.strip(): value.strip() for key, value in named.items()}
        if sorted(named) != sorted(FIELDS):
            return False
        entries = list(named.values())
    return all(not re.fullmatch(r"0[uUlL]*", entry) for entry in entries)


def limits_ok(text, name, seen=()):
    """Every definition of `name` in `text` sets three non-zero fields."""
    if name in seen:
        return False
    found = False
    for match in re.finditer(r"\b" + re.escape(name) +
                             r"\s*=\s*(?:\(\s*maelys_json_limits_t\s*\)\s*)?(\{[^}]*\}|[A-Za-z_]\w*)\s*;",
                             text):
        found = True
        value = match.group(1)
        if value.startswith("{"):
            if not initializer_ok(value[1:-1]):
                return False
        elif not limits_ok(text, value, seen + (name,)):
            return False
    for match in re.finditer(r"\b" + re.escape(name) + r"\.(\w+)\s*=\s*([^;]+);", text):
        if match.group(1) not in FIELDS or re.fullmatch(r"0[uUlL]*", match.group(2).strip()):
            return False
    return found


def writers(names):
    for name in names:
        if not name.endswith((".c", ".h")) or not name.startswith(("src/", "tests/", "cmd/")):
            continue
        text = (SOURCE / name).read_text()
        for match in re.finditer(r"maelys_json_writer_create\s*\(\s*[^,]+,\s*([^,]+),", text):
            argument = match.group(1).strip()
            line = text.count("\n", 0, match.start()) + 1
            if not argument.startswith("&") or not limits_ok(text, argument[1:].strip()):
                failures.append(f"{name}:{line}: writer created without three explicit limits: {argument}")


def symbols():
    for path in FILES:
        output = subprocess.run([NM, "-g", path], check=True, capture_output=True, text=True).stdout
        for line in output.splitlines():
            fields = line.split()
            if fields and re.fullmatch(r"_?(json_[a-z0-9_]+|jansson_[a-z0-9_]+)", fields[-1]):
                failures.append(f"{path}: symbol {fields[-1]}")


self_test()
names = tree()
assert any(name.startswith("src/") for name in names), "the tree was not listed"
scan(names)
writers(names)
symbols()
if failures:
    print("\n".join(failures), file=sys.stderr)
    sys.exit(1)
print(f"one JSON library: {len(names)} files, {len(FILES)} binaries, writer limits: ok")
