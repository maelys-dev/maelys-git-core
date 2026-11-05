"""State assertions for the GIT-C10 qualification harness (plan §2.5).

Pure readers over the agent journal (SQLite, read-only, short transactions,
no lock held), Git repositories, the grants store, processes and command
envelopes; and a recorder that writes one JSON line per assertion into
assertions.jsonl: {"assertion", "expected", "observed", "ok"}. Standard
library only. Process readers use /proc on Linux, sysctl, libproc and getsid(2) on
macOS; what a
platform cannot observe is recorded as "not_applicable", never as passed.
"""
import json
import os
import re
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

ZERO_OID = "0" * 40
LINUX = sys.platform.startswith("linux")


# ---- recorder ---------------------------------------------------------------
class Assertions:
    def __init__(self, path):
        self.path = Path(path)
        self.failed = 0
        self.count = 0
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text("")

    def record(self, name, expected, observed, ok=None):
        if ok is None:
            ok = expected == observed
        self.count += 1
        if not ok:
            self.failed += 1
        with self.path.open("a") as out:
            out.write(json.dumps(dict(assertion=name, expected=expected, observed=observed, ok=bool(ok)),
                                 ensure_ascii=False, default=str) + "\n")
        return ok

    def check(self, name, expected, observed):
        if not self.record(name, expected, observed):
            print(f"FAIL {name}: expected {expected!r}, observed {observed!r}", file=sys.stderr)
        return expected == observed

    def not_applicable(self, name, why):
        self.count += 1
        with self.path.open("a") as out:
            out.write(json.dumps(dict(assertion=name, expected=None, observed="not_applicable: " + why, ok=None)) + "\n")

    def summary(self):
        return dict(assertions=self.count, failed=self.failed)


# ---- journal ----------------------------------------------------------------
def _connect(database):
    uri = "file:" + str(Path(database).resolve()) + "?mode=ro"
    connection = sqlite3.connect(uri, uri=True, timeout=5.0)
    connection.row_factory = sqlite3.Row
    return connection


def _one(database, sql, *parameters):
    with _connect(database) as connection:
        row = connection.execute(sql, parameters).fetchone()
    return dict(row) if row is not None else None


def _all(database, sql, *parameters):
    with _connect(database) as connection:
        rows = connection.execute(sql, parameters).fetchall()
    return [dict(row) for row in rows]


def command_state(database, message_id):
    row = _one(database, "SELECT state FROM commands WHERE id=?", message_id)
    return row["state"] if row else None


def command_result(database, message_id):
    row = _one(database, "SELECT result_json FROM commands WHERE id=?", message_id)
    return json.loads(row["result_json"]) if row and row["result_json"] else None


ATTEMPT_COLUMNS = ("attempt", "grants_sha256", "started_at_ms")


def attempt(database, message_id):
    """The attempt columns of C; None for each one the schema lacks (B) or
    when the row is absent. Defaults and the row are merged without passing
    a keyword twice (review 2B-04)."""
    columns = {row["name"] for row in _all(database, "PRAGMA table_info(commands)")}
    wanted = [c for c in ATTEMPT_COLUMNS if c in columns]
    result = {c: None for c in ATTEMPT_COLUMNS}
    if wanted:
        row = _one(database, f"SELECT {','.join(wanted)} FROM commands WHERE id=?", message_id)
        if row:
            result.update(row)
    return result


# The audit event_id contract of the journal at B (store.c): the full id is
# "<family>:<message_id>" for the families below; "poll:<cursor>:<n>" names no
# command. A message_id may itself contain ":" (protocol.c), so the event id
# is compared whole against the id built from the contract, never split
# (reviews 2B-02, 843-01). A family of C that appends a declared suffix is
# matched as "<family>:<message_id>:<suffix without colon>", the family given
# by the caller; nothing of C's future grammar is assumed by default.
AUDIT_FAMILIES = ("command", "receipt", "explanation", "grants")
SUFFIXED_FAMILIES = ()  # e.g. ("attempt",) once C declares "attempt:<message_id>:<n>"


def audit_entries(database, message_id, families=AUDIT_FAMILIES, suffixed=SUFFIXED_FAMILIES):
    """The audit rows correlated exactly to message_id, in sequence order:
    event_id == family + ":" + message_id, or, for a suffixed family,
    event_id == family + ":" + message_id + ":" + a suffix without colon."""
    exact = {f"{family}:{message_id}" for family in families}
    prefixes = [f"{family}:{message_id}:" for family in suffixed]
    rows = _all(database, "SELECT sequence,event_id,kind,payload,created_at_ms FROM audit ORDER BY sequence")
    matched = []
    for row in rows:
        event_id = row["event_id"]
        if event_id in exact:
            matched.append(row)
            continue
        for prefix in prefixes:
            if event_id.startswith(prefix) and ":" not in event_id[len(prefix):]:
                matched.append(row)
                break
    return matched


def audit_kinds(database, message_id):
    """The audit kinds correlated exactly to the command, in insertion order."""
    return [row["kind"] for row in audit_entries(database, message_id)]


def outbox(database, message_id, suffixes=()):
    """The outbox rows whose id is exactly message_id, or message_id followed
    by one of the given suffixes (the event ids of C name their kind by a
    suffix; none is assumed by default)."""
    wanted = {message_id, *(message_id + suffix for suffix in suffixes)}
    columns = {row["name"] for row in _all(database, "PRAGMA table_info(outbox)")}
    fields = ["id", "kind", "acked_at_ms", "payload", "attempts", "created_at_ms"] + (["held"] if "held" in columns else [])
    rows = [row for row in _all(database, f"SELECT {','.join(fields)} FROM outbox ORDER BY rowid") if row["id"] in wanted]
    for row in rows:
        row["payload"] = json.loads(row["payload"]) if row.get("payload") else None
    return rows


def outbox_unacked(database):
    """The outbox rows not acknowledged yet, oldest first: what the agent
    still has to post."""
    return _all(database, "SELECT id,kind,attempts,created_at_ms FROM outbox WHERE acked_at_ms IS NULL ORDER BY created_at_ms")


def metadata(database, key):
    row = _one(database, "SELECT value FROM metadata WHERE key=?", key)
    return row["value"] if row else None


def cursor(database):
    return metadata(database, "cursor")


def journal_inventory(database):
    """A logical inventory of a journal: every column of every table, read in
    one deferred transaction so that the picture is coherent, independent of
    the file's bytes and sidecars. It is what a compatibility barrier is
    judged on (plan §2.5): any mutation of any stored value changes it
    (review 2B-02). Nothing is excluded."""
    with _connect(database) as connection:
        connection.execute("BEGIN")
        tables = [row["name"] for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
        inventory = {}
        for table in tables:
            columns = [row["name"] for row in connection.execute(f"PRAGMA table_info({table})")]
            order = "sequence" if "sequence" in columns else ("rowid" if table != "metadata" else "key")
            inventory[table] = dict(columns=columns, rows=[list(row) for row in connection.execute(
                f"SELECT {','.join(columns)} FROM {table} ORDER BY {order}")])
        connection.execute("COMMIT")
    return inventory


# ---- Git --------------------------------------------------------------------
def _git(repository, *args):
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null")
    return subprocess.run(["git", "--git-dir", str(repository), *args], capture_output=True, text=True,
                          env=env, timeout=30)


def ref(repository, name):
    result = _git(repository, "rev-parse", "--verify", "--quiet", name + "^{}")
    if result.returncode:
        result = _git(repository, "rev-parse", "--verify", "--quiet", name)
    return result.stdout.strip() if result.returncode == 0 else None


def reflog_chain(repository, name, marker=None):
    """The reflog of name as a list of {old, new, message}, oldest first, with
    the index of the line carrying marker (plan §2.5: a line may precede a
    publication that failed; the publication is read by ref())."""
    path = Path(repository) / "logs" / name
    if not path.exists():
        return dict(present=False, lines=[], marked_index=None)
    lines = []
    for raw in path.read_text(errors="replace").splitlines():
        match = re.match(r"^([0-9a-f]{40}) ([0-9a-f]{40}) (.*?)(?:\t(.*))?$", raw)
        if match:
            lines.append(dict(old=match.group(1), new=match.group(2), who=match.group(3),
                              message=match.group(4) or ""))
    marked = next((i for i, line in enumerate(lines) if marker and marker in line["message"]), None)
    return dict(present=True, lines=lines, marked_index=marked)


def lock_files(repository):
    return sorted(str(p.relative_to(repository)) for p in Path(repository).rglob("*.lock")
                  if "objects" not in p.parts)


def repo_valid(path):
    path = Path(path)
    if not path.is_dir():
        return False
    result = _git(path, "rev-parse", "--is-bare-repository")
    return result.returncode == 0 and result.stdout.strip() == "true" and \
        all((path / name).exists() for name in ("HEAD", "config", "objects", "refs"))


def ref_format(repository):
    result = _git(repository, "rev-parse", "--show-ref-format")
    return result.stdout.strip() if result.returncode == 0 else "unknown"


# ---- grants store -----------------------------------------------------------
def store_entries(store):
    import hashlib
    entries = []
    for entry in sorted(Path(store).glob("*.json")):
        digest = hashlib.sha256(entry.read_bytes()).hexdigest()
        entries.append(dict(name=entry.name, mode=oct(entry.stat().st_mode & 0o777),
                            digest_matches_name=entry.stem == digest))
    return entries


# ---- processes --------------------------------------------------------------
class TopologyError(OSError):
    """The process table could not be read: it says nothing about any
    process, and in particular proves no stop."""


def parse_proc_stat(text):
    """pid, ppid, pgid, sid, state (one letter, `Z` for a zombie), comm and
    start (clock ticks since boot) of one /proc/<pid>/stat; raises
    TopologyError on a malformed line."""
    try:
        comm = text[text.index("(") + 1:text.rindex(")")]
        fields = text[text.rindex(")") + 2:].split()
        return dict(pid=int(text.split(None, 1)[0]), ppid=int(fields[1]), pgid=int(fields[2]), sid=int(fields[3]),
                    state=fields[0][:1], comm=comm, start=int(fields[19]))
    except (ValueError, IndexError) as error:
        raise TopologyError(f"malformed stat line {text[:80]!r}: {error!r}") from error


KINFO_PROC_SIZE = 648  # struct kinfo_proc on 64-bit macOS (sys/sysctl.h)
KINFO_OFFSETS = dict(p_starttime=0, p_stat=36, p_pid=40, p_comm=243, e_ppid=560, e_pgid=564)  # extern_proc, eproc
SZOMB = 5


def parse_kinfo_procs(buffer, self_pid=None):
    """Rows pid, ppid, pgid, state (`Z` for a zombie), comm and start (the
    start timeval) of a KERN_PROC_ALL buffer (macOS). The layout is checked
    on the buffer itself: its length a multiple of the record size, and the
    record of self_pid (ours, when given) carrying our parent and group at
    the expected offsets; otherwise TopologyError, never a guess."""
    import struct
    if not buffer or len(buffer) % KINFO_PROC_SIZE:
        raise TopologyError(f"kern.proc.all buffer of {len(buffer)} bytes is no multiple of {KINFO_PROC_SIZE}")
    rows = {}
    o = KINFO_OFFSETS
    for start in range(0, len(buffer), KINFO_PROC_SIZE):
        record = buffer[start:start + KINFO_PROC_SIZE]
        pid = struct.unpack_from("<i", record, o["p_pid"])[0]
        stat = record[o["p_stat"]]
        comm = record[o["p_comm"]:o["p_comm"] + 17].split(b"\0", 1)[0].decode("utf-8", "replace")
        ppid, pgid = struct.unpack_from("<ii", record, o["e_ppid"])
        started = struct.unpack_from("<qi", record, o["p_starttime"])
        if pid <= 0:
            continue  # the kernel's own record
        rows[pid] = dict(pid=pid, ppid=ppid, pgid=pgid, sid=None, state="Z" if stat == SZOMB else "S", comm=comm,
                         start=started)
    if not rows:
        raise TopologyError("kern.proc.all listed no process")
    if self_pid is not None:
        own = rows.get(self_pid)
        if own is None or own["ppid"] != os.getppid() or own["pgid"] != os.getpgrp():
            raise TopologyError(f"kern.proc.all layout check failed on our own record: {own}")
    return rows


def kern_proc_all():
    """The raw KERN_PROC_ALL buffer (macOS): one sysctl, a few milliseconds,
    every process alive or zombie with its parent, group, state and
    command."""
    import ctypes
    libc = ctypes.CDLL(None, use_errno=True)
    mib = (ctypes.c_int * 3)(1, 14, 0)  # CTL_KERN, KERN_PROC, KERN_PROC_ALL
    size = ctypes.c_size_t(0)
    if libc.sysctl(mib, 3, None, ctypes.byref(size), None, 0) != 0:
        raise TopologyError(f"sysctl kern.proc.all size: errno {ctypes.get_errno()}")
    capacity = size.value + size.value // 2 + 64 * KINFO_PROC_SIZE
    buffer = ctypes.create_string_buffer(capacity)
    size = ctypes.c_size_t(capacity)
    if libc.sysctl(mib, 3, buffer, ctypes.byref(size), None, 0) != 0:
        raise TopologyError(f"sysctl kern.proc.all: errno {ctypes.get_errno()}")
    return buffer.raw[:size.value]


def list_proc():
    """The entries of /proc (Linux): the listing, as one call so that a
    test can impose an ordering around it."""
    return list(Path("/proc").iterdir())


def topology(pids=None, timeout=30.0):
    """PID, PPID, PGID, SID, state, command and start of the given pids (or
    all): a diagnostic, never a proof. No listing is a snapshot: /proc is a
    readdir then one reading per pid (Linux); KERN_PROC_ALL collects the
    pids, then fills each row later (macOS), where the session is then
    getsid(2), since `ps -o sess` prints 0 on the verified Mac. A process
    that ended between the listing and its reading is a row with sid=None
    and `sid_error` `gone` (or `zombie` when listed as such), never
    dropped; `denied` and `malformed` say why else a session is missing; a
    reader that fails, a malformed line or record, an empty table or the
    deadline `timeout` (seconds) raise TopologyError. What a stop may
    conclude from a table is lab_process's, under its authority."""
    deadline = time.monotonic() + timeout
    rows = {}
    if LINUX:
        try:
            entries = list_proc()
        except OSError as error:
            raise TopologyError(f"/proc unreadable: {error!r}") from error
        for proc in entries:
            if not proc.name.isdigit():
                continue
            pid = int(proc.name)
            if pids and pid not in pids:
                continue
            if time.monotonic() > deadline:
                raise TopologyError("deadline expired while reading /proc")
            try:
                rows[pid] = parse_proc_stat((proc / "stat").read_text())
            except (FileNotFoundError, ProcessLookupError):
                rows[pid] = dict(pid=pid, ppid=None, pgid=None, sid=None, state=None, comm=None, sid_error="gone")
            except TopologyError as error:
                rows[pid] = dict(pid=pid, ppid=None, pgid=None, sid=None, state=None, comm=None,
                                 sid_error="malformed", error=str(error))
            except OSError as error:
                rows[pid] = dict(pid=pid, ppid=None, pgid=None, sid=None, state=None, comm=None,
                                 sid_error="denied", error=repr(error))
    else:
        for pid, row in parse_kinfo_procs(kern_proc_all(), os.getpid()).items():
            if pids and pid not in pids:
                continue
            if row["state"] == "Z":
                row["sid_error"] = "zombie"
            else:
                try:
                    row["sid"] = os.getsid(pid)
                except ProcessLookupError:
                    row["sid_error"] = "gone"
                except PermissionError:
                    row["sid_error"] = "denied"
            rows[pid] = row
        if time.monotonic() > deadline:
            raise TopologyError("deadline expired while reading the sessions")
    if not rows:
        raise TopologyError("no process listed")
    return rows


def descendants(root_pid, rows=None):
    rows = rows or topology()
    found, frontier = [], [root_pid]
    while frontier:
        parent = frontier.pop()
        for row in rows.values():
            if row["ppid"] == parent and row["pid"] not in found:
                found.append(row["pid"])
                frontier.append(row["pid"])
    return [rows[p] for p in found]


def cgroup_procs(path):
    if not LINUX:
        return None
    try:
        return [int(p) for p in Path(path, "cgroup.procs").read_text().split()]
    except OSError:
        return None


# ---- envelopes and secrets --------------------------------------------------
def envelope(text):
    """The agent-cli/v2 envelope of a command's stdout or stderr."""
    try:
        data = json.loads(text)
    except ValueError:
        return dict(ok=None, exitCode=None, error_code=None, parse_error=True)
    error = data.get("error") or {}
    return dict(ok=data.get("ok"), exitCode=data.get("exitCode"), error_code=error.get("code"), data=data.get("data"))


def secret_representations(secret):
    import base64
    import urllib.parse
    return {
        "raw": secret,
        "base64": base64.b64encode(secret.encode()).decode(),
        "urlencoded": urllib.parse.quote(secret, safe=""),
        "json_escaped": json.dumps(secret)[1:-1],
    }


def secret_absent(secret, paths):
    """Which files of the explicit output set contain the secret in any of its
    representations (plan §2.5: the value is searched, never its digest).
    paths is the closed set of outputs to inspect, files or directories; a
    file that cannot be read fails the inspection (OSError propagates), it is
    never skipped (review 2B-03)."""
    hits = []
    reps = secret_representations(secret)
    for base in paths:
        base = Path(base)
        files = [base] if base.is_file() else sorted(p for p in base.rglob("*") if p.is_file())
        if not base.exists():
            raise OSError(f"output to inspect does not exist: {base}")
        for file in files:
            text = file.read_bytes().decode("utf-8", "replace")
            for kind, value in reps.items():
                if value and value in text:
                    hits.append(dict(file=str(file), representation=kind))
    return hits


def wait_until(predicate, timeout_s=10.0, interval_s=0.05):
    """Bounded wait on an observable condition (plan §2.4): the deadline fails
    the caller's test, it never makes it pass."""
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(interval_s)
    return None
