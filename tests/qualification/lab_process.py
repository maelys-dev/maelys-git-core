"""Process-scope cleanup for the qualification harness (review 843-02, its
follow-up on 570154a and review B8 of b8bdb60).

Scope of a launch. Every agent the harness starts gets its own session
(start_new_session, forced here): the agent is the leader of a session whose
id is its own pid, fixed by the kernel before exec, so the scope of a launch
is known at the launch, before any wait. The real executor becomes the
leader of another process group (POSIX_SPAWN_SETPGROUP, src/common/process.c)
but stays in that session, as do Git and the lab hook, and so does anything
they start after the agent's death. A search by session therefore finds an
executor re-parented after the agent's exit, which a search by parent pid
cannot: that is the counter-example of 570154a.

Authority (B8-01). A session is joined by inheritance only, and its id is a
pid that the kernel does not reuse while the leader exists, a zombie
included. The harness therefore keeps its authority over the scope by not
reaping the agent before the sweep: Launch.finish() reads the outputs and
the exit status without reaping (waitid WNOWAIT), and stop_scope() reaps
the agent only after it has observed the session empty of any other member.
While that holds, every process observed with the session id is a
descendant, whatever its start time; once the agent has been reaped the
number may be reused and the authority is lost: stop_scope() then refuses
to signal anything, answers unconfirmed with that reason, and the caller
keeps the fixture in place. No start time is compared, no number is
signalled from memory.

Targets (03-02). A signal is sent only to a process whose identity can be
held until the signal: the agent, our own unreaped child, on every
platform; a descendant only through a pidfd (Linux), which names the
process and not its number. Without a pidfd (macOS), a descendant is
never signalled: its number could change hands between a check and a
kill. The cleanup then only waits, bounded, for the scope to drain by the
descendants' own ends (the product gives no guarantee here: the life
descriptor between agent and executor is read by the agent, a dead agent
escalates nothing); a descendant still there at the deadline leaves the
stop unconfirmed with that reason. PINNABLE_DESCENDANTS says which case
this host is in.

Observation (03-01, C0-01). A process table is read in two phases, a
listing then one reading per pid, so it is not a snapshot. Two rules make
an empty observation conclusive. The agent's exit status is read BEFORE
each table (waitid WNOWAIT) and an empty scope is concluded only from a
table read after the agent was seen exited, so the agent itself forks
nothing after the listing. And a table in which any listed process
disappeared before its reading is indeterminate: that process may have
been a member that forked after the listing, and its child, born after
the listing, is in no row. Every member alive at the listing is then in
the table, seen or gone; a member born later descends from one that was,
seen or gone; so a table with no member and no disappearance, read after
the agent's exit, proves the scope empty, provided the listing is one
snapshot (sysctl on macOS; readdir on Linux, complete while pids do not
wrap). A zombie listed as such had exited before the listing and creates
nothing: it is neither; and a disappeared process whose group leader is
read in another session was not a member, a group never spanning
sessions. An indeterminate table is read again under the same deadline.

Outcome. stop_scope() works under one monotonic deadline handed to every
reading and checked after each reading, before each signal and after the
reap; it signals the targets it may, re-observes until the scope is
empty, reaps the agent, and answers `confirmed` only when that empty
observation and the reap both happened before the deadline. A reader that
fails or that reports a row it could not read, a lost authority, a member
remaining at the deadline or an agent that cannot be reaped leave
`confirmed` false with the reason, and the caller keeps the original
fixture and fails. A descendant that creates its own session leaves the
scope and is not covered: the Linux laboratory proves confinement by
cgroup.
"""
import json
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

import lab_state as S

LINUX = sys.platform.startswith("linux")
# Whether a descendant's identity can be held until the signal (a pidfd):
# without it, descendants are observed and waited for, never signalled.
PINNABLE_DESCENDANTS = LINUX and hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal")


def _alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


class Launch:
    """One process started in its own session, with its scope fixed at the
    launch: the session id is the pid. The outputs and the exit status are
    read without reaping (finish); the reap is explicit (reap), done by
    stop_scope() after the sweep, because the reap ends the authority."""

    def __init__(self, args, **popen):
        popen["start_new_session"] = True
        self.process = subprocess.Popen(args, **popen)
        self.pid = self.process.pid
        self.sid = self.pid
        self.launched_at = time.monotonic()
        self.exit = None        # (code, signal) once exited, read without reaping
        self.reaped_at = None
        self.stop = None        # the record of the stop, once done
        self.output = {}
        self._readers = []
        for name in ("stdout", "stderr"):
            stream = getattr(self.process, name)
            if stream is not None:
                reader = threading.Thread(target=self._read, args=(name, stream), daemon=True)
                reader.start()
                self._readers.append(reader)

    def _read(self, name, stream):
        try:
            self.output[name] = stream.read()
        except (OSError, ValueError):
            self.output[name] = None

    @property
    def reaped(self):
        return self.process.returncode is not None

    def exited(self):
        """Whether the process has exited, read without reaping it."""
        if self.exit is None and not self.reaped:
            info = os.waitid(os.P_PID, self.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            if info is not None:
                if info.si_code == os.CLD_EXITED:
                    self.exit = (info.si_status, None)
                else:
                    self.exit = (None, info.si_status)
        return self.exit is not None or self.reaped

    @property
    def returncode(self):
        if self.reaped:
            return self.process.returncode
        if self.exit is None:
            return None
        code, sig = self.exit
        return code if sig is None else -sig

    def finish(self, timeout):
        """Read the outputs to EOF and wait for the exit, bounded, without
        reaping; returns (stdout, stderr). Raises subprocess.TimeoutExpired
        when the process, or a survivor holding its outputs, outlasts it."""
        deadline = time.monotonic() + timeout
        for reader in self._readers:
            reader.join(max(0.0, deadline - time.monotonic()))
        while not self.exited():
            if time.monotonic() >= deadline:
                raise subprocess.TimeoutExpired(self.process.args, timeout)
            time.sleep(0.02)
        if any(reader.is_alive() for reader in self._readers):
            raise subprocess.TimeoutExpired(self.process.args, timeout)
        return self.output.get("stdout"), self.output.get("stderr")

    def reap(self, timeout=None):
        """Wait for and reap the process: the end of the authority."""
        try:
            return self.process.wait(timeout=timeout)
        finally:
            if self.reaped and self.reaped_at is None:
                self.reaped_at = time.monotonic()

    def record(self):
        return dict(pid=self.pid, sid=self.sid, exited=self.exit is not None, reaped=self.reaped,
                    returncode=self.returncode, launched_at=self.launched_at, reaped_at=self.reaped_at)


def session_of(pid):
    """The session id of pid read now, or None when it cannot be read."""
    try:
        if LINUX:
            with open(f"/proc/{pid}/stat") as stat_file:
                return S.parse_proc_stat(stat_file.read())["sid"]
        return os.getsid(pid)
    except (OSError, S.TopologyError):
        return None


def signal_member(pid, sid, sig, launch):
    """Signal pid if its identity can be held until the signal and it still
    carries the session sid: True when signalled, False when it no longer
    names a member (gone, or the number reused outside the session), None
    when refused because the identity cannot be held. The agent (launch) is
    our unreaped child: its number is pinned, kill(2) is exact. A descendant
    is signalled through a pidfd only, which names the process and not its
    number; the check of its session then names the same process or a
    later one whose session cannot be sid while the leader is held."""
    if pid == launch.pid:
        if launch.reaped:
            return None
        try:
            os.kill(pid, sig)
            return True
        except ProcessLookupError:
            return False
    if not PINNABLE_DESCENDANTS:
        return None
    try:
        fd = os.pidfd_open(pid)
    except OSError:
        return False
    try:
        if session_of(pid) != sid:
            return False
        signal.pidfd_send_signal(fd, sig)
        return True
    except ProcessLookupError:
        return False
    finally:
        os.close(fd)


def members(launch, rows, leader_exited):
    """The members of the launch's session in an observed table, the rows
    whose session could not be read, and the processes that disappeared
    between the listing and their reading: (members, unreadable, gone).
    leader_exited is the agent's status read BEFORE the table (03-01): an
    agent seen exited before the reading is left to the reap, an agent
    alive at that moment stays a member even if the table shows it gone.
    A disappearance other than the agent's makes the table indeterminate
    (C0-01) unless the process provably was not in the session: a process
    group never spans sessions, so a disappeared process whose group leader
    is read with another session was in that other session (the reader's
    own `ps`, or any busy unrelated process); one in the agent's group, one
    whose group leader is a member, gone, a zombie or absent, stays a
    disappearance the caller never concludes an empty scope from. A zombie
    had exited before the listing: it creates nothing, it is neither a
    member nor a disappearance (an unrelated zombie may live for ever)."""
    found, unreadable, gone = [], [], []
    seen_leader = False

    def possibly_member(row):
        if row.get("pgid") in (None, launch.sid):
            return True
        leader = rows.get(row["pgid"])
        if leader is None or leader.get("sid") is None:
            return True  # group leader unknown: the group's session is unknown
        return leader["sid"] == launch.sid

    for row in rows.values():
        if row["pid"] == launch.pid:
            seen_leader = True
            if leader_exited:
                continue
            found.append(row)
            continue
        if row["pid"] == os.getpid():
            continue
        if row.get("state") == "Z" or row.get("sid_error") == "zombie":
            continue
        if row.get("sid") is None:
            if row.get("sid_error") == "gone":
                if possibly_member(row):
                    gone.append(row)
            else:
                unreadable.append(row)
            continue
        if row["sid"] != launch.sid:
            continue
        found.append(row)
    if not leader_exited and not seen_leader:
        # Alive before the reading, absent from it: the table is not a
        # proof of anything about its children; keep it a member.
        found.append(dict(pid=launch.pid, ppid=None, pgid=None, sid=launch.sid, comm=None, sid_error="gone"))
    return found, unreadable, gone


def stop_scope(launch, timeout_s=10.0, interval_s=0.05, sig=signal.SIGKILL):
    """Stop every process of the launch's scope under one deadline, reap the
    launched process, and return {'confirmed', 'sid', 'signalled',
    'refused', 'sweeps', 'indeterminate', 'remaining', 'unreadable', 'gone',
    'errors', 'elapsed_ms', 'launch'}. A stop already confirmed is returned
    as it was: the scope is final."""
    if launch.stop is not None and launch.stop["confirmed"]:
        return launch.stop
    t0 = time.monotonic()
    deadline = t0 + timeout_s
    signalled, refused, errors, sweeps, indeterminate = [], [], [], 0, 0
    remaining, unreadable, gone = [], [], []
    confirmed = False

    def expired(stage):
        if time.monotonic() > deadline:
            errors.append(f"deadline expired {stage}")
            return True
        return False

    if launch.reaped:
        errors.append(f"authority lost: launch {launch.pid} was reaped before the sweep, its session id may be reused")
    else:
        while True:
            if expired("before a reading"):
                break
            leader_exited = launch.exited()  # before the table (03-01)
            try:
                rows = S.topology(timeout=deadline - time.monotonic())
            except S.TopologyError as error:
                errors.append(f"topology unreadable: {error}")
                break
            sweeps += 1
            remaining, unreadable, gone = members(launch, rows, leader_exited)
            if unreadable:
                errors.append(f"{len(unreadable)} row(s) unreadable: no conclusion about them")
                break
            if expired("after a reading"):
                break
            if gone:
                indeterminate += 1  # a listed process vanished before its reading: read again
            elif not remaining:
                confirmed = True
                break
            for row in remaining:
                if expired("before a signal"):
                    break
                try:
                    sent = signal_member(row["pid"], launch.sid, sig, launch)
                except PermissionError as error:
                    errors.append(f"pid {row['pid']}: {error!r}")
                    continue
                if sent:
                    signalled.append(row["pid"])
                elif sent is None and row["pid"] not in refused:
                    refused.append(row["pid"])
            else:
                time.sleep(max(0.0, min(interval_s, deadline - time.monotonic())))
                continue
            break
        if confirmed:
            try:
                launch.reap(timeout=max(0.0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                errors.append(f"launch {launch.pid} not reaped before the deadline")
                confirmed = False
            if confirmed and expired("after the reap"):
                confirmed = False
    if refused and not confirmed:
        errors.append(f"{len(refused)} descendant(s) not signalled: identity cannot be held until the signal "
                      "on this host (no pidfd); waited for the scope to drain")
    if gone and not confirmed:
        errors.append(f"last table indeterminate: {len(gone)} listed process(es) disappeared before their reading")
    outcome = dict(confirmed=confirmed, sid=launch.sid, signalled=sorted(set(signalled)), refused=sorted(refused),
                   sweeps=sweeps, indeterminate=indeterminate, remaining=remaining, unreadable=unreadable,
                   gone=gone, errors=errors, elapsed_ms=int((time.monotonic() - t0) * 1000),
                   launch=launch.record())
    launch.stop = outcome
    return outcome


def stop_all(launches, **options):
    """Stop every launch, in order, whatever the outcome of the previous
    one; a launch whose stop is already confirmed keeps that record."""
    return [stop_scope(launch, **options) for launch in launches]


def preserve_fixture(root, evidence, stop_confirmed, failed, names, cleanups=()):
    """What becomes of the fixture directory after the stops. With every stop
    confirmed and the scenario failed, `names` of root are copied into
    evidence/failure as a coherent state; with a stop not confirmed, nothing
    is copied (writers may remain, no copy is presented as coherent) and
    root is to be kept in place, recorded in evidence/fixture-kept.json.
    Returns {'kept': root or None, 'copied': the copy or None}; removing
    root, when it is not kept, is the caller's."""
    root, evidence = Path(root), Path(evidence)
    if not stop_confirmed:
        (evidence / "fixture-kept.json").write_text(json.dumps(dict(
            path=str(root), reason="stop of a launch not confirmed", cleanups=list(cleanups)), indent=2, default=str))
        return dict(kept=root, copied=None)
    if not failed:
        return dict(kept=None, copied=None)
    keep = evidence / "failure"
    keep.mkdir(exist_ok=True)
    for name in names:
        source = root / name
        if source.is_dir():
            shutil.copytree(source, keep / name, dirs_exist_ok=True)
        elif source.is_file():
            shutil.copy2(source, keep / name)
    return dict(kept=None, copied=keep)
