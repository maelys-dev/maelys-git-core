"""Process-scope cleanup for the qualification harness (review 843-02 and
the reviews of 570154a, b8bdb60, 03b12b6, c0e5e1f, d310295, 49b7115).

Scope of a launch. Every agent the harness starts gets its own session
(start_new_session, forced here): the agent is the leader of a session whose
id is its own pid, fixed by the kernel before exec, so the scope of a launch
is known at the launch, before any wait. The real executor becomes the
leader of another process group (POSIX_SPAWN_SETPGROUP, src/common/process.c)
but stays in that session, as do Git and the lab hook, and so does anything
they start after the agent's death.

Observation and proof are kept apart. A process table (lab_state.topology)
is a diagnostic: no listing is a snapshot, a descendant may fork and
vanish between the listing and its reading, so an empty observation
(`observed_empty`) never authorizes the removal of a fixture nor a copy
presented as coherent. `swept` says that the sweep of a launch ended
under the authority available, with the agent reaped in time: it rests
on the tables read, so it is not the proof that nothing of the launch
remains (a living descendant omitted by a table is not seen by it). The
proof is scope_closed(), read from the kernel immediately before the
decision, and it rests on a kernel authority only:

- the agent is our child, held unreaped (waitid WNOWAIT reads its exit
  status) until the sweep is over: its pid, hence its session id, is not
  reused meanwhile, and a session is joined by inheritance only;
- on Linux, this process claims PR_SET_CHILD_SUBREAPER (claim_authority):
  every orphaned descendant of a launch, at any depth, with or without a
  session of its own, is re-parented to us the moment its parent dies,
  so a living descendant always has a living ancestor that is our child,
  and our children are pinned until we reap them. The sweep of a launch
  ends when the agent has exited, no process of its session is observed
  alive, no child of ours is a zombie still to reap (its orphans may have
  just been adopted), and no child of ours is unattributed (a descendant
  that made its own session: not a member by session, still ours); the
  whole scope of every launch is proven closed when waitid(P_ALL) reports
  no child at all (no_children), which is what the scenario requires
  before it removes anything. On Linux the authority is required
  (EXPECTED_AUTHORITY): a refused claim fails the qualification with its
  errno, it never falls back to observation;
- on macOS there is no such authority: the cleanup signals the agent,
  waits, bounded, for the descendants it may not signal, reports what it
  observed, and the fixture is kept.

Targets. A signal is sent only to an identity held until the signal: our
own unreaped children (the agent, and on Linux the adopted orphans) by
kill(2), whose numbers are pinned; another descendant through a pidfd
only (Linux), which names the process and not its number; otherwise the
request is refused and the descendant is waited for. PINNABLE_DESCENDANTS
says whether a pidfd is available. A member reaped by us before the sweep
is a lost authority: nothing is signalled, the stop is unswept.

Outcome. stop_scope() works under one monotonic deadline handed to every
reading and checked after each reading, before each signal and after the
reap; it answers `swept` only under the authority above, before the
deadline, with the agent reaped before the deadline; every other end
leaves it false with the reason.
"""
import ctypes
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
# Whether a descendant that is not our child can be signalled through a
# pidfd; without it such a descendant is observed and waited for.
PINNABLE_DESCENDANTS = LINUX and hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal")
# The authority a proof rests on, once claimed: "subreaper" (Linux) or
# None (observation only, nothing removed); the one this host must
# provide for a run to qualify.
AUTHORITY = None
EXPECTED_AUTHORITY = "subreaper" if LINUX else None
PR_SET_CHILD_SUBREAPER = 36


def claim_authority():
    """Make this process the subreaper of its descendants (Linux,
    prctl(2) PR_SET_CHILD_SUBREAPER, no privilege): every orphaned
    descendant of a launch is re-parented to it, pinned until it reaps
    it, and waitid(P_ALL) proves when none remains. To be called before
    any launch. Returns the authority name, or None where the host has
    none (macOS); raises OSError, with the errno, where the host has one
    and refuses it (Linux): the caller fails the qualification then, it
    never falls back to observation."""
    global AUTHORITY
    if not LINUX:
        return None
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0:
        errno = ctypes.get_errno()
        raise OSError(errno, f"prctl(PR_SET_CHILD_SUBREAPER) refused: {os.strerror(errno)}")
    AUTHORITY = "subreaper"
    return AUTHORITY


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


def is_our_child(pid):
    """Whether pid is a child of ours not yet reaped (running or a zombie):
    waitid(P_PID, WNOWAIT) answers without reaping, and refuses any other
    pid. Such a pid is pinned until we reap it."""
    try:
        os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        return True
    except ChildProcessError:
        return False


def no_children():
    """Whether this process has no child at all, zombies included:
    waitid(P_ALL, WNOHANG | WNOWAIT) refusing with ECHILD. Under the
    subreaper authority, no child means no living descendant of any
    launch: that is the proof the scenario requires before removing a
    fixture."""
    try:
        os.waitid(os.P_ALL, 0, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        return False
    except ChildProcessError:
        return True


def signal_member(pid, sid, sig, launch):
    """Signal pid if its identity can be held until the signal and it still
    carries the session sid: True when signalled, False when it no longer
    names a member (gone, or the number reused outside the session), None
    when refused because the identity cannot be held. A child of ours, the
    agent (launch) or an adopted orphan, is pinned: kill(2) is exact. Any
    other descendant is signalled through a pidfd only, which names the
    process and not its number; the check of its session then names the
    same process or a later one whose session cannot be sid while the
    leader is held."""
    if pid == launch.pid:
        if launch.reaped:
            return None
        try:
            os.kill(pid, sig)
            return True
        except ProcessLookupError:
            return False
    if is_our_child(pid):
        try:
            if session_of(pid) != sid:
                return False
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


def classify(launch, rows, leader_exited, held=()):
    """Classify an observed table for the launch: a dict of lists
    `members` (alive, in the launch's session: targets), `unreadable`
    (rows whose session could not be read for another reason than their
    end: nothing can be concluded about them), `ours_exited` (children of
    ours, launch excluded, exited and not yet reaped: their orphans may
    have just been adopted by us, the table may not show them yet),
    `unattributed` (children of ours in no session of a held launch nor
    ours: a descendant that made its own session, which the session-based
    scope cannot attribute). A held launch (`held`: the pids, hence the
    session ids, of the other launches the caller still holds) is never a
    member here nor reaped here. leader_exited is the agent's status read
    BEFORE the table (03-01): an agent alive at that moment stays a member
    whatever the table says."""
    me, my_sid = os.getpid(), os.getsid(0)
    known = set(held) | {launch.sid, my_sid}
    out = dict(members=[], unreadable=[], ours_exited=[], unattributed=[])
    seen_leader = False
    for row in rows.values():
        pid = row["pid"]
        if pid == me or pid in held:
            continue  # a held launch is another scope's agent: neither a member here nor ours to reap
        if pid == launch.pid:
            seen_leader = True
            if not leader_exited:
                out["members"].append(row)
            continue
        ours = row.get("ppid") == me or (row.get("sid") is None and is_our_child(pid))
        exited = row.get("state") == "Z" or row.get("sid_error") in ("gone", "zombie")
        if ours and exited:
            out["ours_exited"].append(row)
            continue
        if row.get("sid") is None:
            if row.get("sid_error") not in ("gone", "zombie"):
                out["unreadable"].append(row)
            continue  # ended between the listing and its reading: a diagnostic, no member to signal
        if row["sid"] == launch.sid:
            out["members"].append(row)
        elif ours and row["sid"] not in known:
            out["unattributed"].append(row)
    if not leader_exited and not seen_leader:
        out["members"].append(dict(pid=launch.pid, ppid=None, pgid=None, sid=launch.sid, comm=None,
                                   sid_error="gone"))
    return out


def stop_scope(launch, held=(), timeout_s=10.0, interval_s=0.05, sig=signal.SIGKILL):
    """Stop every process of the launch's scope under one deadline, reap the
    launched process and the orphans adopted meanwhile, and return
    {'swept', 'observed_empty', 'authority', 'sid', 'signalled',
    'refused', 'reaped_adopted', 'sweeps', 'remaining', 'unattributed',
    'unreadable', 'errors', 'elapsed_ms', 'launch'}. `held` names the
    session ids (pids) of the other launches the caller still holds, to
    which adopted orphans are attributed. `swept` only under the
    authority described in the module (Linux subreaper), and it is the
    end of the sweep, not the proof that nothing remains (scope_closed);
    elsewhere the sweep stops after two consecutive empty observations
    following the agent's exit, a diagnostic, and reaps the agent. A
    launch already swept has its agent reaped: no later sweep holds the
    authority, its record is returned as it stands."""
    if launch.stop is not None and launch.stop["swept"]:
        return launch.stop
    t0 = time.monotonic()
    deadline = t0 + timeout_s
    signalled, refused, reaped_adopted, errors, sweeps = [], [], [], [], 0
    seen = dict(members=[], unreadable=[], ours_exited=[], unattributed=[])
    swept, observed_empty, empties = False, False, 0

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
            seen = classify(launch, rows, leader_exited, held)
            if seen["unreadable"]:
                errors.append(f"{len(seen['unreadable'])} row(s) unreadable: no conclusion about them")
                break
            if expired("after a reading"):
                break
            for row in seen["ours_exited"]:
                try:  # an adopted orphan, or any child of ours, that has exited: reap it, its own orphans are ours now
                    if os.waitpid(row["pid"], os.WNOHANG)[0] == row["pid"]:
                        reaped_adopted.append(row["pid"])
                except ChildProcessError:
                    pass
            empties = empties + 1 if not seen["members"] else 0
            if not seen["members"]:
                if AUTHORITY is None:
                    # Observed, never proven on this host: two consecutive
                    # empty tables after the agent's exit end the sweep (a
                    # descendant forked just before the first listing is in
                    # the second), as a diagnostic, not a guarantee.
                    if leader_exited and empties >= 2:
                        observed_empty = True
                        break
                elif leader_exited and not seen["ours_exited"] and not seen["unattributed"]:
                    observed_empty = swept = True
                    break
            for row in seen["members"]:
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
        if observed_empty or swept:
            try:
                launch.reap(timeout=max(0.0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                errors.append(f"launch {launch.pid} not reaped before the deadline")
                swept = False
            if swept and expired("after the reap"):
                swept = False
    if refused and not swept:
        errors.append(f"{len(refused)} descendant(s) not signalled: identity cannot be held until the signal "
                      "on this host (no pidfd, not adopted); waited for the scope to drain")
    if AUTHORITY is None and observed_empty:
        errors.append("no authority on this host: the scope was observed empty, not proven closed")
    elif seen["unattributed"] and not swept:
        errors.append(f"{len(seen['unattributed'])} child(ren) of ours in a session of no held launch")
    outcome = dict(swept=swept, observed_empty=observed_empty, authority=AUTHORITY, sid=launch.sid,
                   signalled=sorted(set(signalled)), refused=sorted(refused), reaped_adopted=sorted(reaped_adopted),
                   sweeps=sweeps, remaining=seen["members"], unattributed=seen["unattributed"],
                   unreadable=seen["unreadable"], errors=errors, elapsed_ms=int((time.monotonic() - t0) * 1000),
                   launch=launch.record())
    launch.stop = outcome
    return outcome


def stop_all(launches, **options):
    """Stop every launch, in order, the others held; a launch whose stop is
    already swept keeps that record."""
    sids = [launch.sid for launch in launches]
    return [stop_scope(launch, held=[sid for sid in sids if sid != launch.sid], **options) for launch in launches]


def scope_closed(outcomes):
    """The proof the scenario needs before removing a fixture, read from
    the kernel now, immediately before the decision: every sweep ended
    under the authority, and no child of ours left at all."""
    return bool(outcomes) and all(o["swept"] for o in outcomes) and AUTHORITY is not None and no_children()


def preserve_fixture(fixture, evidence, closed, failed, cleanups=()):
    """What becomes of the fixture directory, which lives in the evidence
    directory: removed only when the scope is proven closed and the
    scenario succeeded; kept otherwise, with evidence/fixture-kept.json
    saying why (a failed scenario keeps its state as it is; an unproven
    scope keeps it because a writer may remain: no copy is presented as
    coherent). Returns {'kept': path or None, 'reason'}."""
    fixture, evidence = Path(fixture), Path(evidence)
    if closed and not failed:
        shutil.rmtree(fixture, ignore_errors=True)
        return dict(kept=None, reason=None)
    reason = "scenario failed" if failed else ("no authority on this host" if AUTHORITY is None else
                                               "scope not proven closed")
    (evidence / "fixture-kept.json").write_text(json.dumps(dict(
        path=str(fixture), reason=reason, authority=AUTHORITY, cleanups=list(cleanups)), indent=2, default=str))
    return dict(kept=fixture, reason=reason)
