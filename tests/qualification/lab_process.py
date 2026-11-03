"""Process-scope cleanup for the qualification harness (review 843-02 and
its follow-up on 570154a).

Scope of a launch. Every agent the harness starts gets its own session
(start_new_session, forced here): the agent is the leader of a session whose
id is its own pid, fixed by the kernel before exec, so the scope of a launch
is known at the launch, before any wait that could reap the agent. The real
executor becomes the leader of another process group (POSIX_SPAWN_SETPGROUP,
src/common/process.c) but stays in that session, as do Git and the lab hook.
A search by session therefore finds an executor re-parented after the
agent's death, which a search by parent pid cannot: that is the
counter-example of 570154a.

Identity. A session id names a session only while a member carries it; a
remembered number reserves nothing. A process is taken as a member of a
launch's scope when it is observed with that session id AND it started no
later than the moment the agent was reaped (a process reusing the number
afterwards would have to start after that moment and call setsid with
exactly that pid). Session ids come from getsid(2) (on this macOS `ps -o
sess` prints 0 for every process); start times from /proc/<pid>/stat on
Linux, compared on CLOCK_BOOTTIME, and from `ps -o lstart` on macOS,
compared on the wall clock at the second: a process reusing the number
within the second of the reap is the residual ambiguity.

Outcome. stop_scope() signals each process group observed in the scope at
the moment of the sweep, repeats until the scope is observed empty or the
bounded deadline (monotonic clock) passes, reaps the launched process and
returns a record whose `confirmed` is true only after that empty
observation with the root reaped. A failing topology reader, a member whose
start time cannot be read or lies after the reap (identity uncertain: never
signalled), a member remaining at the deadline, or a root that cannot be
reaped leave `confirmed` false with the reason, and the caller keeps the
original fixture in place and fails. A descendant that creates its own
session leaves the scope and is not covered: the Linux laboratory proves
confinement by cgroup.
"""
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

import lab_state as S

LINUX = sys.platform.startswith("linux")


def boundary_clock():
    """Seconds on the clock process start times are compared with."""
    if LINUX:
        return time.clock_gettime(time.CLOCK_BOOTTIME)
    return time.time()


def started_at(pid):
    """Start of pid on boundary_clock(), or None when it cannot be read."""
    try:
        if LINUX:
            with open(f"/proc/{pid}/stat") as stat_file:
                stat = stat_file.read()
            fields = stat[stat.rindex(")") + 2:].split()
            return int(fields[19]) / os.sysconf("SC_CLK_TCK")
        out = subprocess.run(["ps", "-o", "lstart=", "-p", str(pid)], capture_output=True, text=True, timeout=10)
        if out.returncode != 0 or not out.stdout.strip():
            return None
        return time.mktime(time.strptime(out.stdout.strip(), "%a %b %d %H:%M:%S %Y"))
    except (OSError, ValueError, IndexError, subprocess.TimeoutExpired):
        return None


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
    launch: the session id is the pid. Waiting goes through this object so
    that the moment of the reap is recorded on boundary_clock()."""

    def __init__(self, args, **popen):
        popen["start_new_session"] = True
        self.process = subprocess.Popen(args, **popen)
        self.pid = self.process.pid
        self.sid = self.pid
        self.launched_at = boundary_clock()
        self.reaped_at = None
        try:
            self.sid_observed = os.getsid(self.pid)
        except ProcessLookupError:
            self.sid_observed = None  # already exited: the scope holds by construction
        if self.sid_observed not in (None, self.sid):
            raise RuntimeError(f"launch {self.pid}: session {self.sid_observed} observed, {self.sid} expected")

    @property
    def returncode(self):
        return self.process.returncode

    def _reaped(self):
        if self.process.returncode is not None and self.reaped_at is None:
            self.reaped_at = boundary_clock()

    def poll(self):
        code = self.process.poll()
        self._reaped()
        return code

    def wait(self, timeout=None):
        try:
            return self.process.wait(timeout=timeout)
        finally:
            self._reaped()

    def communicate(self, input=None, timeout=None):
        try:
            return self.process.communicate(input=input, timeout=timeout)
        finally:
            self._reaped()

    def record(self):
        return dict(pid=self.pid, sid=self.sid, sid_observed=self.sid_observed, launched_at=self.launched_at,
                    reaped_at=self.reaped_at, returncode=self.returncode)


def members(sid, boundary, rows=None):
    """Observed members of a session: (targets, uncertain, unreadable).
    targets started no later than boundary; uncertain are observed in the
    session but their identity is not established (start time unreadable or
    after the boundary); unreadable are rows whose session could not be read
    (`denied`): nothing can be concluded about them."""
    rows = S.topology() if rows is None else rows
    targets, uncertain, unreadable = [], [], []
    for row in rows.values():
        if row["pid"] == os.getpid():
            continue
        if row.get("sid") is None:
            if row.get("sid_error") == "denied":
                unreadable.append(row)
            continue  # gone between the two readings
        if row["sid"] != sid:
            continue
        started = started_at(row["pid"])
        if started is None:
            if _alive(row["pid"]):
                uncertain.append(dict(row, started=None, reason="start time unreadable"))
        elif started > boundary:
            uncertain.append(dict(row, started=started, reason="started after the reap"))
        else:
            targets.append(dict(row, started=started))
    return targets, uncertain, unreadable


def stop_scope(launch, timeout_s=10.0, interval_s=0.05, sig=signal.SIGKILL):
    """Stop every process of the launch's scope, reap the launched process,
    and return {'confirmed', 'sid', 'signalled_groups', 'sweeps', 'remaining',
    'uncertain', 'unreadable', 'errors', 'elapsed_ms', 'launch'}."""
    t0 = time.monotonic()
    deadline = t0 + timeout_s
    signalled, errors, sweeps = set(), [], 0
    targets, uncertain, unreadable = [], [], []
    own_group = os.getpgid(0)
    confirmed = False
    while True:
        launch.poll()
        boundary = launch.reaped_at if launch.reaped_at is not None else boundary_clock()
        try:
            targets, uncertain, unreadable = members(launch.sid, boundary)
        except S.TopologyError as error:
            errors.append(f"topology unreadable: {error!r}")
            break
        sweeps += 1
        if not targets and not uncertain and not unreadable:
            confirmed = True
            break
        for pgid in sorted({row["pgid"] for row in targets}):
            if pgid <= 1 or pgid == own_group:
                errors.append(f"group {pgid} refused: never init's nor our own")
                continue
            try:
                os.killpg(pgid, sig)
                signalled.add(pgid)
            except ProcessLookupError:
                pass
            except PermissionError as error:
                errors.append(f"group {pgid}: {error!r}")
        if time.monotonic() >= deadline:
            break
        if launch.returncode is None:
            try:
                launch.wait(timeout=interval_s)
            except subprocess.TimeoutExpired:
                pass
        else:
            time.sleep(interval_s)
    if launch.returncode is None:
        try:
            launch.wait(timeout=max(interval_s, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            errors.append(f"launch {launch.pid} not reaped")
            confirmed = False
    return dict(confirmed=confirmed, sid=launch.sid, signalled_groups=sorted(signalled), sweeps=sweeps,
                remaining=targets, uncertain=uncertain, unreadable=unreadable, errors=errors,
                elapsed_ms=int((time.monotonic() - t0) * 1000), launch=launch.record())


def stop_all(launches, **options):
    """Stop every launch, in order, whatever the outcome of the previous
    one; a scope already empty confirms at once."""
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
