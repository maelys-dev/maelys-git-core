"""Process-tree cleanup for the qualification harness (review 843-02).

A launched agent sits in its own session; its executor is, by design, the
leader of another process group, which Git and the lab hook join. Signalling
the agent's group therefore never covers the executor's. stop_tree() covers
the real scope of a fixture: it collects the whole descendant tree of the
root process by observation (lab_state.topology), signals every distinct
process group found there plus the root's own, reaps the root, then waits,
bounded, until no process of the tree remains, re-signalling what appears
late. It returns a record saying whether the stop is CONFIRMED; a caller
copies state or removes a fixture only after a confirmed stop and keeps an
explicit failure state otherwise. A group id is signalled only while a
process observed in the tree still carries it, never from memory.
"""
import os
import signal
import subprocess
import time

import lab_state as S


def _alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def tree_rows(root_pid):
    rows = S.topology()
    return [rows[root_pid]] + S.descendants(root_pid, rows) if root_pid in rows else S.descendants(root_pid, rows)


def stop_tree(root_proc, timeout_s=10.0, interval_s=0.05, sig=signal.SIGKILL):
    """Stop root_proc (a subprocess.Popen) and every descendant, whatever its
    process group; reap the root; return {'confirmed', 'signalled_groups',
    'remaining', 'elapsed_ms', 'root_returncode'}."""
    t0 = time.time()
    signalled = set()
    deadline = t0 + timeout_s
    remaining = []
    while True:
        rows = tree_rows(root_proc.pid) if root_proc.poll() is None or _alive(root_proc.pid) else S.descendants(root_proc.pid)
        # Descendants of a reaped root are re-parented: keep looking by pgid.
        groups = {row["pgid"] for row in rows} | ({os.getpgid(root_proc.pid)} if _alive(root_proc.pid) else set())
        for pgid in sorted(groups):
            if pgid <= 1 or pgid == os.getpgid(0):
                continue  # never our own group nor init's
            try:
                os.killpg(pgid, sig)
                signalled.add(pgid)
            except ProcessLookupError:
                pass
            except PermissionError:
                pass
        if root_proc.poll() is None:
            try:
                root_proc.wait(timeout=interval_s)
            except subprocess.TimeoutExpired:
                pass
        remaining = [row for row in S.descendants(root_proc.pid)] + ([{"pid": root_proc.pid}] if root_proc.poll() is None else [])
        # Also anything still in a group we signalled: a process re-parented
        # after the root's reap keeps its pgid.
        if not remaining:
            rows_all = S.topology()
            remaining = [row for row in rows_all.values() if row["pgid"] in signalled and row["pid"] != os.getpid()]
        if not remaining:
            break
        if time.time() >= deadline:
            break
        time.sleep(interval_s)
    return dict(confirmed=not remaining, signalled_groups=sorted(signalled), remaining=remaining,
                elapsed_ms=int((time.time() - t0) * 1000), root_returncode=root_proc.returncode)
