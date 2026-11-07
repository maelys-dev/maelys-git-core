"""GIT-C10 qualification harness, fault scenario (plan §4, 2c).

Every point of B of the laboratory (plan §2.3) reached by the real
maelys-git-agent-lab and maelys-git-executor-lab, each fault applied once,
the markers it writes read, and the state it leaves asserted: a kill at a
point leaves the journal where the plan says, a synthetic or VFS fault
takes the product's error path with its code, a pause holds the agent
until the resume file, each alteration of the executor's result is
treated by the agent as the plan expects at B. The http trace and the
VFS survey of the operations of each phase are written to vfs-survey.json
and http-trace.json: the initial survey the plan moved from 2b to 2c.

    scenario_faults.py AGENT_LAB EXECUTOR_LAB MAELYS_GIT OPENSSL FAULT_FILE [EVIDENCE_ROOT]

FAULT_FILE is the path the executor-lab was configured with
(MG_LAB_FAULT_FILE); the markers (markers.jsonl) and the resume files
(resume.<point>) live beside it. The agent-lab reads its faults from
MG_QUAL_FAULT in its environment. Each run writes into a fresh directory
EVIDENCE_ROOT/<utc timestamp>-<pid>/: provenance.json, assertions.jsonl,
one directory per case under cases/ (the agent's outputs and the markers
of the case), vfs-survey.json, http-trace.json, cleanups.json,
summary.json; the fixture is removed only on a proven closed scope and a
successful scenario (lab_process). Exit 0 when every assertion holds, 1
otherwise.
"""
import hashlib
import json
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lab_fixture  # noqa: E402
import lab_process  # noqa: E402
import lab_state as S  # noqa: E402
from lab_cloud_server import LabCloudServer, command  # noqa: E402
from lab_fixture import ENV, GIT, git  # noqa: E402

AGENT, EXECUTOR, MAELYS_GIT, OPENSSL = map(lambda arg: str(Path(arg).resolve()), sys.argv[1:5])
FAULT_FILE = Path(sys.argv[5]).resolve()
ROOT_DIR = Path(sys.argv[6]).resolve() if len(sys.argv) > 6 else Path(tempfile.mkdtemp(prefix="gitc10-faults-"))
EVIDENCE = ROOT_DIR / (time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + f"-{os.getpid()}")
EVIDENCE.mkdir(parents=True, exist_ok=False)
(EVIDENCE / "cases").mkdir()
try:  # before any launch: the subreaper adopts every orphan
    AUTHORITY, AUTHORITY_ERROR = lab_process.claim_authority(), None
except OSError as error:
    AUTHORITY, AUTHORITY_ERROR = None, error
PRODUCT = Path(__file__).resolve().parents[2]
LAB_DIR = FAULT_FILE.parent
MARKERS = LAB_DIR / "markers.jsonl"
REQUEST_TIMEOUT_MS = 5000
SIGKILLED = -signal.SIGKILL


def sha256_file(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def provenance():
    """What this run ran on: the product revision, the tree of the
    worktree content in the scopes (untracked files included) and the
    digest of the patch; the digests of the binaries used."""
    patch = subprocess.run([GIT, "-C", str(PRODUCT), "diff", "HEAD", "--", *lab_fixture.SCOPES],
                           capture_output=True, text=True).stdout
    return dict(**lab_fixture.worktree_identity(PRODUCT),
                patch_sha256=hashlib.sha256(patch.encode()).hexdigest() if patch else None,
                binaries={Path(p).name: sha256_file(p) for p in (AGENT, EXECUTOR, MAELYS_GIT)},
                binary_class="B-lab", fault_file=str(FAULT_FILE), platform=sys.platform, python=sys.version.split()[0],
                git_version=git("--version").stdout.strip())


A = S.Assertions(EVIDENCE / "assertions.jsonl")
(EVIDENCE / "provenance.json").write_text(json.dumps(provenance(), indent=2))
A.check("authority.claimed", lab_process.EXPECTED_AUTHORITY,
        AUTHORITY if AUTHORITY_ERROR is None else repr(AUTHORITY_ERROR))
QUALIFIED = AUTHORITY == lab_process.EXPECTED_AUTHORITY
outputs = []
failed_exception = None
server = None
launches = []
cleanups = []
agent_runs = 0


# ---- the laboratory's files ---------------------------------------------------
def write_fault(*lines):
    """The executor's faults, one per line, mode 0600 of this account."""
    FAULT_FILE.write_text("".join(line + "\n" for line in lines))
    FAULT_FILE.chmod(0o600)


def clear_fault():
    if FAULT_FILE.exists():
        FAULT_FILE.unlink()


def clear_resumes():
    for path in LAB_DIR.glob("resume.*"):
        path.unlink()


def marker_offset():
    return MARKERS.stat().st_size if MARKERS.exists() else 0


def markers_since(offset):
    """The marker lines appended since OFFSET, parsed; a line that does not
    parse is kept as {'unparsed': line} so that nothing is silently lost."""
    if not MARKERS.exists():
        return []
    with MARKERS.open("rb") as stream:
        stream.seek(offset)
        data = stream.read()
    rows = []
    for line in data.decode("utf-8", "replace").splitlines():
        if not line.strip():
            continue
        try:
            rows.append(json.loads(line))
        except ValueError:
            rows.append(dict(unparsed=line))
    return rows


def events(rows, **where):
    return [row for row in rows if all(row.get(key) == value for key, value in where.items())]


def reached(rows, point, **where):
    return events(rows, event="reached", point=point, **where)


# ---- launches -------------------------------------------------------------------
def start_agent(config_path, spec=None):
    """Every launch of the agent: its own session (lab_process), the faults
    of the agent in MG_QUAL_FAULT when given."""
    env = dict(ENV)
    if spec:
        env["MG_QUAL_FAULT"] = spec
    launch = lab_process.Launch([AGENT, "run", "--config", str(config_path), "--once", "--format", "json",
                                 "--non-interactive"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                env=env)
    launches.append(launch)
    return launch


class Run:
    def __init__(self, launch, out, err, timed_out, markers):
        self.launch, self.out, self.err, self.timed_out, self.markers = launch, out, err, timed_out, markers
        self.returncode = launch.returncode


def agent_run(case, config_path, spec=None, timeout_s=60, before_finish=None):
    """One `run --once` of the agent-lab, its outputs and the markers of
    the run kept under cases/CASE; BEFORE_FINISH(launch) runs in a thread
    while the agent runs (a pause needs its resume file written)."""
    global agent_runs
    agent_runs += 1
    case_dir = EVIDENCE / "cases" / case
    case_dir.mkdir(exist_ok=True)
    offset = marker_offset()
    launch = start_agent(config_path, spec)
    watcher = None
    if before_finish:
        watcher = threading.Thread(target=before_finish, args=(launch,), daemon=True)
        watcher.start()
    try:
        out, err = launch.finish(timeout_s)
        timed_out = False
    except subprocess.TimeoutExpired:
        cleanups.append(lab_process.stop_scope(launch, timeout_s=10))
        out, err = launch.output.get("stdout"), launch.output.get("stderr")
        timed_out = True
    if watcher:
        watcher.join(timeout=5)
    rows = markers_since(offset)
    # The markers of the run are read by offset: another writer of the
    # file during the run (a laboratory program started by hand, a test
    # run beside this one) would be read as this agent's. Its agent-role
    # markers carry another pid: diagnosed, never silently absorbed.
    foreign = [row for row in rows if row.get("role") == "agent" and row.get("pid") != launch.pid]
    if foreign:
        A.record(f"{case}.run_{agent_runs}_foreign_agent_markers", 0, len(foreign), ok=False)
    stem = f"run-{agent_runs}"
    for name, text in ((f"{stem}.stdout", out), (f"{stem}.stderr", err)):
        (case_dir / name).write_text(text or "")
        outputs.append(case_dir / name)
    with (case_dir / f"{stem}.markers.jsonl").open("w") as stream:
        for row in rows:
            stream.write(json.dumps(row) + "\n")
    outputs.append(case_dir / f"{stem}.markers.jsonl")
    if spec:
        (case_dir / f"{stem}.spec").write_text(spec + "\n")
    if timed_out:
        A.record(f"{case}.run_{agent_runs}_timed_out", False, True, ok=False)
    return Run(launch, out, err, timed_out, rows)


def result_message(database, message_id):
    result = S.command_result(database, message_id) or {}
    return ((result.get("payload") or {}).get("message")), result.get("status")


root = EVIDENCE / "fixture"
scope_closed, kept = False, dict(kept=None, reason="qualification refused: the authority was not claimed")
if QUALIFIED:
    root.mkdir()
    LAB_DIR.mkdir(parents=True, exist_ok=True)
    clear_fault()
    clear_resumes()
    MARKERS.write_bytes(b"")
    try:
        cert, key = lab_fixture.certificate(OPENSSL, root)
        server = LabCloudServer(str(cert), str(key)).start()
        manifest, grants = lab_fixture.policy(MAELYS_GIT, root)
        work, bare, head = lab_fixture.repository(root)
        config_path, database, token = lab_fixture.configuration(root, server, cert, manifest, grants, EXECUTOR,
                                                                 request_timeout_ms=REQUEST_TIMEOUT_MS)

        def health(message_id):
            return command(message_id, "health")

        def authorize(message_id, principal="alice"):
            return command(message_id, "authorize", repository="example.git", principal=principal,
                           payload=dict(operation="write"))

        def update_ref(message_id, ref, old, new, principal="alice"):
            return command(message_id, "update_ref", repository="example.git", principal=principal,
                           payload=dict(ref=ref, old_oid=old, new_oid=new))

        def serve_and_run(case, message, spec=None, **options):
            server.enqueue(message)
            return agent_run(case, config_path, spec, **options)

        def executor_inits(rows):
            return events(rows, event="init", role="executor")

        # ---- 1. the trace: http.trace and vfs.trace on a health, twice ----------------
        # The first run executes the command (every agent point of the
        # command path is reached), the second posts its result (before_ack).
        case = "trace"
        trace = "http.trace:log;vfs.trace:log"
        first = serve_and_run(case, health("t-health"), trace)
        A.check(f"{case}.agent_exit", 0, first.returncode)
        A.check(f"{case}.state", "complete", S.command_state(database, "t-health"))
        init = events(first.markers, event="init", role="agent")
        A.check(f"{case}.agent_init_marker", 1, len(init))
        A.check(f"{case}.agent_init_faults", trace.split(";"), init[0].get("faults") if init else None)
        A.check(f"{case}.agent_built_with", "MG_LAB_FAULTS", init[0].get("built_with") if init else None)
        A.check(f"{case}.executor_init_marker", 1, len(executor_inits(first.markers)))
        A.check(f"{case}.executor_record_launch", 1, len(reached(first.markers, "executor.record_launch",
                                                                  role="executor", message_id="t-health")))
        for point in ("store.open_after_barrier", "http.after_poll", "store.pending_insert", "grants.sync",
                      "supervisor.after_spawn", "supervisor.before_validate", "store.complete_commit"):
            A.check(f"{case}.reached.{point}", True, len(reached(first.markers, point, role="agent")) >= 1)
        order = [row["point"] for row in events(first.markers, event="reached", role="agent")]
        A.check(f"{case}.order_of_the_command_path", True,
                order.index("store.pending_insert") < order.index("grants.sync") < order.index("supervisor.after_spawn")
                < order.index("supervisor.before_validate") < order.index("store.complete_commit"))
        # One advance may complete a whole exchange: at least one marker per
        # request (the poll here; the post of the result in the second run).
        advances = events(first.markers, event="http_advance")
        A.check(f"{case}.http_advance_markers", True, len(advances) >= 1)
        A.check(f"{case}.http_advance_fields", True, all(
            isinstance(row.get("duration_ms"), int) and row.get("method") in ("GET", "POST") and "target" in row
            for row in advances))
        opens = events(first.markers, event="vfs_open")
        A.check(f"{case}.vfs_open_main_and_wal", True, {"main", "wal"} <= {row.get("file") for row in opens})
        ops = events(first.markers, event="vfs_op")
        A.check(f"{case}.vfs_op_markers", True, len(ops) >= 1)
        # The survey: the operations of each phase, counted by file and op.
        survey = {}
        for row in ops:
            phase = survey.setdefault(row.get("phase") or "(before any point)", {})
            key = f"{row.get('file')}:{row.get('op')}"
            phase[key] = phase.get(key, 0) + 1
        (EVIDENCE / "vfs-survey.json").write_text(json.dumps(dict(
            run="t-health", phases=survey, opens=opens,
            note="operations seen by the VFS maelys-lab between a point and the next (phase = the point)"), indent=2))
        outputs.append(EVIDENCE / "vfs-survey.json")
        (EVIDENCE / "http-trace.json").write_text(json.dumps(advances, indent=2))
        outputs.append(EVIDENCE / "http-trace.json")
        # With journal_mode=WAL and synchronous=FULL the WAL is synced at the
        # commit of the completion: the phase store.complete_commit holds it.
        A.check(f"{case}.complete_commit_phase_syncs_wal", True,
                survey.get("store.complete_commit", {}).get("wal:xSync", 0) >= 1)
        A.check(f"{case}.complete_commit_phase_writes_wal", True,
                survey.get("store.complete_commit", {}).get("wal:xWrite", 0) >= 1)
        second = agent_run(case, config_path, trace)
        A.check(f"{case}.second_exit", 0, second.returncode)
        advances += events(second.markers, event="http_advance")
        A.check(f"{case}.http_advance_post_traced", True,
                any(row.get("method") == "POST" for row in events(second.markers, event="http_advance")))
        A.check(f"{case}.reached.http.before_ack", 1, len(reached(second.markers, "http.before_ack", role="agent")))
        A.check(f"{case}.event_posted", True, server.wait_for_request(
            lambda r: r["method"] == "POST" and r["idempotency_key"] == "t-health", 10) is not None)

        # ---- 2. store.pending_insert:kill ---------------------------------------------
        case = "pending_insert_kill"
        message = health("p-health")
        run = serve_and_run(case, message, "store.pending_insert:kill")
        A.check(f"{case}.agent_killed", SIGKILLED, run.returncode)
        A.check(f"{case}.kill_marker", 1, len(events(run.markers, event="kill", point="store.pending_insert")))
        A.check(f"{case}.state_pending", "pending", S.command_state(database, "p-health"))
        A.check(f"{case}.no_executor", 0, len(executor_inits(run.markers)))
        run = serve_and_run(case, message)
        A.check(f"{case}.reexecuted_exit", 0, run.returncode)
        A.check(f"{case}.reexecuted_state", "complete", S.command_state(database, "p-health"))
        A.check(f"{case}.entries", 1, len(reached(run.markers, "executor.record_launch", message_id="p-health")))

        # ---- 3. store.open_after_barrier:kill -----------------------------------------
        case = "open_after_barrier_kill"
        before = S.journal_inventory(database)
        run = agent_run(case, config_path, "store.open_after_barrier:kill")
        A.check(f"{case}.agent_killed", SIGKILLED, run.returncode)
        A.check(f"{case}.kill_marker", 1, len(events(run.markers, event="kill", point="store.open_after_barrier")))
        A.check(f"{case}.journal_intact", before, S.journal_inventory(database))
        run = agent_run(case, config_path)
        A.check(f"{case}.next_open_exit", 0, run.returncode)

        # ---- 4. supervisor.after_spawn:kill -------------------------------------------
        case = "after_spawn_kill"
        message = health("s-health")
        run = serve_and_run(case, message, "supervisor.after_spawn:kill")
        A.check(f"{case}.agent_killed", SIGKILLED, run.returncode)
        A.check(f"{case}.kill_marker", 1, len(events(run.markers, event="kill", point="supervisor.after_spawn")))
        A.check(f"{case}.state_running", "running", S.command_state(database, "s-health"))
        A.check(f"{case}.executor_started", 1, len(executor_inits(run.markers)))
        A.check(f"{case}.executor_got_no_command", 0,
                len(reached(run.markers, "executor.record_launch", message_id="s-health")))
        run = serve_and_run(case, message)
        A.check(f"{case}.reexecuted_exit", 0, run.returncode)
        A.check(f"{case}.reexecuted_state", "complete", S.command_state(database, "s-health"))
        A.check(f"{case}.entries_after_reexecution", 1,
                len(reached(run.markers, "executor.record_launch", message_id="s-health")))

        # ---- 5. supervisor.before_validate:kill, after a real Git effect -----------------
        case = "before_validate_kill"
        message = update_ref("u-main", "refs/heads/main", S.ZERO_OID, head)
        run = serve_and_run(case, message, "supervisor.before_validate:kill")
        A.check(f"{case}.agent_killed", SIGKILLED, run.returncode)
        A.check(f"{case}.kill_marker", 1, len(events(run.markers, event="kill", point="supervisor.before_validate")))
        A.check(f"{case}.effect_applied", head, S.ref(bare, "refs/heads/main"))
        A.check(f"{case}.state_running", "running", S.command_state(database, "u-main"))
        A.check(f"{case}.entries", 1, len(reached(run.markers, "executor.record_launch", message_id="u-main")))
        run = serve_and_run(case, message)
        # B puts the command back to pending and runs it again: the second
        # executor sees a ref already at the new value. What B does with it
        # is recorded, not asserted (the reproduction is 2d's object).
        A.check(f"{case}.reexecuted_exit", 0, run.returncode)
        A.check(f"{case}.reexecuted_terminal", True, S.command_state(database, "u-main") in ("complete", "failed"))
        A.record(f"{case}.reexecuted_observed", None,
                 dict(state=S.command_state(database, "u-main"), result=result_message(database, "u-main"),
                      entries=len(reached(run.markers, "executor.record_launch", message_id="u-main"))), ok=True)
        A.check(f"{case}.ref_still_at_head", head, S.ref(bare, "refs/heads/main"))

        # ---- 6. store.complete_commit: kill, synthetic, VFS ------------------------------
        case = "complete_commit_kill"
        message = health("c-kill")
        run = serve_and_run(case, message, "store.complete_commit:kill")
        A.check(f"{case}.agent_killed", SIGKILLED, run.returncode)
        A.check(f"{case}.state_running", "running", S.command_state(database, "c-kill"))
        A.check(f"{case}.no_result", None, S.command_result(database, "c-kill"))
        A.check(f"{case}.no_outbox", [], S.outbox(database, "c-kill"))
        run = serve_and_run(case, message)
        A.check(f"{case}.reexecuted_state", "complete", S.command_state(database, "c-kill"))

        case = "complete_commit_synthetic"
        message = health("c-synthetic")
        run = serve_and_run(case, message, "store.complete_commit:synthetic=SQLITE_FULL")
        A.check(f"{case}.agent_exit", 1, run.returncode)
        synthetic = events(run.markers, event="synthetic", point="store.complete_commit")
        A.check(f"{case}.synthetic_marker", [dict(code=13, code_name="SQLITE_FULL")],
                [dict(code=row.get("code"), code_name=row.get("code_name")) for row in synthetic])
        A.check(f"{case}.state_running", "running", S.command_state(database, "c-synthetic"))
        A.check(f"{case}.error_named", True, "synthetic fault SQLITE_FULL" in (run.err or ""))
        run = serve_and_run(case, message)
        A.check(f"{case}.reexecuted_state", "complete", S.command_state(database, "c-synthetic"))

        case = "complete_commit_vfs"
        message = health("c-vfs")
        run = serve_and_run(case, message, "store.complete_commit:vfs=wal:xSync:SQLITE_IOERR_FSYNC")
        A.check(f"{case}.agent_exit", 1, run.returncode)
        armed = events(run.markers, event="armed", point="store.complete_commit")
        A.check(f"{case}.armed_marker", [dict(file="wal", op="xSync", code=1034, occurrence=1)],
                [dict(file=r.get("file"), op=r.get("op"), code=r.get("code"), occurrence=r.get("occurrence"))
                 for r in armed])
        fault = events(run.markers, event="vfs_fault")
        A.check(f"{case}.vfs_fault_marker", [dict(file="wal", op="xSync", occurrence=1, code=1034,
                                                  code_name="SQLITE_IOERR_FSYNC", phase="store.complete_commit")],
                [dict(file=r.get("file"), op=r.get("op"), occurrence=r.get("occurrence"), code=r.get("code"),
                      code_name=r.get("code_name"), phase=r.get("phase")) for r in fault])
        A.check(f"{case}.no_unreached_marker", 0, len(events(run.markers, event="vfs_unreached")))
        A.check(f"{case}.state_running", "running", S.command_state(database, "c-vfs"))
        # B reports the failure of the completion as IO_FAILED; the message
        # it carries is the one of its explicit ROLLBACK after SQLite rolled
        # the transaction back itself on the I/O error, not the fsync code:
        # recorded as observed, an observation for the stabilization.
        A.check(f"{case}.agent_reports_io_failure", "IO_FAILED", S.envelope(run.err or "").get("error_code"))
        A.record(f"{case}.agent_message_observed", None,
                 ((json.loads(run.err) if run.err else {}).get("error") or {}).get("message"), ok=True)
        run = serve_and_run(case, message)
        A.check(f"{case}.reexecuted_state", "complete", S.command_state(database, "c-vfs"))

        # ---- 7. grants.sync:synthetic=EIO -----------------------------------------------
        case = "grants_sync_synthetic"
        run = serve_and_run(case, health("g-health"), "grants.sync:synthetic=EIO")
        A.check(f"{case}.agent_exit", 0, run.returncode)
        A.check(f"{case}.synthetic_marker", 1, len(events(run.markers, event="synthetic", point="grants.sync")))
        A.check(f"{case}.state_failed", "failed", S.command_state(database, "g-health"))
        message_text, _ = result_message(database, "g-health")
        A.check(f"{case}.result_names_the_store", True, (message_text or "").startswith("grants store unavailable: "))
        A.check(f"{case}.errno_named", True, "Input/output error" in (message_text or ""))
        A.check(f"{case}.no_executor", 0, len(executor_inits(run.markers)))

        # ---- 8. http.after_poll: kill, then pause -----------------------------------------
        case = "after_poll_kill"
        cursor_before = S.cursor(database)
        message = health("a-kill")
        run = serve_and_run(case, message, "http.after_poll:kill")
        A.check(f"{case}.agent_killed", SIGKILLED, run.returncode)
        A.check(f"{case}.no_row", None, S.command_state(database, "a-kill"))
        A.check(f"{case}.cursor_unchanged", cursor_before, S.cursor(database))
        run = serve_and_run(case, message)
        A.check(f"{case}.reexecuted_state", "complete", S.command_state(database, "a-kill"))

        case = "after_poll_pause"
        seen = {}

        def resume_after_poll(launch):
            offset = seen["offset"]
            if S.wait_until(lambda: any(r.get("event") == "paused" for r in markers_since(offset)), 30):
                seen["state_while_paused"] = S.command_state(database, "a-pause")
                (LAB_DIR / "resume.http.after_poll").write_text("go\n")
            else:
                seen["error"] = "no paused marker within 30 s"

        seen["offset"] = marker_offset()
        run = serve_and_run(case, health("a-pause"), "http.after_poll:pause", before_finish=resume_after_poll)
        clear_resumes()
        A.check(f"{case}.agent_exit", 0, run.returncode)
        A.check(f"{case}.paused_then_resumed", ["paused", "resumed"],
                [r["event"] for r in run.markers if r.get("point") == "http.after_poll" and r.get("event") in ("paused", "resumed")])
        A.check(f"{case}.nothing_recorded_while_paused", None, seen.get("state_while_paused", "(not observed)"))
        A.check(f"{case}.completed_after_resume", "complete", S.command_state(database, "a-pause"))

        # ---- 9. http.before_ack:kill ----------------------------------------------------
        case = "before_ack_kill"
        posts_before = len(server.posts)
        run = agent_run(case, config_path, "http.before_ack:kill")
        A.check(f"{case}.agent_killed", SIGKILLED, run.returncode)
        posted = server.posts[posts_before:]
        A.check(f"{case}.one_event_posted", 1, len(posted))
        key = posted[0]["idempotency_key"] if posted else None
        A.check(f"{case}.outbox_not_acked", [None], [row["acked_at_ms"] for row in S.outbox(database, key or "")])
        run = agent_run(case, config_path)
        A.check(f"{case}.resend_exit", 0, run.returncode)
        resent = [p for p in server.posts[posts_before:] if p["idempotency_key"] == key]
        A.check(f"{case}.resent_identical", True, len(resent) == 2 and resent[0]["body"] == resent[1]["body"])
        A.check(f"{case}.acked_after_resend", True,
                all(row["acked_at_ms"] is not None for row in S.outbox(database, key or "")))

        # ---- 10. the executor's alterations --------------------------------------------
        def alteration(case, point, message, expected_state, expected_message=None, expect_apply=True):
            write_fault(point)
            run = serve_and_run(case, message)
            clear_fault()
            A.check(f"{case}.agent_exit", 0, run.returncode)
            A.check(f"{case}.executor_read_the_fault", [point],
                    (events(run.markers, event="init", role="executor") or [{}])[0].get("faults"))
            applied = events(run.markers, event="apply", point=point)
            skipped = events(run.markers, event="skipped", point=point)
            A.check(f"{case}.applied", expect_apply, len(applied) == 1 and not skipped)
            A.check(f"{case}.state", expected_state, S.command_state(database, message["message_id"]))
            text, status = result_message(database, message["message_id"])
            if expected_message is not None:
                A.check(f"{case}.result_message", True, expected_message in (text or ""))
            return run, text, status

        alteration("alter_receipt", "executor.alter_receipt", authorize("x-alter"), "failed",
                   "the receipt is not the one its digest names")
        # A result whose receipt does not verify is a failed command and
        # nothing of it is audited beside the failure (store.c): no receipt,
        # and no grants event either.
        A.check("alter_receipt.audit_without_receipt", ["command_failed"], S.audit_kinds(database, "x-alter"))
        alteration("wrong_grants", "executor.wrong_grants", authorize("x-wrong-grants"), "failed",
                   "names grants other than those the executor was given")
        alteration("receipt_without_grants", "executor.receipt_without_grants", authorize("x-no-grants"), "complete")
        receipt = ((S.command_result(database, "x-no-grants") or {}).get("payload") or {}).get("receipt") or {}
        A.check("receipt_without_grants.version_1_without_grants", (1, False), (receipt.get("version"), "grants" in receipt))
        A.check("receipt_without_grants.receipt_audited", ["command_complete", "authorization_receipt", "grants_snapshot"],
                S.audit_kinds(database, "x-no-grants"))
        alteration("drop_receipt_and_text", "executor.drop_receipt_and_text", authorize("x-drop-all"), "complete")
        payload = (S.command_result(database, "x-drop-all") or {}).get("payload") or {}
        A.check("drop_receipt_and_text.payload_without_receipt", False, "receipt" in payload or "receipt_sha256" in payload)
        A.check("drop_receipt_and_text.audit_without_receipt", ["command_complete", "grants_snapshot"],
                S.audit_kinds(database, "x-drop-all"))
        # A denial of a repository change carries the explanation text the
        # receipt vouches for: with the receipt removed, the text vouches
        # for nothing and the agent refuses the result.
        alteration("drop_receipt_keep_text", "executor.drop_receipt_keep_text",
                   update_ref("x-keep-text", "refs/heads/other", S.ZERO_OID, head, principal="bob"), "failed",
                   "explanation text without a receipt")
        A.check("drop_receipt_keep_text.nothing_published", None, S.ref(bare, "refs/heads/other"))
        alteration("invalid_envelope", "executor.invalid_envelope", health("x-invalid"), "failed")
        A.check("invalid_envelope.code", "executor_failed",
                ((S.command_result(database, "x-invalid") or {}).get("payload") or {}).get("code"))
        alteration("hang", "executor.hang", health("x-hang"), "failed", "executor process group timed out")
        alteration("exit_after_effect", "executor.exit_after_effect", health("x-exit"), "failed", "executor failed")

        # ---- 11. the outbox drained, every result posted ---------------------------------
        case = "drain"
        for _ in range(40):
            if not S.outbox_unacked(database):
                break
            run = agent_run(case, config_path)
            if run.returncode != 0:
                break
        A.check(f"{case}.outbox_empty", [], [row["id"] for row in S.outbox_unacked(database)])
        inventory = S.journal_inventory(database)
        A.check("inventory.tables", ["audit", "commands", "metadata", "outbox"], sorted(inventory))
    except BaseException as error:  # noqa: BLE001 — recorded, evidence preserved, re-raised below
        failed_exception = error
        A.record("scenario.exception", None, repr(error), ok=False)
    finally:
        clear_fault()
        clear_resumes()
        final = lab_process.stop_all(launches, timeout_s=10)
        cleanups.extend(final)
        for outcome in final:
            A.check(f"cleanup.observed_empty.{outcome['sid']}", True, outcome["observed_empty"])
            if AUTHORITY is not None:
                A.check(f"cleanup.swept.{outcome['sid']}", True, outcome["swept"])
        (EVIDENCE / "cleanups.json").write_text(json.dumps(cleanups, indent=2, default=str))
        outputs.append(EVIDENCE / "cleanups.json")
        if server is not None:
            with server.lock:
                (EVIDENCE / "server-requests.json").write_text(
                    json.dumps(dict(requests=server.requests, posts=server.posts), indent=2))
            outputs.append(EVIDENCE / "server-requests.json")
            secret = server.token
            server.stop()
        else:
            secret = None
        if MARKERS.exists():
            (EVIDENCE / "markers.jsonl").write_bytes(MARKERS.read_bytes())
            outputs.append(EVIDENCE / "markers.jsonl")
        scope_closed = lab_process.scope_closed(final)
        kept = lab_process.preserve_fixture(root, EVIDENCE, scope_closed, failed_exception is not None or A.failed,
                                            cleanups)
        if AUTHORITY is not None:
            A.check("cleanup.scope_closed", True, scope_closed)
        else:
            A.record("cleanup.scope_closed", None, "no authority on this host: observed, not proven", ok=True)
        if kept["kept"] is not None:
            outputs.append(EVIDENCE / "fixture-kept.json")
        if secret:
            A.check("secret.absent_from_outputs", [], S.secret_absent(secret, outputs + [EVIDENCE / "assertions.jsonl"]))

summary = A.summary()
(EVIDENCE / "summary.json").write_text(json.dumps(dict(
    scenario="faults", platform=sys.platform, authority=AUTHORITY, scope_closed=scope_closed, agent_runs=agent_runs,
    fixture_kept=str(kept["kept"]) if kept["kept"] is not None else None, fixture_kept_reason=kept["reason"],
    **summary), indent=2))
print(json.dumps(dict(evidence=str(EVIDENCE), **summary)))
sys.exit(1 if summary["failed"] or failed_exception is not None else 0)
