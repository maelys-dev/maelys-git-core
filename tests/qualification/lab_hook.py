"""The lab `reference-transaction` hook of the qualification harness (plan §2.2).

Installed by a scenario in the `hooks/` directory of a synthetic repository,
it runs as Git's child, in the executor's process group, and gives the
harness its Git synchronisation points: at `prepared` (every ref locked,
nothing published) it writes a marker with the updates it was given and
waits for a resume file; at `committed` and `aborted` it writes a marker.
A wait that expires REFUSES (exit 1, which aborts the transaction: nothing
is published) and leaves `prepared.expired`: an expired deadline never
authorises Git to go on. The script text is generated here so that its
expiry branch can be run directly by the component tests with a short bound.
"""
import shlex


def hook_script(markers_dir, max_steps=600, step_s=0.1):
    """The hook as a POSIX sh script; max_steps * step_s bounds the wait."""
    return (
        "#!/bin/sh\n"
        "# Lab reference-transaction hook (GIT-C10 harness, plan 2.2).\n"
        f"state=$1; dir={shlex.quote(str(markers_dir))}\n"
        "cat > \"$dir/$state.updates\"\n"
        "printf '%s %s %s %s\\n' \"$$\" \"$PPID\" \"$(date +%s)\" \"$state\" > \"$dir/$state\"\n"
        "if [ \"$state\" = prepared ]; then\n"
        f"  i=0; while [ ! -e \"$dir/resume\" ] && [ $i -lt {int(max_steps)} ]; do sleep {step_s}; i=$((i+1)); done\n"
        "  if [ ! -e \"$dir/resume\" ]; then\n"
        "    printf 'expired after %s steps\\n' \"$i\" > \"$dir/prepared.expired\"\n"
        "    echo 'lab hook: wait for resume expired, refusing the transaction' >&2\n"
        "    exit 1\n"
        "  fi\n"
        "fi\n"
        "exit 0\n"
    )


def install(repository, markers_dir, **bounds):
    """Write the hook into repository/hooks and return its path."""
    from pathlib import Path
    path = Path(repository) / "hooks" / "reference-transaction"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(hook_script(markers_dir, **bounds))
    path.chmod(0o700)
    return path
