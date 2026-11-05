"""The fixture the qualification scenarios share (plan §2.1, §2.2): the lab
certificate, a migrated Gitolite policy, a synthetic bare repository with
a seed commit, and the agent's configuration as test_cloud_transport.py
writes it. Pure construction: nothing here launches the agent.
"""
import json
import os
import subprocess
from pathlib import Path

GIT = "/usr/bin/git"
ENV = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
ENV.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null")


def run(*args, ok=True, input=None, timeout=60):
    result = subprocess.run(list(map(str, args)), input=input, capture_output=True, text=True, env=ENV,
                            timeout=timeout)
    if ok and result.returncode:
        raise AssertionError(f"{args}: {result.stdout}\n{result.stderr}")
    return result


def git(*args, **kwargs):
    return run(GIT, *args, **kwargs)


def certificate(openssl, root):
    """A self-signed certificate for localhost, one day: (cert, key)."""
    cert, key = Path(root) / "cert.pem", Path(root) / "key.pem"
    run(openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=localhost",
        "-addext", "subjectAltName=DNS:localhost", "-keyout", key, "-out", cert)
    return cert, key


def policy(maelys_git, root, conf_text="repo example\n    RW+ refs/heads/ = alice\n"):
    """A migrated Gitolite configuration: (manifest, grants). By default
    alice writes refs/heads/ of example; anyone else is denied."""
    conf, migrated = Path(root) / "gitolite.conf", Path(root) / "migrated"
    conf.write_text(conf_text)
    run(maelys_git, "migrate", "gitolite", conf, migrated, "--apply", "--format", "json", "--non-interactive")
    return migrated / "manifest.json", migrated / "grants.json"


def repository(root):
    """A bare repository example.git with a seed commit on refs/heads/seed
    and a reflog on every ref, as the profile configures it: (work, bare,
    head)."""
    work, bare = Path(root) / "work", Path(root) / "example.git"
    git("init", "-q", work)
    for k, v in (("user.name", "Lab"), ("user.email", "lab@example.invalid"), ("commit.gpgSign", "false")):
        git("-C", work, "config", k, v)
    (work / "a.txt").write_text("a\n")
    git("-C", work, "add", ".")
    git("-C", work, "commit", "-qm", "seed")
    head = git("-C", work, "rev-parse", "HEAD").stdout.strip()
    git("init", "-q", "--bare", bare)
    git("--git-dir", bare, "config", "core.logAllRefUpdates", "always")
    git("-C", work, "push", "-q", bare, "HEAD:refs/heads/seed")
    return work, bare, head


def configuration(root, server, cert, manifest, grants, executor, request_timeout_ms=30000):
    """The agent's configuration file, mode 0600, with the token file
    legitimately holding the lab secret (it is not an output): (config_path,
    database, token)."""
    root = Path(root)
    token, config_path, database = root / "token", root / "config.json", root / "agent.sqlite3"
    token.write_text(server.token)
    token.chmod(0o600)
    config = dict(version=1, agent_id="lab-agent", authority=f"localhost:{server.port}", ca_file=str(cert),
                  token_file=str(token), database_path=str(database), manifest_path=str(manifest),
                  grants_path=str(grants), repository_root=str(root), git_executable=GIT, executor_path=str(executor),
                  command_target="/commands", event_target="/events", poll_timeout_ms=1000,
                  request_timeout_ms=request_timeout_ms)
    config_path.write_text(json.dumps(config))
    config_path.chmod(0o600)
    return config_path, database, token
