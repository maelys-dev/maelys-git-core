# Security policy

Maelys Git Core is pre-release software and has not been externally audited.
Please report suspected vulnerabilities privately to the repository owner and
avoid including secrets or exploit details in public issues.

The implementation follows thirteen invariants:

1. policy load and evaluation errors deny access;
2. incoming text is never evaluated by a command shell;
3. repository paths are canonicalized below one configured root;
4. ref updates use Git's compare-and-swap primitive with an expected old OID;
5. duplicate JSON keys, unknown fields and oversized messages are rejected;
6. command IDs cannot be reused with different command content;
7. commands are journaled before execution and results are transactionally
   inserted into a durable outbox;
8. the network process never receives an arbitrary executable or argument list
   from the cloud protocol.
9. administrative mutations return a read-only plan unless `--apply` is
   explicitly present;
10. protocol-stream commands reject CLI envelope rendering and keep stdout
    reserved for their declared wire protocol;
11. child executables have absolute paths, receive a minimal allowlisted
    environment and run in process groups that are terminated as a unit on
    deadline;
12. PR apply repeats authorization and requires the reviewed target identity,
    prepared OID, policy fingerprint and, for forks, source identity;
13. PR inputs reject object alternates, indirect repository structure and local
    Git configuration capable of launching commands or loading external files.

The executor process boundary does not by itself change Unix credentials. A
production service definition should give the network agent no repository
write access and launch the executor through a narrowly configured privilege
boundary. Configuration directories and the executor binary are trusted.

These invariants should be treated as release-blocking when reviewing changes.
