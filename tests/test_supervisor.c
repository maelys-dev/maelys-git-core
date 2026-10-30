#include "agent/agent_internal.h"

#include <maelys/cli/digest.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/file.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static const char valid_result[] =
    "{\"protocol\":\"maelys-git-agent/1\",\"message_id\":\"supervised\","
    "\"agent_id\":\"agent-1\",\"type\":\"result\",\"command\":\"health\","
    "\"status\":\"ok\",\"payload\":{}}";

static void pause_ms(long milliseconds) {
    struct timespec delay = {
        .tv_sec = milliseconds / 1000,
        .tv_nsec = (milliseconds % 1000) * 1000000L};
    while (nanosleep(&delay, &delay) != 0 && errno == EINTR) {
    }
}

static int ends_with(const char *value, const char *suffix) {
    size_t value_length = strlen(value);
    size_t suffix_length = strlen(suffix);
    return value_length >= suffix_length &&
           strcmp(value + value_length - suffix_length, suffix) == 0;
}

/* The descendant of the term-order executor: on the group's SIGTERM, says
 * whether the leader still exists, reaped or not. Everything here is
 * async-signal-safe: kill(2), open(2), write(2), close(2). */
static pid_t term_order_leader;
static char term_order_marker[4096];
static void record_term_order(int signo) {
    (void)signo;
    int saved = errno;
    int unreaped = kill(term_order_leader, 0) == 0 || errno == EPERM;
    int fd = open(term_order_marker, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd >= 0) {
        const char *line = unreaped ? "leader-unreaped\n" : "leader-reaped\n";
        (void)!write(fd, line, strlen(line));
        (void)close(fd);
    }
    errno = saved;
}

static int executor_mode(const char *executable, const char *marker) {
    if (ends_with(marker, "/reply")) {
        char buffer[4096];
        while (fread(buffer, 1u, sizeof(buffer), stdin) > 0u) {}
        FILE *reply = fopen(marker, "rb");
        if (!reply) return 2;
        size_t count;
        while ((count = fread(buffer, 1u, sizeof(buffer), reply)) > 0u)
            if (fwrite(buffer, 1u, count, stdout) != count) { fclose(reply); return 2; }
        return fclose(reply) == 0 ? 0 : 2;
    }
    /* An executor that exits before reading its request. */
    if (ends_with(marker, "/exit-early")) return 0;
    /* An executor that answers, closes its stdout and goes on: it must not
     * outlive the terminal result, whatever the supervisor's wait said. */
    if (ends_with(marker, "/wait-fault")) {
        char request[16];
        if (!fgets(request, sizeof(request), stdin)) return 2;
        (void)fputs(valid_result, stdout);
        (void)fputc('\n', stdout);
        (void)fflush(stdout);
        (void)close(STDOUT_FILENO);
        pause_ms(700);
        FILE *stream = fopen(marker, "wb");
        if (stream) {
            (void)fputs("survived\n", stream);
            (void)fclose(stream);
        }
        return 0;
    }
    if (ends_with(marker, "/stdout-closed")) {
        char request[16];
        if (!fgets(request, sizeof(request), stdin)) return 2;
        (void)fputs(valid_result, stdout);
        (void)fputc('\n', stdout);
        (void)fflush(stdout);
        (void)close(STDOUT_FILENO);
        pause_ms(5000);
        return 0;
    }
    /* An executor that answers, closes stdout and exits soon after. */
    if (ends_with(marker, "/late-exit")) {
        char request[16];
        if (!fgets(request, sizeof(request), stdin)) return 2;
        (void)fputs(valid_result, stdout);
        (void)fputc('\n', stdout);
        (void)fflush(stdout);
        (void)close(STDOUT_FILENO);
        pause_ms(50);
        return 0;
    }
    if (ends_with(marker, "/nested")) {
        char *argv[] = {(char *)executable, "--descendant", (char *)marker, NULL};
        maelys_git_error_t error = {0};
        return mg_process_run_with_timeout(executable, argv, 4000u, NULL, &error) == MAELYS_GIT_OK ? 0 : 2;
    }
    /* Taken before the fork: once the leader has exited, getppid() would
     * name the process that adopted the descendant. */
    term_order_leader = getpid();
    pid_t descendant = fork();
    if (descendant < 0) return 2;
    if (descendant == 0) {
        if (ends_with(marker, "/term-order")) {
            /* Handles the group's SIGTERM instead of ignoring it, to record
             * whether the leader, its parent, was already reaped by then;
             * then lives on, for the SIGKILL that must follow. Its stdout
             * closes only once the handler is in place: the supervisor
             * takes that EOF as the executor's end and signals the group. */
            (void)snprintf(term_order_marker, sizeof(term_order_marker), "%s", marker);
            struct sigaction record = {.sa_handler = record_term_order};
            (void)sigemptyset(&record.sa_mask);
            if (sigaction(SIGTERM, &record, NULL) != 0) _exit(2);
            (void)close(STDOUT_FILENO);
            pause_ms(700);
            FILE *stream = fopen(marker, "ab");
            if (stream) {
                (void)fputs("survived\n", stream);
                (void)fclose(stream);
            }
            _exit(0);
        }
        if (ends_with(marker, "/success-descendant")) {
            (void)close(STDOUT_FILENO);
            (void)signal(SIGTERM, SIG_IGN);
        }
        pause_ms(700);
        FILE *stream = fopen(marker, "wb");
        if (stream) {
            (void)fputs("survived\n", stream);
            (void)fclose(stream);
        }
        _exit(0);
    }
    if (ends_with(marker, "/success-descendant") || ends_with(marker, "/term-order")) {
        (void)fputs(valid_result, stdout);
        (void)fputc('\n', stdout);
        return 0;
    }
    pause_ms(5000);
    (void)waitpid(descendant, NULL, 0);
    return 0;
}

/* An executor that records its arguments, one per line, beside its marker,
 * then answers. */
static int record_arguments(int argc, char **argv) {
    char request[64];
    if (!fgets(request, sizeof(request), stdin)) return 2;
    char path[4200];
    (void)snprintf(path, sizeof(path), "%s.arguments", argv[3]);
    FILE *file = fopen(path, "w");
    if (!file) return 2;
    for (int i = 1; i < argc; ++i) (void)fprintf(file, "%s\n", argv[i]);
    /* The store's lock, as a purge would try it while this executor runs. */
    for (int i = 1; i + 1 < argc; ++i) {
        if (strcmp(argv[i], "--grants") != 0) continue;
        char lock_path[4200];
        (void)snprintf(lock_path, sizeof(lock_path), "%s", argv[i + 1]);
        char *slash = strrchr(lock_path, '/');
        if (slash) (void)snprintf(slash, sizeof(lock_path) - (size_t)(slash - lock_path), "/.lock");
        int lock = open(lock_path, O_RDWR | O_CLOEXEC);
        int held = lock >= 0 && flock(lock, LOCK_EX | LOCK_NB) != 0 && errno == EWOULDBLOCK;
        if (lock >= 0) (void)close(lock);
        (void)fprintf(file, "store lock %s\n", held ? "held" : "free");
    }
    if (fclose(file) != 0) return 2;
    (void)fputs(valid_result, stdout);
    (void)fputc('\n', stdout);
    return 0;
}

/* Publishes TEXT at PATH by a rename, as the publication contract asks. */
static int publish(const char *path, const char *text) {
    char temporary[4300];
    (void)snprintf(temporary, sizeof(temporary), "%s.new", path);
    FILE *file = fopen(temporary, "wb");
    if (!file) return 0;
    int ok = fputs(text, file) >= 0;
    ok = fclose(file) == 0 && ok;
    return ok && chmod(temporary, 0644) == 0 && rename(temporary, path) == 0;
}

static int write_text(const char *path, const char *text) {
    FILE *file = fopen(path, "wb");
    if (!file) return 0;
    int ok = fputs(text, file) >= 0;
    return fclose(file) == 0 && ok;
}

static int read_text(const char *path, char *out, size_t capacity) {
    FILE *file = fopen(path, "rb");
    if (!file) return 0;
    size_t size = fread(out, 1u, capacity - 1u, file);
    (void)fclose(file);
    out[size] = '\0';
    return 1;
}

/* Removes the files of DIRECTORY, one level. */
static int remove_entries(const char *directory) {
    DIR *stream = opendir(directory);
    if (!stream) return 0;
    int ok = 1;
    for (struct dirent *entry; (entry = readdir(stream)) != NULL;) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        char path[4300];
        (void)snprintf(path, sizeof(path), "%s/%s", directory, entry->d_name);
        if (unlink(path) != 0) ok = 0;
    }
    return closedir(stream) == 0 && ok;
}

static int fail(const char *message) {
    fprintf(stderr, "test_supervisor: %s\n", message);
    return 1;
}

int main(int argc, char **argv) {
    if (argc == 3 && strcmp(argv[1], "--descendant") == 0) {
        pause_ms(700);
        FILE *file = fopen(argv[2], "w");
        if (file) { (void)fputs("survived\n", file); (void)fclose(file); }
        return 0;
    }
    if (argc >= 4 && strcmp(argv[1], "serve") == 0 &&
        strcmp(argv[2], "--manifest") == 0)
        return ends_with(argv[3], "/arguments") ? record_arguments(argc, argv) : executor_mode(argv[0], argv[3]);

    char executable[4096];
    if (!realpath(argv[0], executable)) return fail("cannot resolve test executable");
    char directory[] = "/tmp/maelys-supervisor-test-XXXXXX";
    if (!mkdtemp(directory)) return fail("cannot create temporary directory");
    char marker[4096];
    int written = snprintf(marker, sizeof(marker), "%s/descendant-marker", directory);
    if (written < 0 || (size_t)written >= sizeof(marker))
        return fail("temporary marker path is too long");

    maelys_git_agent_config_t config = {0};
    (void)snprintf(config.executor_path, sizeof(config.executor_path), "%s", executable);
    (void)snprintf(config.manifest_path, sizeof(config.manifest_path), "%s", marker);
    (void)snprintf(config.repository_root, sizeof(config.repository_root), "/tmp");
    (void)snprintf(config.git_executable, sizeof(config.git_executable), "/usr/bin/git");
    config.request_timeout_ms = 100u;
    mg_agent_message_t command = {.message_id = "supervised", .agent_id = "agent-1", .command = "health"};
    int succeeded = 0;
    char *response = NULL;
#if defined(MG_SUPERVISOR_WAIT_FAULT)
    /* The supervisor's first observation of its executor fails, EPERM: the
     * request fails with that error, and the executor, answered and still
     * running, does not outlive the terminal result. */
    (void)snprintf(config.manifest_path, sizeof(config.manifest_path), "%s/wait-fault", directory);
    config.request_timeout_ms = 2000u;
    maelys_git_error_t fault = {0};
    int64_t fault_started = mg_monotonic_ms();
    maelys_git_result_t faulted = mg_supervisor_execute(
        &config, &command, "{}", NULL, &response, &succeeded, &fault);
    int64_t fault_elapsed = mg_monotonic_ms() - fault_started;
    free(response);
    if (faulted != MAELYS_GIT_ERR_PROCESS || response != NULL ||
        !strstr(fault.message, "executor wait failed: ") || !strstr(fault.message, strerror(EPERM)))
        return fail("a failed wait did not fail the request with its error");
    if (fault_elapsed > 1500) return fail("a failed wait did not stop the executor group at once");
    pause_ms(900);
    if (access(config.manifest_path, F_OK) == 0)
        return fail("the executor outlived a terminal result after a failed wait");
    if (rmdir(directory) != 0) return fail("cannot remove temporary directory");
    return 0;
#endif
    char *request = malloc(MAELYS_GIT_MAX_PROTOCOL_LINE + 1u);
    if (!request) return fail("cannot allocate supervisor request");
    memset(request, 'x', MAELYS_GIT_MAX_PROTOCOL_LINE);
    request[MAELYS_GIT_MAX_PROTOCOL_LINE] = '\0';
    maelys_git_error_t error = {0};
    maelys_git_result_t result = mg_supervisor_execute(
        &config, &command, request, NULL, &response, &succeeded, &error);
    free(request);
    free(response);
    if (result != MAELYS_GIT_ERR_LIMIT)
        return fail("supervisor timeout did not fail with the limit category");
    pause_ms(900);
    struct stat status;
    if (lstat(marker, &status) == 0)
        return fail("executor descendant survived supervisor timeout");
    if (errno != ENOENT) return fail("cannot inspect executor descendant marker");

    /* A child that closes its stdin before the request is written must yield
     * a failure, never a SIGPIPE that terminates the supervisor. */
    (void)snprintf(config.manifest_path, sizeof(config.manifest_path), "%s/exit-early",
                   directory);
    config.request_timeout_ms = 2000u;
    request = malloc(MAELYS_GIT_MAX_PROTOCOL_LINE + 1u);
    if (!request) return fail("cannot allocate supervisor request");
    memset(request, 'x', MAELYS_GIT_MAX_PROTOCOL_LINE);
    request[MAELYS_GIT_MAX_PROTOCOL_LINE] = '\0';
    response = NULL;
    memset(&error, 0, sizeof(error));
    result = mg_supervisor_execute(&config, &command, request, NULL, &response, &succeeded, &error);
    free(request);
    free(response);
    if (result == MAELYS_GIT_OK)
        return fail("executor that exited before reading was reported as success");

    const char *cases[] = {"stdout-closed", "nested", "success-descendant"};
    for (size_t i = 0u; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        (void)snprintf(config.manifest_path, sizeof(config.manifest_path), "%s/%s", directory, cases[i]);
        config.request_timeout_ms = i == 2u ? 2000u : 200u;
        response = NULL;
        int64_t started = mg_monotonic_ms();
        result = mg_supervisor_execute(&config, &command, "{}", NULL, &response, &succeeded, &error);
        free(response);
        if (result != (i == 2u ? MAELYS_GIT_OK : MAELYS_GIT_ERR_LIMIT))
            return fail("closed stdout or nested subprocess bypassed supervision");
        if (mg_monotonic_ms() - started > 1500)
            return fail("wait after stdout EOF ignored the deadline");
        pause_ms(900);
        if (access(config.manifest_path, F_OK) == 0)
            return fail("descendant survived a terminal executor result");
    }
    /* An executor that answers, then outlives its deadline: the wait for
     * its exit spends the rest of the budget, then ends it, its group and
     * its zombie. */
    (void)snprintf(config.manifest_path, sizeof(config.manifest_path), "%s/stdout-closed", directory);
    config.request_timeout_ms = 300u;
    response = NULL;
    memset(&error, 0, sizeof(error));
    int64_t started = mg_monotonic_ms();
    result = mg_supervisor_execute(&config, &command, "{}", NULL, &response, &succeeded, &error);
    int64_t elapsed = mg_monotonic_ms() - started;
    free(response);
    if (result != MAELYS_GIT_ERR_LIMIT || strcmp(error.message, "executor process group timed out") != 0)
        return fail("an executor that outlived its deadline was not reported as timed out");
    if (elapsed < 300 || elapsed > 1500)
        return fail("the executor wait did not end at its deadline");
    errno = 0;
    if (waitpid(-1, NULL, WNOHANG) != -1 || errno != ECHILD)
        return fail("an executor that outlived its deadline was not reaped");
    /* An exit after the answer is waited for, not taken for a timeout. */
    (void)snprintf(config.manifest_path, sizeof(config.manifest_path), "%s/late-exit", directory);
    config.request_timeout_ms = 5000u;
    response = NULL;
    result = mg_supervisor_execute(&config, &command, "{}", NULL, &response, &succeeded, &error);
    free(response);
    if (result != MAELYS_GIT_OK || !succeeded)
        return fail("an executor that exited after its answer was not waited for");
    /* The executor exits on its own; a descendant handles SIGTERM and lives
     * on. The group's SIGTERM reaches it while the leader is not reaped yet,
     * so the group's number can name no stranger, and the SIGKILL that
     * follows still ends it: no "survived" after its record. */
    (void)snprintf(config.manifest_path, sizeof(config.manifest_path), "%s/term-order", directory);
    config.request_timeout_ms = 2000u;
    response = NULL;
    result = mg_supervisor_execute(&config, &command, "{}", NULL, &response, &succeeded, &error);
    free(response);
    if (result != MAELYS_GIT_OK) return fail("the term-order executor failed");
    pause_ms(900);
    char order[64];
    if (!read_text(config.manifest_path, order, sizeof(order)))
        return fail("the descendant did not record the group's SIGTERM");
    if (strcmp(order, "leader-unreaped\n") != 0) {
        fprintf(stderr, "test_supervisor: descendant recorded %s", order);
        return fail("the group was signaled after its leader was reaped, or a descendant survived");
    }
    if (unlink(config.manifest_path) != 0) return fail("cannot remove the term-order record");

    (void)snprintf(config.manifest_path, sizeof(config.manifest_path), "%s/reply", directory);
    config.request_timeout_ms = 5000u;
    char *wire = malloc(MAELYS_GIT_MAX_PROTOCOL_LINE + 4u);
    if (!wire) return fail("cannot allocate response fixture");
    for (size_t test = 0u; test < 8u; ++test) {
        size_t size = strlen(valid_result);
        memcpy(wire, valid_result, size);
        maelys_git_result_t expected = MAELYS_GIT_OK;
        if (test <= 2u) {
            memset(wire + size, ' ', MAELYS_GIT_MAX_PROTOCOL_LINE - size);
            size = MAELYS_GIT_MAX_PROTOCOL_LINE;
            if (test == 1u) wire[size++] = '\r';
            if (test == 2u) { wire[size++] = ' '; expected = MAELYS_GIT_ERR_LIMIT; }
        } else if (test == 3u) {
            wire[size++] = '\0'; expected = MAELYS_GIT_ERR_PROTOCOL;
        } else if (test == 4u) {
            wire[size++] = '\n'; expected = MAELYS_GIT_ERR_PROTOCOL;
        } else if (test == 5u) {
            memcpy(wire + size, "{}", 2u); size += 2u; expected = MAELYS_GIT_ERR_PROTOCOL;
        } else if (test == 6u) {
            wire[0] = '['; expected = MAELYS_GIT_ERR_PROTOCOL;
        } else {
            expected = MAELYS_GIT_ERR_PROTOCOL; /* No final newline. */
        }
        if (test != 7u) wire[size++] = '\n';
        FILE *file = fopen(config.manifest_path, "wb");
        if (!file || fwrite(wire, 1u, size, file) != size || fclose(file) != 0)
            return fail("cannot write response fixture");
        succeeded = 1;
        result = mg_supervisor_execute(&config, &command, "{}", NULL, &response, &succeeded, &error);
        if (result != expected || succeeded != (expected == MAELYS_GIT_OK) ||
            (response != NULL) != (expected == MAELYS_GIT_OK))
            return fail("response framing, limit or success state was not enforced");
        free(response);
    }
    free(wire);
    if (unlink(config.manifest_path) != 0) return fail("cannot remove response fixture");

    /* GIT-C06 test 12. The executor receives the snapshot kept in the
     * agent's store and its digest, never the configured path, and no
     * --grants without one. */
    (void)snprintf(config.manifest_path, sizeof(config.manifest_path), "%s/arguments", directory);
    (void)snprintf(config.database_path, sizeof(config.database_path), "%s/journal.sqlite", directory);
    char recorded[4200], source[4200], store[4200];
    (void)snprintf(recorded, sizeof(recorded), "%s.arguments", config.manifest_path);
    (void)snprintf(source, sizeof(source), "%s/grants.json", directory);
    (void)snprintf(store, sizeof(store), "%s/grants-store", directory);
    static const char first[] = "first generation of grants";
    static const char second[] = "second generation of grants";
    char first_sha[65], second_sha[65], kept[4200];
    maelys_cli_sha256_hex(first, strlen(first), first_sha);
    maelys_cli_sha256_hex(second, strlen(second), second_sha);
    if (!publish(source, first)) return fail("cannot publish the grants");
    mg_grants_archive_t grants;

    /* Under a SIGCHLD disposition the kernel reaps by, the supervisor could
     * not keep its executor, nor its number: no executor starts. */
    struct sigaction ignore_children = {.sa_handler = SIG_IGN}, former;
    (void)sigemptyset(&ignore_children.sa_mask);
    if (sigaction(SIGCHLD, &ignore_children, &former) != 0) return fail("cannot ignore SIGCHLD");
    response = NULL;
    memset(&error, 0, sizeof(error));
    result = mg_supervisor_execute(&config, &command, "{}", &grants, &response, &succeeded, &error);
    free(response);
    if (sigaction(SIGCHLD, &former, NULL) != 0) return fail("cannot restore SIGCHLD");
    if (result != MAELYS_GIT_ERR_PROCESS || !strstr(error.message, "SIGCHLD is ignored") ||
        access(recorded, F_OK) == 0)
        return fail("an executor started under an ignored SIGCHLD");
    for (int with_grants = 0; with_grants < 2; ++with_grants) {
        (void)snprintf(config.grants_path, sizeof(config.grants_path), "%s", with_grants ? source : "");
        response = NULL;
        result = mg_supervisor_execute(&config, &command, "{}", &grants, &response, &succeeded, &error);
        free(response);
        if (result != MAELYS_GIT_OK || !succeeded) return fail("the recording executor failed");
        char arguments[8192];
        if (!read_text(recorded, arguments, sizeof(arguments))) return fail("no recorded arguments");
        if (!with_grants) {
            if (strstr(arguments, "--grants") || grants.sha256[0] || access(store, F_OK) == 0)
                return fail("an executor without grants received some");
        } else {
            (void)snprintf(kept, sizeof(kept), "%s/%s.json", store, first_sha);
            char expected[9000];
            (void)snprintf(expected, sizeof(expected), "\n--grants\n%s\n--expected-grants-fingerprint\n%s\n", kept,
                           first_sha);
            if (!strstr(arguments, expected) || strstr(arguments, source) || strcmp(grants.sha256, first_sha) != 0 ||
                strcmp(grants.path, kept) != 0)
                return fail("the executor did not receive the kept snapshot and its digest");
            if (!strstr(arguments, "\nstore lock held\n") || grants.lock != -1)
                return fail("the store was not locked while the executor ran, or stayed locked after it");
            /* Kept before the executor started: private, read-only, these bytes. */
            char bytes[256];
            struct stat entry, holder;
            if (!read_text(kept, bytes, sizeof(bytes)) || strcmp(bytes, first) != 0 ||
                lstat(kept, &entry) != 0 || (entry.st_mode & 0777) != 0400 ||
                lstat(store, &holder) != 0 || (holder.st_mode & 0777) != 0700)
                return fail("the store does not hold the snapshot as given");
        }
        if (unlink(recorded) != 0) return fail("cannot remove recorded arguments");
    }

    /* The source changes: the store keeps the bytes the first command used
     * and adds the new ones; the same snapshot again is read back. */
    if (!publish(source, second)) return fail("cannot publish the grants");
    for (int round = 0; round < 2; ++round) {
        response = NULL;
        result = mg_supervisor_execute(&config, &command, "{}", &grants, &response, &succeeded, &error);
        free(response);
        if (result != MAELYS_GIT_OK || !succeeded || strcmp(grants.sha256, second_sha) != 0)
            return fail("a new snapshot was not kept");
        if (unlink(recorded) != 0) return fail("cannot remove recorded arguments");
    }
    char bytes[256];
    if (!read_text(kept, bytes, sizeof(bytes)) || strcmp(bytes, first) != 0)
        return fail("the store lost the bytes an earlier command used");

    /* An entry that no longer holds the bytes its name says is refused, and
     * an unwritable store too: no executor starts, the command fails. */
    char second_kept[4200];
    (void)snprintf(second_kept, sizeof(second_kept), "%s/%s.json", store, second_sha);
    if (chmod(second_kept, 0600) != 0 || !write_text(second_kept, "tampered") || chmod(second_kept, 0400) != 0)
        return fail("cannot tamper with the store entry");
    static const char third[] = "third generation of grants";
    for (int test = 0; test < 2; ++test) {
        if (test == 1) {
            if (!publish(source, third) || chmod(store, 0500) != 0) return fail("cannot close the store");
        }
        response = NULL;
        succeeded = 1;
        result = mg_supervisor_execute(&config, &command, "{}", &grants, &response, &succeeded, &error);
        int refused = result == MAELYS_GIT_OK && response && !succeeded && !grants.sha256[0] &&
                      strstr(response, "\"status\":\"failed\"") &&
                      strstr(response, "\"message\":\"grants store unavailable: ") &&
                      mg_protocol_validate_result(response, strlen(response), &command, &succeeded, &error) ==
                          MAELYS_GIT_OK &&
                      !succeeded;
        free(response);
        if (!refused) return fail(test ? "an unwritable store did not fail the command"
                                       : "a tampered store entry was trusted");
        if (access(recorded, F_OK) == 0) return fail("an executor started without its kept snapshot");
    }
    if (chmod(store, 0700) != 0) return fail("cannot reopen the store");
    if (!remove_entries(store) || rmdir(store) != 0 || unlink(source) != 0)
        return fail("cannot remove the store");
    if (rmdir(directory) != 0) return fail("cannot remove temporary directory");
    return 0;
}
