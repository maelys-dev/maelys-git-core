#include "agent_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void close_fd(int *fd) {
    if (*fd >= 0) { (void)close(*fd); *fd = -1; }
}

/* The executor's stdin is a Unix socket rather than a pipe so that a write
 * after the child exited fails with EPIPE instead of raising SIGPIPE: the
 * parent's end is marked SO_NOSIGPIPE where the platform has it, and writes
 * use MSG_NOSIGNAL where that exists. The process signal dispositions are
 * never touched. Element 0 goes to the child, element 1 stays here. */
static int open_request_channel(int fds[2]) {
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) return 0;
    int ok = 1;
    for (size_t i = 0u; i < 2u; ++i) {
        int flags = fcntl(fds[i], F_GETFD);
        if (flags < 0 || fcntl(fds[i], F_SETFD, flags | FD_CLOEXEC) != 0) ok = 0;
    }
#ifdef SO_NOSIGPIPE
    int no_sigpipe = 1;
    if (ok && setsockopt(fds[1], SOL_SOCKET, SO_NOSIGPIPE, &no_sigpipe,
                         sizeof(no_sigpipe)) != 0)
        ok = 0;
#endif
    if (!ok) {
        int saved = errno;
        (void)close(fds[0]);
        (void)close(fds[1]);
        fds[0] = fds[1] = -1;
        errno = saved;
    }
    return ok;
}

static ssize_t write_quiet(int fd, const void *bytes, size_t length) {
#ifdef MSG_NOSIGNAL
    return send(fd, bytes, length, MSG_NOSIGNAL);
#else
    return write(fd, bytes, length);
#endif
}

static int remaining_timeout(int64_t deadline, int *out_timeout) {
    int64_t now = mg_monotonic_ms();
    if (deadline < 0 || now < 0) return 0;
    int64_t remaining = deadline - now;
    if (remaining <= 0) {
        *out_timeout = 0;
        return 1;
    }
    *out_timeout = remaining > INT_MAX ? INT_MAX : (int)remaining;
    return 1;
}

static int write_all_until(int fd, const void *bytes, size_t length,
                           int64_t deadline, int *out_timed_out) {
    int descriptor_flags = fcntl(fd, F_GETFL);
    if (descriptor_flags < 0 ||
        fcntl(fd, F_SETFL, descriptor_flags | O_NONBLOCK) != 0)
        return 0;
    const unsigned char *cursor = bytes;
    int ok = 1;
    while (length > 0u) {
        ssize_t count = write_quiet(fd, cursor, length);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            int timeout = 0;
            if (!remaining_timeout(deadline, &timeout)) { ok = 0; break; }
            if (timeout == 0) { *out_timed_out = 1; ok = 0; break; }
            struct pollfd descriptor = {
                .fd = fd, .events = POLLOUT | POLLHUP | POLLERR};
            int ready = poll(&descriptor, 1u, timeout);
            if (ready < 0 && errno == EINTR) continue;
            if (ready == 0) *out_timed_out = 1;
            if (ready <= 0 || (descriptor.revents & (POLLHUP | POLLERR))) {
                ok = 0;
                break;
            }
            continue;
        }
        if (count <= 0) { ok = 0; break; }
        cursor += (size_t)count;
        length -= (size_t)count;
    }
    int saved = errno;
    if (fcntl(fd, F_SETFL, descriptor_flags) != 0) ok = 0;
    errno = saved;
    return ok;
}

/* Observes the executor's end without reaping it: 0 with *ended naming it
 * once it ended, 0 with si_pid 0 while it runs, -1 with errno otherwise. */
static int observe_executor(pid_t child, siginfo_t *ended) {
#if defined(MG_SUPERVISOR_WAIT_FAULT)
    /* A test build whose first observation fails as a host may refuse it. */
    static int faulted;
    if (!faulted) {
        faulted = 1;
        errno = EPERM;
        return -1;
    }
#endif
    return waitid(P_PID, (id_t)child, ended, WEXITED | WNOWAIT | WNOHANG);
}

/* One executor for COMMAND, on the kept snapshot GRANTS names (none when its
 * digest is empty). */
static maelys_git_result_t run_executor(const maelys_git_agent_config_t *config,
                                        const mg_agent_message_t *command,
                                        const char *request_json,
                                        const mg_grants_archive_t *grants,
                                        char **out_response_json,
                                        int *out_succeeded,
                                        maelys_git_error_t *error) {
    /* The supervisor alone reaps its executor, and only after the last
     * signal to its group: that is what keeps the group's number the
     * executor's own. A SIGCHLD disposition the kernel reaps by, ignored or
     * SA_NOCLDWAIT, inherited from whatever started the agent, would reap it
     * first; no executor starts under it. */
    struct sigaction on_child;
    if (sigaction(SIGCHLD, NULL, &on_child) != 0 || on_child.sa_handler == SIG_IGN ||
        (on_child.sa_flags & SA_NOCLDWAIT)) {
        mg_error_set(error, MAELYS_GIT_ERR_PROCESS, 0,
                     "the supervisor cannot keep its executor: SIGCHLD is ignored");
        return MAELYS_GIT_ERR_PROCESS;
    }
    int input_pipe[2] = {-1, -1};
    int output_pipe[2] = {-1, -1};
    if (!open_request_channel(input_pipe) || !mg_pipe_cloexec(output_pipe)) {
        close_fd(&input_pipe[0]); close_fd(&input_pipe[1]);
        close_fd(&output_pipe[0]); close_fd(&output_pipe[1]);
        mg_error_set(error, MAELYS_GIT_ERR_IO, errno, "cannot create executor pipes");
        return MAELYS_GIT_ERR_IO;
    }
    posix_spawn_file_actions_t actions;
    int action_result = posix_spawn_file_actions_init(&actions);
    int actions_initialized = action_result == 0;
    if (action_result == 0)
        action_result = posix_spawn_file_actions_adddup2(
            &actions, input_pipe[0], STDIN_FILENO);
    if (action_result == 0)
        action_result = posix_spawn_file_actions_adddup2(
            &actions, output_pipe[1], STDOUT_FILENO);
    if (action_result == 0)
        action_result = posix_spawn_file_actions_addclose(&actions, input_pipe[0]);
    if (action_result == 0)
        action_result = posix_spawn_file_actions_addclose(&actions, input_pipe[1]);
    if (action_result == 0)
        action_result = posix_spawn_file_actions_addclose(&actions, output_pipe[0]);
    if (action_result == 0)
        action_result = posix_spawn_file_actions_addclose(&actions, output_pipe[1]);
    if (action_result != 0) {
        if (actions_initialized) (void)posix_spawn_file_actions_destroy(&actions);
        close_fd(&input_pipe[0]); close_fd(&input_pipe[1]);
        close_fd(&output_pipe[0]); close_fd(&output_pipe[1]);
        mg_error_set(error, MAELYS_GIT_ERR_PROCESS, action_result,
                     "cannot configure isolated executor descriptors");
        return MAELYS_GIT_ERR_PROCESS;
    }
    char *argv[] = {
        (char *)config->executor_path, "serve", "--manifest", (char *)config->manifest_path,
        "--root", (char *)config->repository_root, "--git",
        (char *)config->git_executable, NULL, NULL, NULL, NULL, NULL
    };
    /* The kept snapshot, never the configured path, and the digest every
     * reading of it must have. */
    if (grants->sha256[0]) {
        argv[8] = "--grants";
        argv[9] = (char *)grants->path;
        argv[10] = "--expected-grants-fingerprint";
        argv[11] = (char *)grants->sha256;
    }
    pid_t child = -1;
    maelys_git_result_t spawn_result = mg_spawn_executor(
        &child, config->executor_path, &actions, argv, error);
    (void)posix_spawn_file_actions_destroy(&actions);
    close_fd(&input_pipe[0]);
    close_fd(&output_pipe[1]);
    if (spawn_result != MAELYS_GIT_OK) {
        close_fd(&input_pipe[1]); close_fd(&output_pipe[0]);
        return spawn_result;
    }
    int64_t deadline = mg_monotonic_ms();
    if (deadline >= 0) deadline += (int64_t)config->request_timeout_ms;
    size_t request_length = strlen(request_json);
    int timed_out = 0;
    int wrote = deadline >= 0 &&
                write_all_until(input_pipe[1], request_json, request_length,
                                deadline, &timed_out) &&
                write_all_until(input_pipe[1], "\n", 1u, deadline, &timed_out);
    close_fd(&input_pipe[1]);
    /* JSON bytes plus CRLF and one probe byte to detect overflow. */
    const size_t wire_capacity = MAELYS_GIT_MAX_PROTOCOL_LINE + 3u;
    char *response = malloc(wire_capacity + 1u);
    size_t used = 0u;
    int read_failed = 0;
    while (wrote && response && used < wire_capacity) {
        int timeout = 0;
        if (!remaining_timeout(deadline, &timeout)) { read_failed = 1; break; }
        if (timeout == 0) { timed_out = 1; break; }
        struct pollfd descriptor = {
            .fd = output_pipe[0], .events = POLLIN | POLLHUP | POLLERR};
        int ready = poll(&descriptor, 1, timeout);
        if (ready < 0 && errno == EINTR) continue;
        if (ready == 0) { timed_out = 1; break; }
        if (ready < 0) { read_failed = 1; break; }
        ssize_t count = read(output_pipe[0], response + used,
                             wire_capacity - used);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) { read_failed = 1; break; }
        if (count == 0) break;
        used += (size_t)count;
    }
    close_fd(&output_pipe[0]);
    int oversized = used > MAELYS_GIT_MAX_PROTOCOL_LINE + 2u;
    /* One escalation, SIGTERM, a grace, SIGKILL, for the whole group: now
     * when the exchange failed, else once the executor has ended. */
    int escalated = !wrote || !response || timed_out || read_failed || oversized;
    if (escalated) mg_terminate_process_group(child);
    /* The executor's end is observed without reaping it: its number, the
     * group's, stays its own until the last signal below has been sent. A
     * wait that fails with ECHILD says something else reaped it: the number
     * is nobody's to signal, and the request fails. Any other failure of
     * the wait, as a seccomp filter may answer, leaves the executor where it
     * is: the group is stopped once, the executor reaped last, and the
     * request fails with that error even when the reap succeeds. */
    int lost = 0, wait_failed = 0;
    for (;;) {
        siginfo_t ended;
        memset(&ended, 0, sizeof(ended));
        int observed = observe_executor(child, &ended);
        if (observed < 0 && errno == EINTR) continue;
        if (observed < 0) {
            wait_failed = errno;
            lost = errno == ECHILD;
            break;
        }
        if (ended.si_pid == child) break;
        int timeout = 0;
        if (!remaining_timeout(deadline, &timeout) || timeout == 0) {
            timed_out = 1;
            break;
        }
        struct timespec pause = {0, 1000000L * (timeout < 10 ? timeout : 10)};
        (void)nanosleep(&pause, NULL);
    }
    /* No descendant may keep mutating repositories after a terminal result,
     * even if the executor returned successfully or closed stdout early. The
     * leader is not reaped yet, so the group's number can name no stranger,
     * and a descendant that ignores SIGTERM still takes the SIGKILL. */
    if (!lost && !escalated) mg_terminate_process_group(child);
    int status = 0;
    pid_t waited = 0;
    if (!lost) {
        do { waited = waitpid(child, &status, 0); } while (waited < 0 && errno == EINTR);
    }
    if (!wrote || !response || timed_out || read_failed || wait_failed || used == 0u ||
        oversized || waited != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        free(response);
        maelys_git_result_t result = timed_out || oversized ?
            MAELYS_GIT_ERR_LIMIT : MAELYS_GIT_ERR_PROCESS;
        if (wait_failed && !lost) {
            mg_error_set(error, result, wait_failed, "executor wait failed: %s",
                         strerror(wait_failed));
            return result;
        }
        mg_error_set(error, result, errno,
                     timed_out ? "executor process group timed out" :
                     oversized ? "executor response exceeded 64 KiB" :
                     read_failed ? "executor response read failed" :
                     lost ? "executor was reaped outside the supervisor" : "executor failed");
        return result;
    }
    /* Exactly one JSONL response: no missing delimiter or second frame. */
    if (response[used - 1u] != '\n' || memchr(response, '\n', used - 1u)) {
        free(response);
        mg_error_set(error, MAELYS_GIT_ERR_PROTOCOL, 0, "executor must return one complete JSONL result");
        return MAELYS_GIT_ERR_PROTOCOL;
    }
    --used;
    if (used > 0u && response[used - 1u] == '\r') --used;
    response[used] = '\0';
    maelys_git_result_t validated = mg_protocol_validate_result(
        response, used, command, out_succeeded, error);
    if (validated != MAELYS_GIT_OK) {
        free(response);
        return validated;
    }
    *out_response_json = response;
    return MAELYS_GIT_OK;
}

maelys_git_result_t mg_supervisor_execute(const maelys_git_agent_config_t *config,
                                          const mg_agent_message_t *command,
                                          const char *request_json,
                                          mg_grants_archive_t *out_grants,
                                          char **out_response_json,
                                          int *out_succeeded,
                                          maelys_git_error_t *error) {
    if (!out_response_json || !out_succeeded) return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    *out_response_json = NULL;
    *out_succeeded = 0;
    mg_grants_archive_t local_grants;
    mg_grants_archive_t *grants = out_grants ? out_grants : &local_grants;
    memset(grants, 0, sizeof(*grants));
    grants->lock = -1;
    if (!config || !command || !request_json) return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    /* The bytes the executor will read are kept before it starts; without
     * them it does not start. */
    if (config->grants_path[0]) {
        maelys_git_error_t store_error = {0};
        maelys_git_result_t stored = mg_grants_store_archive(config->grants_path, config->database_path,
                                                             grants, &store_error);
        if (stored != MAELYS_GIT_OK) {
            char reason[MAELYS_GIT_MAX_ERROR];
            (void)snprintf(reason, sizeof(reason), "grants store unavailable: %.900s", store_error.message);
            mg_json_t json;
            mg_protocol_result_begin(&json, command, "failed");
            mg_json_string(&json, "code", maelys_git_result_name(stored));
            mg_json_string(&json, "message", reason);
            *out_response_json = mg_protocol_result_end(&json, error);
            return *out_response_json ? MAELYS_GIT_OK : MAELYS_GIT_ERR_IO;
        }
    }
    /* The store stays locked, shared, until the executor has exited: a purge
     * never removes the file it reads. */
    maelys_git_result_t result = run_executor(config, command, request_json, grants, out_response_json,
                                              out_succeeded, error);
    mg_grants_archive_release(grants);
    return result;
}
