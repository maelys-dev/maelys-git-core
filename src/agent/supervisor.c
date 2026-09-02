#include "agent_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <spawn.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
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

maelys_git_result_t mg_supervisor_execute(const maelys_git_agent_config_t *config,
                                          const char *request_json,
                                          char **out_response_json,
                                          maelys_git_error_t *error) {
    if (!config || !request_json || !out_response_json) return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    *out_response_json = NULL;
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
        (char *)config->git_executable, NULL
    };
    pid_t child = -1;
    maelys_git_result_t spawn_result = mg_spawn_isolated(
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
    char *response = malloc(MAELYS_GIT_MAX_PROTOCOL_LINE + 2u);
    size_t used = 0u;
    int read_failed = 0;
    while (wrote && response && used < MAELYS_GIT_MAX_PROTOCOL_LINE + 1u) {
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
                             MAELYS_GIT_MAX_PROTOCOL_LINE + 1u - used);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) { read_failed = 1; break; }
        if (count == 0) break;
        used += (size_t)count;
    }
    close_fd(&output_pipe[0]);
    int oversized = used > MAELYS_GIT_MAX_PROTOCOL_LINE;
    if (!wrote || !response || timed_out || read_failed || oversized)
        mg_terminate_process_group(child);
    int status = 0;
    pid_t waited;
    do { waited = waitpid(child, &status, 0); } while (waited < 0 && errno == EINTR);
    if (!wrote || !response || timed_out || read_failed || used == 0u ||
        oversized || waited != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        free(response);
        maelys_git_result_t result = timed_out || oversized ?
            MAELYS_GIT_ERR_LIMIT : MAELYS_GIT_ERR_PROCESS;
        mg_error_set(error, result, errno,
                     timed_out ? "executor process group timed out" :
                     oversized ? "executor response exceeded 64 KiB" :
                     read_failed ? "executor response read failed" : "executor failed");
        return result;
    }
    while (used > 0u && (response[used - 1u] == '\n' || response[used - 1u] == '\r')) --used;
    response[used] = '\0';
    json_error_t json_error;
    json_t *root = json_loadb(response, used, JSON_REJECT_DUPLICATES, &json_error);
    if (!root || !json_is_object(root)) {
        json_decref(root);
        free(response);
        mg_error_set(error, MAELYS_GIT_ERR_PROTOCOL, 0, "executor returned invalid JSON");
        return MAELYS_GIT_ERR_PROTOCOL;
    }
    json_decref(root);
    *out_response_json = response;
    return MAELYS_GIT_OK;
}
