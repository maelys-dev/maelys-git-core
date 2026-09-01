#include "agent_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

static void close_fd(int *fd) {
    if (*fd >= 0) { (void)close(*fd); *fd = -1; }
}

static int write_all(int fd, const void *bytes, size_t length) {
    const unsigned char *cursor = bytes;
    while (length > 0u) {
        ssize_t count = write(fd, cursor, length);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return 0;
        cursor += (size_t)count;
        length -= (size_t)count;
    }
    return 1;
}

maelys_git_result_t mg_supervisor_execute(const maelys_git_agent_config_t *config,
                                          const char *request_json,
                                          char **out_response_json,
                                          maelys_git_error_t *error) {
    if (!config || !request_json || !out_response_json) return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    *out_response_json = NULL;
    int input_pipe[2] = {-1, -1};
    int output_pipe[2] = {-1, -1};
    if (pipe(input_pipe) != 0 || pipe(output_pipe) != 0) {
        close_fd(&input_pipe[0]); close_fd(&input_pipe[1]);
        close_fd(&output_pipe[0]); close_fd(&output_pipe[1]);
        mg_error_set(error, MAELYS_GIT_ERR_IO, errno, "cannot create executor pipes");
        return MAELYS_GIT_ERR_IO;
    }
    (void)fcntl(input_pipe[0], F_SETFD, FD_CLOEXEC);
    (void)fcntl(input_pipe[1], F_SETFD, FD_CLOEXEC);
    (void)fcntl(output_pipe[0], F_SETFD, FD_CLOEXEC);
    (void)fcntl(output_pipe[1], F_SETFD, FD_CLOEXEC);
    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_adddup2(&actions, input_pipe[0], STDIN_FILENO);
    posix_spawn_file_actions_adddup2(&actions, output_pipe[1], STDOUT_FILENO);
    posix_spawn_file_actions_addclose(&actions, input_pipe[1]);
    posix_spawn_file_actions_addclose(&actions, output_pipe[0]);
    char *argv[] = {
        (char *)config->executor_path, "serve", "--manifest", (char *)config->manifest_path,
        "--root", (char *)config->repository_root, "--git",
        (char *)config->git_executable, NULL
    };
    pid_t child = -1;
    int spawn_result = posix_spawn(&child, config->executor_path, &actions, NULL, argv, environ);
    posix_spawn_file_actions_destroy(&actions);
    close_fd(&input_pipe[0]);
    close_fd(&output_pipe[1]);
    if (spawn_result != 0) {
        close_fd(&input_pipe[1]); close_fd(&output_pipe[0]);
        mg_error_set(error, MAELYS_GIT_ERR_PROCESS, spawn_result, "cannot launch isolated executor");
        return MAELYS_GIT_ERR_PROCESS;
    }
    size_t request_length = strlen(request_json);
    int wrote = write_all(input_pipe[1], request_json, request_length) &&
                write_all(input_pipe[1], "\n", 1u);
    close_fd(&input_pipe[1]);
    char *response = malloc(MAELYS_GIT_MAX_PROTOCOL_LINE + 2u);
    size_t used = 0u;
    int timed_out = 0;
    while (wrote && response && used < MAELYS_GIT_MAX_PROTOCOL_LINE + 1u) {
        struct pollfd descriptor = {.fd = output_pipe[0], .events = POLLIN};
        int ready = poll(&descriptor, 1, (int)config->request_timeout_ms);
        if (ready < 0 && errno == EINTR) continue;
        if (ready == 0) { timed_out = 1; break; }
        if (ready < 0) break;
        ssize_t count = read(output_pipe[0], response + used,
                             MAELYS_GIT_MAX_PROTOCOL_LINE + 1u - used);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) break;
        used += (size_t)count;
    }
    close_fd(&output_pipe[0]);
    if (timed_out) (void)kill(child, SIGKILL);
    int status = 0;
    while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
    if (!wrote || !response || timed_out || used == 0u ||
        used > MAELYS_GIT_MAX_PROTOCOL_LINE || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        free(response);
        mg_error_set(error, timed_out ? MAELYS_GIT_ERR_LIMIT : MAELYS_GIT_ERR_PROCESS, errno,
                     timed_out ? "executor timed out" : "executor failed");
        return timed_out ? MAELYS_GIT_ERR_LIMIT : MAELYS_GIT_ERR_PROCESS;
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
