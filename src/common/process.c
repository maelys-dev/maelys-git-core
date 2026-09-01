#include "internal.h"

#include <errno.h>
#include <spawn.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

static maelys_git_result_t wait_child(pid_t pid,
                                      int *out_exit_status,
                                      maelys_git_error_t *error) {
    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno == EINTR) continue;
        mg_error_set(error, MAELYS_GIT_ERR_PROCESS, errno, "waitpid failed: %s", strerror(errno));
        return MAELYS_GIT_ERR_PROCESS;
    }
    int exit_status = WIFEXITED(status) ? WEXITSTATUS(status) : 128;
    if (out_exit_status) *out_exit_status = exit_status;
    if (!WIFEXITED(status) || exit_status != 0) {
        mg_error_set(error,
                     MAELYS_GIT_ERR_PROCESS,
                     0,
                     "child process failed with status %d",
                     exit_status);
        return MAELYS_GIT_ERR_PROCESS;
    }
    return MAELYS_GIT_OK;
}

maelys_git_result_t mg_process_run(const char *executable,
                                   char *const argv[],
                                   int *out_exit_status,
                                   maelys_git_error_t *error) {
    if (!executable || !argv) return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    pid_t pid = 0;
    int rc = posix_spawn(&pid, executable, NULL, NULL, argv, environ);
    if (rc != 0) {
        mg_error_set(error, MAELYS_GIT_ERR_PROCESS, rc, "posix_spawn failed: %s", strerror(rc));
        return MAELYS_GIT_ERR_PROCESS;
    }
    return wait_child(pid, out_exit_status, error);
}

maelys_git_result_t mg_process_capture(const char *executable,
                                       char *const argv[],
                                       unsigned char **out_data,
                                       size_t *out_length,
                                       size_t max_length,
                                       maelys_git_error_t *error) {
    if (!executable || !argv || !out_data || !out_length || max_length == 0u) {
        return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    }
    *out_data = NULL;
    *out_length = 0u;
    int pipe_fds[2];
    if (pipe(pipe_fds) != 0) {
        mg_error_set(error, MAELYS_GIT_ERR_IO, errno, "pipe failed: %s", strerror(errno));
        return MAELYS_GIT_ERR_IO;
    }

    posix_spawn_file_actions_t actions;
    int rc = posix_spawn_file_actions_init(&actions);
    if (rc == 0) rc = posix_spawn_file_actions_adddup2(&actions, pipe_fds[1], STDOUT_FILENO);
    if (rc == 0) rc = posix_spawn_file_actions_addclose(&actions, pipe_fds[0]);
    if (rc == 0) rc = posix_spawn_file_actions_addclose(&actions, pipe_fds[1]);
    if (rc != 0) {
        (void)close(pipe_fds[0]);
        (void)close(pipe_fds[1]);
        (void)posix_spawn_file_actions_destroy(&actions);
        mg_error_set(error, MAELYS_GIT_ERR_PROCESS, rc, "spawn action setup failed: %s", strerror(rc));
        return MAELYS_GIT_ERR_PROCESS;
    }

    pid_t pid = 0;
    rc = posix_spawn(&pid, executable, &actions, NULL, argv, environ);
    (void)posix_spawn_file_actions_destroy(&actions);
    (void)close(pipe_fds[1]);
    if (rc != 0) {
        (void)close(pipe_fds[0]);
        mg_error_set(error, MAELYS_GIT_ERR_PROCESS, rc, "posix_spawn failed: %s", strerror(rc));
        return MAELYS_GIT_ERR_PROCESS;
    }

    unsigned char *data = malloc(max_length + 1u);
    if (!data) {
        (void)close(pipe_fds[0]);
        (void)wait_child(pid, NULL, NULL);
        mg_error_set(error, MAELYS_GIT_ERR_IO, ENOMEM, "unable to allocate process output buffer");
        return MAELYS_GIT_ERR_IO;
    }

    size_t used = 0u;
    int overflow = 0;
    for (;;) {
        unsigned char discard[4096];
        unsigned char *destination = used < max_length ? data + used : discard;
        size_t available = used < max_length ? max_length - used : sizeof(discard);
        ssize_t count = read(pipe_fds[0], destination, available);
        if (count > 0) {
            if (used < max_length) used += (size_t)count;
            else overflow = 1;
            continue;
        }
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) {
            int saved = errno;
            free(data);
            (void)close(pipe_fds[0]);
            (void)wait_child(pid, NULL, NULL);
            mg_error_set(error, MAELYS_GIT_ERR_IO, saved, "read from child failed: %s", strerror(saved));
            return MAELYS_GIT_ERR_IO;
        }
        break;
    }
    (void)close(pipe_fds[0]);
    maelys_git_result_t wait_result = wait_child(pid, NULL, error);
    if (wait_result != MAELYS_GIT_OK) {
        free(data);
        return wait_result;
    }
    if (overflow || used == max_length) {
        free(data);
        mg_error_set(error, MAELYS_GIT_ERR_LIMIT, 0, "child output exceeds %zu bytes", max_length);
        return MAELYS_GIT_ERR_LIMIT;
    }
    data[used] = '\0';
    *out_data = data;
    *out_length = used;
    return MAELYS_GIT_OK;
}
