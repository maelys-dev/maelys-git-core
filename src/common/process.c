#include "internal.h"

#include <errno.h>
#include <dirent.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <spawn.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;

#define MG_PROCESS_TIMEOUT_MS 120000LL

static long long monotonic_ms(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return -1;
    return (long long)now.tv_sec * 1000LL + now.tv_nsec / 1000000LL;
}

static void terminate_child(pid_t pid) {
    (void)kill(pid, SIGTERM);
    struct timespec pause = {.tv_sec = 0, .tv_nsec = 100000000L};
    (void)nanosleep(&pause, NULL);
    if (waitpid(pid, NULL, WNOHANG) == 0) (void)kill(pid, SIGKILL);
}

static maelys_git_result_t wait_child(pid_t pid,
                                      int *out_exit_status,
                                      int require_success,
                                      maelys_git_error_t *error) {
    int status = 0;
    long long started = monotonic_ms();
    for (;;) {
        pid_t waited = waitpid(pid, &status, WNOHANG);
        if (waited == pid) break;
        if (waited < 0 && errno != EINTR) {
            mg_error_set(error, MAELYS_GIT_ERR_PROCESS, errno, "waitpid failed: %s", strerror(errno));
            return MAELYS_GIT_ERR_PROCESS;
        }
        long long now = monotonic_ms();
        if (started >= 0 && now >= 0 && now - started >= MG_PROCESS_TIMEOUT_MS) {
            terminate_child(pid);
            while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
            }
            mg_error_set(error, MAELYS_GIT_ERR_PROCESS, 0,
                         "child process exceeded the %lld ms execution limit",
                         MG_PROCESS_TIMEOUT_MS);
            return MAELYS_GIT_ERR_PROCESS;
        }
        struct timespec pause = {.tv_sec = 0, .tv_nsec = 10000000L};
        (void)nanosleep(&pause, NULL);
    }
    int exit_status = WIFEXITED(status) ? WEXITSTATUS(status) : 128;
    if (out_exit_status) *out_exit_status = exit_status;
    if (!WIFEXITED(status) || (require_success && exit_status != 0)) {
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
    return wait_child(pid, out_exit_status, 1, error);
}

maelys_git_result_t mg_process_run_status(const char *executable,
                                          char *const argv[],
                                          int *out_exit_status,
                                          maelys_git_error_t *error) {
    if (!executable || !argv || !out_exit_status) return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    pid_t pid = 0;
    int rc = posix_spawn(&pid, executable, NULL, NULL, argv, environ);
    if (rc != 0) {
        mg_error_set(error, MAELYS_GIT_ERR_PROCESS, rc, "posix_spawn failed: %s", strerror(rc));
        return MAELYS_GIT_ERR_PROCESS;
    }
    return wait_child(pid, out_exit_status, 0, error);
}

static maelys_git_result_t process_capture_status(const char *executable,
                                                  char *const argv[],
                                                  unsigned char **out_data,
                                                  size_t *out_length,
                                                  size_t max_length,
                                                  int reject_overflow,
                                                  int *out_exit_status,
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
        (void)wait_child(pid, NULL, 0, NULL);
        mg_error_set(error, MAELYS_GIT_ERR_IO, ENOMEM, "unable to allocate process output buffer");
        return MAELYS_GIT_ERR_IO;
    }

    size_t used = 0u;
    int overflow = 0;
    long long started = monotonic_ms();
    for (;;) {
        struct pollfd descriptor = {.fd = pipe_fds[0], .events = POLLIN | POLLHUP};
        int ready = poll(&descriptor, 1u, 100);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0) {
            int saved = errno;
            terminate_child(pid);
            free(data);
            (void)close(pipe_fds[0]);
            (void)waitpid(pid, NULL, 0);
            mg_error_set(error, MAELYS_GIT_ERR_IO, saved, "poll child output failed: %s", strerror(saved));
            return MAELYS_GIT_ERR_IO;
        }
        long long now = monotonic_ms();
        if (started >= 0 && now >= 0 && now - started >= MG_PROCESS_TIMEOUT_MS) {
            terminate_child(pid);
            close(pipe_fds[0]);
            while (waitpid(pid, NULL, 0) < 0 && errno == EINTR) {
            }
            free(data);
            mg_error_set(error, MAELYS_GIT_ERR_PROCESS, 0,
                         "child process exceeded the %lld ms execution limit",
                         MG_PROCESS_TIMEOUT_MS);
            return MAELYS_GIT_ERR_PROCESS;
        }
        if (ready == 0) continue;
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
            (void)wait_child(pid, NULL, 0, NULL);
            mg_error_set(error, MAELYS_GIT_ERR_IO, saved, "read from child failed: %s", strerror(saved));
            return MAELYS_GIT_ERR_IO;
        }
        break;
    }
    (void)close(pipe_fds[0]);
    int exit_status = 0;
    maelys_git_result_t wait_result = wait_child(pid, &exit_status, 0, error);
    if (wait_result != MAELYS_GIT_OK) {
        free(data);
        return wait_result;
    }
    if (reject_overflow && (overflow || used == max_length)) {
        free(data);
        mg_error_set(error, MAELYS_GIT_ERR_LIMIT, 0, "child output exceeds %zu bytes", max_length);
        return MAELYS_GIT_ERR_LIMIT;
    }
    data[used] = '\0';
    *out_data = data;
    *out_length = used;
    if (out_exit_status) *out_exit_status = exit_status;
    return MAELYS_GIT_OK;
}

maelys_git_result_t mg_process_capture_status(const char *executable,
                                              char *const argv[],
                                              unsigned char **out_data,
                                              size_t *out_length,
                                              size_t max_length,
                                              int *out_exit_status,
                                              maelys_git_error_t *error) {
    return process_capture_status(executable, argv, out_data, out_length,
                                  max_length, 1, out_exit_status, error);
}

maelys_git_result_t mg_process_capture_prefix(const char *executable,
                                              char *const argv[],
                                              unsigned char **out_data,
                                              size_t *out_length,
                                              size_t prefix_length,
                                              int *out_exit_status,
                                              maelys_git_error_t *error) {
    return process_capture_status(executable, argv, out_data, out_length,
                                  prefix_length, 0, out_exit_status, error);
}

maelys_git_result_t mg_process_capture(const char *executable,
                                       char *const argv[],
                                       unsigned char **out_data,
                                       size_t *out_length,
                                       size_t max_length,
                                       maelys_git_error_t *error) {
    int status = 0;
    maelys_git_result_t result = mg_process_capture_status(
        executable, argv, out_data, out_length, max_length, &status, error);
    if (result != MAELYS_GIT_OK) return result;
    if (status != 0) {
        free(*out_data);
        *out_data = NULL;
        *out_length = 0u;
        mg_error_set(error, MAELYS_GIT_ERR_PROCESS, 0,
                     "child process failed with status %d", status);
        return MAELYS_GIT_ERR_PROCESS;
    }
    return MAELYS_GIT_OK;
}

maelys_git_result_t mg_process_to_file(const char *executable,
                                       char *const argv[],
                                       FILE *output,
                                       int *out_exit_status,
                                       maelys_git_error_t *error) {
    return mg_process_spool_status(executable, argv, output,
                                   256u * 1024u * 1024u,
                                   out_exit_status, error);
}

static maelys_git_result_t process_filter_spool_status(
    const char *executable,
    char *const argv[],
    FILE *input,
    FILE *output,
    size_t max_length,
    int *out_exit_status,
    maelys_git_error_t *error) {
    if (!executable || !argv || !output || !out_exit_status || max_length == 0u)
        return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    int input_fd = input ? fileno(input) : -1;
    if (input && input_fd < 0) return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    int pipe_fds[2];
    if (pipe(pipe_fds) != 0) {
        mg_error_set(error, MAELYS_GIT_ERR_IO, errno,
                     "pipe failed: %s", strerror(errno));
        return MAELYS_GIT_ERR_IO;
    }
    posix_spawn_file_actions_t actions;
    int rc = posix_spawn_file_actions_init(&actions);
    if (rc == 0 && input)
        rc = posix_spawn_file_actions_adddup2(&actions, input_fd, STDIN_FILENO);
    if (rc == 0) rc = posix_spawn_file_actions_adddup2(&actions, pipe_fds[1], STDOUT_FILENO);
    if (rc == 0) rc = posix_spawn_file_actions_addclose(&actions, pipe_fds[0]);
    if (rc == 0) rc = posix_spawn_file_actions_addclose(&actions, pipe_fds[1]);
    if (rc != 0) {
        (void)posix_spawn_file_actions_destroy(&actions);
        close(pipe_fds[0]); close(pipe_fds[1]);
        mg_error_set(error, MAELYS_GIT_ERR_PROCESS, rc, "spawn action setup failed: %s", strerror(rc));
        return MAELYS_GIT_ERR_PROCESS;
    }
    pid_t pid = 0;
    rc = posix_spawn(&pid, executable, &actions, NULL, argv, environ);
    (void)posix_spawn_file_actions_destroy(&actions);
    close(pipe_fds[1]);
    if (rc != 0) {
        close(pipe_fds[0]);
        mg_error_set(error, MAELYS_GIT_ERR_PROCESS, rc, "posix_spawn failed: %s", strerror(rc));
        return MAELYS_GIT_ERR_PROCESS;
    }
    unsigned char buffer[16384];
    size_t total = 0u;
    int overflow = 0;
    long long started = monotonic_ms();
    for (;;) {
        struct pollfd descriptor = {.fd = pipe_fds[0], .events = POLLIN | POLLHUP};
        int ready = poll(&descriptor, 1u, 100);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0) {
            int saved = errno;
            terminate_child(pid);
            close(pipe_fds[0]);
            (void)waitpid(pid, NULL, 0);
            mg_error_set(error, MAELYS_GIT_ERR_IO, saved,
                         "poll child output failed: %s", strerror(saved));
            return MAELYS_GIT_ERR_IO;
        }
        long long now = monotonic_ms();
        if (started >= 0 && now >= 0 && now - started >= MG_PROCESS_TIMEOUT_MS) {
            terminate_child(pid); close(pipe_fds[0]);
            while (waitpid(pid, NULL, 0) < 0 && errno == EINTR) {
            }
            mg_error_set(error, MAELYS_GIT_ERR_PROCESS, 0,
                         "child process exceeded the %lld ms execution limit",
                         MG_PROCESS_TIMEOUT_MS);
            return MAELYS_GIT_ERR_PROCESS;
        }
        if (ready == 0) continue;
        ssize_t count = read(pipe_fds[0], buffer, sizeof(buffer));
        if (count > 0) {
            if ((size_t)count > max_length - (total > max_length ? max_length : total)) {
                overflow = 1;
            } else if (!overflow && fwrite(buffer, 1u, (size_t)count, output) != (size_t)count) {
                int saved = errno;
                terminate_child(pid); close(pipe_fds[0]); (void)waitpid(pid, NULL, 0);
                mg_error_set(error, MAELYS_GIT_ERR_IO, saved,
                             "write child output failed: %s", strerror(saved));
                return MAELYS_GIT_ERR_IO;
            }
            total += (size_t)count;
            if (overflow) terminate_child(pid);
            continue;
        }
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) {
            int saved = errno;
            terminate_child(pid); close(pipe_fds[0]); (void)waitpid(pid, NULL, 0);
            mg_error_set(error, MAELYS_GIT_ERR_IO, saved,
                         "read from child failed: %s", strerror(saved));
            return MAELYS_GIT_ERR_IO;
        }
        break;
    }
    close(pipe_fds[0]);
    if (overflow) {
        while (waitpid(pid, NULL, 0) < 0 && errno == EINTR) {
        }
        mg_error_set(error, MAELYS_GIT_ERR_LIMIT, 0,
                     "child output exceeds %zu bytes", max_length);
        return MAELYS_GIT_ERR_LIMIT;
    }
    maelys_git_result_t result = wait_child(pid, out_exit_status, 0, error);
    if (result == MAELYS_GIT_OK && fflush(output) != 0) {
        mg_error_set(error, MAELYS_GIT_ERR_IO, errno, "flush child output failed: %s", strerror(errno));
        return MAELYS_GIT_ERR_IO;
    }
    return result;
}

maelys_git_result_t mg_process_spool_status(const char *executable,
                                            char *const argv[],
                                            FILE *output,
                                            size_t max_length,
                                            int *out_exit_status,
                                            maelys_git_error_t *error) {
    return process_filter_spool_status(executable, argv, NULL, output,
                                       max_length, out_exit_status, error);
}

maelys_git_result_t mg_process_filter_spool_status(const char *executable,
                                                   char *const argv[],
                                                   FILE *input,
                                                   FILE *output,
                                                   size_t max_length,
                                                   int *out_exit_status,
                                                   maelys_git_error_t *error) {
    if (!input) return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    if (fflush(input) != 0 || fseek(input, 0L, SEEK_SET) != 0) {
        mg_error_set(error, MAELYS_GIT_ERR_IO, errno,
                     "cannot rewind child input: %s", strerror(errno));
        return MAELYS_GIT_ERR_IO;
    }
    return process_filter_spool_status(executable, argv, input, output,
                                       max_length, out_exit_status, error);
}

int mg_remove_tree(const char *path) {
    if (!path || !*path || !strcmp(path, "/")) return 0;
    struct stat status;
    if (lstat(path, &status) != 0) return errno == ENOENT;
    if (!S_ISDIR(status.st_mode)) return unlink(path) == 0;
    DIR *directory = opendir(path);
    if (!directory) return 0;
    int ok = 1;
    struct dirent *entry;
    while ((entry = readdir(directory)) != NULL) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        char child[4096];
        int count = snprintf(child, sizeof(child), "%s/%s", path, entry->d_name);
        if (count < 0 || (size_t)count >= sizeof(child) || !mg_remove_tree(child)) ok = 0;
    }
    (void)closedir(directory);
    return rmdir(path) == 0 && ok;
}
