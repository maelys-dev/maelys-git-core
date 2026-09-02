#include "internal.h"

#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
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

#define MG_PROCESS_TIMEOUT_MS 120000LL

static char *const isolated_environment[] = {
    "PATH=/usr/bin:/bin",
    "LANG=C",
    "LC_ALL=C",
    "GIT_CONFIG_NOSYSTEM=1",
    "GIT_CONFIG_GLOBAL=/dev/null",
    "GIT_TERMINAL_PROMPT=0",
    "GIT_ASKPASS=/bin/false",
    "SSH_ASKPASS=/bin/false",
    "GCM_INTERACTIVE=Never",
    NULL
};

int64_t mg_monotonic_ms(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return -1;
    return (int64_t)now.tv_sec * 1000LL + now.tv_nsec / 1000000LL;
}

int mg_pipe_cloexec(int pipe_fds[2]) {
    if (!pipe_fds || pipe(pipe_fds) != 0) return 0;
    for (size_t i = 0u; i < 2u; ++i) {
        int flags = fcntl(pipe_fds[i], F_GETFD);
        if (flags < 0 || fcntl(pipe_fds[i], F_SETFD, flags | FD_CLOEXEC) != 0) {
            int saved = errno;
            (void)close(pipe_fds[0]);
            (void)close(pipe_fds[1]);
            errno = saved;
            return 0;
        }
    }
    return 1;
}

maelys_git_result_t mg_spawn_isolated(
    pid_t *out_pid,
    const char *executable,
    const posix_spawn_file_actions_t *actions,
    char *const argv[],
    maelys_git_error_t *error) {
    if (!out_pid || !executable || !argv || executable[0] != '/')
        return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    posix_spawnattr_t attributes;
    int rc = posix_spawnattr_init(&attributes);
    int initialized = rc == 0;
    if (rc == 0) rc = posix_spawnattr_setpgroup(&attributes, 0);
    if (rc == 0) rc = posix_spawnattr_setflags(&attributes, POSIX_SPAWN_SETPGROUP);
    char home_entry[PATH_MAX + 6u];
    const char *home = getenv("HOME");
    int home_length = home && home[0] == '/' ?
        snprintf(home_entry, sizeof(home_entry), "HOME=%s", home) : -1;
    if (home_length < 0 || (size_t)home_length >= sizeof(home_entry))
        (void)snprintf(home_entry, sizeof(home_entry), "HOME=/nonexistent");
    char *environment[sizeof(isolated_environment) / sizeof(isolated_environment[0]) + 1u];
    environment[0] = home_entry;
    size_t environment_index = 1u;
    for (size_t i = 0u; isolated_environment[i]; ++i)
        environment[environment_index++] = isolated_environment[i];
    environment[environment_index] = NULL;
    if (rc == 0)
        rc = posix_spawn(out_pid, executable, actions, &attributes,
                         argv, environment);
    if (initialized) (void)posix_spawnattr_destroy(&attributes);
    if (rc != 0) {
        mg_error_set(error, MAELYS_GIT_ERR_PROCESS, rc,
                     "isolated posix_spawn failed: %s", strerror(rc));
        return MAELYS_GIT_ERR_PROCESS;
    }
    return MAELYS_GIT_OK;
}

void mg_terminate_process_group(pid_t pid) {
    if (pid <= 0) return;
    (void)kill(-pid, SIGTERM);
    struct timespec pause = {.tv_sec = 0, .tv_nsec = 100000000L};
    (void)nanosleep(&pause, NULL);
    (void)kill(-pid, SIGKILL);
}

static maelys_git_result_t wait_child(pid_t pid,
                                      uint64_t timeout_ms,
                                      int *out_exit_status,
                                      int require_success,
                                      maelys_git_error_t *error) {
    int status = 0;
    int64_t started = mg_monotonic_ms();
    for (;;) {
        pid_t waited = waitpid(pid, &status, WNOHANG);
        if (waited == pid) break;
        if (waited < 0 && errno != EINTR) {
            mg_error_set(error, MAELYS_GIT_ERR_PROCESS, errno, "waitpid failed: %s", strerror(errno));
            return MAELYS_GIT_ERR_PROCESS;
        }
        int64_t now = mg_monotonic_ms();
        if (started >= 0 && now >= 0 && (uint64_t)(now - started) >= timeout_ms) {
            mg_terminate_process_group(pid);
            while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
            }
            mg_error_set(error, MAELYS_GIT_ERR_PROCESS, 0,
                         "child process group exceeded the %llu ms execution limit",
                         (unsigned long long)timeout_ms);
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
    return mg_process_run_with_timeout(executable, argv, MG_PROCESS_TIMEOUT_MS,
                                       out_exit_status, error);
}

maelys_git_result_t mg_process_run_with_timeout(
    const char *executable,
    char *const argv[],
    uint64_t timeout_ms,
    int *out_exit_status,
    maelys_git_error_t *error) {
    if (!executable || !argv || timeout_ms == 0u)
        return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    pid_t pid = 0;
    maelys_git_result_t result = mg_spawn_isolated(
        &pid, executable, NULL, argv, error);
    if (result != MAELYS_GIT_OK) return result;
    return wait_child(pid, timeout_ms, out_exit_status, 1, error);
}

maelys_git_result_t mg_process_run_status(const char *executable,
                                          char *const argv[],
                                          int *out_exit_status,
                                          maelys_git_error_t *error) {
    if (!executable || !argv || !out_exit_status) return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    pid_t pid = 0;
    maelys_git_result_t result = mg_spawn_isolated(
        &pid, executable, NULL, argv, error);
    if (result != MAELYS_GIT_OK) return result;
    return wait_child(pid, MG_PROCESS_TIMEOUT_MS, out_exit_status, 0, error);
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
    if (!mg_pipe_cloexec(pipe_fds)) {
        mg_error_set(error, MAELYS_GIT_ERR_IO, errno, "pipe failed: %s", strerror(errno));
        return MAELYS_GIT_ERR_IO;
    }

    posix_spawn_file_actions_t actions;
    int rc = posix_spawn_file_actions_init(&actions);
    int actions_initialized = rc == 0;
    if (rc == 0) rc = posix_spawn_file_actions_adddup2(&actions, pipe_fds[1], STDOUT_FILENO);
    if (rc == 0) rc = posix_spawn_file_actions_addclose(&actions, pipe_fds[0]);
    if (rc == 0) rc = posix_spawn_file_actions_addclose(&actions, pipe_fds[1]);
    if (rc != 0) {
        (void)close(pipe_fds[0]);
        (void)close(pipe_fds[1]);
        if (actions_initialized) (void)posix_spawn_file_actions_destroy(&actions);
        mg_error_set(error, MAELYS_GIT_ERR_PROCESS, rc, "spawn action setup failed: %s", strerror(rc));
        return MAELYS_GIT_ERR_PROCESS;
    }

    pid_t pid = 0;
    maelys_git_result_t spawn_result = mg_spawn_isolated(
        &pid, executable, &actions, argv, error);
    (void)posix_spawn_file_actions_destroy(&actions);
    (void)close(pipe_fds[1]);
    if (spawn_result != MAELYS_GIT_OK) {
        (void)close(pipe_fds[0]);
        return spawn_result;
    }

    unsigned char *data = malloc(max_length + 1u);
    if (!data) {
        (void)close(pipe_fds[0]);
        mg_terminate_process_group(pid);
        while (waitpid(pid, NULL, 0) < 0 && errno == EINTR) {
        }
        mg_error_set(error, MAELYS_GIT_ERR_IO, ENOMEM, "unable to allocate process output buffer");
        return MAELYS_GIT_ERR_IO;
    }

    size_t used = 0u;
    int overflow = 0;
    int64_t started = mg_monotonic_ms();
    for (;;) {
        struct pollfd descriptor = {.fd = pipe_fds[0], .events = POLLIN | POLLHUP};
        int ready = poll(&descriptor, 1u, 100);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0) {
            int saved = errno;
            mg_terminate_process_group(pid);
            free(data);
            (void)close(pipe_fds[0]);
            (void)waitpid(pid, NULL, 0);
            mg_error_set(error, MAELYS_GIT_ERR_IO, saved, "poll child output failed: %s", strerror(saved));
            return MAELYS_GIT_ERR_IO;
        }
        int64_t now = mg_monotonic_ms();
        if (started >= 0 && now >= 0 && now - started >= MG_PROCESS_TIMEOUT_MS) {
            mg_terminate_process_group(pid);
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
            mg_terminate_process_group(pid);
            while (waitpid(pid, NULL, 0) < 0 && errno == EINTR) {
            }
            mg_error_set(error, MAELYS_GIT_ERR_IO, saved, "read from child failed: %s", strerror(saved));
            return MAELYS_GIT_ERR_IO;
        }
        break;
    }
    (void)close(pipe_fds[0]);
    int exit_status = 0;
    maelys_git_result_t wait_result = wait_child(
        pid, MG_PROCESS_TIMEOUT_MS, &exit_status, 0, error);
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
    if (!mg_pipe_cloexec(pipe_fds)) {
        mg_error_set(error, MAELYS_GIT_ERR_IO, errno,
                     "pipe failed: %s", strerror(errno));
        return MAELYS_GIT_ERR_IO;
    }
    posix_spawn_file_actions_t actions;
    int rc = posix_spawn_file_actions_init(&actions);
    int actions_initialized = rc == 0;
    if (rc == 0 && input)
        rc = posix_spawn_file_actions_adddup2(&actions, input_fd, STDIN_FILENO);
    if (rc == 0 && input)
        rc = posix_spawn_file_actions_addclose(&actions, input_fd);
    if (rc == 0) rc = posix_spawn_file_actions_adddup2(&actions, pipe_fds[1], STDOUT_FILENO);
    if (rc == 0) rc = posix_spawn_file_actions_addclose(&actions, pipe_fds[0]);
    if (rc == 0) rc = posix_spawn_file_actions_addclose(&actions, pipe_fds[1]);
    if (rc != 0) {
        if (actions_initialized) (void)posix_spawn_file_actions_destroy(&actions);
        close(pipe_fds[0]); close(pipe_fds[1]);
        mg_error_set(error, MAELYS_GIT_ERR_PROCESS, rc, "spawn action setup failed: %s", strerror(rc));
        return MAELYS_GIT_ERR_PROCESS;
    }
    pid_t pid = 0;
    maelys_git_result_t spawn_result = mg_spawn_isolated(
        &pid, executable, &actions, argv, error);
    (void)posix_spawn_file_actions_destroy(&actions);
    close(pipe_fds[1]);
    if (spawn_result != MAELYS_GIT_OK) {
        close(pipe_fds[0]);
        return spawn_result;
    }
    unsigned char buffer[16384];
    size_t total = 0u;
    int overflow = 0;
    int64_t started = mg_monotonic_ms();
    for (;;) {
        struct pollfd descriptor = {.fd = pipe_fds[0], .events = POLLIN | POLLHUP};
        int ready = poll(&descriptor, 1u, 100);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0) {
            int saved = errno;
            mg_terminate_process_group(pid);
            close(pipe_fds[0]);
            (void)waitpid(pid, NULL, 0);
            mg_error_set(error, MAELYS_GIT_ERR_IO, saved,
                         "poll child output failed: %s", strerror(saved));
            return MAELYS_GIT_ERR_IO;
        }
        int64_t now = mg_monotonic_ms();
        if (started >= 0 && now >= 0 && now - started >= MG_PROCESS_TIMEOUT_MS) {
            mg_terminate_process_group(pid); close(pipe_fds[0]);
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
                mg_terminate_process_group(pid); close(pipe_fds[0]); (void)waitpid(pid, NULL, 0);
                mg_error_set(error, MAELYS_GIT_ERR_IO, saved,
                             "write child output failed: %s", strerror(saved));
                return MAELYS_GIT_ERR_IO;
            }
            total += (size_t)count;
            if (overflow) mg_terminate_process_group(pid);
            continue;
        }
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) {
            int saved = errno;
            mg_terminate_process_group(pid); close(pipe_fds[0]); (void)waitpid(pid, NULL, 0);
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
    maelys_git_result_t result = wait_child(
        pid, MG_PROCESS_TIMEOUT_MS, out_exit_status, 0, error);
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
