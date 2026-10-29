/* Isolated subprocess execution. Every child runs from an absolute path with
 * an allowlisted environment and a wall-clock budget. Git children join their
 * supervised executor's group; standalone children get a new group. */
#include "internal.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#if defined(__APPLE__)
#include <sys/event.h>
#elif defined(__linux__)
#include <sys/syscall.h>
#endif

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

static _Thread_local char receive_objects[PATH_MAX + 32u];
static _Thread_local char receive_alternates[4u * PATH_MAX + 48u];

void mg_receive_objects_end(void) {
    receive_objects[0] = receive_alternates[0] = '\0';
}

maelys_git_result_t mg_receive_objects_begin(const char *repository_path,
                                             maelys_git_error_t *error) {
    mg_receive_objects_end();
    const char *objects = getenv("GIT_OBJECT_DIRECTORY");
    const char *quarantine = getenv("GIT_QUARANTINE_PATH");
    if (!objects && !quarantine && !getenv("GIT_ALTERNATE_OBJECT_DIRECTORIES"))
        return MAELYS_GIT_OK;
    char repository[PATH_MAX], main_objects[PATH_MAX], incoming[PATH_MAX], actual[PATH_MAX];
    struct stat status;
    if (!objects || !quarantine || !repository_path ||
        !realpath(repository_path, repository)) goto denied;
    int length = snprintf(main_objects, sizeof(main_objects), "%s/objects", repository);
    if (length < 0 || (size_t)length >= sizeof(main_objects) ||
        lstat(main_objects, &status) != 0 || !S_ISDIR(status.st_mode) ||
        !realpath(quarantine, incoming) || !realpath(objects, actual) ||
        strcmp(incoming, actual) != 0) goto denied;
    size_t prefix = strlen(main_objects);
    if (strncmp(incoming, main_objects, prefix) != 0 ||
        incoming[prefix] != '/' || !incoming[prefix + 1u] ||
        strchr(incoming + prefix + 1u, '/') ||
        lstat(quarantine, &status) != 0 || !S_ISDIR(status.st_mode) ||
        status.st_uid != geteuid()) goto denied;
    (void)snprintf(receive_objects, sizeof(receive_objects), "GIT_OBJECT_DIRECTORY=%s", incoming);
    /* Git accepts C-quoted entries in its colon-separated alternate list.
     * Reconstruct the only permitted alternate, never copy the incoming list. */
    size_t used = (size_t)snprintf(receive_alternates, sizeof(receive_alternates),
                                  "GIT_ALTERNATE_OBJECT_DIRECTORIES=\"");
    for (const unsigned char *p = (const unsigned char *)main_objects; *p; ++p) {
        if (*p == '\\' || *p == '"') receive_alternates[used++] = '\\';
        if (*p < 32u || *p == 127u) {
            int count = snprintf(receive_alternates + used, sizeof(receive_alternates) - used,
                                  "\\%03o", (unsigned)*p);
            used += (size_t)count;
        } else receive_alternates[used++] = (char)*p;
    }
    receive_alternates[used++] = '"';
    receive_alternates[used] = '\0';
    return MAELYS_GIT_OK;
denied:
    mg_error_set(error, MAELYS_GIT_ERR_DENIED, 0,
                 "receive quarantine must be a direct incoming directory of this repository");
    return MAELYS_GIT_ERR_DENIED;
}

/* This marker is emitted only by mg_spawn_executor and is not forwarded to
 * Git. A supervised executor is the leader of the group owned by the agent. */
static pid_t supervised_group(void) {
    const char *marker = getenv("MAELYS_GIT_SUPERVISED");
    return marker && strcmp(marker, "1") == 0 && getpgrp() == getpid() ? getpid() : 0;
}

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

static maelys_git_result_t spawn_isolated(
    pid_t *out_pid,
    const char *executable,
    const posix_spawn_file_actions_t *actions,
    char *const argv[],
    int executor,
    maelys_git_error_t *error) {
    if (!out_pid || !executable || !argv || executable[0] != '/')
        return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    posix_spawnattr_t attributes;
    int rc = posix_spawnattr_init(&attributes);
    int initialized = rc == 0;
    if (rc == 0) rc = posix_spawnattr_setpgroup(&attributes, executor ? 0 : supervised_group());
    if (rc == 0) rc = posix_spawnattr_setflags(&attributes, POSIX_SPAWN_SETPGROUP);
    /* Only the absolute service-account HOME survives: Git reads signature
     * trust stores from it. Everything else comes from the allowlist. */
    char home_entry[PATH_MAX + 6u];
    const char *home = getenv("HOME");
    int home_length = home && home[0] == '/' ?
        snprintf(home_entry, sizeof(home_entry), "HOME=%s", home) : -1;
    if (home_length < 0 || (size_t)home_length >= sizeof(home_entry))
        (void)snprintf(home_entry, sizeof(home_entry), "HOME=/nonexistent");
    char *environment[sizeof(isolated_environment) / sizeof(isolated_environment[0]) + 4u];
    size_t environment_index = 0u;
    environment[environment_index++] = home_entry;
    for (size_t i = 0u; isolated_environment[i]; ++i)
        environment[environment_index++] = isolated_environment[i];
    if (executor) environment[environment_index++] = "MAELYS_GIT_SUPERVISED=1";
    else if (receive_objects[0]) {
        environment[environment_index++] = receive_objects;
        environment[environment_index++] = receive_alternates;
    }
    environment[environment_index] = NULL;
    if (rc == 0)
        rc = posix_spawn(out_pid, executable, actions, &attributes, argv, environment);
    if (initialized) (void)posix_spawnattr_destroy(&attributes);
    if (rc != 0) {
        mg_error_set(error, MAELYS_GIT_ERR_PROCESS, rc,
                     "isolated posix_spawn failed: %s", strerror(rc));
        return MAELYS_GIT_ERR_PROCESS;
    }
    return MAELYS_GIT_OK;
}

maelys_git_result_t mg_spawn_isolated(
    pid_t *out_pid, const char *executable,
    const posix_spawn_file_actions_t *actions, char *const argv[],
    maelys_git_error_t *error) {
    return spawn_isolated(out_pid, executable, actions, argv, 0, error);
}

maelys_git_result_t mg_spawn_executor(
    pid_t *out_pid, const char *executable,
    const posix_spawn_file_actions_t *actions, char *const argv[],
    maelys_git_error_t *error) {
    return spawn_isolated(out_pid, executable, actions, argv, 1, error);
}

void mg_terminate_process_group(pid_t pid) {
    if (pid <= 0) return;
    /* Inside a supervised executor the agent owns group cleanup, including
     * after a local Git failure. Do not terminate ourselves while encoding it. */
    pid_t target = supervised_group() ? pid : -pid;
    if (kill(target, SIGTERM) != 0 && errno == ESRCH) return;
    struct timespec pause = {.tv_sec = 0, .tv_nsec = 100000000L};
    (void)nanosleep(&pause, NULL);
    (void)kill(target, SIGKILL);
}

static void reap_child(pid_t pid) {
    int status = 0;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
    }
}

/* 0 once the budget is spent or the clock cannot be trusted. */
static uint64_t remaining_ms(int64_t started, uint64_t timeout_ms) {
    int64_t now = mg_monotonic_ms();
    if (started < 0 || now < started || (uint64_t)(now - started) >= timeout_ms) return 0u;
    return timeout_ms - (uint64_t)(now - started);
}

static int deadline_elapsed(int64_t started, uint64_t timeout_ms) {
    return remaining_ms(started, timeout_ms) == 0u;
}

static maelys_git_result_t timeout_failure(maelys_git_error_t *error, uint64_t timeout_ms) {
    mg_error_set(error, MAELYS_GIT_ERR_PROCESS, 0,
                 "child process group exceeded the %" PRIu64 " ms execution limit",
                 timeout_ms);
    return MAELYS_GIT_ERR_PROCESS;
}

/* An exit watcher lets the wait block until the child exits, bounded by the
 * remaining budget, instead of sleeping a fixed quantum: kqueue EVFILT_PROC
 * on macOS, a pidfd on Linux. No signal handler is installed. -1 means no
 * watcher; the wait then backs off. Either descriptor is close-on-exec: a
 * kqueue is never inherited, pidfd_open sets O_CLOEXEC. */
static int exit_watcher_open(pid_t pid) {
#if defined(MG_PROCESS_NO_EXIT_WATCHER)
    /* A test build that runs the backoff, as a host without a watcher would. */
    (void)pid;
    return -1;
#elif defined(__APPLE__)
    int queue = kqueue();
    if (queue < 0) return -1;
    struct kevent change;
    EV_SET(&change, (uintptr_t)pid, EVFILT_PROC, EV_ADD | EV_ONESHOT, NOTE_EXIT, 0, NULL);
    if (kevent(queue, &change, 1, NULL, 0, NULL) != 0) {
        (void)close(queue);
        return -1;
    }
    return queue;
#elif defined(__linux__) && defined(SYS_pidfd_open)
    long descriptor = syscall(SYS_pidfd_open, pid, 0u);
    return descriptor < 0 ? -1 : (int)descriptor;
#else
    (void)pid;
    return -1;
#endif
}

/* 1 when the watcher reported the exit, 0 on timeout or interruption, -1 when
 * it failed. */
static int exit_watcher_wait(int watcher, uint64_t budget_ms) {
    if (budget_ms > INT32_MAX) budget_ms = INT32_MAX;
#if defined(__APPLE__)
    struct timespec limit = {.tv_sec = (time_t)(budget_ms / 1000u),
                             .tv_nsec = (long)(budget_ms % 1000u) * 1000000L};
    struct kevent event;
    int ready = kevent(watcher, NULL, 0, &event, 1, &limit);
#else
    struct pollfd descriptor = {.fd = watcher, .events = POLLIN};
    int ready = poll(&descriptor, 1u, (int)budget_ms);
#endif
    if (ready < 0) return errno == EINTR ? 0 : -1;
    return ready > 0;
}

static maelys_git_result_t wait_child(pid_t pid,
                                      int64_t started,
                                      uint64_t timeout_ms,
                                      int *out_exit_status,
                                      int require_success,
                                      maelys_git_error_t *error) {
    int status = 0;
    int watcher = -1, watched = 0;
    long backoff_ns = 50000L;
    for (;;) {
        pid_t waited = waitpid(pid, &status, WNOHANG);
        if (waited == pid) break;
        if (waited < 0 && errno != EINTR) {
            int saved = errno;
            if (watcher >= 0) (void)close(watcher);
            mg_error_set(error, MAELYS_GIT_ERR_PROCESS, saved,
                         "waitpid failed: %s", strerror(saved));
            return MAELYS_GIT_ERR_PROCESS;
        }
        uint64_t remaining = remaining_ms(started, timeout_ms);
        if (remaining == 0u) {
            if (watcher >= 0) (void)close(watcher);
            mg_terminate_process_group(pid);
            reap_child(pid);
            return timeout_failure(error, timeout_ms);
        }
        /* Look again once the watcher exists: an exit just before it was
         * registered may not be reported. */
        if (!watched) {
            watched = 1;
            watcher = exit_watcher_open(pid);
            continue;
        }
        /* A reported exit can precede the moment waitpid sees it; a kqueue
         * reports it once and a pidfd stays readable: back off after it. */
        if (watcher >= 0 && exit_watcher_wait(watcher, remaining) != 0) {
            (void)close(watcher);
            watcher = -1;
        } else if (watcher < 0) {
            long limit_ns = remaining < 10u ? (long)remaining * 1000000L : 10000000L;
            struct timespec pause = {.tv_sec = 0,
                                     .tv_nsec = backoff_ns < limit_ns ? backoff_ns : limit_ns};
            (void)nanosleep(&pause, NULL);
            if (backoff_ns < 10000000L) backoff_ns *= 2;
        }
    }
    if (watcher >= 0) (void)close(watcher);
    int exit_status = WIFEXITED(status) ? WEXITSTATUS(status) : 128;
    if (out_exit_status) *out_exit_status = exit_status;
    if (!WIFEXITED(status) || (require_success && exit_status != 0)) {
        mg_error_set(error, MAELYS_GIT_ERR_PROCESS, 0,
                     "child process failed with status %d", exit_status);
        return MAELYS_GIT_ERR_PROCESS;
    }
    return MAELYS_GIT_OK;
}

/* ---- children whose stdout is consumed by the parent ---------------------- */

typedef struct {
    pid_t pid;
    int output_fd;
    int diagnostic_fd;
    char diagnostic[256];
} child_output_t;

/* Private stdout/stderr pipes keep child diagnostics out of CLI envelopes.
 * Protocol streams use the lower-level spawn interface instead. */
static maelys_git_result_t spawn_with_output_pipe(const char *executable,
                                                  char *const argv[],
                                                  int input_fd,
                                                  child_output_t *out,
                                                  maelys_git_error_t *error) {
    memset(out, 0, sizeof(*out));
    int pipe_fds[2], diagnostic_fds[2];
    if (!mg_pipe_cloexec(pipe_fds)) {
        mg_error_set(error, MAELYS_GIT_ERR_IO, errno, "pipe failed: %s", strerror(errno));
        return MAELYS_GIT_ERR_IO;
    }
    if (!mg_pipe_cloexec(diagnostic_fds)) {
        int saved = errno;
        (void)close(pipe_fds[0]);
        (void)close(pipe_fds[1]);
        mg_error_set(error, MAELYS_GIT_ERR_IO, saved, "diagnostic pipe failed: %s", strerror(saved));
        return MAELYS_GIT_ERR_IO;
    }
    posix_spawn_file_actions_t actions;
    int rc = posix_spawn_file_actions_init(&actions);
    int actions_initialized = rc == 0;
    if (rc == 0 && input_fd >= 0)
        rc = posix_spawn_file_actions_adddup2(&actions, input_fd, STDIN_FILENO);
    if (rc == 0 && input_fd > STDIN_FILENO)
        rc = posix_spawn_file_actions_addclose(&actions, input_fd);
    if (rc == 0) rc = posix_spawn_file_actions_adddup2(&actions, pipe_fds[1], STDOUT_FILENO);
    if (rc == 0) rc = posix_spawn_file_actions_addclose(&actions, pipe_fds[0]);
    if (rc == 0) rc = posix_spawn_file_actions_addclose(&actions, pipe_fds[1]);
    if (rc == 0) rc = posix_spawn_file_actions_adddup2(&actions, diagnostic_fds[1], STDERR_FILENO);
    if (rc == 0) rc = posix_spawn_file_actions_addclose(&actions, diagnostic_fds[0]);
    if (rc == 0) rc = posix_spawn_file_actions_addclose(&actions, diagnostic_fds[1]);
    if (rc != 0) {
        if (actions_initialized) (void)posix_spawn_file_actions_destroy(&actions);
        (void)close(pipe_fds[0]);
        (void)close(pipe_fds[1]);
        (void)close(diagnostic_fds[0]);
        (void)close(diagnostic_fds[1]);
        mg_error_set(error, MAELYS_GIT_ERR_PROCESS, rc,
                     "spawn action setup failed: %s", strerror(rc));
        return MAELYS_GIT_ERR_PROCESS;
    }
    pid_t pid = 0;
    maelys_git_result_t result = mg_spawn_isolated(&pid, executable, &actions, argv, error);
    (void)posix_spawn_file_actions_destroy(&actions);
    (void)close(pipe_fds[1]);
    (void)close(diagnostic_fds[1]);
    if (result != MAELYS_GIT_OK) {
        (void)close(pipe_fds[0]);
        (void)close(diagnostic_fds[0]);
        return result;
    }
    out->pid = pid;
    out->output_fd = pipe_fds[0];
    out->diagnostic_fd = diagnostic_fds[0];
    return MAELYS_GIT_OK;
}

typedef enum {
    SINK_CONTINUE = 0,
    SINK_ABORT = 1,  /* the sink refused more output; error is set (limit) */
    SINK_FAILED = -1 /* the sink could not store the output; error is set */
} sink_status_t;

typedef sink_status_t (*sink_fn)(void *context,
                                 const unsigned char *bytes,
                                 size_t count,
                                 maelys_git_error_t *error);

/* Drain both streams concurrently, keeping only a bounded diagnostic prefix.
 * Even oversized stderr must be drained so it cannot block the child. On any
 * failure the process group is terminated and reaped; the descriptor is
 * always closed before returning. */
static maelys_git_result_t pump_output(child_output_t *child,
                                       int64_t started,
                                       uint64_t timeout_ms,
                                       sink_fn sink,
                                       void *sink_context,
                                       maelys_git_error_t *error) {
    unsigned char buffer[16384];
    struct pollfd descriptors[2] = {
        {.fd = child->output_fd, .events = POLLIN | POLLHUP},
        {.fd = child->diagnostic_fd, .events = POLLIN | POLLHUP}};
    size_t diagnostic_used = 0u;
    maelys_git_result_t failure = MAELYS_GIT_OK;
    while (descriptors[0].fd >= 0 || descriptors[1].fd >= 0) {
        int ready = poll(descriptors, 2u, 100);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0) {
            mg_error_set(error, MAELYS_GIT_ERR_IO, errno,
                         "poll child output failed: %s", strerror(errno));
            failure = MAELYS_GIT_ERR_IO;
            break;
        }
        if (deadline_elapsed(started, timeout_ms)) {
            failure = timeout_failure(error, timeout_ms);
            break;
        }
        if (ready == 0) continue;
        for (size_t i = 0u; i < 2u; ++i) {
            if (descriptors[i].fd < 0 || !descriptors[i].revents) continue;
            ssize_t count = read(descriptors[i].fd, buffer, sizeof(buffer));
            if (count < 0 && errno == EINTR) continue;
            if (count < 0) {
                mg_error_set(error, MAELYS_GIT_ERR_IO, errno,
                             "read from child failed: %s", strerror(errno));
                failure = MAELYS_GIT_ERR_IO;
                break;
            }
            if (count == 0) {
                (void)close(descriptors[i].fd);
                descriptors[i].fd = -1;
            } else if (i == 0u) {
                sink_status_t status = sink(sink_context, buffer, (size_t)count, error);
                if (status == SINK_ABORT) failure = MAELYS_GIT_ERR_LIMIT;
                if (status == SINK_FAILED) failure = MAELYS_GIT_ERR_IO;
            } else {
                for (size_t j = 0u; j < (size_t)count &&
                     diagnostic_used < sizeof(child->diagnostic) - 1u; ++j) {
                    unsigned char byte = buffer[j];
                    /* Diagnostics can contain filenames with arbitrary bytes.
                     * Only printable ASCII reaches the strict CLI writer. */
                    child->diagnostic[diagnostic_used++] =
                        byte >= 32u && byte < 127u ? (char)byte : ' ';
                }
            }
            if (failure != MAELYS_GIT_OK) break;
        }
        if (failure != MAELYS_GIT_OK) break;
    }
    child->diagnostic[diagnostic_used] = '\0';
    if (failure != MAELYS_GIT_OK) mg_terminate_process_group(child->pid);
    for (size_t i = 0u; i < 2u; ++i)
        if (descriptors[i].fd >= 0) (void)close(descriptors[i].fd);
    if (failure != MAELYS_GIT_OK) reap_child(child->pid);
    return failure;
}

static maelys_git_result_t finish_child(child_output_t *child, int64_t started,
                                        uint64_t timeout_ms, int *status,
                                        maelys_git_error_t *error) {
    if (deadline_elapsed(started, timeout_ms)) {
        mg_terminate_process_group(child->pid);
        reap_child(child->pid);
        return timeout_failure(error, timeout_ms);
    }
    /* The budget runs from the spawn: a timeout names the configured limit. */
    maelys_git_result_t result = wait_child(child->pid, started, timeout_ms, status, 0, error);
    if (result == MAELYS_GIT_OK)
        mg_error_set(error, MAELYS_GIT_OK, 0, "%s", *status ? child->diagnostic : "");
    return result;
}

void mg_process_status_error(maelys_git_error_t *error, const char *operation, int status) {
    char diagnostic[256] = {0};
    if (error && error->code == MAELYS_GIT_OK)
        (void)snprintf(diagnostic, sizeof(diagnostic), "%.255s", error->message);
    mg_error_set(error, MAELYS_GIT_ERR_PROCESS, 0, "%s failed with status %d%s%s",
                 operation, status, diagnostic[0] ? ": " : "", diagnostic);
}

static sink_status_t discard_sink(void *context, const unsigned char *bytes,
                                   size_t count, maelys_git_error_t *error) {
    (void)context; (void)bytes; (void)count; (void)error;
    return SINK_CONTINUE;
}

static maelys_git_result_t run_process(const char *executable, char *const argv[],
                                      uint64_t timeout_ms, int require_success,
                                      int *out_exit_status, maelys_git_error_t *error) {
    if (!executable || !argv || timeout_ms == 0u) return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    child_output_t child;
    maelys_git_result_t result = spawn_with_output_pipe(executable, argv, -1, &child, error);
    if (result != MAELYS_GIT_OK) return result;
    int64_t started = mg_monotonic_ms();
    result = pump_output(&child, started, timeout_ms, discard_sink, NULL, error);
    int status = 0;
    if (result == MAELYS_GIT_OK) result = finish_child(&child, started, timeout_ms, &status, error);
    if (result != MAELYS_GIT_OK) return result;
    if (out_exit_status) *out_exit_status = status;
    if (require_success && status != 0) {
        mg_process_status_error(error, "child process", status);
        return MAELYS_GIT_ERR_PROCESS;
    }
    return MAELYS_GIT_OK;
}

maelys_git_result_t mg_process_run_with_timeout(const char *executable, char *const argv[],
    uint64_t timeout_ms, int *out_exit_status, maelys_git_error_t *error) {
    return run_process(executable, argv, timeout_ms, 1, out_exit_status, error);
}

maelys_git_result_t mg_process_run(const char *executable, char *const argv[],
    int *out_exit_status, maelys_git_error_t *error) {
    return run_process(executable, argv, MG_PROCESS_TIMEOUT_MS, 1, out_exit_status, error);
}

maelys_git_result_t mg_process_run_status(const char *executable, char *const argv[],
    int *out_exit_status, maelys_git_error_t *error) {
    if (!out_exit_status) return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    return run_process(executable, argv, MG_PROCESS_TIMEOUT_MS, 0, out_exit_status, error);
}

typedef struct {
    unsigned char *data;
    size_t used;
    size_t max_length;
    int overflow;
} capture_sink_t;

static sink_status_t capture_sink(void *context,
                                  const unsigned char *bytes,
                                  size_t count,
                                  maelys_git_error_t *error) {
    (void)error;
    capture_sink_t *sink = context;
    size_t room = sink->max_length - sink->used;
    size_t taken = count < room ? count : room;
    memcpy(sink->data + sink->used, bytes, taken);
    sink->used += taken;
    if (taken < count) sink->overflow = 1;
    return SINK_CONTINUE;
}

static maelys_git_result_t capture(const char *executable,
                                   char *const argv[],
                                   unsigned char **out_data,
                                   size_t *out_length,
                                   size_t max_length,
                                   int reject_overflow,
                                   int *out_exit_status,
                                   maelys_git_error_t *error) {
    if (!executable || !argv || !out_data || !out_length || max_length == 0u)
        return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    *out_data = NULL;
    *out_length = 0u;
    unsigned char *data = malloc(max_length + 1u);
    if (!data) {
        mg_error_set(error, MAELYS_GIT_ERR_IO, ENOMEM,
                     "unable to allocate process output buffer");
        return MAELYS_GIT_ERR_IO;
    }
    child_output_t child;
    maelys_git_result_t result = spawn_with_output_pipe(executable, argv, -1, &child, error);
    if (result != MAELYS_GIT_OK) {
        free(data);
        return result;
    }
    capture_sink_t sink = {.data = data, .max_length = max_length};
    int64_t started = mg_monotonic_ms();
    result = pump_output(&child, started, MG_PROCESS_TIMEOUT_MS,
                         capture_sink, &sink, error);
    int exit_status = 0;
    if (result == MAELYS_GIT_OK)
        result = finish_child(&child, started, MG_PROCESS_TIMEOUT_MS, &exit_status, error);
    if (result == MAELYS_GIT_OK && reject_overflow &&
        (sink.overflow || sink.used == max_length)) {
        mg_error_set(error, MAELYS_GIT_ERR_LIMIT, 0,
                     "child output exceeds %zu bytes", max_length);
        result = MAELYS_GIT_ERR_LIMIT;
    }
    if (result != MAELYS_GIT_OK) {
        free(data);
        return result;
    }
    data[sink.used] = '\0';
    *out_data = data;
    *out_length = sink.used;
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
    return capture(executable, argv, out_data, out_length, max_length, 1,
                   out_exit_status, error);
}

maelys_git_result_t mg_process_capture_prefix(const char *executable,
                                              char *const argv[],
                                              unsigned char **out_data,
                                              size_t *out_length,
                                              size_t prefix_length,
                                              int *out_exit_status,
                                              maelys_git_error_t *error) {
    return capture(executable, argv, out_data, out_length, prefix_length, 0,
                   out_exit_status, error);
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
        mg_process_status_error(error, "child process", status);
        return MAELYS_GIT_ERR_PROCESS;
    }
    return MAELYS_GIT_OK;
}

typedef struct {
    FILE *output;
    size_t max_length;
    size_t total;
} spool_sink_t;

static sink_status_t spool_sink(void *context,
                                const unsigned char *bytes,
                                size_t count,
                                maelys_git_error_t *error) {
    spool_sink_t *sink = context;
    if (count > sink->max_length - sink->total) {
        mg_error_set(error, MAELYS_GIT_ERR_LIMIT, 0,
                     "child output exceeds %zu bytes", sink->max_length);
        return SINK_ABORT;
    }
    if (fwrite(bytes, 1u, count, sink->output) != count) {
        mg_error_set(error, MAELYS_GIT_ERR_IO, errno,
                     "write child output failed: %s", strerror(errno));
        return SINK_FAILED;
    }
    sink->total += count;
    return SINK_CONTINUE;
}

static maelys_git_result_t spool(const char *executable,
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
    child_output_t child;
    maelys_git_result_t result = spawn_with_output_pipe(
        executable, argv, input_fd, &child, error);
    if (result != MAELYS_GIT_OK) return result;
    spool_sink_t sink = {.output = output, .max_length = max_length};
    int64_t started = mg_monotonic_ms();
    result = pump_output(&child, started, MG_PROCESS_TIMEOUT_MS,
                         spool_sink, &sink, error);
    if (result != MAELYS_GIT_OK) return result;
    result = finish_child(&child, started, MG_PROCESS_TIMEOUT_MS, out_exit_status, error);
    if (result == MAELYS_GIT_OK && fflush(output) != 0) {
        mg_error_set(error, MAELYS_GIT_ERR_IO, errno,
                     "flush child output failed: %s", strerror(errno));
        return MAELYS_GIT_ERR_IO;
    }
    return result;
}

maelys_git_result_t mg_process_to_file(const char *executable,
                                       char *const argv[],
                                       FILE *output,
                                       int *out_exit_status,
                                       maelys_git_error_t *error) {
    return spool(executable, argv, NULL, output, 256u * 1024u * 1024u,
                 out_exit_status, error);
}

maelys_git_result_t mg_process_spool_status(const char *executable,
                                            char *const argv[],
                                            FILE *output,
                                            size_t max_length,
                                            int *out_exit_status,
                                            maelys_git_error_t *error) {
    return spool(executable, argv, NULL, output, max_length, out_exit_status, error);
}

maelys_git_result_t mg_process_filter_spool_status(const char *executable,
                                                   char *const argv[],
                                                   FILE *input,
                                                   FILE *output,
                                                   size_t max_length,
                                                   int *out_exit_status,
                                                   maelys_git_error_t *error) {
    if (!input) return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    /* The child reads the descriptor directly: hand it the complete file
     * from its first byte. */
    if (fflush(input) != 0 || fseek(input, 0L, SEEK_SET) != 0) {
        mg_error_set(error, MAELYS_GIT_ERR_IO, errno,
                     "cannot rewind child input: %s", strerror(errno));
        return MAELYS_GIT_ERR_IO;
    }
    return spool(executable, argv, input, output, max_length, out_exit_status, error);
}
