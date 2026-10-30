#include "internal.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int fail(const char *message) {
    fprintf(stderr, "test_process: %s\n", message);
    return 1;
}

static void pause_ms(long milliseconds) {
    struct timespec delay = {
        .tv_sec = milliseconds / 1000,
        .tv_nsec = (milliseconds % 1000) * 1000000L};
    while (nanosleep(&delay, &delay) != 0 && errno == EINTR) {
    }
}

static int descendant_mode(const char *marker) {
    pid_t child = fork();
    if (child < 0) return 2;
    if (child == 0) {
        pause_ms(700);
        FILE *stream = fopen(marker, "wb");
        if (stream) {
            (void)fputs("survived\n", stream);
            (void)fclose(stream);
        }
        _exit(0);
    }
    pause_ms(5000);
    (void)waitpid(child, NULL, 0);
    return 0;
}

/* A child that closes its output, so the parent is past pump_output and
 * waiting for the exit, then outlives any budget and ignores SIGTERM. */
static int linger_mode(const char *marker) {
    FILE *stream = fopen(marker, "wb");
    if (!stream) return 2;
    (void)fprintf(stream, "%ld\n", (long)getpid());
    if (fclose(stream) != 0) return 2;
    (void)signal(SIGTERM, SIG_IGN);
    (void)close(STDOUT_FILENO);
    (void)close(STDERR_FILENO);
    pause_ms(30000);
    return 0;
}

/* Says whether SIGTERM is blocked and SIGPIPE ignored in this process. */
static int signals_mode(void) {
    sigset_t blocked;
    struct sigaction pipe_action;
    if (sigprocmask(SIG_BLOCK, NULL, &blocked) != 0 ||
        sigaction(SIGPIPE, NULL, &pipe_action) != 0)
        return 2;
    (void)printf("term-blocked=%d pipe-ignored=%d\n",
                 sigismember(&blocked, SIGTERM) == 1,
                 pipe_action.sa_handler == SIG_IGN);
    return 0;
}

/* The launcher of this process may block or ignore signals, as sshd ignores
 * SIGPIPE: a child starts with none blocked and every one at its default. */
static int child_starts_with_default_signals(const char *executable) {
    sigset_t term, saved;
    if (sigemptyset(&term) != 0 || sigaddset(&term, SIGTERM) != 0 ||
        sigprocmask(SIG_BLOCK, &term, &saved) != 0)
        return fail("cannot block SIGTERM");
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) return fail("cannot ignore SIGPIPE");
    char *signals_argv[] = {(char *)executable, "--signals", NULL};
    unsigned char *data = NULL;
    size_t length = 0u;
    maelys_git_error_t error = {0};
    maelys_git_result_t result = mg_process_capture(
        executable, signals_argv, &data, &length, 64u, &error);
    if (sigprocmask(SIG_SETMASK, &saved, NULL) != 0 ||
        signal(SIGPIPE, SIG_DFL) == SIG_ERR)
        return fail("cannot restore the test's signals");
    if (result != MAELYS_GIT_OK) return fail(error.message);
    int inherited = strcmp((char *)data, "term-blocked=0 pipe-ignored=0\n") != 0;
    if (inherited) fprintf(stderr, "test_process: child saw %s", (char *)data);
    free(data);
    return inherited ? fail("child inherited a blocked or ignored signal") : 0;
}

static int lingering_child_is_killed(const char *executable) {
    char directory[] = "/tmp/maelys-process-linger-XXXXXX";
    if (!mkdtemp(directory)) return fail("cannot create temporary directory");
    char marker[4096];
    int written = snprintf(marker, sizeof(marker), "%s/pid", directory);
    if (written < 0 || (size_t)written >= sizeof(marker))
        return fail("temporary marker path is too long");
    char *linger_argv[] = {(char *)executable, "--linger", marker, NULL};
    maelys_git_error_t error = {0};
    int64_t started = mg_monotonic_ms();
    maelys_git_result_t result = mg_process_run_with_timeout(
        executable, linger_argv, 200u, NULL, &error);
    int64_t elapsed = mg_monotonic_ms() - started;
    if (result != MAELYS_GIT_ERR_PROCESS ||
        !strstr(error.message, "exceeded the 200 ms execution limit"))
        return fail("a child that does not exit was not reported as timed out");
    if (elapsed < 200 || elapsed > 5000)
        return fail("a child that does not exit was not stopped at its deadline");
    FILE *stream = fopen(marker, "rb");
    long pid = 0;
    if (!stream || fscanf(stream, "%ld", &pid) != 1 || pid <= 0) {
        if (stream) (void)fclose(stream);
        return fail("lingering child did not record its pid");
    }
    (void)fclose(stream);
    /* Reaped: the pid no longer names a child, not even a zombie. */
    if (waitpid((pid_t)pid, NULL, WNOHANG) != -1 || errno != ECHILD)
        return fail("timed-out child was not reaped");
    if (unlink(marker) != 0 || rmdir(directory) != 0)
        return fail("cannot remove temporary directory");
    return 0;
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--diagnostics") == 0) {
        (void)fputs("diagnostic prefix: ", stderr);
        (void)fputc(255, stderr);
        (void)fputc(0, stderr);
        char block[4096];
        memset(block, 'x', sizeof(block));
        for (size_t i = 0; i < 64u; ++i) (void)fwrite(block, 1u, sizeof(block), stderr);
        (void)fputs("captured\n", stdout);
        return 7;
    }
    if (argc == 2 && strcmp(argv[1], "--closed-output") == 0) {
        (void)close(STDOUT_FILENO);
        (void)close(STDERR_FILENO);
        pause_ms(5000);
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "--descendant") == 0)
        return descendant_mode(argv[2]);
    if (argc == 3 && strcmp(argv[1], "--linger") == 0)
        return linger_mode(argv[2]);
    if (argc == 2 && strcmp(argv[1], "--signals") == 0) return signals_mode();
    if (argc == 2 && strcmp(argv[1], "--late-exit") == 0) {
        (void)close(STDOUT_FILENO);
        (void)close(STDERR_FILENO);
        pause_ms(50);
        return 3;
    }

    if (setenv("MAELYS_TEST_SECRET", "must-not-cross-exec", 1) != 0)
        return fail("cannot set test environment variable");
    char *env_argv[] = {"/usr/bin/env", NULL};
    unsigned char *environment = NULL;
    size_t environment_length = 0u;
    maelys_git_error_t error = {0};
    maelys_git_result_t result = mg_process_capture(
        "/usr/bin/env", env_argv, &environment, &environment_length,
        16u * 1024u, &error);
    if (result != MAELYS_GIT_OK) return fail(error.message);
    if (strstr((char *)environment, "MAELYS_TEST_SECRET") != NULL) {
        free(environment);
        return fail("child inherited an untrusted environment variable");
    }
    if (strstr((char *)environment, "GIT_CONFIG_NOSYSTEM=1") == NULL ||
        strstr((char *)environment, "GIT_TERMINAL_PROMPT=0") == NULL) {
        free(environment);
        return fail("child did not receive the isolated Git environment");
    }
    free(environment);

    char executable[4096];
    if (!realpath(argv[0], executable)) return fail("cannot resolve test executable");
    char *noisy_argv[] = {executable, "--diagnostics", NULL};
    unsigned char *data = NULL;
    size_t length = 0u;
    int child_status = 0;
    result = mg_process_capture_status(executable, noisy_argv, &data, &length,
                                       32u, &child_status, &error);
    if (result != MAELYS_GIT_OK || child_status != 7 || length != 9u ||
        strcmp((char *)data, "captured\n") ||
        !strstr(error.message, "diagnostic prefix:   x") || strlen(error.message) > 255u)
        return fail("stderr was not drained into a bounded sanitized diagnostic");
    free(data);
    result = mg_process_capture(executable, noisy_argv, &data, &length, 32u, &error);
    if (result != MAELYS_GIT_ERR_PROCESS || data || length ||
        !strstr(error.message, "diagnostic prefix:"))
        return fail("captured failure lost its diagnostic or returned stale output");
    char *closed_argv[] = {executable, "--closed-output", NULL};
    int64_t started = mg_monotonic_ms();
    result = mg_process_run_with_timeout(executable, closed_argv, 150u, NULL, &error);
    if (result != MAELYS_GIT_ERR_PROCESS || mg_monotonic_ms() - started > 1500)
        return fail("closed output bypassed the subprocess deadline");
    /* A child that exits some time after its output closed keeps its status:
     * the wait does not end with the output. */
    char *late_argv[] = {executable, "--late-exit", NULL};
    child_status = 0;
    result = mg_process_run_status(executable, late_argv, &child_status, &error);
    if (result != MAELYS_GIT_OK || child_status != 3)
        return fail("an exit after the output closed lost its status");
    if (child_starts_with_default_signals(executable) != 0) return 1;
    if (lingering_child_is_killed(executable) != 0) return 1;
    char directory[] = "/tmp/maelys-process-test-XXXXXX";
    if (!mkdtemp(directory)) return fail("cannot create temporary directory");
    char marker[4096];
    int written = snprintf(marker, sizeof(marker), "%s/descendant-marker", directory);
    if (written < 0 || (size_t)written >= sizeof(marker))
        return fail("temporary marker path is too long");
    char *child_argv[] = {executable, "--descendant", marker, NULL};
    maelys_git_error_clear(&error);
    result = mg_process_run_with_timeout(
        executable, child_argv, 100u, NULL, &error);
    if (result != MAELYS_GIT_ERR_PROCESS)
        return fail("timed process did not report a process error");
    pause_ms(900);
    struct stat status;
    if (lstat(marker, &status) == 0)
        return fail("timed-out descendant survived its process group");
    if (errno != ENOENT) return fail("cannot inspect descendant marker");
    if (rmdir(directory) != 0) return fail("cannot remove temporary directory");

    char *relative_argv[] = {"env", NULL};
    result = mg_process_run_with_timeout("env", relative_argv, 100u, NULL, &error);
    if (result != MAELYS_GIT_ERR_INVALID_ARGUMENT)
        return fail("relative executable path bypassed the isolated spawn contract");
    return 0;
}
