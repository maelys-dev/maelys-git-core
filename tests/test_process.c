#include "internal.h"

#include <errno.h>
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
