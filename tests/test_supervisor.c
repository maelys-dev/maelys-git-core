#include "agent/agent_internal.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

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

static int executor_mode(const char *marker) {
    /* An executor that exits before reading its request. */
    if (ends_with(marker, "/exit-early")) return 0;
    pid_t descendant = fork();
    if (descendant < 0) return 2;
    if (descendant == 0) {
        pause_ms(700);
        FILE *stream = fopen(marker, "wb");
        if (stream) {
            (void)fputs("survived\n", stream);
            (void)fclose(stream);
        }
        _exit(0);
    }
    pause_ms(5000);
    (void)waitpid(descendant, NULL, 0);
    return 0;
}

static int fail(const char *message) {
    fprintf(stderr, "test_supervisor: %s\n", message);
    return 1;
}

int main(int argc, char **argv) {
    if (argc >= 4 && strcmp(argv[1], "serve") == 0 &&
        strcmp(argv[2], "--manifest") == 0)
        return executor_mode(argv[3]);

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
    char *response = NULL;
    char *request = malloc(MAELYS_GIT_MAX_PROTOCOL_LINE + 1u);
    if (!request) return fail("cannot allocate supervisor request");
    memset(request, 'x', MAELYS_GIT_MAX_PROTOCOL_LINE);
    request[MAELYS_GIT_MAX_PROTOCOL_LINE] = '\0';
    maelys_git_error_t error = {0};
    maelys_git_result_t result = mg_supervisor_execute(
        &config, request, &response, &error);
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
    result = mg_supervisor_execute(&config, request, &response, &error);
    free(request);
    free(response);
    if (result == MAELYS_GIT_OK)
        return fail("executor that exited before reading was reported as success");
    if (rmdir(directory) != 0) return fail("cannot remove temporary directory");
    return 0;
}
